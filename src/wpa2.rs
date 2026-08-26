//! Allocation-free WPA2-Personal supplicant.
//!
//! This module implements the RSN four-way handshake for CCMP-128. It rejects
//! unsupported descriptor versions, stale replay counters, invalid MICs,
//! unexpected peers, malformed key data, and incomplete key installation.
//! The caller must provide each SNonce from a cryptographically secure random
//! source. Key bytes are cleared when their owners are dropped.

use aes::Aes128;
use aes::cipher::{Block, BlockDecrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::control::{KeyConfig, KeyType, RSN_CIPHER_CCMP_128};

/// Maximum complete EAPOL-Key frame retained by the supplicant.
pub const MAX_EAPOL_FRAME_LEN: usize = 512;
/// Maximum RSN information-element bytes sent in Message 2.
pub const MAX_RSN_IE_LEN: usize = 256;
/// Maximum encrypted key-data bytes accepted from an authenticator.
pub const MAX_KEY_DATA_LEN: usize = MAX_EAPOL_FRAME_LEN - 99;
/// WPA2 passphrase minimum length.
pub const WPA2_PASSPHRASE_MIN_LEN: usize = 8;
/// WPA2 passphrase maximum length.
pub const WPA2_PASSPHRASE_MAX_LEN: usize = 63;
/// WPA2 PBKDF2 iteration count.
pub const WPA2_PBKDF2_ITERATIONS: u32 = 4096;
/// CCMP temporal-key length.
pub const CCMP_KEY_LEN: usize = 16;
/// CCMP packet-number bytes accepted by the Nordic key command.
pub const CCMP_RECEIVE_SEQUENCE_LEN: usize = 6;
/// Pairwise transient-key length for WPA2-PSK with CCMP.
pub const WPA2_PTK_LEN: usize = 48;

const EAPOL_HEADER_LEN: usize = 4;
const EAPOL_KEY_FIXED_BODY_LEN: usize = 95;
const EAPOL_KEY_MIN_LEN: usize = EAPOL_HEADER_LEN + EAPOL_KEY_FIXED_BODY_LEN;
const EAPOL_PACKET_TYPE_KEY: u8 = 3;
const RSN_KEY_DESCRIPTOR_TYPE: u8 = 2;
const KEY_INFO_VERSION_MASK: u16 = 0x0007;
const KEY_INFO_PAIRWISE: u16 = 1 << 3;
const KEY_INFO_INSTALL: u16 = 1 << 6;
const KEY_INFO_ACK: u16 = 1 << 7;
const KEY_INFO_MIC: u16 = 1 << 8;
const KEY_INFO_SECURE: u16 = 1 << 9;
const KEY_INFO_ERROR: u16 = 1 << 10;
const KEY_INFO_REQUEST: u16 = 1 << 11;
const KEY_INFO_ENCRYPTED: u16 = 1 << 12;
const KEY_INFO_SMK: u16 = 1 << 13;
const KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES: u16 = 2;
const KEY_MIC_START: usize = 81;
const KEY_MIC_END: usize = 97;
const KEY_DATA_LENGTH_OFFSET: usize = 97;
const KEY_DATA_OFFSET: usize = 99;
const WPA2_PRF_LABEL: &[u8] = b"Pairwise key expansion";
const AES_KEY_WRAP_IV: [u8; 8] = [0xa6; 8];
const GTK_KDE_OUI_TYPE: [u8; 4] = [0x00, 0x0f, 0xac, 0x01];
const RSN_CIPHER_CCMP_SUITE: [u8; 4] = [0x00, 0x0f, 0xac, 0x04];
const RSN_AKM_PSK_SUITE: [u8; 4] = [0x00, 0x0f, 0xac, 0x02];
const RSN_CAP_MFPR: u16 = 1 << 6;
const RSN_CAP_MFPC: u16 = 1 << 7;

/// Nordic default-key flag.
pub const NRF_WIFI_KEY_DEFAULT: u16 = 1 << 0;
/// Nordic default-key type selector flag.
pub const NRF_WIFI_KEY_DEFAULT_TYPES: u16 = 1 << 1;
/// Nordic multicast default-key selector.
pub const NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST: u16 = 1 << 4;

/// WPA2 handshake phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2Phase {
    AwaitingMessage1,
    AwaitingMessage3,
    InstallingKeys,
    Complete,
    Failed,
}

/// Parsed EAPOL-Key message category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EapolKeyMessage {
    PairwiseMessage1,
    PairwiseMessage2,
    PairwiseMessage3,
    PairwiseMessage4,
    GroupMessage1,
    GroupMessage2,
    Other,
}

/// Fail-closed WPA2 error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2Error {
    InvalidPassphraseLength,
    InvalidSsidLength,
    InvalidRsnInformationElement,
    UnsupportedRsnCapabilities,
    InvalidSupplicantNonce,
    FrameTooShort,
    FrameTooLarge,
    LengthMismatch,
    NotEapolKey,
    UnsupportedProtocolVersion(u8),
    UnsupportedDescriptor,
    UnsupportedDescriptorVersion(u8),
    InvalidPairwiseKeyLength(u16),
    UnsupportedMessage,
    WrongPeer,
    InvalidPhase,
    StaleReplayCounter,
    ConflictingRetransmission,
    NewPairwiseHandshakeRequiresNonce,
    InvalidAuthenticatorNonce,
    InvalidMic,
    MissingEncryptedKeyData,
    InvalidEncryptedKeyData,
    KeyUnwrapIntegrity,
    MissingGroupKey,
    UnsupportedGroupKeyLength,
    Busy,
    StaleCompletion,
    InstallFailed,
    OutputTooSmall,
}

/// Pairwise master key. Bytes are cleared on drop.
pub struct Pmk([u8; 32]);

impl Pmk {
    /// Imports one provisioned 256-bit PSK.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives a WPA2 PSK from a passphrase and SSID.
    pub fn derive(passphrase: &[u8], ssid: &[u8]) -> Result<Self, Wpa2Error> {
        if !(WPA2_PASSPHRASE_MIN_LEN..=WPA2_PASSPHRASE_MAX_LEN).contains(&passphrase.len()) {
            return Err(Wpa2Error::InvalidPassphraseLength);
        }
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(Wpa2Error::InvalidSsidLength);
        }
        let mut bytes = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha1>(passphrase, ssid, WPA2_PBKDF2_ITERATIONS, &mut bytes);
        Ok(Self(bytes))
    }

    fn derive_ptk(
        &self,
        authenticator_address: [u8; 6],
        supplicant_address: [u8; 6],
        authenticator_nonce: [u8; 32],
        supplicant_nonce: [u8; 32],
    ) -> Ptk {
        let mut context = [0u8; 76];
        let (first_address, second_address) = ordered(&authenticator_address, &supplicant_address);
        context[..6].copy_from_slice(first_address);
        context[6..12].copy_from_slice(second_address);
        let (first_nonce, second_nonce) = ordered(&authenticator_nonce, &supplicant_nonce);
        context[12..44].copy_from_slice(first_nonce);
        context[44..76].copy_from_slice(second_nonce);

        let mut bytes = [0u8; WPA2_PTK_LEN];
        let mut written = 0usize;
        let mut counter = 0u8;
        while written < bytes.len() {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&self.0)
                .expect("a fixed WPA2 PMK length is valid for HMAC");
            mac.update(WPA2_PRF_LABEL);
            mac.update(&[0]);
            mac.update(&context);
            mac.update(&[counter]);
            let block = mac.finalize().into_bytes();
            let count = core::cmp::min(block.len(), bytes.len() - written);
            bytes[written..written + count].copy_from_slice(&block[..count]);
            written += count;
            counter = counter.wrapping_add(1);
        }
        context.zeroize();
        Ptk(bytes)
    }
}

impl Drop for Pmk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct Ptk([u8; WPA2_PTK_LEN]);

impl Ptk {
    fn kck(&self) -> &[u8; 16] {
        self.0[..16]
            .try_into()
            .expect("the KCK is the first 16 PTK bytes")
    }

    fn kek(&self) -> &[u8; 16] {
        self.0[16..32]
            .try_into()
            .expect("the KEK is PTK bytes 16 through 31")
    }

    fn temporal_key(&self) -> &[u8; CCMP_KEY_LEN] {
        self.0[32..48]
            .try_into()
            .expect("the CCMP key is PTK bytes 32 through 47")
    }
}

impl Drop for Ptk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One complete EAPOL-Key response.
pub struct EapolTxFrame {
    peer: [u8; 6],
    len: usize,
    bytes: [u8; MAX_EAPOL_FRAME_LEN],
}

impl EapolTxFrame {
    /// Returns the destination peer.
    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }

    /// Returns the EAPOL payload without an Ethernet header.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the EAPOL payload length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the frame has no bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for EapolTxFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

/// Pairwise CCMP key prepared for firmware installation.
pub struct PairwiseKeyInstall {
    peer: [u8; 6],
    key: [u8; CCMP_KEY_LEN],
}

impl PairwiseKeyInstall {
    /// Returns a Nordic key command view.
    pub fn key_config(&self) -> KeyConfig<'_> {
        KeyConfig {
            cipher_suite: RSN_CIPHER_CCMP_128,
            key_type: KeyType::Pairwise,
            key_index: 0,
            key: &self.key,
            sequence: &[],
            flags: 0,
        }
    }

    /// Returns the peer address.
    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }
}

impl Drop for PairwiseKeyInstall {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Group CCMP key prepared for firmware installation.
pub struct GroupKeyInstall {
    key_index: u8,
    key_len: usize,
    key: [u8; 32],
    receive_sequence: [u8; 8],
}

impl GroupKeyInstall {
    /// Returns a Nordic new-key command view.
    pub fn key_config(&self) -> KeyConfig<'_> {
        KeyConfig {
            cipher_suite: RSN_CIPHER_CCMP_128,
            key_type: KeyType::Group,
            key_index: self.key_index,
            key: &self.key[..self.key_len],
            sequence: &self.receive_sequence[..CCMP_RECEIVE_SEQUENCE_LEN],
            flags: NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST,
        }
    }

    /// Returns a Nordic set-default-key command view.
    pub fn default_key_config(&self) -> KeyConfig<'_> {
        KeyConfig {
            cipher_suite: 0,
            key_type: KeyType::Group,
            key_index: self.key_index,
            key: &[],
            sequence: &[],
            flags: NRF_WIFI_KEY_DEFAULT | NRF_WIFI_KEY_DEFAULT_TYPE_MULTICAST,
        }
    }

    /// Returns the GTK index.
    pub const fn key_index(&self) -> u8 {
        self.key_index
    }
}

impl Drop for GroupKeyInstall {
    fn drop(&mut self) {
        self.key.zeroize();
        self.receive_sequence.zeroize();
    }
}

/// Transaction produced by pairwise Message 3.
pub struct Wpa2KeyInstallRequest {
    ticket: u32,
    replay_counter: u64,
    pairwise: PairwiseKeyInstall,
    group: GroupKeyInstall,
    response: EapolTxFrame,
}

impl Wpa2KeyInstallRequest {
    /// Returns the pairwise key transaction.
    pub const fn pairwise(&self) -> &PairwiseKeyInstall {
        &self.pairwise
    }

    /// Returns the group key transaction.
    pub const fn group(&self) -> &GroupKeyInstall {
        &self.group
    }

    /// Returns the authenticator replay counter.
    pub const fn replay_counter(&self) -> u64 {
        self.replay_counter
    }
}

/// Transaction produced by a connected-state group-key Message 1.
pub struct Wpa2GroupKeyInstallRequest {
    ticket: u32,
    replay_counter: u64,
    group: GroupKeyInstall,
    response: EapolTxFrame,
}

impl Wpa2GroupKeyInstallRequest {
    /// Returns the group key transaction.
    pub const fn group(&self) -> &GroupKeyInstall {
        &self.group
    }

    /// Returns the authenticator replay counter.
    pub const fn replay_counter(&self) -> u64 {
        self.replay_counter
    }
}

/// Action produced by one EAPOL-Key input.
pub enum Wpa2Action {
    None,
    Transmit(EapolTxFrame),
    InstallKeys(Wpa2KeyInstallRequest),
    InstallGroupKey(Wpa2GroupKeyInstallRequest),
}

/// Allocation-free WPA2-Personal station supplicant.
pub struct Wpa2Supplicant {
    local: [u8; 6],
    peer: [u8; 6],
    phase: Wpa2Phase,
    pmk: Pmk,
    ptk: Option<Ptk>,
    supplicant_nonce: [u8; 32],
    authenticator_nonce: [u8; 32],
    rsn_ie_len: usize,
    rsn_ie: [u8; MAX_RSN_IE_LEN],
    message1_replay: Option<u64>,
    message1_digest: Option<[u8; 32]>,
    completed_replay: Option<u64>,
    completed_message3_digest: Option<[u8; 32]>,
    last_group_replay: Option<u64>,
    last_group_message1_digest: Option<[u8; 32]>,
    pending_ticket: Option<(u32, u64, bool)>,
    pending_frame_digest: Option<[u8; 32]>,
    next_ticket: u32,
}

impl Wpa2Supplicant {
    /// Creates one handshake. `supplicant_nonce` must come from a CSPRNG.
    pub fn new(
        local: [u8; 6],
        peer: [u8; 6],
        supplicant_nonce: [u8; 32],
        pmk: Pmk,
        rsn_ie: &[u8],
    ) -> Result<Self, Wpa2Error> {
        validate_supplicant_nonce(&supplicant_nonce)?;
        validate_rsn_ie(rsn_ie)?;
        let mut stored_rsn_ie = [0u8; MAX_RSN_IE_LEN];
        stored_rsn_ie[..rsn_ie.len()].copy_from_slice(rsn_ie);
        Ok(Self {
            local,
            peer,
            phase: Wpa2Phase::AwaitingMessage1,
            pmk,
            ptk: None,
            supplicant_nonce,
            authenticator_nonce: [0; 32],
            rsn_ie_len: rsn_ie.len(),
            rsn_ie: stored_rsn_ie,
            message1_replay: None,
            message1_digest: None,
            completed_replay: None,
            completed_message3_digest: None,
            last_group_replay: None,
            last_group_message1_digest: None,
            pending_ticket: None,
            pending_frame_digest: None,
            next_ticket: 1,
        })
    }

    /// Returns the current handshake phase.
    pub const fn phase(&self) -> Wpa2Phase {
        self.phase
    }

    /// Returns the configured supplicant address.
    pub const fn local(&self) -> [u8; 6] {
        self.local
    }

    /// Returns the configured authenticator address.
    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }

    /// Starts a new pairwise handshake with a fresh CSPRNG nonce.
    pub fn restart_pairwise(&mut self, supplicant_nonce: [u8; 32]) -> Result<(), Wpa2Error> {
        validate_supplicant_nonce(&supplicant_nonce)?;
        if self.pending_ticket.is_some() {
            return Err(Wpa2Error::Busy);
        }
        self.ptk = None;
        self.supplicant_nonce.zeroize();
        self.supplicant_nonce = supplicant_nonce;
        self.authenticator_nonce.zeroize();
        self.message1_replay = None;
        clear_digest(&mut self.message1_digest);
        self.completed_replay = None;
        clear_digest(&mut self.completed_message3_digest);
        self.last_group_replay = None;
        clear_digest(&mut self.last_group_message1_digest);
        clear_digest(&mut self.pending_frame_digest);
        self.phase = Wpa2Phase::AwaitingMessage1;
        Ok(())
    }

    /// Processes one complete EAPOL-Key payload from `peer`.
    pub fn on_eapol(&mut self, peer: [u8; 6], bytes: &[u8]) -> Result<Wpa2Action, Wpa2Error> {
        if peer != self.peer {
            return self.fail(Wpa2Error::WrongPeer);
        }
        let frame = EapolKeyFrame::parse(bytes)?;
        if frame.key_info().descriptor_version() != KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES as u8 {
            return self.fail(Wpa2Error::UnsupportedDescriptorVersion(
                frame.key_info().descriptor_version(),
            ));
        }
        let message = frame.message();
        if matches!(
            message,
            EapolKeyMessage::PairwiseMessage1 | EapolKeyMessage::PairwiseMessage3
        ) && frame.key_length() != CCMP_KEY_LEN as u16
        {
            return self.fail(Wpa2Error::InvalidPairwiseKeyLength(frame.key_length()));
        }
        let digest = frame.digest();
        if let Some((_, replay, group)) = self.pending_ticket {
            if frame.replay_counter() == replay {
                let expected = if group {
                    EapolKeyMessage::GroupMessage1
                } else {
                    EapolKeyMessage::PairwiseMessage3
                };
                if message == expected && self.pending_frame_digest == Some(digest) {
                    return Ok(Wpa2Action::None);
                }
                return self.fail(Wpa2Error::ConflictingRetransmission);
            }
            return Err(Wpa2Error::Busy);
        }
        match message {
            EapolKeyMessage::PairwiseMessage1 => self.on_message1(frame),
            EapolKeyMessage::PairwiseMessage3 => self.on_message3(frame),
            EapolKeyMessage::GroupMessage1 => self.on_group_message1(frame),
            _ => self.fail(Wpa2Error::UnsupportedMessage),
        }
    }

    /// Completes the atomic pairwise and group key installation transaction.
    pub fn complete_key_install(
        &mut self,
        request: Wpa2KeyInstallRequest,
        installed: bool,
    ) -> Result<EapolTxFrame, Wpa2Error> {
        if self.pending_ticket != Some((request.ticket, request.replay_counter, false)) {
            return self.fail(Wpa2Error::StaleCompletion);
        }
        let Some(digest) = self.pending_frame_digest.take() else {
            return self.fail(Wpa2Error::StaleCompletion);
        };
        self.pending_ticket = None;
        if !installed {
            return self.fail(Wpa2Error::InstallFailed);
        }
        self.completed_replay = Some(request.replay_counter);
        self.completed_message3_digest = Some(digest);
        self.phase = Wpa2Phase::Complete;
        Ok(request.response)
    }

    /// Completes one connected-state GTK installation transaction.
    pub fn complete_group_key_install(
        &mut self,
        request: Wpa2GroupKeyInstallRequest,
        installed: bool,
    ) -> Result<EapolTxFrame, Wpa2Error> {
        if self.pending_ticket != Some((request.ticket, request.replay_counter, true)) {
            return self.fail(Wpa2Error::StaleCompletion);
        }
        let Some(digest) = self.pending_frame_digest.take() else {
            return self.fail(Wpa2Error::StaleCompletion);
        };
        self.pending_ticket = None;
        if !installed {
            return self.fail(Wpa2Error::InstallFailed);
        }
        self.completed_replay = Some(request.replay_counter);
        self.last_group_replay = Some(request.replay_counter);
        self.last_group_message1_digest = Some(digest);
        self.phase = Wpa2Phase::Complete;
        Ok(request.response)
    }

    fn on_message1(&mut self, frame: EapolKeyFrame<'_>) -> Result<Wpa2Action, Wpa2Error> {
        if !frame.key_data().is_empty() {
            return self.fail(Wpa2Error::UnsupportedMessage);
        }
        let replay = frame.replay_counter();
        let nonce = *frame.nonce();
        let digest = frame.digest();
        if nonce.iter().all(|value| *value == 0) {
            return self.fail(Wpa2Error::InvalidAuthenticatorNonce);
        }

        if self.phase == Wpa2Phase::Complete {
            if self.completed_replay == Some(replay) && self.authenticator_nonce == nonce {
                return self.fail(Wpa2Error::ConflictingRetransmission);
            }
            return Err(Wpa2Error::NewPairwiseHandshakeRequiresNonce);
        }
        if self.phase != Wpa2Phase::AwaitingMessage1 && self.phase != Wpa2Phase::AwaitingMessage3 {
            return self.fail(Wpa2Error::InvalidPhase);
        }

        if let Some(previous) = self.message1_replay {
            if replay < previous {
                return self.fail(Wpa2Error::StaleReplayCounter);
            }
            if replay == previous {
                if self.authenticator_nonce != nonce || self.message1_digest != Some(digest) {
                    return self.fail(Wpa2Error::ConflictingRetransmission);
                }
                let ptk = self.ptk.as_ref().ok_or(Wpa2Error::InvalidPhase)?;
                return Ok(Wpa2Action::Transmit(build_message2(
                    self.peer,
                    frame.protocol_version(),
                    frame.key_length(),
                    replay,
                    self.supplicant_nonce,
                    &self.rsn_ie[..self.rsn_ie_len],
                    ptk,
                )?));
            }
            return Err(Wpa2Error::NewPairwiseHandshakeRequiresNonce);
        }

        self.authenticator_nonce = nonce;
        self.message1_replay = Some(replay);
        self.message1_digest = Some(digest);
        self.ptk = Some(
            self.pmk
                .derive_ptk(self.peer, self.local, nonce, self.supplicant_nonce),
        );
        self.phase = Wpa2Phase::AwaitingMessage3;
        let ptk = self.ptk.as_ref().ok_or(Wpa2Error::InvalidPhase)?;
        Ok(Wpa2Action::Transmit(build_message2(
            self.peer,
            frame.protocol_version(),
            frame.key_length(),
            replay,
            self.supplicant_nonce,
            &self.rsn_ie[..self.rsn_ie_len],
            ptk,
        )?))
    }

    fn on_message3(&mut self, frame: EapolKeyFrame<'_>) -> Result<Wpa2Action, Wpa2Error> {
        let digest = frame.digest();
        let ptk = self.ptk.as_ref().ok_or(Wpa2Error::InvalidPhase)?;
        if *frame.nonce() != self.authenticator_nonce {
            return self.fail(Wpa2Error::InvalidAuthenticatorNonce);
        }
        if !frame.verify_mic(ptk) {
            return self.fail(Wpa2Error::InvalidMic);
        }
        let replay = frame.replay_counter();

        if self.phase == Wpa2Phase::Complete {
            if self.completed_replay != Some(replay) {
                return self.fail(Wpa2Error::StaleReplayCounter);
            }
            if self.completed_message3_digest != Some(digest) {
                return self.fail(Wpa2Error::ConflictingRetransmission);
            }
            return Ok(Wpa2Action::Transmit(build_message4(
                self.peer,
                frame.protocol_version(),
                frame.key_length(),
                replay,
                ptk,
            )?));
        }
        if self.phase != Wpa2Phase::AwaitingMessage3 {
            return self.fail(Wpa2Error::InvalidPhase);
        }
        let message1_replay = self.message1_replay.ok_or(Wpa2Error::InvalidPhase)?;
        if replay <= message1_replay {
            return self.fail(Wpa2Error::StaleReplayCounter);
        }
        if !frame.key_info().encrypted_key_data() || frame.key_data().is_empty() {
            return self.fail(Wpa2Error::MissingEncryptedKeyData);
        }

        let mut plain = [0u8; MAX_KEY_DATA_LEN];
        let plain_len = aes_key_unwrap(ptk.kek(), frame.key_data(), &mut plain)?;
        let gtk = parse_gtk_kde(&plain[..plain_len])?;
        let mut group_key = [0u8; 32];
        group_key[..gtk.key.len()].copy_from_slice(gtk.key);
        let pairwise = PairwiseKeyInstall {
            peer: self.peer,
            key: *ptk.temporal_key(),
        };
        let group = GroupKeyInstall {
            key_index: gtk.key_index,
            key_len: gtk.key.len(),
            key: group_key,
            receive_sequence: *frame.key_receive_sequence(),
        };
        plain.zeroize();
        let response = build_message4(
            self.peer,
            frame.protocol_version(),
            frame.key_length(),
            replay,
            ptk,
        )?;
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        self.pending_ticket = Some((ticket, replay, false));
        self.pending_frame_digest = Some(digest);
        self.phase = Wpa2Phase::InstallingKeys;
        Ok(Wpa2Action::InstallKeys(Wpa2KeyInstallRequest {
            ticket,
            replay_counter: replay,
            pairwise,
            group,
            response,
        }))
    }

    fn on_group_message1(&mut self, frame: EapolKeyFrame<'_>) -> Result<Wpa2Action, Wpa2Error> {
        if self.phase != Wpa2Phase::Complete {
            return self.fail(Wpa2Error::InvalidPhase);
        }
        let digest = frame.digest();
        let ptk = self.ptk.as_ref().ok_or(Wpa2Error::InvalidPhase)?;
        let replay = frame.replay_counter();
        if self.last_group_replay == Some(replay) {
            if !frame.verify_mic(ptk) {
                return self.fail(Wpa2Error::InvalidMic);
            }
            if self.last_group_message1_digest != Some(digest) {
                return self.fail(Wpa2Error::ConflictingRetransmission);
            }
            return Ok(Wpa2Action::Transmit(build_group_message2(
                self.peer,
                frame.protocol_version(),
                frame.key_length(),
                replay,
                ptk,
            )?));
        }
        if replay <= self.completed_replay.unwrap_or(0) {
            return self.fail(Wpa2Error::StaleReplayCounter);
        }
        if !frame.verify_mic(ptk) {
            return self.fail(Wpa2Error::InvalidMic);
        }
        if !frame.key_info().encrypted_key_data() || frame.key_data().is_empty() {
            return self.fail(Wpa2Error::MissingEncryptedKeyData);
        }
        let mut plain = [0u8; MAX_KEY_DATA_LEN];
        let plain_len = aes_key_unwrap(ptk.kek(), frame.key_data(), &mut plain)?;
        let gtk = parse_gtk_kde(&plain[..plain_len])?;
        let mut group_key = [0u8; 32];
        group_key[..gtk.key.len()].copy_from_slice(gtk.key);
        let group = GroupKeyInstall {
            key_index: gtk.key_index,
            key_len: gtk.key.len(),
            key: group_key,
            receive_sequence: *frame.key_receive_sequence(),
        };
        plain.zeroize();
        let response = build_group_message2(
            self.peer,
            frame.protocol_version(),
            frame.key_length(),
            replay,
            ptk,
        )?;
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        self.pending_ticket = Some((ticket, replay, true));
        self.pending_frame_digest = Some(digest);
        Ok(Wpa2Action::InstallGroupKey(Wpa2GroupKeyInstallRequest {
            ticket,
            replay_counter: replay,
            group,
            response,
        }))
    }

    fn fail<T>(&mut self, error: Wpa2Error) -> Result<T, Wpa2Error> {
        self.ptk = None;
        self.supplicant_nonce.zeroize();
        self.authenticator_nonce.zeroize();
        self.message1_replay = None;
        clear_digest(&mut self.message1_digest);
        self.completed_replay = None;
        clear_digest(&mut self.completed_message3_digest);
        self.last_group_replay = None;
        clear_digest(&mut self.last_group_message1_digest);
        self.pending_ticket = None;
        clear_digest(&mut self.pending_frame_digest);
        self.phase = Wpa2Phase::Failed;
        Err(error)
    }
}

impl Drop for Wpa2Supplicant {
    fn drop(&mut self) {
        self.supplicant_nonce.zeroize();
        self.authenticator_nonce.zeroize();
        self.rsn_ie.zeroize();
        clear_digest(&mut self.message1_digest);
        clear_digest(&mut self.completed_message3_digest);
        clear_digest(&mut self.last_group_message1_digest);
        clear_digest(&mut self.pending_frame_digest);
    }
}

#[derive(Clone, Copy)]
struct EapolKeyInfo(u16);

impl EapolKeyInfo {
    const fn descriptor_version(self) -> u8 {
        (self.0 & KEY_INFO_VERSION_MASK) as u8
    }

    const fn is_pairwise(self) -> bool {
        self.0 & KEY_INFO_PAIRWISE != 0
    }

    const fn install(self) -> bool {
        self.0 & KEY_INFO_INSTALL != 0
    }

    const fn ack(self) -> bool {
        self.0 & KEY_INFO_ACK != 0
    }

    const fn mic(self) -> bool {
        self.0 & KEY_INFO_MIC != 0
    }

    const fn secure(self) -> bool {
        self.0 & KEY_INFO_SECURE != 0
    }

    const fn encrypted_key_data(self) -> bool {
        self.0 & KEY_INFO_ENCRYPTED != 0
    }

    const fn classify(self) -> EapolKeyMessage {
        if self.0 & (KEY_INFO_ERROR | KEY_INFO_REQUEST | KEY_INFO_SMK) != 0 {
            return EapolKeyMessage::Other;
        }
        if self.is_pairwise() {
            match (self.ack(), self.mic(), self.install(), self.secure()) {
                (true, false, false, false) => EapolKeyMessage::PairwiseMessage1,
                (false, true, false, false) => EapolKeyMessage::PairwiseMessage2,
                (true, true, true, true) => EapolKeyMessage::PairwiseMessage3,
                (false, true, false, true) => EapolKeyMessage::PairwiseMessage4,
                _ => EapolKeyMessage::Other,
            }
        } else {
            match (self.ack(), self.mic(), self.install(), self.secure()) {
                (true, true, _, true) => EapolKeyMessage::GroupMessage1,
                (false, true, false, true) => EapolKeyMessage::GroupMessage2,
                _ => EapolKeyMessage::Other,
            }
        }
    }
}

#[derive(Clone, Copy)]
struct EapolKeyFrame<'a> {
    bytes: &'a [u8],
    key_info: EapolKeyInfo,
    key_data: &'a [u8],
}

impl<'a> EapolKeyFrame<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Wpa2Error> {
        if bytes.len() < EAPOL_KEY_MIN_LEN {
            return Err(Wpa2Error::FrameTooShort);
        }
        if bytes.len() > MAX_EAPOL_FRAME_LEN {
            return Err(Wpa2Error::FrameTooLarge);
        }
        if !matches!(bytes[0], 1 | 2) {
            return Err(Wpa2Error::UnsupportedProtocolVersion(bytes[0]));
        }
        if bytes[1] != EAPOL_PACKET_TYPE_KEY {
            return Err(Wpa2Error::NotEapolKey);
        }
        let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let total = EAPOL_HEADER_LEN
            .checked_add(body_len)
            .ok_or(Wpa2Error::LengthMismatch)?;
        if total != bytes.len() || body_len < EAPOL_KEY_FIXED_BODY_LEN {
            return Err(Wpa2Error::LengthMismatch);
        }
        if bytes[4] != RSN_KEY_DESCRIPTOR_TYPE {
            return Err(Wpa2Error::UnsupportedDescriptor);
        }
        let key_data_len = u16::from_be_bytes([
            bytes[KEY_DATA_LENGTH_OFFSET],
            bytes[KEY_DATA_LENGTH_OFFSET + 1],
        ]) as usize;
        let key_data_end = KEY_DATA_OFFSET
            .checked_add(key_data_len)
            .ok_or(Wpa2Error::LengthMismatch)?;
        if key_data_end != total {
            return Err(Wpa2Error::LengthMismatch);
        }
        Ok(Self {
            bytes,
            key_info: EapolKeyInfo(u16::from_be_bytes([bytes[5], bytes[6]])),
            key_data: &bytes[KEY_DATA_OFFSET..key_data_end],
        })
    }

    const fn protocol_version(self) -> u8 {
        self.bytes[0]
    }

    const fn key_info(self) -> EapolKeyInfo {
        self.key_info
    }

    const fn message(self) -> EapolKeyMessage {
        self.key_info.classify()
    }

    fn key_length(self) -> u16 {
        u16::from_be_bytes([self.bytes[7], self.bytes[8]])
    }

    fn replay_counter(self) -> u64 {
        u64::from_be_bytes([
            self.bytes[9],
            self.bytes[10],
            self.bytes[11],
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
            self.bytes[16],
        ])
    }

    fn nonce(self) -> &'a [u8; 32] {
        self.bytes[17..49]
            .try_into()
            .expect("the parsed nonce range has 32 bytes")
    }

    fn key_receive_sequence(self) -> &'a [u8; 8] {
        self.bytes[65..73]
            .try_into()
            .expect("the parsed receive-sequence range has 8 bytes")
    }

    fn mic(self) -> &'a [u8; 16] {
        self.bytes[KEY_MIC_START..KEY_MIC_END]
            .try_into()
            .expect("the parsed MIC range has 16 bytes")
    }

    const fn key_data(self) -> &'a [u8] {
        self.key_data
    }

    fn digest(self) -> [u8; 32] {
        let digest = Sha256::digest(self.bytes);
        let mut output = [0u8; 32];
        output.copy_from_slice(&digest);
        output
    }

    fn verify_mic(self, ptk: &Ptk) -> bool {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(ptk.kck())
            .expect("a fixed WPA2 KCK length is valid for HMAC");
        mac.update(&self.bytes[..KEY_MIC_START]);
        mac.update(&[0; KEY_MIC_END - KEY_MIC_START]);
        mac.update(&self.bytes[KEY_MIC_END..]);
        mac.verify_truncated_left(self.mic()).is_ok()
    }
}

struct GtkKde<'a> {
    key_index: u8,
    key: &'a [u8],
}

fn parse_gtk_kde(bytes: &[u8]) -> Result<GtkKde<'_>, Wpa2Error> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes[offset] == 0 {
            break;
        }
        if offset + 2 > bytes.len() {
            return Err(Wpa2Error::MissingGroupKey);
        }
        let element_id = bytes[offset];
        let len = bytes[offset + 1] as usize;
        if len == 0 {
            break;
        }
        let end = offset
            .checked_add(2 + len)
            .ok_or(Wpa2Error::MissingGroupKey)?;
        if end > bytes.len() {
            return Err(Wpa2Error::MissingGroupKey);
        }
        let body = &bytes[offset + 2..end];
        if element_id == 0xdd && body.len() >= 4 && body[..4] == GTK_KDE_OUI_TYPE {
            if body.len() != 22 || body[4] & 0xf8 != 0 || body[5] != 0 {
                return Err(Wpa2Error::InvalidEncryptedKeyData);
            }
            let key = &body[6..];
            if key.len() != CCMP_KEY_LEN {
                return Err(Wpa2Error::UnsupportedGroupKeyLength);
            }
            return Ok(GtkKde {
                key_index: body[4] & 0x03,
                key,
            });
        }
        offset = end;
    }
    Err(Wpa2Error::MissingGroupKey)
}

fn aes_key_unwrap(kek: &[u8; 16], encrypted: &[u8], out: &mut [u8]) -> Result<usize, Wpa2Error> {
    if encrypted.len() < 24 || encrypted.len() & 7 != 0 {
        return Err(Wpa2Error::InvalidEncryptedKeyData);
    }
    let plain_len = encrypted.len() - 8;
    if plain_len > out.len() {
        return Err(Wpa2Error::OutputTooSmall);
    }
    let cipher = Aes128::new_from_slice(kek).map_err(|_| Wpa2Error::InvalidEncryptedKeyData)?;
    let n = plain_len / 8;
    let mut a = [0u8; 8];
    a.copy_from_slice(&encrypted[..8]);
    out[..plain_len].copy_from_slice(&encrypted[8..]);

    for round in (0..=5usize).rev() {
        for index in (1..=n).rev() {
            let t = (n * round + index) as u64;
            let mut block = Block::<Aes128>::default();
            let t_bytes = t.to_be_bytes();
            for position in 0..8 {
                block[position] = a[position] ^ t_bytes[position];
            }
            let start = (index - 1) * 8;
            block[8..].copy_from_slice(&out[start..start + 8]);
            cipher.decrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            out[start..start + 8].copy_from_slice(&block[8..]);
        }
    }
    if a != AES_KEY_WRAP_IV {
        out[..plain_len].zeroize();
        return Err(Wpa2Error::KeyUnwrapIntegrity);
    }
    Ok(plain_len)
}

fn build_message2(
    peer: [u8; 6],
    protocol_version: u8,
    key_length: u16,
    replay_counter: u64,
    supplicant_nonce: [u8; 32],
    rsn_ie: &[u8],
    ptk: &Ptk,
) -> Result<EapolTxFrame, Wpa2Error> {
    build_response(
        peer,
        protocol_version,
        KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_MIC,
        key_length,
        replay_counter,
        supplicant_nonce,
        rsn_ie,
        ptk,
    )
}

fn build_message4(
    peer: [u8; 6],
    protocol_version: u8,
    key_length: u16,
    replay_counter: u64,
    ptk: &Ptk,
) -> Result<EapolTxFrame, Wpa2Error> {
    build_response(
        peer,
        protocol_version,
        KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE,
        key_length,
        replay_counter,
        [0; 32],
        &[],
        ptk,
    )
}

fn build_group_message2(
    peer: [u8; 6],
    protocol_version: u8,
    key_length: u16,
    replay_counter: u64,
    ptk: &Ptk,
) -> Result<EapolTxFrame, Wpa2Error> {
    build_response(
        peer,
        protocol_version,
        KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_MIC | KEY_INFO_SECURE,
        key_length,
        replay_counter,
        [0; 32],
        &[],
        ptk,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_response(
    peer: [u8; 6],
    protocol_version: u8,
    key_info: u16,
    key_length: u16,
    replay_counter: u64,
    nonce: [u8; 32],
    key_data: &[u8],
    ptk: &Ptk,
) -> Result<EapolTxFrame, Wpa2Error> {
    let body_len = EAPOL_KEY_FIXED_BODY_LEN
        .checked_add(key_data.len())
        .ok_or(Wpa2Error::FrameTooLarge)?;
    let total = EAPOL_HEADER_LEN
        .checked_add(body_len)
        .ok_or(Wpa2Error::FrameTooLarge)?;
    if total > MAX_EAPOL_FRAME_LEN || key_data.len() > u16::MAX as usize {
        return Err(Wpa2Error::FrameTooLarge);
    }
    let mut frame = EapolTxFrame {
        peer,
        len: total,
        bytes: [0; MAX_EAPOL_FRAME_LEN],
    };
    frame.bytes[0] = protocol_version;
    frame.bytes[1] = EAPOL_PACKET_TYPE_KEY;
    frame.bytes[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
    frame.bytes[4] = RSN_KEY_DESCRIPTOR_TYPE;
    frame.bytes[5..7].copy_from_slice(&key_info.to_be_bytes());
    frame.bytes[7..9].copy_from_slice(&key_length.to_be_bytes());
    frame.bytes[9..17].copy_from_slice(&replay_counter.to_be_bytes());
    frame.bytes[17..49].copy_from_slice(&nonce);
    frame.bytes[KEY_DATA_LENGTH_OFFSET..KEY_DATA_OFFSET]
        .copy_from_slice(&(key_data.len() as u16).to_be_bytes());
    frame.bytes[KEY_DATA_OFFSET..total].copy_from_slice(key_data);

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(ptk.kck())
        .expect("a fixed WPA2 KCK length is valid for HMAC");
    mac.update(&frame.bytes[..total]);
    let mic = mac.finalize().into_bytes();
    frame.bytes[KEY_MIC_START..KEY_MIC_END].copy_from_slice(&mic[..16]);
    Ok(frame)
}

fn ordered<'a, const N: usize>(
    left: &'a [u8; N],
    right: &'a [u8; N],
) -> (&'a [u8; N], &'a [u8; N]) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn validate_supplicant_nonce(nonce: &[u8; 32]) -> Result<(), Wpa2Error> {
    if nonce.iter().all(|value| *value == 0) {
        Err(Wpa2Error::InvalidSupplicantNonce)
    } else {
        Ok(())
    }
}

fn validate_rsn_ie(rsn_ie: &[u8]) -> Result<(), Wpa2Error> {
    if rsn_ie.len() < 4
        || rsn_ie.len() > MAX_RSN_IE_LEN
        || rsn_ie[0] != 0x30
        || rsn_ie[1] as usize + 2 != rsn_ie.len()
    {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    let body = &rsn_ie[2..];
    let mut offset = 0usize;
    if take_u16(body, &mut offset)? != 1 {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    if take_suite(body, &mut offset)? != RSN_CIPHER_CCMP_SUITE {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }

    let pairwise_count = take_u16(body, &mut offset)? as usize;
    if pairwise_count == 0 {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    let pairwise_len = pairwise_count
        .checked_mul(4)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let pairwise_end = offset
        .checked_add(pairwise_len)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let pairwise = body
        .get(offset..pairwise_end)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    if !pairwise
        .chunks_exact(4)
        .any(|suite| suite == RSN_CIPHER_CCMP_SUITE)
    {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    offset = pairwise_end;

    let akm_count = take_u16(body, &mut offset)? as usize;
    if akm_count == 0 {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    let akm_len = akm_count
        .checked_mul(4)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let akm_end = offset
        .checked_add(akm_len)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let akms = body
        .get(offset..akm_end)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    if !akms.chunks_exact(4).any(|suite| suite == RSN_AKM_PSK_SUITE) {
        return Err(Wpa2Error::InvalidRsnInformationElement);
    }
    offset = akm_end;

    if offset == body.len() {
        return Ok(());
    }
    let capabilities = take_u16(body, &mut offset)?;
    if capabilities & (RSN_CAP_MFPR | RSN_CAP_MFPC) != 0 {
        return Err(Wpa2Error::UnsupportedRsnCapabilities);
    }
    if offset == body.len() {
        return Ok(());
    }
    let pmkid_count = take_u16(body, &mut offset)?;
    if pmkid_count != 0 {
        return Err(Wpa2Error::UnsupportedRsnCapabilities);
    }
    if offset == body.len() {
        return Ok(());
    }
    Err(Wpa2Error::UnsupportedRsnCapabilities)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, Wpa2Error> {
    let end = offset
        .checked_add(2)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    *offset = end;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn take_suite(bytes: &[u8], offset: &mut usize) -> Result<[u8; 4], Wpa2Error> {
    let end = offset
        .checked_add(4)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(Wpa2Error::InvalidRsnInformationElement)?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| Wpa2Error::InvalidRsnInformationElement)
}

fn clear_digest(value: &mut Option<[u8; 32]>) {
    if let Some(bytes) = value.as_mut() {
        bytes.zeroize();
    }
    *value = None;
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockEncrypt;

    use super::*;

    const LOCAL: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const SNONCE: [u8; 32] = [0x11; 32];
    const ANONCE: [u8; 32] = [0x22; 32];
    const RSN_IE: [u8; 22] = [
        0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
    ];

    #[test]
    fn derives_known_ieee_pmk() {
        let pmk = Pmk::derive(b"password", b"IEEE").unwrap();
        assert_eq!(
            pmk.0,
            [
                0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
                0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
                0x97, 0x10, 0xa1, 0x2e,
            ]
        );
    }

    #[test]
    fn rejects_an_rsn_profile_without_ccmp() {
        let mut rsn = RSN_IE;
        rsn[7] = 2;
        assert!(matches!(
            Wpa2Supplicant::new(LOCAL, PEER, SNONCE, Pmk::from_bytes([1; 32]), &rsn),
            Err(Wpa2Error::InvalidRsnInformationElement)
        ));
    }

    #[test]
    fn unwraps_rfc3394_vector() {
        let kek = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let encrypted = [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
            0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ];
        let mut plain = [0u8; 16];
        assert_eq!(aes_key_unwrap(&kek, &encrypted, &mut plain), Ok(16));
        assert_eq!(
            plain,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }

    #[test]
    fn completes_pairwise_handshake_and_accepts_exact_retransmission() {
        let pmk = Pmk::from_bytes([0x33; 32]);
        let mut supplicant = Wpa2Supplicant::new(LOCAL, PEER, SNONCE, pmk, &RSN_IE).unwrap();
        let message1 = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            1,
            ANONCE,
            &[],
            None,
        );
        let Wpa2Action::Transmit(message2) = supplicant.on_eapol(PEER, &message1).unwrap() else {
            panic!("Message 1 must produce Message 2");
        };
        assert_eq!(
            EapolKeyFrame::parse(message2.as_slice()).unwrap().message(),
            EapolKeyMessage::PairwiseMessage2
        );

        let ptk = supplicant.ptk.as_ref().unwrap();
        let gtk = [0x44; 16];
        let mut key_data = [0u8; 24];
        key_data[0] = 0xdd;
        key_data[1] = 22;
        key_data[2..6].copy_from_slice(&GTK_KDE_OUI_TYPE);
        key_data[6] = 1;
        key_data[7] = 0;
        key_data[8..24].copy_from_slice(&gtk);
        let encrypted = aes_key_wrap_for_test(ptk.kek(), &key_data);
        let message3 = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES
                | KEY_INFO_PAIRWISE
                | KEY_INFO_INSTALL
                | KEY_INFO_ACK
                | KEY_INFO_MIC
                | KEY_INFO_SECURE
                | KEY_INFO_ENCRYPTED,
            2,
            ANONCE,
            &encrypted,
            Some(ptk),
        );
        let Wpa2Action::InstallKeys(request) = supplicant.on_eapol(PEER, &message3).unwrap() else {
            panic!("Message 3 must request atomic key installation");
        };
        assert!(matches!(
            supplicant.on_eapol(PEER, &message3),
            Ok(Wpa2Action::None)
        ));
        assert_eq!(request.pairwise().key_config().key.len(), 16);
        assert_eq!(request.group().key_config().key, &gtk);
        assert_eq!(request.group().key_config().sequence.len(), 6);
        let message4 = supplicant.complete_key_install(request, true).unwrap();
        assert_eq!(
            EapolKeyFrame::parse(message4.as_slice()).unwrap().message(),
            EapolKeyMessage::PairwiseMessage4
        );
        assert_eq!(supplicant.phase(), Wpa2Phase::Complete);
        assert!(matches!(
            supplicant.on_eapol(PEER, &message3),
            Ok(Wpa2Action::Transmit(_))
        ));

        let stale = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE,
            1,
            [0; 32],
            &encrypted,
            Some(supplicant.ptk.as_ref().unwrap()),
        );
        assert!(matches!(
            supplicant.on_eapol(PEER, &stale),
            Err(Wpa2Error::StaleReplayCounter)
        ));
    }

    #[test]
    fn rejects_unsupported_protocol_version() {
        let pmk = Pmk::from_bytes([0x33; 32]);
        let mut supplicant = Wpa2Supplicant::new(LOCAL, PEER, SNONCE, pmk, &RSN_IE).unwrap();
        let mut message1 = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            1,
            ANONCE,
            &[],
            None,
        );
        message1[0] = 3;
        assert!(matches!(
            supplicant.on_eapol(PEER, &message1),
            Err(Wpa2Error::UnsupportedProtocolVersion(3))
        ));
    }

    #[test]
    fn rejects_invalid_pairwise_key_length() {
        let pmk = Pmk::from_bytes([0x33; 32]);
        let mut supplicant = Wpa2Supplicant::new(LOCAL, PEER, SNONCE, pmk, &RSN_IE).unwrap();
        let mut message1 = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            1,
            ANONCE,
            &[],
            None,
        );
        message1[7..9].copy_from_slice(&32u16.to_be_bytes());
        assert!(matches!(
            supplicant.on_eapol(PEER, &message1),
            Err(Wpa2Error::InvalidPairwiseKeyLength(32))
        ));
        assert_eq!(supplicant.phase(), Wpa2Phase::Failed);
    }

    #[test]
    fn rejects_wrong_peer_and_clears_the_handshake() {
        let pmk = Pmk::from_bytes([0x33; 32]);
        let mut supplicant = Wpa2Supplicant::new(LOCAL, PEER, SNONCE, pmk, &RSN_IE).unwrap();
        let message1 = build_authenticator_frame(
            KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            1,
            ANONCE,
            &[],
            None,
        );
        assert!(matches!(
            supplicant.on_eapol([9; 6], &message1),
            Err(Wpa2Error::WrongPeer)
        ));
        assert_eq!(supplicant.phase(), Wpa2Phase::Failed);
        assert_eq!(supplicant.supplicant_nonce, [0; 32]);
    }

    fn build_authenticator_frame(
        key_info: u16,
        replay: u64,
        nonce: [u8; 32],
        key_data: &[u8],
        ptk: Option<&Ptk>,
    ) -> std::vec::Vec<u8> {
        let body_len = EAPOL_KEY_FIXED_BODY_LEN + key_data.len();
        let total = EAPOL_HEADER_LEN + body_len;
        let mut bytes = std::vec![0u8; total];
        bytes[0] = 2;
        bytes[1] = EAPOL_PACKET_TYPE_KEY;
        bytes[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
        bytes[4] = RSN_KEY_DESCRIPTOR_TYPE;
        bytes[5..7].copy_from_slice(&key_info.to_be_bytes());
        bytes[7..9].copy_from_slice(&(CCMP_KEY_LEN as u16).to_be_bytes());
        bytes[9..17].copy_from_slice(&replay.to_be_bytes());
        bytes[17..49].copy_from_slice(&nonce);
        bytes[KEY_DATA_LENGTH_OFFSET..KEY_DATA_OFFSET]
            .copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        bytes[KEY_DATA_OFFSET..total].copy_from_slice(key_data);
        if let Some(ptk) = ptk {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(ptk.kck()).unwrap();
            mac.update(&bytes);
            let mic = mac.finalize().into_bytes();
            bytes[KEY_MIC_START..KEY_MIC_END].copy_from_slice(&mic[..16]);
        }
        bytes
    }

    fn aes_key_wrap_for_test(kek: &[u8; 16], plain: &[u8]) -> [u8; 32] {
        assert_eq!(plain.len(), 24);
        let cipher = Aes128::new_from_slice(kek).unwrap();
        let n = plain.len() / 8;
        let mut a = AES_KEY_WRAP_IV;
        let mut output = [0u8; 32];
        output[8..].copy_from_slice(plain);
        for round in 0..=5usize {
            for index in 1..=n {
                let mut block = Block::<Aes128>::default();
                block[..8].copy_from_slice(&a);
                let start = 8 + (index - 1) * 8;
                block[8..].copy_from_slice(&output[start..start + 8]);
                cipher.encrypt_block(&mut block);
                let t = (n * round + index) as u64;
                let t_bytes = t.to_be_bytes();
                for position in 0..8 {
                    a[position] = block[position] ^ t_bytes[position];
                }
                output[start..start + 8].copy_from_slice(&block[8..]);
            }
        }
        output[..8].copy_from_slice(&a);
        output
    }
}
