//! Atomic WPA2-to-radio coordination.
//!
//! The coordinator keeps the controlled port closed until the pairwise key,
//! group key, default group key, EAPOL Message 4 transmission, and firmware
//! authorization command all succeed in order.

use embedded_hal_async::delay::DelayNs;
use sha2::{Digest, Sha256};

use super::bus::Bus;
use super::control::{ControlEvent, EAPOL_ETHERTYPE, KeyConfig};
use super::data::TxDoneEventRef;
use super::protocol::UmacCommand;
use super::runtime::{DriverError, NativeDriver};
use super::station::{StationError, StationState};
use super::wpa2::{
    EapolTxFrame, Wpa2Action, Wpa2Error, Wpa2GroupKeyInstallRequest, Wpa2KeyInstallRequest,
    Wpa2Phase, Wpa2Supplicant,
};

/// Ethernet header bytes before an EAPOL payload.
pub const EAPOL_ETHERNET_HEADER_LEN: usize = 14;
/// Largest Ethernet EAPOL frame built by this coordinator.
pub const MAX_EAPOL_ETHERNET_FRAME_LEN: usize =
    EAPOL_ETHERNET_HEADER_LEN + super::wpa2::MAX_EAPOL_FRAME_LEN;
/// IEEE 802.1X PAE group address.
pub const PAE_GROUP_ADDRESS: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];

/// EAPOL transmit purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EapolTransmitPurpose {
    Message2,
    Message4,
    GroupMessage2,
    Retransmission,
}

/// WPA2 radio integration state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2RuntimeState {
    AwaitingAuthenticator,
    AwaitingEapolTransmit {
        token: u8,
        purpose: EapolTransmitPurpose,
    },
    AwaitingPairwiseKeyStatus,
    AwaitingGroupKeyStatus,
    AwaitingDefaultGroupKeyStatus,
    AwaitingAuthorizationStatus,
    AwaitingCarrier,
    AwaitingGroupRekeyStatus,
    AwaitingDefaultGroupRekeyStatus,
    Complete,
    Failed,
}

/// Bounded WPA2 phase deadlines in milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wpa2Timeouts {
    pub authenticator_ms: u32,
    pub eapol_transmit_ms: u32,
    pub firmware_command_ms: u32,
    pub carrier_ms: u32,
}

impl Wpa2Timeouts {
    /// Conservative production defaults.
    pub const DEFAULT: Self = Self {
        authenticator_ms: 5_000,
        eapol_transmit_ms: 2_000,
        firmware_command_ms: 5_000,
        carrier_ms: 5_000,
    };
}

impl Default for Wpa2Timeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// WPA2 radio integration progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2Progress {
    NoChange,
    EapolSubmitted {
        token: u8,
        purpose: EapolTransmitPurpose,
    },
    PairwiseKeySubmitted,
    GroupKeySubmitted,
    DefaultGroupKeySubmitted,
    AuthorizationSubmitted,
    AwaitingCarrier,
    Complete,
}

/// Fail-closed coordinator error.
#[derive(Debug)]
pub enum Wpa2RuntimeError<E> {
    Wpa2(Wpa2Error),
    Driver(DriverError<E>),
    Station(StationError<E>),
    FrameTooShort,
    FrameTooLarge,
    WrongDestination,
    WrongSource,
    WrongEtherType,
    UnexpectedState(Wpa2RuntimeState),
    UnexpectedCommandStatus {
        expected: UmacCommand,
        received: u32,
    },
    CommandRejected {
        command: u32,
        status: u32,
    },
    MissingInstallRequest,
    TransmitCompletionMismatch {
        expected: u8,
        received: u8,
    },
    TransmitFailed,
    Timeout(Wpa2RuntimeState),
}

impl<E> From<Wpa2Error> for Wpa2RuntimeError<E> {
    fn from(value: Wpa2Error) -> Self {
        Self::Wpa2(value)
    }
}

impl<E> From<DriverError<E>> for Wpa2RuntimeError<E> {
    fn from(value: DriverError<E>) -> Self {
        Self::Driver(value)
    }
}

impl<E> From<StationError<E>> for Wpa2RuntimeError<E> {
    fn from(value: StationError<E>) -> Self {
        Self::Station(value)
    }
}

/// Owns one WPA2 supplicant and its firmware key-install transaction.
pub struct Wpa2Runtime {
    supplicant: Wpa2Supplicant,
    local: [u8; 6],
    wdev_id: u8,
    state: Wpa2RuntimeState,
    pairwise_install: Option<Wpa2KeyInstallRequest>,
    group_install: Option<Wpa2GroupKeyInstallRequest>,
    timeouts: Wpa2Timeouts,
    remaining_ms: Option<u32>,
    last_input_digest: Option<[u8; 32]>,
    frame: [u8; MAX_EAPOL_ETHERNET_FRAME_LEN],
}

#[derive(Clone, Copy)]
enum KeySubmission {
    Pairwise,
    InitialGroup,
    InitialDefaultGroup,
    RekeyGroup,
    RekeyDefaultGroup,
}

#[derive(Clone, Copy)]
enum KeyInstallCompletion {
    Initial,
    Rekey,
}

impl KeyInstallCompletion {
    const fn transmit_purpose(self) -> EapolTransmitPurpose {
        match self {
            Self::Initial => EapolTransmitPurpose::Message4,
            Self::Rekey => EapolTransmitPurpose::GroupMessage2,
        }
    }
}

impl KeySubmission {
    const fn is_default(self) -> bool {
        matches!(self, Self::InitialDefaultGroup | Self::RekeyDefaultGroup)
    }

    const fn next_state(self) -> Wpa2RuntimeState {
        match self {
            Self::Pairwise => Wpa2RuntimeState::AwaitingPairwiseKeyStatus,
            Self::InitialGroup => Wpa2RuntimeState::AwaitingGroupKeyStatus,
            Self::InitialDefaultGroup => Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus,
            Self::RekeyGroup => Wpa2RuntimeState::AwaitingGroupRekeyStatus,
            Self::RekeyDefaultGroup => Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus,
        }
    }

    const fn progress(self) -> Wpa2Progress {
        match self {
            Self::Pairwise => Wpa2Progress::PairwiseKeySubmitted,
            Self::InitialGroup | Self::RekeyGroup => Wpa2Progress::GroupKeySubmitted,
            Self::InitialDefaultGroup | Self::RekeyDefaultGroup => {
                Wpa2Progress::DefaultGroupKeySubmitted
            }
        }
    }
}

macro_rules! runtime_fail_on_error {
    ($runtime:ident, $driver:ident, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return $runtime.fail($driver, error),
        }
    };
}

impl Wpa2Runtime {
    /// Creates one coordinator for a station interface.
    pub fn new(supplicant: Wpa2Supplicant, wdev_id: u8) -> Self {
        let local = supplicant.local();
        let mut runtime = Self {
            supplicant,
            local,
            wdev_id,
            state: Wpa2RuntimeState::AwaitingAuthenticator,
            pairwise_install: None,
            group_install: None,
            timeouts: Wpa2Timeouts::DEFAULT,
            remaining_ms: None,
            last_input_digest: None,
            frame: [0; MAX_EAPOL_ETHERNET_FRAME_LEN],
        };
        runtime.transition(Wpa2RuntimeState::AwaitingAuthenticator);
        runtime
    }

    /// Returns the coordinator state.
    pub const fn state(&self) -> Wpa2RuntimeState {
        self.state
    }

    /// Replaces WPA2 deadlines and rearms the current phase.
    pub fn set_timeouts(&mut self, timeouts: Wpa2Timeouts) {
        self.timeouts = timeouts;
        self.remaining_ms = self.timeout_for(self.state);
    }

    /// Returns the remaining time for the current WPA2 phase.
    pub const fn remaining_time_ms(&self) -> Option<u32> {
        self.remaining_ms
    }

    /// Advances WPA2 phase deadlines and forces recovery on expiry.
    pub fn advance_time<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        elapsed_ms: u32,
    ) -> Result<(), Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        let Some(remaining) = self.remaining_ms else {
            return Ok(());
        };
        if elapsed_ms < remaining {
            self.remaining_ms = Some(remaining - elapsed_ms);
            return Ok(());
        }
        self.fail(driver, Wpa2RuntimeError::Timeout(self.state))
    }

    /// Borrows the underlying supplicant.
    pub const fn supplicant(&self) -> &Wpa2Supplicant {
        &self.supplicant
    }

    /// Starts a new pairwise handshake with a fresh CSPRNG nonce.
    pub fn restart_pairwise(&mut self, supplicant_nonce: [u8; 32]) -> Result<(), Wpa2Error> {
        self.supplicant.restart_pairwise(supplicant_nonce)?;
        self.pairwise_install = None;
        self.group_install = None;
        self.last_input_digest = None;
        self.transition(Wpa2RuntimeState::AwaitingAuthenticator);
        Ok(())
    }

    /// Processes one Ethernet EAPOL frame from the radio.
    pub async fn on_ethernet_frame<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        frame: &[u8],
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let payload = runtime_fail_on_error!(self, driver, self.validate_ethernet_frame(frame));
        let digest = input_digest(payload);
        if let Some(progress) = runtime_fail_on_error!(self, driver, self.pending_input(digest)) {
            return Ok(progress);
        }
        let was_complete = self.supplicant.phase() == Wpa2Phase::Complete;
        let peer = self.supplicant.peer();
        let action = runtime_fail_on_error!(
            self,
            driver,
            self.supplicant
                .on_eapol(peer, payload)
                .map_err(Wpa2RuntimeError::Wpa2)
        );
        self.last_input_digest = Some(digest);
        let result = self
            .dispatch_wpa2_action(driver, delay, action, was_complete)
            .await;
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(driver, error),
        }
    }

    fn pending_input<E>(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<Wpa2Progress>, Wpa2RuntimeError<E>> {
        if !self.has_pending_radio_operation() {
            return Ok(None);
        }
        if self.last_input_digest == Some(digest) {
            // Keep the original deadline. A retransmission cannot extend a
            // stalled firmware command or EAPOL transmit operation.
            return Ok(Some(Wpa2Progress::NoChange));
        }
        Err(Wpa2RuntimeError::UnexpectedState(self.state))
    }

    async fn dispatch_wpa2_action<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        action: Wpa2Action,
        was_complete: bool,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        match action {
            Wpa2Action::None => Ok(Wpa2Progress::NoChange),
            Wpa2Action::Transmit(response) => {
                self.submit_eapol(driver, response, eapol_response_purpose(was_complete))
                    .await
            }
            Wpa2Action::InstallKeys(request) => {
                self.begin_pairwise_install(driver, delay, request).await
            }
            Wpa2Action::InstallGroupKey(request) => {
                self.begin_group_install(driver, delay, request).await
            }
        }
    }

    async fn begin_pairwise_install<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        request: Wpa2KeyInstallRequest,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        if self.state != Wpa2RuntimeState::AwaitingAuthenticator {
            return Err(Wpa2RuntimeError::UnexpectedState(self.state));
        }
        self.pairwise_install = Some(request);
        self.submit_key(driver, delay, KeySubmission::Pairwise)
            .await
    }

    async fn begin_group_install<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        request: Wpa2GroupKeyInstallRequest,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        if self.state != Wpa2RuntimeState::Complete {
            return Err(Wpa2RuntimeError::UnexpectedState(self.state));
        }
        self.group_install = Some(request);
        self.submit_key(driver, delay, KeySubmission::RekeyGroup)
            .await
    }

    /// Applies one command-status event after `NativeDriver` dispatches it.
    pub async fn on_control_event<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        event: ControlEvent<'_>,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let Some((command, status)) = command_status(&event) else {
            return Ok(self.handle_non_command_event(driver));
        };
        if status != 0 {
            return self.fail(
                driver,
                Wpa2RuntimeError::CommandRejected { command, status },
            );
        }
        let result = self.dispatch_command_status(driver, delay, command).await;
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(driver, error),
        }
    }

    fn handle_non_command_event<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
    ) -> Wpa2Progress {
        if driver.station_mut().state() == StationState::Connected {
            self.transition(Wpa2RuntimeState::Complete);
            Wpa2Progress::Complete
        } else {
            Wpa2Progress::NoChange
        }
    }

    async fn dispatch_command_status<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        command: u32,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        match self.state {
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus
            | Wpa2RuntimeState::AwaitingGroupKeyStatus
            | Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus => {
                self.handle_initial_key_status(driver, delay, command).await
            }
            Wpa2RuntimeState::AwaitingAuthorizationStatus => {
                self.handle_authorization_status(driver, command)
            }
            Wpa2RuntimeState::AwaitingGroupRekeyStatus
            | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => {
                self.handle_rekey_status(driver, delay, command).await
            }
            _ => Err(Wpa2RuntimeError::UnexpectedState(self.state)),
        }
    }

    async fn handle_initial_key_status<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        command: u32,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        match self.state {
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus => {
                self.advance_initial_key(driver, delay, command, KeySubmission::InitialGroup)
                    .await
            }
            Wpa2RuntimeState::AwaitingGroupKeyStatus => {
                self.advance_initial_key(driver, delay, command, KeySubmission::InitialDefaultGroup)
                    .await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus => {
                self.complete_key_install(driver, command, KeyInstallCompletion::Initial)
                    .await
            }
            _ => Err(Wpa2RuntimeError::UnexpectedState(self.state)),
        }
    }

    async fn advance_initial_key<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        command: u32,
        submission: KeySubmission,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_command(UmacCommand::NewKey, command)?;
        self.submit_key(driver, delay, submission).await
    }

    fn handle_authorization_status<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        command: u32,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        self.require_command(UmacCommand::SetStation, command)?;
        if driver.station_mut().state() == StationState::Connected {
            self.transition(Wpa2RuntimeState::Complete);
            return Ok(Wpa2Progress::Complete);
        }
        self.transition(Wpa2RuntimeState::AwaitingCarrier);
        Ok(Wpa2Progress::AwaitingCarrier)
    }

    async fn handle_rekey_status<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        command: u32,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        match self.state {
            Wpa2RuntimeState::AwaitingGroupRekeyStatus => {
                self.advance_group_rekey(driver, delay, command).await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => {
                self.complete_key_install(driver, command, KeyInstallCompletion::Rekey)
                    .await
            }
            _ => Err(Wpa2RuntimeError::UnexpectedState(self.state)),
        }
    }

    async fn advance_group_rekey<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        command: u32,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_command(UmacCommand::NewKey, command)?;
        self.submit_key(driver, delay, KeySubmission::RekeyDefaultGroup)
            .await
    }

    async fn complete_key_install<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        command: u32,
        completion: KeyInstallCompletion,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        self.require_command(UmacCommand::SetKey, command)?;
        let response = self.finish_key_install(completion)?;
        self.submit_eapol(driver, response, completion.transmit_purpose())
            .await
    }

    fn finish_key_install<E>(
        &mut self,
        completion: KeyInstallCompletion,
    ) -> Result<EapolTxFrame, Wpa2RuntimeError<E>> {
        match completion {
            KeyInstallCompletion::Initial => {
                let request = self
                    .pairwise_install
                    .take()
                    .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
                self.supplicant.complete_key_install(request, true)
            }
            KeyInstallCompletion::Rekey => {
                let request = self
                    .group_install
                    .take()
                    .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
                self.supplicant.complete_group_key_install(request, true)
            }
        }
        .map_err(Wpa2RuntimeError::Wpa2)
    }

    /// Applies one TX-done event returned by `NativeDriver`.
    pub async fn on_transmit_done<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        event: TxDoneEventRef<'_>,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let purpose = runtime_fail_on_error!(self, driver, self.completed_transmit(&event));
        let Some(purpose) = purpose else {
            return Ok(Wpa2Progress::NoChange);
        };
        match self.dispatch_transmit_purpose(driver, delay, purpose).await {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(driver, error),
        }
    }

    fn completed_transmit<E>(
        &self,
        event: &TxDoneEventRef<'_>,
    ) -> Result<Option<EapolTransmitPurpose>, Wpa2RuntimeError<E>> {
        let Wpa2RuntimeState::AwaitingEapolTransmit { token, purpose } = self.state else {
            return Ok(None);
        };
        if token != event.token {
            return Err(Wpa2RuntimeError::TransmitCompletionMismatch {
                expected: token,
                received: event.token,
            });
        }
        if event.statuses.len() != 1 || !event.all_succeeded() {
            return Err(Wpa2RuntimeError::TransmitFailed);
        }
        Ok(Some(purpose))
    }

    async fn dispatch_transmit_purpose<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        purpose: EapolTransmitPurpose,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        match purpose {
            EapolTransmitPurpose::Message2 => {
                self.transition(Wpa2RuntimeState::AwaitingAuthenticator);
                Ok(Wpa2Progress::NoChange)
            }
            EapolTransmitPurpose::Message4 => self.authorize_after_message4(driver, delay).await,
            EapolTransmitPurpose::GroupMessage2 => self.complete_group_rekey(driver),
            EapolTransmitPurpose::Retransmission => {
                self.transition(Wpa2RuntimeState::Complete);
                Ok(Wpa2Progress::Complete)
            }
        }
    }

    async fn authorize_after_message4<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        {
            let (device, station) = driver.security_parts_mut();
            station.authorize(device, delay).await?;
        }
        self.transition(Wpa2RuntimeState::AwaitingAuthorizationStatus);
        Ok(Wpa2Progress::AuthorizationSubmitted)
    }

    fn complete_group_rekey<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        if driver.station_mut().complete_group_rekey() == StationState::Fault {
            return Err(Wpa2RuntimeError::UnexpectedState(self.state));
        }
        self.transition(Wpa2RuntimeState::Complete);
        Ok(Wpa2Progress::Complete)
    }

    /// Updates completion after carrier-state processing.
    pub fn refresh_carrier<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
    ) -> Wpa2Progress {
        if driver.station_mut().state() == StationState::Connected {
            self.transition(Wpa2RuntimeState::Complete);
            Wpa2Progress::Complete
        } else {
            Wpa2Progress::NoChange
        }
    }

    fn transition(&mut self, state: Wpa2RuntimeState) {
        self.state = state;
        self.remaining_ms = self.timeout_for(state);
    }

    fn timeout_for(&self, state: Wpa2RuntimeState) -> Option<u32> {
        let value = match state {
            Wpa2RuntimeState::AwaitingAuthenticator => self.timeouts.authenticator_ms,
            Wpa2RuntimeState::AwaitingEapolTransmit { .. } => self.timeouts.eapol_transmit_ms,
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus
            | Wpa2RuntimeState::AwaitingGroupKeyStatus
            | Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus
            | Wpa2RuntimeState::AwaitingAuthorizationStatus
            | Wpa2RuntimeState::AwaitingGroupRekeyStatus
            | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => {
                self.timeouts.firmware_command_ms
            }
            Wpa2RuntimeState::AwaitingCarrier => self.timeouts.carrier_ms,
            Wpa2RuntimeState::Complete | Wpa2RuntimeState::Failed => return None,
        };
        Some(value.max(1))
    }

    fn has_pending_radio_operation(&self) -> bool {
        matches!(
            self.state,
            Wpa2RuntimeState::AwaitingEapolTransmit { .. }
                | Wpa2RuntimeState::AwaitingPairwiseKeyStatus
                | Wpa2RuntimeState::AwaitingGroupKeyStatus
                | Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus
                | Wpa2RuntimeState::AwaitingAuthorizationStatus
                | Wpa2RuntimeState::AwaitingGroupRekeyStatus
                | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus
        )
    }

    async fn submit_key<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
        submission: KeySubmission,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        {
            let key = self.submission_key(submission)?;
            submit_firmware_key(driver, delay, &key, submission.is_default()).await?;
        }
        self.transition(submission.next_state());
        Ok(submission.progress())
    }

    fn submission_key<E>(
        &self,
        submission: KeySubmission,
    ) -> Result<KeyConfig<'_>, Wpa2RuntimeError<E>> {
        match submission {
            KeySubmission::Pairwise => self
                .pairwise_install
                .as_ref()
                .map(|request| request.pairwise().key_config()),
            KeySubmission::InitialGroup => self
                .pairwise_install
                .as_ref()
                .map(|request| request.group().key_config()),
            KeySubmission::InitialDefaultGroup => self
                .pairwise_install
                .as_ref()
                .map(|request| request.group().default_key_config()),
            KeySubmission::RekeyGroup => self
                .group_install
                .as_ref()
                .map(|request| request.group().key_config()),
            KeySubmission::RekeyDefaultGroup => self
                .group_install
                .as_ref()
                .map(|request| request.group().default_key_config()),
        }
        .ok_or(Wpa2RuntimeError::MissingInstallRequest)
    }

    async fn submit_eapol<B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        response: EapolTxFrame,
        purpose: EapolTransmitPurpose,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        let len = EAPOL_ETHERNET_HEADER_LEN
            .checked_add(response.len())
            .ok_or(Wpa2RuntimeError::FrameTooLarge)?;
        if len > self.frame.len() {
            return Err(Wpa2RuntimeError::FrameTooLarge);
        }
        self.frame[..6].copy_from_slice(&response.peer());
        self.frame[6..12].copy_from_slice(&self.local);
        self.frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        self.frame[14..len].copy_from_slice(response.as_slice());
        let token = driver.transmit(self.wdev_id, &self.frame[..len], 0).await?;
        self.transition(Wpa2RuntimeState::AwaitingEapolTransmit { token, purpose });
        Ok(Wpa2Progress::EapolSubmitted { token, purpose })
    }

    fn validate_ethernet_frame<'a, E>(
        &self,
        frame: &'a [u8],
    ) -> Result<&'a [u8], Wpa2RuntimeError<E>> {
        validate_ethernet_size(frame)?;
        self.validate_ethernet_header(frame)?;
        Ok(&frame[EAPOL_ETHERNET_HEADER_LEN..])
    }

    fn validate_ethernet_header<E>(&self, frame: &[u8]) -> Result<(), Wpa2RuntimeError<E>> {
        let destination: [u8; 6] = frame[..6]
            .try_into()
            .expect("a size-validated Ethernet destination has six bytes");
        if destination != self.local && destination != PAE_GROUP_ADDRESS {
            return Err(Wpa2RuntimeError::WrongDestination);
        }
        let source: [u8; 6] = frame[6..12]
            .try_into()
            .expect("a size-validated Ethernet source has six bytes");
        if source != self.supplicant.peer() {
            return Err(Wpa2RuntimeError::WrongSource);
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != EAPOL_ETHERTYPE {
            return Err(Wpa2RuntimeError::WrongEtherType);
        }
        Ok(())
    }

    fn require_command<E>(
        &self,
        expected: UmacCommand,
        received: u32,
    ) -> Result<(), Wpa2RuntimeError<E>> {
        if received == expected as u32 {
            Ok(())
        } else {
            Err(Wpa2RuntimeError::UnexpectedCommandStatus { expected, received })
        }
    }

    fn fail<T, B, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        error: Wpa2RuntimeError<B::Error>,
    ) -> Result<T, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
    {
        if let Some(request) = self.pairwise_install.take() {
            let _ = self.supplicant.complete_key_install(request, false);
        }
        if let Some(request) = self.group_install.take() {
            let _ = self.supplicant.complete_group_key_install(request, false);
        }
        self.last_input_digest = None;
        driver.enter_recovery();
        self.transition(Wpa2RuntimeState::Failed);
        Err(error)
    }
}

fn validate_ethernet_size<E>(frame: &[u8]) -> Result<(), Wpa2RuntimeError<E>> {
    if frame.len() < EAPOL_ETHERNET_HEADER_LEN {
        return Err(Wpa2RuntimeError::FrameTooShort);
    }
    if frame.len() > MAX_EAPOL_ETHERNET_FRAME_LEN {
        return Err(Wpa2RuntimeError::FrameTooLarge);
    }
    Ok(())
}

async fn submit_firmware_key<B, D, const RX: usize, const TX: usize>(
    driver: &mut NativeDriver<B, RX, TX>,
    delay: &mut D,
    key: &KeyConfig<'_>,
    default: bool,
) -> Result<(), Wpa2RuntimeError<B::Error>>
where
    B: Bus,
    D: DelayNs,
{
    let (device, station) = driver.security_parts_mut();
    if default {
        station.set_key(device, delay, key).await?;
    } else {
        station
            .key_command(device, delay, UmacCommand::NewKey, key)
            .await?;
    }
    Ok(())
}

fn command_status(event: &ControlEvent<'_>) -> Option<(u32, u32)> {
    match event {
        ControlEvent::CommandStatus {
            command, status, ..
        } => Some((*command, *status)),
        _ => None,
    }
}

const fn eapol_response_purpose(was_complete: bool) -> EapolTransmitPurpose {
    if was_complete {
        EapolTransmitPurpose::Retransmission
    } else {
        EapolTransmitPurpose::Message2
    }
}

fn input_digest(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use aes::Aes128;
    use aes::cipher::{Block, BlockEncrypt, KeyInit};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    use super::super::bus::Bus;
    use super::super::control::{ControlEvent, RSN_CIPHER_CCMP_128};
    use super::super::data::DataEvent;
    use super::super::device::RPU_MEM_TX_CMD_BASE;
    use super::super::protocol::{Hpq, HpqmInfo, UmacHeader};
    use super::super::runtime::DriverState;
    use super::super::test_support::block_on;
    use super::super::wpa2::{Pmk, Wpa2Supplicant};
    use super::*;

    const LOCAL: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const SNONCE: [u8; 32] = [0x11; 32];
    const ANONCE: [u8; 32] = [0x22; 32];
    const GTK: [u8; 16] = [0x44; 16];
    const COMMAND_BUFFER: u32 = 0xb000_1000;
    const COMMAND_BUFFER_HOST: u32 = 0x000c_1000;
    const COMMAND_AVAILABLE_DEQUEUE: u32 = 0xa400_7000;
    const RSN_IE: [u8; 22] = [
        0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
    ];
    const EAPOL_KEY_BODY_LEN: usize = 95;
    const KEY_DATA_LENGTH_OFFSET: usize = 97;
    const KEY_DATA_OFFSET: usize = 99;
    const KEY_MIC_START: usize = 81;
    const KEY_MIC_END: usize = 97;
    const KEY_INFO_PAIRWISE: u16 = 1 << 3;
    const KEY_INFO_INSTALL: u16 = 1 << 6;
    const KEY_INFO_ACK: u16 = 1 << 7;
    const KEY_INFO_MIC: u16 = 1 << 8;
    const KEY_INFO_SECURE: u16 = 1 << 9;
    const KEY_INFO_ENCRYPTED: u16 = 1 << 12;
    const KEY_VERSION: u16 = 2;
    const AES_KEY_WRAP_IV: [u8; 8] = [0xa6; 8];
    const GTK_KDE_OUI_TYPE: [u8; 4] = [0x00, 0x0f, 0xac, 0x01];

    #[derive(Default)]
    struct TestBus {
        commands: Vec<u32>,
    }

    impl Bus for TestBus {
        type Error = ();

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, _address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            data.fill(0);
            if data.len() == 4 {
                data.copy_from_slice(&COMMAND_BUFFER.to_le_bytes());
            }
            Ok(())
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            if address == COMMAND_BUFFER_HOST
                && data.len() >= 24
                && u32::from_le_bytes([data[8], data[9], data[10], data[11]]) == 3
            {
                self.commands
                    .push(u32::from_le_bytes([data[20], data[21], data[22], data[23]]));
            }
            Ok(())
        }
    }

    struct NoDelay;

    impl DelayNs for NoDelay {
        async fn delay_ns(&mut self, _ns: u32) {}
    }

    fn queues() -> HpqmInfo {
        HpqmInfo {
            event_busy: Hpq {
                enqueue_address: 0xa400_6004,
                dequeue_address: 0xa400_6000,
            },
            event_available: Hpq {
                enqueue_address: 0xa400_6014,
                dequeue_address: 0xa400_6010,
            },
            command_busy: Hpq {
                enqueue_address: 0xa400_6024,
                dequeue_address: 0xa400_6020,
            },
            command_available: Hpq {
                enqueue_address: 0xa400_7004,
                dequeue_address: COMMAND_AVAILABLE_DEQUEUE,
            },
            rx_buffer_busy: [
                Hpq {
                    enqueue_address: 0xa400_6034,
                    dequeue_address: 0xa400_6030,
                },
                Hpq {
                    enqueue_address: 0xa400_6044,
                    dequeue_address: 0xa400_6040,
                },
                Hpq {
                    enqueue_address: 0xa400_6054,
                    dequeue_address: 0xa400_6050,
                },
            ],
        }
    }

    fn supplicant() -> Wpa2Supplicant {
        Wpa2Supplicant::new(LOCAL, PEER, SNONCE, Pmk::from_bytes([0x33; 32]), &RSN_IE).unwrap()
    }

    fn driver() -> NativeDriver<TestBus, 1, 2> {
        let mut driver = NativeDriver::new(TestBus::default(), 64, 600, 1, 0, 0).unwrap();
        driver
            .device_mut()
            .initialize_for_test(queues(), 0xb700_1000);
        driver.station_mut().prepare_security_for_test(PEER);
        driver
    }

    fn command_status(command: UmacCommand, status: u32) -> ControlEvent<'static> {
        ControlEvent::CommandStatus {
            header: UmacHeader {
                port_id: 0,
                sequence: 1,
                command_event: 292,
                result: 0,
                valid_ids: 0,
                ifaceindex: 1,
                wiphy_index: 0,
                wdev_id: 0,
            },
            command: command as u32,
            status,
        }
    }

    fn ethernet_eapol(payload: &[u8]) -> [u8; EAPOL_ETHERNET_HEADER_LEN + 4] {
        assert_eq!(payload.len(), 4);
        let mut frame = [0u8; EAPOL_ETHERNET_HEADER_LEN + 4];
        frame[..6].copy_from_slice(&LOCAL);
        frame[6..12].copy_from_slice(&PEER);
        frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        frame[14..].copy_from_slice(payload);
        frame
    }

    fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; EAPOL_ETHERNET_HEADER_LEN + payload.len()];
        frame[..6].copy_from_slice(&LOCAL);
        frame[6..12].copy_from_slice(&PEER);
        frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        frame[14..].copy_from_slice(payload);
        frame
    }

    fn pairwise_message1() -> Vec<u8> {
        authenticator_frame(
            KEY_VERSION | KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            1,
            ANONCE,
            &[],
            None,
        )
    }

    fn pairwise_message3(ptk: &[u8; 48]) -> Vec<u8> {
        let encrypted = encrypted_gtk(&ptk[16..32], GTK);
        authenticator_frame(
            KEY_VERSION
                | KEY_INFO_PAIRWISE
                | KEY_INFO_INSTALL
                | KEY_INFO_ACK
                | KEY_INFO_MIC
                | KEY_INFO_SECURE
                | KEY_INFO_ENCRYPTED,
            2,
            ANONCE,
            &encrypted,
            Some(&ptk[..16]),
        )
    }

    fn group_message1(ptk: &[u8; 48]) -> Vec<u8> {
        let encrypted = encrypted_gtk(&ptk[16..32], [0x55; 16]);
        authenticator_frame(
            KEY_VERSION | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE | KEY_INFO_ENCRYPTED,
            3,
            [0; 32],
            &encrypted,
            Some(&ptk[..16]),
        )
    }

    fn authenticator_frame(
        key_info: u16,
        replay: u64,
        nonce: [u8; 32],
        key_data: &[u8],
        kck: Option<&[u8]>,
    ) -> Vec<u8> {
        let body_len = EAPOL_KEY_BODY_LEN + key_data.len();
        let mut bytes = vec![0u8; 4 + body_len];
        bytes[0] = 2;
        bytes[1] = 3;
        bytes[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
        bytes[4] = 2;
        bytes[5..7].copy_from_slice(&key_info.to_be_bytes());
        bytes[7..9].copy_from_slice(&16u16.to_be_bytes());
        bytes[9..17].copy_from_slice(&replay.to_be_bytes());
        bytes[17..49].copy_from_slice(&nonce);
        bytes[KEY_DATA_LENGTH_OFFSET..KEY_DATA_OFFSET]
            .copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        bytes[KEY_DATA_OFFSET..].copy_from_slice(key_data);
        if let Some(kck) = kck {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(kck).unwrap();
            mac.update(&bytes);
            bytes[KEY_MIC_START..KEY_MIC_END].copy_from_slice(&mac.finalize().into_bytes()[..16]);
        }
        bytes
    }

    fn derive_ptk() -> [u8; 48] {
        let mut context = [0u8; 76];
        context[..6].copy_from_slice(&LOCAL);
        context[6..12].copy_from_slice(&PEER);
        context[12..44].copy_from_slice(&SNONCE);
        context[44..].copy_from_slice(&ANONCE);
        let mut ptk = [0u8; 48];
        let mut written = 0usize;
        let mut counter = 0u8;
        while written < ptk.len() {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&[0x33; 32]).unwrap();
            mac.update(b"Pairwise key expansion");
            mac.update(&[0]);
            mac.update(&context);
            mac.update(&[counter]);
            let block = mac.finalize().into_bytes();
            let count = core::cmp::min(block.len(), ptk.len() - written);
            ptk[written..written + count].copy_from_slice(&block[..count]);
            written += count;
            counter = counter.wrapping_add(1);
        }
        ptk
    }

    fn encrypted_gtk(kek: &[u8], gtk: [u8; 16]) -> [u8; 32] {
        let mut plain = [0u8; 24];
        plain[0] = 0xdd;
        plain[1] = 22;
        plain[2..6].copy_from_slice(&GTK_KDE_OUI_TYPE);
        plain[6] = 1;
        plain[8..].copy_from_slice(&gtk);
        aes_key_wrap(kek, &plain)
    }

    fn aes_key_wrap(kek: &[u8], plain: &[u8; 24]) -> [u8; 32] {
        let cipher = Aes128::new_from_slice(kek).unwrap();
        let mut a = AES_KEY_WRAP_IV;
        let mut output = [0u8; 32];
        output[8..].copy_from_slice(plain);
        for round in 0..=5usize {
            for index in 1..=3usize {
                let mut block = Block::<Aes128>::default();
                block[..8].copy_from_slice(&a);
                let start = 8 + (index - 1) * 8;
                block[8..].copy_from_slice(&output[start..start + 8]);
                cipher.encrypt_block(&mut block);
                let counter = (3 * round + index).to_be_bytes();
                for position in 0..8 {
                    a[position] = block[position] ^ counter[position];
                }
                output[start..start + 8].copy_from_slice(&block[8..]);
            }
        }
        output[..8].copy_from_slice(&a);
        output
    }

    fn acknowledge(
        runtime: &mut Wpa2Runtime,
        driver: &mut NativeDriver<TestBus, 1, 2>,
        delay: &mut NoDelay,
        command: UmacCommand,
    ) -> Wpa2Progress {
        let event = command_status(command, 0);
        driver
            .station_mut()
            .handle_control_event::<()>(event)
            .unwrap();
        block_on(runtime.on_control_event(driver, delay, event)).unwrap()
    }

    fn complete_transmit(
        runtime: &mut Wpa2Runtime,
        driver: &mut NativeDriver<TestBus, 1, 2>,
        delay: &mut NoDelay,
        token: u8,
    ) -> Wpa2Progress {
        driver.data_mut().complete_tx(token).unwrap();
        block_on(runtime.on_transmit_done(
            driver,
            delay,
            TxDoneEventRef {
                token,
                statuses: &[0],
            },
        ))
        .unwrap()
    }

    #[test]
    fn malformed_eapol_forces_driver_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        let mut driver = driver();
        let mut delay = NoDelay;
        let result = block_on(runtime.on_ethernet_frame(&mut driver, &mut delay, &[0; 8]));
        assert!(matches!(result, Err(Wpa2RuntimeError::FrameTooShort)));
        assert_eq!(runtime.state(), Wpa2RuntimeState::Failed);
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn exact_pending_retransmission_is_ignored_without_extending_the_deadline() {
        let payload = [2, 3, 0, 0];
        let frame = ethernet_eapol(&payload);
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingPairwiseKeyStatus;
        runtime.remaining_ms = Some(123);
        runtime.last_input_digest = Some(input_digest(&payload));
        let mut driver = driver();
        let mut delay = NoDelay;
        let progress =
            block_on(runtime.on_ethernet_frame(&mut driver, &mut delay, &frame)).unwrap();
        assert_eq!(progress, Wpa2Progress::NoChange);
        assert_eq!(runtime.state(), Wpa2RuntimeState::AwaitingPairwiseKeyStatus);
        assert_eq!(runtime.remaining_time_ms(), Some(123));
        assert_ne!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn conflicting_frame_during_pending_operation_forces_recovery() {
        let payload = [2, 3, 0, 0];
        let conflicting = [2, 3, 0, 1];
        let frame = ethernet_eapol(&conflicting);
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingPairwiseKeyStatus;
        runtime.last_input_digest = Some(input_digest(&payload));
        let mut driver = driver();
        let mut delay = NoDelay;
        let result = block_on(runtime.on_ethernet_frame(&mut driver, &mut delay, &frame));
        assert!(matches!(
            result,
            Err(Wpa2RuntimeError::UnexpectedState(
                Wpa2RuntimeState::AwaitingPairwiseKeyStatus
            ))
        ));
        assert_eq!(runtime.state(), Wpa2RuntimeState::Failed);
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn command_mismatch_forces_driver_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingPairwiseKeyStatus;
        let mut driver = driver();
        let mut delay = NoDelay;
        let result = block_on(runtime.on_control_event(
            &mut driver,
            &mut delay,
            command_status(UmacCommand::SetKey, 0),
        ));
        assert!(matches!(
            result,
            Err(Wpa2RuntimeError::UnexpectedCommandStatus { .. })
        ));
        assert_eq!(runtime.state(), Wpa2RuntimeState::Failed);
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn rejected_command_forces_driver_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingPairwiseKeyStatus;
        let mut driver = driver();
        let mut delay = NoDelay;
        let result = block_on(runtime.on_control_event(
            &mut driver,
            &mut delay,
            command_status(UmacCommand::NewKey, 7),
        ));
        assert!(matches!(
            result,
            Err(Wpa2RuntimeError::CommandRejected { status: 7, .. })
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn mismatched_tx_token_forces_driver_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingEapolTransmit {
            token: 2,
            purpose: EapolTransmitPurpose::Message4,
        };
        let mut driver = driver();
        let mut delay = NoDelay;
        let statuses = [0u8];
        let result = block_on(runtime.on_transmit_done(
            &mut driver,
            &mut delay,
            TxDoneEventRef {
                token: 3,
                statuses: &statuses,
            },
        ));
        assert!(matches!(
            result,
            Err(Wpa2RuntimeError::TransmitCompletionMismatch { .. })
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn failed_message4_tx_forces_driver_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingEapolTransmit {
            token: 2,
            purpose: EapolTransmitPurpose::Message4,
        };
        let mut driver = driver();
        let mut delay = NoDelay;
        let statuses = [1u8];
        let result = block_on(runtime.on_transmit_done(
            &mut driver,
            &mut delay,
            TxDoneEventRef {
                token: 2,
                statuses: &statuses,
            },
        ));
        assert!(matches!(result, Err(Wpa2RuntimeError::TransmitFailed)));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn complete_pairwise_and_group_rekey_transactions_are_ordered() {
        let ptk = derive_ptk();
        let message1 = pairwise_message1();
        let message3 = pairwise_message3(&ptk);
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        let mut driver = driver();
        let mut delay = NoDelay;

        let progress = block_on(runtime.on_ethernet_frame(
            &mut driver,
            &mut delay,
            &ethernet_frame(&message1),
        ))
        .unwrap();
        let Wpa2Progress::EapolSubmitted { token, purpose } = progress else {
            panic!("pairwise Message 1 must submit Message 2");
        };
        assert_eq!(purpose, EapolTransmitPurpose::Message2);
        assert_eq!(
            runtime.state(),
            Wpa2RuntimeState::AwaitingEapolTransmit { token, purpose }
        );
        assert_eq!(
            complete_transmit(&mut runtime, &mut driver, &mut delay, token),
            Wpa2Progress::NoChange
        );
        assert_eq!(runtime.state(), Wpa2RuntimeState::AwaitingAuthenticator);

        assert_eq!(
            block_on(runtime.on_ethernet_frame(
                &mut driver,
                &mut delay,
                &ethernet_frame(&message3),
            ))
            .unwrap(),
            Wpa2Progress::PairwiseKeySubmitted
        );
        assert_eq!(
            acknowledge(&mut runtime, &mut driver, &mut delay, UmacCommand::NewKey),
            Wpa2Progress::GroupKeySubmitted
        );
        assert_eq!(
            acknowledge(&mut runtime, &mut driver, &mut delay, UmacCommand::NewKey),
            Wpa2Progress::DefaultGroupKeySubmitted
        );
        let message4 = acknowledge(&mut runtime, &mut driver, &mut delay, UmacCommand::SetKey);
        let Wpa2Progress::EapolSubmitted { token, purpose } = message4 else {
            panic!("default GTK acknowledgement must submit Message 4");
        };
        assert_eq!(purpose, EapolTransmitPurpose::Message4);
        assert_eq!(runtime.supplicant().phase(), Wpa2Phase::Complete);
        assert_eq!(
            complete_transmit(&mut runtime, &mut driver, &mut delay, token),
            Wpa2Progress::AuthorizationSubmitted
        );
        assert_eq!(
            acknowledge(
                &mut runtime,
                &mut driver,
                &mut delay,
                UmacCommand::SetStation,
            ),
            Wpa2Progress::AwaitingCarrier
        );
        driver
            .station_mut()
            .handle_data_event::<()>(DataEvent::CarrierOn { wdev_id: 0 })
            .unwrap();
        assert_eq!(runtime.refresh_carrier(&mut driver), Wpa2Progress::Complete);

        let retransmission = block_on(runtime.on_ethernet_frame(
            &mut driver,
            &mut delay,
            &ethernet_frame(&message3),
        ))
        .unwrap();
        let Wpa2Progress::EapolSubmitted { token, purpose } = retransmission else {
            panic!("completed handshake must retransmit Message 4");
        };
        assert_eq!(purpose, EapolTransmitPurpose::Retransmission);
        assert_eq!(
            complete_transmit(&mut runtime, &mut driver, &mut delay, token),
            Wpa2Progress::Complete
        );

        assert_eq!(
            block_on(runtime.on_ethernet_frame(
                &mut driver,
                &mut delay,
                &ethernet_frame(&group_message1(&ptk)),
            ))
            .unwrap(),
            Wpa2Progress::GroupKeySubmitted
        );
        assert_eq!(
            acknowledge(&mut runtime, &mut driver, &mut delay, UmacCommand::NewKey),
            Wpa2Progress::DefaultGroupKeySubmitted
        );
        let group_message2 =
            acknowledge(&mut runtime, &mut driver, &mut delay, UmacCommand::SetKey);
        let Wpa2Progress::EapolSubmitted { token, purpose } = group_message2 else {
            panic!("default rekey acknowledgement must submit group Message 2");
        };
        assert_eq!(purpose, EapolTransmitPurpose::GroupMessage2);
        assert_eq!(
            complete_transmit(&mut runtime, &mut driver, &mut delay, token),
            Wpa2Progress::Complete
        );
        assert_eq!(runtime.state(), Wpa2RuntimeState::Complete);
        assert_eq!(driver.station_mut().state(), StationState::Connected);
        assert_eq!(
            driver.device_mut().rpu_mut().bus_mut().commands,
            [
                UmacCommand::NewKey as u32,
                UmacCommand::NewKey as u32,
                UmacCommand::SetKey as u32,
                UmacCommand::SetStation as u32,
                UmacCommand::NewKey as u32,
                UmacCommand::SetKey as u32,
            ]
        );
    }

    #[test]
    fn key_submission_metadata_and_missing_request_paths_are_exact() {
        let runtime = Wpa2Runtime::new(supplicant(), 0);
        let cases = [
            (
                KeySubmission::Pairwise,
                false,
                Wpa2RuntimeState::AwaitingPairwiseKeyStatus,
                Wpa2Progress::PairwiseKeySubmitted,
            ),
            (
                KeySubmission::InitialGroup,
                false,
                Wpa2RuntimeState::AwaitingGroupKeyStatus,
                Wpa2Progress::GroupKeySubmitted,
            ),
            (
                KeySubmission::InitialDefaultGroup,
                true,
                Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus,
                Wpa2Progress::DefaultGroupKeySubmitted,
            ),
            (
                KeySubmission::RekeyGroup,
                false,
                Wpa2RuntimeState::AwaitingGroupRekeyStatus,
                Wpa2Progress::GroupKeySubmitted,
            ),
            (
                KeySubmission::RekeyDefaultGroup,
                true,
                Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus,
                Wpa2Progress::DefaultGroupKeySubmitted,
            ),
        ];
        for (submission, default, state, progress) in cases {
            assert_eq!(submission.is_default(), default);
            assert_eq!(submission.next_state(), state);
            assert_eq!(submission.progress(), progress);
            assert!(matches!(
                runtime.submission_key::<()>(submission),
                Err(Wpa2RuntimeError::MissingInstallRequest)
            ));
        }
    }

    #[test]
    fn non_command_events_complete_only_after_station_connection() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingCarrier;
        let mut driver = driver();
        let mut delay = NoDelay;
        let event = ControlEvent::Other {
            header: UmacHeader {
                port_id: 0,
                sequence: 1,
                command_event: 999,
                result: 0,
                valid_ids: 0,
                ifaceindex: 1,
                wiphy_index: 0,
                wdev_id: 0,
            },
            body: &[],
        };
        assert_eq!(
            block_on(runtime.on_control_event(&mut driver, &mut delay, event)).unwrap(),
            Wpa2Progress::NoChange
        );
        assert_eq!(runtime.state(), Wpa2RuntimeState::AwaitingCarrier);

        driver.station_mut().prepare_connected_for_test(PEER);
        assert_eq!(
            block_on(runtime.on_control_event(&mut driver, &mut delay, event)).unwrap(),
            Wpa2Progress::Complete
        );
        assert_eq!(runtime.state(), Wpa2RuntimeState::Complete);
    }

    #[test]
    fn failure_rejects_pending_pairwise_and_group_install_transactions() {
        let ptk = derive_ptk();

        let mut pairwise = Wpa2Runtime::new(supplicant(), 0);
        assert!(matches!(
            pairwise.supplicant.on_eapol(PEER, &pairwise_message1()),
            Ok(Wpa2Action::Transmit(_))
        ));
        let Wpa2Action::InstallKeys(request) = pairwise
            .supplicant
            .on_eapol(PEER, &pairwise_message3(&ptk))
            .unwrap()
        else {
            panic!("Message 3 must create a pending pairwise install");
        };
        pairwise.pairwise_install = Some(request);
        let mut pairwise_driver = driver();
        let result: Result<(), _> =
            pairwise.fail(&mut pairwise_driver, Wpa2RuntimeError::FrameTooShort);
        assert!(matches!(result, Err(Wpa2RuntimeError::FrameTooShort)));
        assert_eq!(pairwise.supplicant.phase(), Wpa2Phase::Failed);

        let mut group = Wpa2Runtime::new(supplicant(), 0);
        group
            .supplicant
            .on_eapol(PEER, &pairwise_message1())
            .unwrap();
        let Wpa2Action::InstallKeys(request) = group
            .supplicant
            .on_eapol(PEER, &pairwise_message3(&ptk))
            .unwrap()
        else {
            panic!("Message 3 must create a pairwise install");
        };
        group
            .supplicant
            .complete_key_install(request, true)
            .unwrap();
        let Wpa2Action::InstallGroupKey(request) = group
            .supplicant
            .on_eapol(PEER, &group_message1(&ptk))
            .unwrap()
        else {
            panic!("group Message 1 must create a pending GTK install");
        };
        group.group_install = Some(request);
        let mut group_driver = driver();
        let result: Result<(), _> = group.fail(&mut group_driver, Wpa2RuntimeError::FrameTooLarge);
        assert!(matches!(result, Err(Wpa2RuntimeError::FrameTooLarge)));
        assert_eq!(group.supplicant.phase(), Wpa2Phase::Failed);
    }

    #[test]
    fn restart_pairwise_clears_runtime_input_and_rejects_a_busy_handshake() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::Failed;
        runtime.last_input_digest = Some([9; 32]);
        runtime.restart_pairwise(SNONCE).unwrap();
        assert_eq!(runtime.state(), Wpa2RuntimeState::AwaitingAuthenticator);
        assert_eq!(runtime.last_input_digest, None);

        runtime
            .supplicant
            .on_eapol(PEER, &pairwise_message1())
            .unwrap();
        assert!(matches!(
            runtime
                .supplicant
                .on_eapol(PEER, &pairwise_message3(&derive_ptk())),
            Ok(Wpa2Action::InstallKeys(_))
        ));
        assert!(matches!(
            runtime.restart_pairwise([0x88; 32]),
            Err(Wpa2Error::Busy)
        ));
    }

    #[test]
    fn runtime_deadlines_cover_every_state_and_clamp_zero() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        let timeouts = Wpa2Timeouts {
            authenticator_ms: 11,
            eapol_transmit_ms: 22,
            firmware_command_ms: 33,
            carrier_ms: 0,
        };
        runtime.set_timeouts(timeouts);
        assert_eq!(runtime.remaining_time_ms(), Some(11));
        let cases = [
            (Wpa2RuntimeState::AwaitingAuthenticator, Some(11)),
            (
                Wpa2RuntimeState::AwaitingEapolTransmit {
                    token: 9,
                    purpose: EapolTransmitPurpose::Message2,
                },
                Some(22),
            ),
            (Wpa2RuntimeState::AwaitingPairwiseKeyStatus, Some(33)),
            (Wpa2RuntimeState::AwaitingGroupKeyStatus, Some(33)),
            (Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus, Some(33)),
            (Wpa2RuntimeState::AwaitingAuthorizationStatus, Some(33)),
            (Wpa2RuntimeState::AwaitingCarrier, Some(1)),
            (Wpa2RuntimeState::AwaitingGroupRekeyStatus, Some(33)),
            (Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus, Some(33)),
            (Wpa2RuntimeState::Complete, None),
            (Wpa2RuntimeState::Failed, None),
        ];
        for (state, expected) in cases {
            assert_eq!(runtime.timeout_for(state), expected);
        }
        runtime.remaining_ms = None;
        let mut driver = driver();
        assert!(runtime.advance_time(&mut driver, 99).is_ok());
        runtime.remaining_ms = Some(10);
        assert!(runtime.advance_time(&mut driver, 4).is_ok());
        assert_eq!(runtime.remaining_time_ms(), Some(6));
    }

    #[test]
    fn ethernet_validation_checks_all_boundaries_and_header_fields() {
        let runtime = Wpa2Runtime::new(supplicant(), 0);
        let valid = ethernet_frame(&[]);
        assert_eq!(runtime.validate_ethernet_frame::<()>(&valid).unwrap(), &[]);

        let mut wrong = valid.clone();
        wrong[0] ^= 1;
        assert!(matches!(
            runtime.validate_ethernet_frame::<()>(&wrong),
            Err(Wpa2RuntimeError::WrongDestination)
        ));
        wrong = valid.clone();
        wrong[..6].copy_from_slice(&PAE_GROUP_ADDRESS);
        assert!(runtime.validate_ethernet_frame::<()>(&wrong).is_ok());
        wrong = valid.clone();
        wrong[6] ^= 1;
        assert!(matches!(
            runtime.validate_ethernet_frame::<()>(&wrong),
            Err(Wpa2RuntimeError::WrongSource)
        ));
        wrong = valid;
        wrong[13] ^= 1;
        assert!(matches!(
            runtime.validate_ethernet_frame::<()>(&wrong),
            Err(Wpa2RuntimeError::WrongEtherType)
        ));
        assert!(matches!(
            runtime.validate_ethernet_frame::<()>(&[0; EAPOL_ETHERNET_HEADER_LEN - 1]),
            Err(Wpa2RuntimeError::FrameTooShort)
        ));
        let oversized = vec![0; MAX_EAPOL_ETHERNET_FRAME_LEN + 1];
        assert!(matches!(
            runtime.validate_ethernet_frame::<()>(&oversized),
            Err(Wpa2RuntimeError::FrameTooLarge)
        ));
    }

    #[test]
    fn authorization_starts_only_after_message4_tx_success() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        runtime.state = Wpa2RuntimeState::AwaitingEapolTransmit {
            token: 2,
            purpose: EapolTransmitPurpose::Message4,
        };
        let mut driver = driver();
        assert!(driver.device_mut().rpu_mut().bus_mut().commands.is_empty());
        let mut delay = NoDelay;
        let statuses = [0u8];
        let progress = block_on(runtime.on_transmit_done(
            &mut driver,
            &mut delay,
            TxDoneEventRef {
                token: 2,
                statuses: &statuses,
            },
        ))
        .unwrap();
        assert_eq!(progress, Wpa2Progress::AuthorizationSubmitted);
        assert_eq!(
            runtime.state(),
            Wpa2RuntimeState::AwaitingAuthorizationStatus
        );
        assert_eq!(driver.station_mut().state(), StationState::Authorizing);
        assert_eq!(
            driver.device_mut().rpu_mut().bus_mut().commands,
            [UmacCommand::SetStation as u32]
        );
        assert_eq!(RPU_MEM_TX_CMD_BASE, 0xb000_00b8);
        assert_eq!(RSN_CIPHER_CCMP_128, 0x000f_ac04);
    }

    #[test]
    fn wpa2_phase_timeout_forces_runtime_recovery() {
        let mut runtime = Wpa2Runtime::new(supplicant(), 0);
        let mut driver = driver();
        assert_eq!(runtime.remaining_time_ms(), Some(5_000));
        assert!(matches!(
            runtime.advance_time(&mut driver, 5_000),
            Err(Wpa2RuntimeError::Timeout(
                Wpa2RuntimeState::AwaitingAuthenticator
            ))
        ));
        assert_eq!(runtime.state(), Wpa2RuntimeState::Failed);
        assert_eq!(driver.state(), DriverState::Recovering);
    }
}
