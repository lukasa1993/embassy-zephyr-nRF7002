//! Atomic WPA2-to-radio coordination.
//!
//! The coordinator keeps the controlled port closed until the pairwise key,
//! group key, default group key, EAPOL Message 4 transmission, and firmware
//! authorization command all succeed in order.

use embedded_hal_async::delay::DelayNs;
use sha2::{Digest, Sha256};

use super::bus::Bus;
use super::control::{ControlEvent, EAPOL_ETHERTYPE};
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
        let payload = match self.validate_ethernet_frame(frame) {
            Ok(payload) => payload,
            Err(error) => return self.fail(driver, error),
        };
        let digest = input_digest(payload);
        if self.has_pending_radio_operation() {
            if self.last_input_digest == Some(digest) {
                // Keep the original deadline. A retransmission cannot extend
                // a stalled firmware command or an EAPOL transmit operation.
                return Ok(Wpa2Progress::NoChange);
            }
            return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
        }

        let was_complete = self.supplicant.phase() == Wpa2Phase::Complete;
        let peer = self.supplicant.peer();
        let action = match self.supplicant.on_eapol(peer, payload) {
            Ok(action) => action,
            Err(error) => return self.fail(driver, Wpa2RuntimeError::Wpa2(error)),
        };
        self.last_input_digest = Some(digest);
        let result = match action {
            Wpa2Action::None => return Ok(Wpa2Progress::NoChange),
            Wpa2Action::Transmit(response) => {
                let purpose = if was_complete {
                    EapolTransmitPurpose::Retransmission
                } else {
                    EapolTransmitPurpose::Message2
                };
                self.submit_eapol(driver, response, purpose).await
            }
            Wpa2Action::InstallKeys(request) => {
                if self.state != Wpa2RuntimeState::AwaitingAuthenticator {
                    return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
                }
                self.pairwise_install = Some(request);
                self.submit_pairwise_key(driver, delay).await
            }
            Wpa2Action::InstallGroupKey(request) => {
                if self.state != Wpa2RuntimeState::Complete {
                    return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
                }
                self.group_install = Some(request);
                self.submit_group_rekey(driver, delay).await
            }
        };
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(driver, error),
        }
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
        let ControlEvent::CommandStatus {
            command, status, ..
        } = event
        else {
            if driver.station_mut().state() == StationState::Connected {
                self.transition(Wpa2RuntimeState::Complete);
                return Ok(Wpa2Progress::Complete);
            }
            return Ok(Wpa2Progress::NoChange);
        };

        if status != 0 {
            return self.fail(
                driver,
                Wpa2RuntimeError::CommandRejected { command, status },
            );
        }

        let result = match self.state {
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus => {
                if let Err(error) = self.require_command(UmacCommand::NewKey, command) {
                    return self.fail(driver, error);
                }
                self.submit_group_key(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingGroupKeyStatus => {
                if let Err(error) = self.require_command(UmacCommand::NewKey, command) {
                    return self.fail(driver, error);
                }
                self.submit_default_group_key(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus => {
                if let Err(error) = self.require_command(UmacCommand::SetKey, command) {
                    return self.fail(driver, error);
                }
                let Some(request) = self.pairwise_install.take() else {
                    return self.fail(driver, Wpa2RuntimeError::MissingInstallRequest);
                };
                let response = match self.supplicant.complete_key_install(request, true) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.fail(driver, Wpa2RuntimeError::Wpa2(error));
                    }
                };
                self.submit_eapol(driver, response, EapolTransmitPurpose::Message4)
                    .await
            }
            Wpa2RuntimeState::AwaitingAuthorizationStatus => {
                if let Err(error) = self.require_command(UmacCommand::SetStation, command) {
                    return self.fail(driver, error);
                }
                if driver.station_mut().state() == StationState::Connected {
                    self.transition(Wpa2RuntimeState::Complete);
                    return Ok(Wpa2Progress::Complete);
                }
                self.transition(Wpa2RuntimeState::AwaitingCarrier);
                return Ok(Wpa2Progress::AwaitingCarrier);
            }
            Wpa2RuntimeState::AwaitingGroupRekeyStatus => {
                if let Err(error) = self.require_command(UmacCommand::NewKey, command) {
                    return self.fail(driver, error);
                }
                self.submit_default_group_rekey(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => {
                if let Err(error) = self.require_command(UmacCommand::SetKey, command) {
                    return self.fail(driver, error);
                }
                let Some(request) = self.group_install.take() else {
                    return self.fail(driver, Wpa2RuntimeError::MissingInstallRequest);
                };
                let response = match self.supplicant.complete_group_key_install(request, true) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.fail(driver, Wpa2RuntimeError::Wpa2(error));
                    }
                };
                self.submit_eapol(driver, response, EapolTransmitPurpose::GroupMessage2)
                    .await
            }
            _ => {
                return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
            }
        };
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(driver, error),
        }
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
        let Wpa2RuntimeState::AwaitingEapolTransmit { token, purpose } = self.state else {
            return Ok(Wpa2Progress::NoChange);
        };
        if token != event.token {
            return self.fail(
                driver,
                Wpa2RuntimeError::TransmitCompletionMismatch {
                    expected: token,
                    received: event.token,
                },
            );
        }
        if event.statuses.len() != 1 || !event.all_succeeded() {
            return self.fail(driver, Wpa2RuntimeError::TransmitFailed);
        }

        match purpose {
            EapolTransmitPurpose::Message2 => {
                self.transition(Wpa2RuntimeState::AwaitingAuthenticator);
                Ok(Wpa2Progress::NoChange)
            }
            EapolTransmitPurpose::Message4 => {
                let result = {
                    let (device, station) = driver.security_parts_mut();
                    station.authorize(device, delay).await
                };
                match result {
                    Ok(()) => {
                        self.transition(Wpa2RuntimeState::AwaitingAuthorizationStatus);
                        Ok(Wpa2Progress::AuthorizationSubmitted)
                    }
                    Err(error) => self.fail(driver, Wpa2RuntimeError::Station(error)),
                }
            }
            EapolTransmitPurpose::GroupMessage2 => {
                if driver.station_mut().complete_group_rekey() == StationState::Fault {
                    return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
                }
                self.transition(Wpa2RuntimeState::Complete);
                Ok(Wpa2Progress::Complete)
            }
            EapolTransmitPurpose::Retransmission => {
                self.transition(Wpa2RuntimeState::Complete);
                Ok(Wpa2Progress::Complete)
            }
        }
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

    async fn submit_pairwise_key<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let request = self
            .pairwise_install
            .as_ref()
            .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
        let key = request.pairwise().key_config();
        let (device, station) = driver.security_parts_mut();
        station
            .key_command(device, delay, UmacCommand::NewKey, &key)
            .await?;
        self.transition(Wpa2RuntimeState::AwaitingPairwiseKeyStatus);
        Ok(Wpa2Progress::PairwiseKeySubmitted)
    }

    async fn submit_group_key<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let request = self
            .pairwise_install
            .as_ref()
            .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
        let key = request.group().key_config();
        let (device, station) = driver.security_parts_mut();
        station
            .key_command(device, delay, UmacCommand::NewKey, &key)
            .await?;
        self.transition(Wpa2RuntimeState::AwaitingGroupKeyStatus);
        Ok(Wpa2Progress::GroupKeySubmitted)
    }

    async fn submit_default_group_key<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let request = self
            .pairwise_install
            .as_ref()
            .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
        let key = request.group().default_key_config();
        let (device, station) = driver.security_parts_mut();
        station.set_key(device, delay, &key).await?;
        self.transition(Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus);
        Ok(Wpa2Progress::DefaultGroupKeySubmitted)
    }

    async fn submit_group_rekey<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let request = self
            .group_install
            .as_ref()
            .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
        let key = request.group().key_config();
        let (device, station) = driver.security_parts_mut();
        station
            .key_command(device, delay, UmacCommand::NewKey, &key)
            .await?;
        self.transition(Wpa2RuntimeState::AwaitingGroupRekeyStatus);
        Ok(Wpa2Progress::GroupKeySubmitted)
    }

    async fn submit_default_group_rekey<B, D, const RX: usize, const TX: usize>(
        &mut self,
        driver: &mut NativeDriver<B, RX, TX>,
        delay: &mut D,
    ) -> Result<Wpa2Progress, Wpa2RuntimeError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        let request = self
            .group_install
            .as_ref()
            .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
        let key = request.group().default_key_config();
        let (device, station) = driver.security_parts_mut();
        station.set_key(device, delay, &key).await?;
        self.transition(Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus);
        Ok(Wpa2Progress::DefaultGroupKeySubmitted)
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
        if frame.len() < EAPOL_ETHERNET_HEADER_LEN {
            return Err(Wpa2RuntimeError::FrameTooShort);
        }
        if frame.len() > MAX_EAPOL_ETHERNET_FRAME_LEN {
            return Err(Wpa2RuntimeError::FrameTooLarge);
        }
        let destination: [u8; 6] = frame[..6]
            .try_into()
            .map_err(|_| Wpa2RuntimeError::FrameTooShort)?;
        if destination != self.local && destination != PAE_GROUP_ADDRESS {
            return Err(Wpa2RuntimeError::WrongDestination);
        }
        let source: [u8; 6] = frame[6..12]
            .try_into()
            .map_err(|_| Wpa2RuntimeError::FrameTooShort)?;
        if source != self.supplicant.peer() {
            return Err(Wpa2RuntimeError::WrongSource);
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != EAPOL_ETHERTYPE {
            return Err(Wpa2RuntimeError::WrongEtherType);
        }
        Ok(&frame[EAPOL_ETHERNET_HEADER_LEN..])
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

fn input_digest(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::sync::Arc;
    use std::task::Wake;
    use std::vec::Vec;

    use super::super::bus::Bus;
    use super::super::control::{ControlEvent, RSN_CIPHER_CCMP_128};
    use super::super::device::RPU_MEM_TX_CMD_BASE;
    use super::super::protocol::{Hpq, HpqmInfo, UmacHeader};
    use super::super::runtime::DriverState;
    use super::super::wpa2::{Pmk, Wpa2Supplicant};
    use super::*;

    const LOCAL: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
    const COMMAND_BUFFER: u32 = 0xb000_1000;
    const COMMAND_BUFFER_HOST: u32 = 0x000c_1000;
    const COMMAND_AVAILABLE_DEQUEUE: u32 = 0xa400_7000;
    const RSN_IE: [u8; 22] = [
        0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
    ];

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

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
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
        Wpa2Supplicant::new(
            LOCAL,
            PEER,
            [0x11; 32],
            Pmk::from_bytes([0x33; 32]),
            &RSN_IE,
        )
        .unwrap()
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
        let progress = block_on(runtime.on_ethernet_frame(&mut driver, &mut delay, &frame)).unwrap();
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
