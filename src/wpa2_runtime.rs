//! Atomic WPA2-to-radio coordination.
//!
//! The coordinator keeps the controlled port closed until the pairwise key,
//! group key, default group key, EAPOL Message 4 transmission, and firmware
//! authorization command all succeed in order.

use embedded_hal_async::delay::DelayNs;

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
    frame: [u8; MAX_EAPOL_ETHERNET_FRAME_LEN],
}

impl Wpa2Runtime {
    /// Creates one coordinator for a station interface.
    pub fn new(supplicant: Wpa2Supplicant, wdev_id: u8) -> Self {
        let local = supplicant.local();
        Self {
            supplicant,
            local,
            wdev_id,
            state: Wpa2RuntimeState::AwaitingAuthenticator,
            pairwise_install: None,
            group_install: None,
            frame: [0; MAX_EAPOL_ETHERNET_FRAME_LEN],
        }
    }

    /// Returns the coordinator state.
    pub const fn state(&self) -> Wpa2RuntimeState {
        self.state
    }

    /// Borrows the underlying supplicant.
    pub const fn supplicant(&self) -> &Wpa2Supplicant {
        &self.supplicant
    }

    /// Starts a new pairwise handshake with a fresh CSPRNG nonce.
    pub fn restart_pairwise(&mut self, supplicant_nonce: [u8; 32]) -> Result<(), Wpa2RuntimeError<()>> {
        self.supplicant.restart_pairwise(supplicant_nonce)?;
        self.pairwise_install = None;
        self.group_install = None;
        self.state = Wpa2RuntimeState::AwaitingAuthenticator;
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
        let payload = self.validate_ethernet_frame(frame)?;
        if matches!(
            self.state,
            Wpa2RuntimeState::AwaitingEapolTransmit { .. }
                | Wpa2RuntimeState::AwaitingPairwiseKeyStatus
                | Wpa2RuntimeState::AwaitingGroupKeyStatus
                | Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus
                | Wpa2RuntimeState::AwaitingAuthorizationStatus
                | Wpa2RuntimeState::AwaitingGroupRekeyStatus
                | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus
        ) {
            return self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state));
        }

        let was_complete = self.supplicant.phase() == Wpa2Phase::Complete;
        match self.supplicant.on_eapol(self.supplicant.peer(), payload)? {
            Wpa2Action::None => Ok(Wpa2Progress::NoChange),
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
                self.state = Wpa2RuntimeState::Complete;
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

        match self.state {
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus => {
                self.require_command(UmacCommand::NewKey, command)?;
                self.submit_group_key(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingGroupKeyStatus => {
                self.require_command(UmacCommand::NewKey, command)?;
                self.submit_default_group_key(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus => {
                self.require_command(UmacCommand::SetKey, command)?;
                let request = self
                    .pairwise_install
                    .take()
                    .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
                let response = self.supplicant.complete_key_install(request, true)?;
                self.submit_eapol(driver, response, EapolTransmitPurpose::Message4)
                    .await
            }
            Wpa2RuntimeState::AwaitingAuthorizationStatus => {
                self.require_command(UmacCommand::SetStation, command)?;
                if driver.station_mut().state() == StationState::Connected {
                    self.state = Wpa2RuntimeState::Complete;
                    Ok(Wpa2Progress::Complete)
                } else {
                    self.state = Wpa2RuntimeState::AwaitingCarrier;
                    Ok(Wpa2Progress::AwaitingCarrier)
                }
            }
            Wpa2RuntimeState::AwaitingGroupRekeyStatus => {
                self.require_command(UmacCommand::NewKey, command)?;
                self.submit_default_group_rekey(driver, delay).await
            }
            Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => {
                self.require_command(UmacCommand::SetKey, command)?;
                let request = self
                    .group_install
                    .take()
                    .ok_or(Wpa2RuntimeError::MissingInstallRequest)?;
                let response = self.supplicant.complete_group_key_install(request, true)?;
                self.submit_eapol(driver, response, EapolTransmitPurpose::GroupMessage2)
                    .await
            }
            _ => self.fail(driver, Wpa2RuntimeError::UnexpectedState(self.state)),
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
                self.state = Wpa2RuntimeState::AwaitingAuthenticator;
                Ok(Wpa2Progress::NoChange)
            }
            EapolTransmitPurpose::Message4 => {
                let (device, station) = driver.security_parts_mut();
                station.authorize(device, delay).await?;
                self.state = Wpa2RuntimeState::AwaitingAuthorizationStatus;
                Ok(Wpa2Progress::AuthorizationSubmitted)
            }
            EapolTransmitPurpose::GroupMessage2 | EapolTransmitPurpose::Retransmission => {
                self.state = Wpa2RuntimeState::Complete;
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
            self.state = Wpa2RuntimeState::Complete;
            Wpa2Progress::Complete
        } else {
            Wpa2Progress::NoChange
        }
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
        self.state = Wpa2RuntimeState::AwaitingPairwiseKeyStatus;
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
        self.state = Wpa2RuntimeState::AwaitingGroupKeyStatus;
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
        self.state = Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus;
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
        self.state = Wpa2RuntimeState::AwaitingGroupRekeyStatus;
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
        self.state = Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus;
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
        self.state = Wpa2RuntimeState::AwaitingEapolTransmit { token, purpose };
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
    ) -> Result<T, Wpa2RuntimeError<B::Error>> {
        if let Some(request) = self.pairwise_install.take() {
            let _ = self.supplicant.complete_key_install(request, false);
        }
        if let Some(request) = self.group_install.take() {
            let _ = self.supplicant.complete_group_key_install(request, false);
        }
        driver.enter_recovery();
        self.state = Wpa2RuntimeState::Failed;
        Err(error)
    }
}
