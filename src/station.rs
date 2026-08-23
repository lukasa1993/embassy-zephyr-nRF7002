//! Fail-closed station connection state machine.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::{
    AssociationRequest, AuthenticationRequest, ControlEvent, KeyConfig, MAX_STATION_MESSAGE_LEN,
    PowerSaveState, encode_associate, encode_authenticate, encode_interface_state,
    encode_key_command, encode_power_save, encode_power_save_timeout, encode_set_key,
    encode_set_regulatory, encode_station_authorized,
};
use super::data::DataEvent;
use super::device::{Device, DeviceError};
use super::protocol::{
    ProtocolError, ScanReason, ScanRequest, UmacCommand, encode_get_scan_results, encode_scan,
};

const MLME_FRAME_VALID: u32 = 1 << 0;
const MLME_TIMED_OUT: u32 = 1 << 0;

/// Station lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationState {
    Down,
    Idle,
    RegulatoryPending,
    InterfaceUpPending,
    Scanning,
    ScanComplete,
    ReadingScanResults,
    Authenticating,
    Authenticated,
    Associating,
    Securing,
    Authorizing,
    AwaitingCarrier,
    Connected,
    PowerSavePending,
    Disconnecting,
    InterfaceDownPending,
    Recovering,
    Fault,
}

/// Bounded station-state deadlines in milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StationTimeouts {
    pub regulatory_ms: u32,
    pub interface_ms: u32,
    pub scan_ms: u32,
    pub scan_complete_ms: u32,
    pub scan_results_ms: u32,
    pub authentication_ms: u32,
    pub authenticated_ms: u32,
    pub association_ms: u32,
    pub key_exchange_ms: u32,
    pub authorization_ms: u32,
    pub carrier_ms: u32,
    pub power_save_ms: u32,
    pub disconnect_ms: u32,
}

impl StationTimeouts {
    /// Conservative production defaults.
    pub const DEFAULT: Self = Self {
        regulatory_ms: 5_000,
        interface_ms: 5_000,
        scan_ms: 30_000,
        scan_complete_ms: 10_000,
        scan_results_ms: 10_000,
        authentication_ms: 5_000,
        authenticated_ms: 10_000,
        association_ms: 5_000,
        key_exchange_ms: 10_000,
        authorization_ms: 5_000,
        carrier_ms: 5_000,
        power_save_ms: 5_000,
        disconnect_ms: 5_000,
    };
}

impl Default for StationTimeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Last fail-closed station fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationFault {
    CommandRejected { command: u32, status: u32 },
    AuthenticationFailed(u16),
    AssociationFailed(u16),
    MlmeTimeout,
    PeerMismatch,
    UnexpectedEvent,
    CarrierLost,
    Timeout(StationState),
}

/// Station operation failure.
#[derive(Debug)]
pub enum StationError<E> {
    Device(DeviceError<E>),
    Protocol(ProtocolError),
    InvalidState {
        current: StationState,
        required: StationState,
    },
    Fault(StationFault),
}

impl<E> From<DeviceError<E>> for StationError<E> {
    fn from(value: DeviceError<E>) -> Self {
        Self::Device(value)
    }
}

impl<E> From<ProtocolError> for StationError<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Allocation-free station command and event controller.
pub struct StationController {
    ifaceindex: i32,
    firmware_index: i8,
    wdev_id: u32,
    state: StationState,
    last_fault: Option<StationFault>,
    peer: Option<[u8; 6]>,
    secure_connection: bool,
    controlled_port_authorized: bool,
    carrier_on: bool,
    pending_command: Option<UmacCommand>,
    pending_return_state: Option<StationState>,
    timeouts: StationTimeouts,
    remaining_ms: Option<u32>,
    command: [u8; MAX_STATION_MESSAGE_LEN],
}

impl StationController {
    /// Creates a controller for one firmware interface.
    pub const fn new(ifaceindex: i32, firmware_index: i8, wdev_id: u32) -> Self {
        Self {
            ifaceindex,
            firmware_index,
            wdev_id,
            state: StationState::Down,
            last_fault: None,
            peer: None,
            secure_connection: false,
            controlled_port_authorized: false,
            carrier_on: false,
            pending_command: None,
            pending_return_state: None,
            timeouts: StationTimeouts::DEFAULT,
            remaining_ms: None,
            command: [0; MAX_STATION_MESSAGE_LEN],
        }
    }

    /// Returns the current station state.
    pub const fn state(&self) -> StationState {
        self.state
    }

    /// Replaces the state deadlines and rearms the current pending state.
    pub fn set_timeouts(&mut self, timeouts: StationTimeouts) {
        self.timeouts = timeouts;
        self.remaining_ms = self.timeout_for(self.state);
    }

    /// Returns the remaining time for the current pending state.
    pub const fn remaining_time_ms(&self) -> Option<u32> {
        self.remaining_ms
    }

    /// Advances the station deadlines.
    ///
    /// The caller must invoke this method from a monotonic timer path.
    pub fn advance_time(&mut self, elapsed_ms: u32) -> Result<(), StationFault> {
        let Some(remaining) = self.remaining_ms else {
            return Ok(());
        };
        if elapsed_ms < remaining {
            self.remaining_ms = Some(remaining - elapsed_ms);
            return Ok(());
        }
        let fault = StationFault::Timeout(self.state);
        self.last_fault = Some(fault);
        self.pending_command = None;
        self.pending_return_state = None;
        self.transition(StationState::Fault);
        Err(fault)
    }

    /// Returns the most recent fail-closed fault.
    pub const fn last_fault(&self) -> Option<StationFault> {
        self.last_fault
    }

    /// Returns the selected peer address.
    pub const fn peer(&self) -> Option<[u8; 6]> {
        self.peer
    }

    /// Returns true while a host supplicant must process EAPOL traffic.
    pub const fn eapol_required(&self) -> bool {
        self.secure_connection
            && matches!(
                self.state,
                StationState::Securing | StationState::Authorizing | StationState::AwaitingCarrier
            )
    }

    #[cfg(test)]
    pub(crate) fn prepare_security_for_test(&mut self, peer: [u8; 6]) {
        self.transition(StationState::Securing);
        self.last_fault = None;
        self.peer = Some(peer);
        self.secure_connection = true;
        self.controlled_port_authorized = false;
        self.carrier_on = false;
        self.pending_command = None;
    }

    /// Restores connected state after a successful group-key rekey.
    pub fn complete_group_rekey(&mut self) -> StationState {
        let next_state = if self.secure_connection && self.controlled_port_authorized {
            if self.carrier_on {
                StationState::Connected
            } else {
                StationState::AwaitingCarrier
            }
        } else {
            StationState::Fault
        };
        self.transition(next_state);
        self.state
    }

    /// Enters recovery and clears all connection ownership.
    pub fn begin_recovery(&mut self) {
        self.transition(StationState::Recovering);
        self.peer = None;
        self.secure_connection = false;
        self.controlled_port_authorized = false;
        self.carrier_on = false;
        self.pending_command = None;
    }

    /// Marks recovery complete after firmware and queues are initialized.
    pub fn recovery_complete(&mut self) {
        self.transition(StationState::Down);
        self.last_fault = None;
    }

    /// Requests one regulatory country code.
    pub async fn set_regulatory<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        country: [u8; 2],
        user_hint_type: u32,
        force: bool,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_one_of(&[StationState::Down, StationState::Idle])?;
        let len = encode_set_regulatory(
            &mut self.command,
            self.ifaceindex,
            country,
            user_hint_type,
            force,
        )?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::RequestSetRegulatory);
        self.transition(StationState::RegulatoryPending);
        Ok(())
    }

    /// Brings the firmware interface up.
    pub async fn bring_up<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Down)?;
        let len = encode_interface_state(
            &mut self.command,
            self.ifaceindex,
            true,
            self.firmware_index,
        )?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::SetInterfaceFlags);
        self.transition(StationState::InterfaceUpPending);
        Ok(())
    }

    /// Brings the firmware interface down.
    pub async fn bring_down<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_one_of(&[
            StationState::Idle,
            StationState::Connected,
            StationState::Fault,
        ])?;
        let len = encode_interface_state(
            &mut self.command,
            self.ifaceindex,
            false,
            self.firmware_index,
        )?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::SetInterfaceFlags);
        self.transition(StationState::InterfaceDownPending);
        Ok(())
    }

    /// Starts one scan.
    pub async fn start_scan<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        request: &ScanRequest<'_>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Idle)?;
        let len = encode_scan(&mut self.command, self.ifaceindex, request)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::TriggerScan);
        self.transition(StationState::Scanning);
        Ok(())
    }

    /// Requests the result stream after a scan-done event.
    pub async fn request_scan_results<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        reason: ScanReason,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::ScanComplete)?;
        let len = encode_get_scan_results(&mut self.command, self.ifaceindex, reason)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::GetScanResults);
        self.transition(StationState::ReadingScanResults);
        Ok(())
    }

    /// Sends an authentication request.
    pub async fn authenticate<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        request: &AuthenticationRequest<'_>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Idle)?;
        let len = encode_authenticate(&mut self.command, self.ifaceindex, request)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.peer = Some(request.bssid);
        self.pending_command = Some(UmacCommand::Authenticate);
        self.transition(StationState::Authenticating);
        Ok(())
    }

    /// Sends an association request after authentication succeeds.
    pub async fn associate<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        request: &AssociationRequest<'_>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Authenticated)?;
        if self.peer != Some(request.bssid) {
            return self.fail(StationFault::PeerMismatch);
        }
        let len = encode_associate(&mut self.command, self.ifaceindex, request)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.secure_connection = request.security.is_some();
        self.controlled_port_authorized = !self.secure_connection;
        self.pending_command = Some(UmacCommand::Associate);
        self.transition(StationState::Associating);
        Ok(())
    }

    /// Adds or removes a peer key.
    pub async fn key_command<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        command: UmacCommand,
        key: &KeyConfig<'_>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_one_of(&[
            StationState::Securing,
            StationState::Authorizing,
            StationState::Connected,
        ])?;
        let peer = self
            .peer
            .ok_or(StationError::Fault(StationFault::PeerMismatch))?;
        let len = encode_key_command(&mut self.command, self.ifaceindex, command, peer, key)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(command);
        self.transition(StationState::Securing);
        Ok(())
    }

    /// Selects a key as default in firmware.
    pub async fn set_key<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        key: &KeyConfig<'_>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Securing)?;
        let len = encode_set_key(&mut self.command, self.ifaceindex, key)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::SetKey);
        self.transition(StationState::Securing);
        Ok(())
    }

    /// Opens the controlled port after all pairwise and group keys are installed.
    pub async fn authorize<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require(StationState::Securing)?;
        let peer = self
            .peer
            .ok_or(StationError::Fault(StationFault::PeerMismatch))?;
        let len = encode_station_authorized(&mut self.command, self.ifaceindex, peer, true)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::SetStation);
        self.transition(StationState::Authorizing);
        Ok(())
    }

    /// Configures firmware power save.
    pub async fn set_power_save<B, D>(
        &mut self,
        device: &mut Device<B>,
        delay: &mut D,
        state: PowerSaveState,
        timeout_ms: Option<i32>,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
        D: DelayNs,
    {
        self.require_one_of(&[StationState::Idle, StationState::Connected])?;
        let return_state = self.state;
        if let Some(timeout_ms) = timeout_ms {
            let len = encode_power_save_timeout(&mut self.command, self.ifaceindex, timeout_ms)?;
            device
                .send_control_reliable(&self.command[..len], delay)
                .await?;
        }
        let len = encode_power_save(&mut self.command, self.ifaceindex, state)?;
        device
            .send_control_reliable(&self.command[..len], delay)
            .await?;
        self.pending_command = Some(UmacCommand::SetPowerSave);
        self.pending_return_state = Some(return_state);
        self.transition(StationState::PowerSavePending);
        Ok(())
    }

    /// Starts a deauthentication sequence.
    pub async fn disconnect<B>(
        &mut self,
        device: &mut Device<B>,
        reason_code: u16,
    ) -> Result<(), StationError<B::Error>>
    where
        B: Bus,
    {
        self.require_one_of(&[
            StationState::Authenticated,
            StationState::Associating,
            StationState::Securing,
            StationState::Authorizing,
            StationState::AwaitingCarrier,
            StationState::Connected,
        ])?;
        let peer = self
            .peer
            .ok_or(StationError::Fault(StationFault::PeerMismatch))?;
        device
            .deauthenticate(self.ifaceindex, peer, reason_code, false)
            .await?;
        self.pending_command = Some(UmacCommand::Deauthenticate);
        self.transition(StationState::Disconnecting);
        Ok(())
    }

    /// Applies one parsed control event.
    pub fn handle_control_event<E>(
        &mut self,
        event: ControlEvent<'_>,
    ) -> Result<(), StationError<E>> {
        match event {
            ControlEvent::CommandStatus {
                command, status, ..
            } => self.handle_command_status(command, status),
            ControlEvent::InterfaceState { status, .. } => {
                if status != 0 {
                    return self.fail(StationFault::CommandRejected {
                        command: UmacCommand::SetInterfaceFlags as u32,
                        status: status as u32,
                    });
                }
                match self.state {
                    StationState::InterfaceUpPending => {
                        self.transition(StationState::Idle);
                        self.pending_command = None;
                        Ok(())
                    }
                    StationState::InterfaceDownPending => {
                        self.clear_connection();
                        self.transition(StationState::Down);
                        self.pending_command = None;
                        Ok(())
                    }
                    _ => self.fail(StationFault::UnexpectedEvent),
                }
            }
            ControlEvent::ScanDone { status, .. } => {
                if self.state != StationState::Scanning {
                    return self.fail(StationFault::UnexpectedEvent);
                }
                self.pending_command = None;
                if status == 0 {
                    self.transition(StationState::ScanComplete);
                    Ok(())
                } else {
                    self.transition(StationState::Idle);
                    self.fail(StationFault::CommandRejected {
                        command: UmacCommand::TriggerScan as u32,
                        status: status as u32,
                    })
                }
            }
            ControlEvent::ScanResult(result) => {
                if self.state != StationState::ReadingScanResults {
                    return self.fail(StationFault::UnexpectedEvent);
                }
                if result.header.sequence == 0 {
                    self.pending_command = None;
                    self.transition(StationState::Idle);
                }
                Ok(())
            }
            ControlEvent::Authentication(event) => {
                if self.state != StationState::Authenticating {
                    return self.fail(StationFault::UnexpectedEvent);
                }
                self.check_peer(event.bssid)?;
                let status = mlme_status(&event, 28)?;
                if status != 0 {
                    return self.fail(StationFault::AuthenticationFailed(status));
                }
                self.pending_command = None;
                self.transition(StationState::Authenticated);
                Ok(())
            }
            ControlEvent::Association(event) => {
                if self.state != StationState::Associating {
                    return self.fail(StationFault::UnexpectedEvent);
                }
                self.check_peer(event.bssid)?;
                let status = mlme_status(&event, 26)?;
                if status != 0 {
                    return self.fail(StationFault::AssociationFailed(status));
                }
                self.pending_command = None;
                let next_state = if self.secure_connection {
                    StationState::Securing
                } else {
                    StationState::AwaitingCarrier
                };
                self.transition(next_state);
                self.refresh_connected();
                Ok(())
            }
            ControlEvent::Deauthentication(_) | ControlEvent::Disassociation(_) => {
                self.clear_connection();
                self.pending_command = None;
                self.transition(StationState::Idle);
                Ok(())
            }
            ControlEvent::RegulatoryChange { .. } => {
                if self.state == StationState::RegulatoryPending {
                    self.pending_command = None;
                    self.transition(StationState::Down);
                    Ok(())
                } else {
                    Ok(())
                }
            }
            ControlEvent::Other { .. } => Ok(()),
        }
    }

    /// Applies one data event to link state.
    pub fn handle_data_event<E>(&mut self, event: DataEvent) -> Result<(), StationError<E>> {
        match event {
            DataEvent::CarrierOn { wdev_id } if wdev_id == self.wdev_id => {
                self.carrier_on = true;
                self.refresh_connected();
                Ok(())
            }
            DataEvent::CarrierOff { wdev_id } if wdev_id == self.wdev_id => {
                self.carrier_on = false;
                if self.state == StationState::Connected {
                    self.clear_connection();
                    self.transition(StationState::Idle);
                    return self.fail(StationFault::CarrierLost);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_command_status<E>(
        &mut self,
        command: u32,
        status: u32,
    ) -> Result<(), StationError<E>> {
        if self.pending_command.map(|value| value as u32) != Some(command) {
            return self.fail(StationFault::UnexpectedEvent);
        }
        if status != 0 {
            return self.fail(StationFault::CommandRejected { command, status });
        }
        self.pending_command = None;
        if command == UmacCommand::NewKey as u32
            || command == UmacCommand::DeleteKey as u32
            || command == UmacCommand::SetKey as u32
        {
            self.transition(StationState::Securing);
        } else if command == UmacCommand::SetStation as u32
            && self.state == StationState::Authorizing
        {
            self.controlled_port_authorized = true;
            self.transition(StationState::AwaitingCarrier);
            self.refresh_connected();
        } else if command == UmacCommand::SetPowerSave as u32
            && self.state == StationState::PowerSavePending
        {
            let return_state = self
                .pending_return_state
                .take()
                .unwrap_or(StationState::Fault);
            self.transition(return_state);
        }
        Ok(())
    }

    fn transition(&mut self, state: StationState) {
        self.state = state;
        self.remaining_ms = self.timeout_for(state);
    }

    fn timeout_for(&self, state: StationState) -> Option<u32> {
        let value = match state {
            StationState::RegulatoryPending => self.timeouts.regulatory_ms,
            StationState::InterfaceUpPending | StationState::InterfaceDownPending => {
                self.timeouts.interface_ms
            }
            StationState::Scanning => self.timeouts.scan_ms,
            StationState::ScanComplete => self.timeouts.scan_complete_ms,
            StationState::ReadingScanResults => self.timeouts.scan_results_ms,
            StationState::Authenticating => self.timeouts.authentication_ms,
            StationState::Authenticated => self.timeouts.authenticated_ms,
            StationState::Associating => self.timeouts.association_ms,
            StationState::Securing => self.timeouts.key_exchange_ms,
            StationState::Authorizing => self.timeouts.authorization_ms,
            StationState::AwaitingCarrier => self.timeouts.carrier_ms,
            StationState::PowerSavePending => self.timeouts.power_save_ms,
            StationState::Disconnecting => self.timeouts.disconnect_ms,
            StationState::Down
            | StationState::Idle
            | StationState::Connected
            | StationState::Recovering
            | StationState::Fault => return None,
        };
        Some(value.max(1))
    }

    fn check_peer<E>(&mut self, peer: [u8; 6]) -> Result<(), StationError<E>> {
        if peer != [0; 6] && self.peer != Some(peer) {
            self.fail(StationFault::PeerMismatch)
        } else {
            Ok(())
        }
    }

    fn refresh_connected(&mut self) {
        if self.carrier_on && self.controlled_port_authorized {
            self.transition(StationState::Connected);
        }
    }

    fn clear_connection(&mut self) {
        self.peer = None;
        self.secure_connection = false;
        self.controlled_port_authorized = false;
        self.carrier_on = false;
    }

    fn require<E>(&self, required: StationState) -> Result<(), StationError<E>> {
        if self.state == required {
            Ok(())
        } else {
            Err(StationError::InvalidState {
                current: self.state,
                required,
            })
        }
    }

    fn require_one_of<E>(&self, required: &[StationState]) -> Result<(), StationError<E>> {
        if required.contains(&self.state) {
            Ok(())
        } else {
            Err(StationError::InvalidState {
                current: self.state,
                required: required[0],
            })
        }
    }

    fn fail<T, E>(&mut self, fault: StationFault) -> Result<T, StationError<E>> {
        self.last_fault = Some(fault);
        self.pending_command = None;
        self.pending_return_state = None;
        self.transition(StationState::Fault);
        Err(StationError::Fault(fault))
    }
}

fn mlme_status<E>(
    event: &super::control::MlmeEvent<'_>,
    status_offset: usize,
) -> Result<u16, StationError<E>> {
    if event.flags & MLME_TIMED_OUT != 0 {
        return Err(StationError::Fault(StationFault::MlmeTimeout));
    }
    if event.header.result != 0 {
        return Ok(event.header.result as u16);
    }
    if event.valid_fields & MLME_FRAME_VALID == 0 {
        return Ok(0);
    }
    if event.frame.len() < status_offset + 2 {
        return Err(StationError::Fault(StationFault::UnexpectedEvent));
    }
    Ok(u16::from_le_bytes([
        event.frame[status_offset],
        event.frame[status_offset + 1],
    ]))
}

#[cfg(test)]
mod tests {
    use super::super::control::MlmeEvent;
    use super::super::protocol::UmacHeader;
    use super::*;

    fn header(event: UmacCommand) -> UmacHeader {
        UmacHeader {
            port_id: 0,
            sequence: 1,
            command_event: event as u32,
            result: 0,
            valid_ids: 0,
            ifaceindex: 1,
            wiphy_index: 0,
            wdev_id: 0,
        }
    }

    #[test]
    fn secure_connection_needs_authorization_and_carrier() {
        let mut station = StationController::new(1, 0, 7);
        station.state = StationState::Associating;
        station.peer = Some([1, 2, 3, 4, 5, 6]);
        station.secure_connection = true;
        let mut frame = [0u8; 30];
        frame[26..28].copy_from_slice(&0u16.to_le_bytes());
        station
            .handle_control_event::<()>(ControlEvent::Association(MlmeEvent {
                header: header(UmacCommand::Associate),
                valid_fields: MLME_FRAME_VALID,
                frequency_mhz: 2412,
                signal_dbm: -40,
                flags: 0,
                cookie: 0,
                bssid: [1, 2, 3, 4, 5, 6],
                frame: &frame,
                request_information_elements: &[],
            }))
            .unwrap();
        assert_eq!(station.state(), StationState::Securing);
        station
            .handle_data_event::<()>(DataEvent::CarrierOn { wdev_id: 7 })
            .unwrap();
        assert_eq!(station.state(), StationState::Securing);
        station.state = StationState::Authorizing;
        station.pending_command = Some(UmacCommand::SetStation);
        station
            .handle_control_event::<()>(ControlEvent::CommandStatus {
                header: header(UmacCommand::SetStation),
                command: UmacCommand::SetStation as u32,
                status: 0,
            })
            .unwrap();
        assert_eq!(station.state(), StationState::Connected);
    }

    #[test]
    fn command_failure_is_fail_closed() {
        let mut station = StationController::new(1, 0, 7);
        station.state = StationState::Authenticating;
        station.pending_command = Some(UmacCommand::Authenticate);
        assert!(
            station
                .handle_control_event::<()>(ControlEvent::CommandStatus {
                    header: header(UmacCommand::Authenticate),
                    command: UmacCommand::Authenticate as u32,
                    status: 5,
                })
                .is_err()
        );
        assert_eq!(station.state(), StationState::Fault);
    }

    #[test]
    fn pending_station_state_has_a_bounded_deadline() {
        let mut station = StationController::new(1, 0, 7);
        station.transition(StationState::Authenticating);
        assert_eq!(station.remaining_time_ms(), Some(5_000));
        assert_eq!(station.advance_time(4_999), Ok(()));
        assert_eq!(
            station.advance_time(1),
            Err(StationFault::Timeout(StationState::Authenticating))
        );
        assert_eq!(station.state(), StationState::Fault);
    }
}
