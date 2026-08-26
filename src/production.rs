//! Fail-closed high-level runtime for production integration.
//!
//! This module does not make hardware validation optional. It provides one
//! controlled API that closes the data port before authorization, routes
//! uncertain ownership to recovery, and does not expose mutable low-level
//! device state.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::{AssociationRequest, AuthenticationRequest, EAPOL_ETHERTYPE, PowerSaveState};
use super::data::{DataError, DataLayoutError, ReceivedFrame, RxEventRef};
use super::device::{DeviceError, FragmentLimitError};
use super::firmware::{FirmwareBundle, FirmwareReport, FirmwareTrustPolicy};
use super::protocol::{ScanReason, ScanRequest, SystemInitConfig};
use super::runtime::{
    DriverError, DriverEvent, DriverState, NativeDriver, Platform, RecoveryError,
};
use super::station::{StationError, StationState, StationTimeouts};

#[cfg(feature = "embassy-net")]
use super::embassy::NetworkRunner;

#[cfg(feature = "wpa2")]
use super::control::ControlEvent;
#[cfg(feature = "wpa2")]
use super::data::TxDoneEventRef;
#[cfg(feature = "wpa2")]
use super::protocol::UmacCommand;
#[cfg(feature = "wpa2")]
use super::wpa2::{Wpa2Error, Wpa2Supplicant};
#[cfg(feature = "wpa2")]
use super::wpa2_runtime::{
    Wpa2Progress, Wpa2Runtime, Wpa2RuntimeError, Wpa2RuntimeState, Wpa2Timeouts,
};

/// Fail-closed production API error.
#[derive(Debug)]
pub enum ProductionError<E> {
    /// The portable driver reported an error.
    Driver(DriverError<E>),
    /// The station command or state machine reported an error.
    Station(StationError<E>),
    /// The Ethernet frame is shorter than its fixed header.
    InvalidEthernetFrame,
    /// The controlled port does not permit this EtherType.
    ControlledPortClosed { ether_type: u16 },
}

impl<E> From<DriverError<E>> for ProductionError<E> {
    fn from(value: DriverError<E>) -> Self {
        Self::Driver(value)
    }
}

impl<E> From<StationError<E>> for ProductionError<E> {
    fn from(value: StationError<E>) -> Self {
        Self::Station(value)
    }
}

/// High-level driver that keeps low-level mutable state private.
pub struct MissionCriticalDriver<B, const RX: usize, const TX: usize> {
    inner: NativeDriver<B, RX, TX>,
}

macro_rules! run_station_command {
    ($driver:ident, $delay:expr, $method:ident $(, $argument:expr)* $(,)?) => {{
        $driver.ensure_ready()?;
        let result = {
            let (device, station) = $driver.inner.security_parts_mut();
            station.$method(device, $delay $(, $argument)*).await
        };
        $driver.finish_station(result)
    }};
}

impl<B, const RX: usize, const TX: usize> MissionCriticalDriver<B, RX, TX> {
    /// Creates one cold fail-closed driver.
    pub fn new(
        bus: B,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        ifaceindex: i32,
        firmware_index: i8,
        wdev_id: u32,
    ) -> Result<Self, DataLayoutError> {
        Ok(Self {
            inner: NativeDriver::new(
                bus,
                rx_buffer_size,
                tx_buffer_size,
                ifaceindex,
                firmware_index,
                wdev_id,
            )?,
        })
    }

    /// Wraps an existing cold or recovered native driver.
    pub const fn from_native(inner: NativeDriver<B, RX, TX>) -> Self {
        Self { inner }
    }

    /// Returns the top-level lifecycle state.
    pub const fn state(&self) -> DriverState {
        self.inner.state()
    }

    /// Returns the station lifecycle state.
    pub fn station_state(&mut self) -> StationState {
        self.inner.station_mut().state()
    }

    /// Returns true only when normal network traffic is permitted.
    pub fn controlled_port_open(&mut self) -> bool {
        self.inner.station_mut().controlled_port_open()
    }

    /// Sets bounded station-operation deadlines.
    pub fn set_station_timeouts(&mut self, timeouts: StationTimeouts) {
        self.inner.station_mut().set_timeouts(timeouts);
    }

    /// Sets protocol fragment limits within the pinned Nordic limits.
    pub fn set_fragment_limits(
        &mut self,
        command_len: usize,
        event_len: usize,
    ) -> Result<(), FragmentLimitError> {
        self.inner
            .device_mut()
            .set_fragment_limits(command_len, event_len)
    }

    /// Returns the low-level bus and consumes all driver state.
    pub fn into_inner(self) -> B {
        self.inner.into_inner()
    }

    #[cfg(feature = "embassy-net")]
    /// Synchronizes an Embassy network queue with the authorized port state.
    pub fn sync_embassy_link<const FRAME_SIZE: usize>(
        &mut self,
        runner: &NetworkRunner<'_, FRAME_SIZE>,
    ) {
        runner.sync_station_link(self.inner.station_mut());
    }
}

impl<B, const RX: usize, const TX: usize> MissionCriticalDriver<B, RX, TX>
where
    B: Bus,
{
    /// Performs the complete reset, firmware, queue, RX, interrupt, and init sequence.
    pub async fn recover<P, D, T>(
        &mut self,
        platform: &mut P,
        delay: &mut D,
        bundle: &FirmwareBundle<'_>,
        trust: &T,
        config: &SystemInitConfig,
    ) -> Result<FirmwareReport, RecoveryError<B::Error, P::Error>>
    where
        P: Platform,
        D: DelayNs,
        T: FirmwareTrustPolicy + ?Sized,
    {
        self.inner
            .recover(platform, delay, bundle, trust, config)
            .await
    }

    /// Waits for the board host-interrupt signal.
    pub async fn wait_for_interrupt<P>(
        &mut self,
        platform: &mut P,
    ) -> Result<(), RecoveryError<B::Error, P::Error>>
    where
        P: Platform,
    {
        self.inner.wait_for_interrupt(platform).await
    }

    /// Creates and validates one station interface.
    pub async fn create_station_interface<D>(
        &mut self,
        delay: &mut D,
        mac_address: [u8; 6],
        interface_name: &[u8],
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, create_interface, mac_address, interface_name)
    }

    /// Applies and validates one regulatory country code.
    pub async fn set_regulatory<D>(
        &mut self,
        delay: &mut D,
        country: [u8; 2],
        user_hint_type: u32,
        force: bool,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, set_regulatory, country, user_hint_type, force)
    }

    /// Brings the station interface up.
    pub async fn bring_up<D>(&mut self, delay: &mut D) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, bring_up)
    }

    /// Brings the station interface down.
    pub async fn bring_down<D>(&mut self, delay: &mut D) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, bring_down)
    }

    /// Starts one bounded scan.
    pub async fn start_scan<D>(
        &mut self,
        delay: &mut D,
        request: &ScanRequest<'_>,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, start_scan, request)
    }

    /// Requests the scan-result stream.
    pub async fn request_scan_results<D>(
        &mut self,
        delay: &mut D,
        reason: ScanReason,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, request_scan_results, reason)
    }

    /// Starts 802.11 authentication.
    pub async fn authenticate<D>(
        &mut self,
        delay: &mut D,
        request: &AuthenticationRequest<'_>,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, authenticate, request)
    }

    /// Starts 802.11 association.
    pub async fn associate<D>(
        &mut self,
        delay: &mut D,
        request: &AssociationRequest<'_>,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, associate, request)
    }

    /// Starts a firmware power-save state update.
    pub async fn set_power_save<D>(
        &mut self,
        delay: &mut D,
        state: PowerSaveState,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, set_power_save, state)
    }

    /// Starts a firmware power-save timeout update.
    ///
    /// Process its command-status event before a power-save state update.
    pub async fn set_power_save_timeout<D>(
        &mut self,
        delay: &mut D,
        timeout_ms: i32,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, set_power_save_timeout, timeout_ms)
    }

    /// Starts a reliable deauthentication sequence.
    pub async fn disconnect<D>(
        &mut self,
        delay: &mut D,
        reason_code: u16,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        run_station_command!(self, delay, disconnect, reason_code)
    }

    /// Advances all station deadlines.
    pub fn advance_time(&mut self, elapsed_ms: u32) -> Result<(), ProductionError<B::Error>> {
        let result = self.inner.advance_time(elapsed_ms);
        self.finish_driver(result, DriverOperation::Control)
    }

    /// Polls and dispatches one complete firmware event.
    pub async fn poll_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<DriverEvent<'a>>, ProductionError<B::Error>> {
        let result = self.inner.poll_event(scratch).await;
        self.finish_driver(result, DriverOperation::Event)
    }

    /// Reads one packet and drops it when the controlled port rejects it.
    pub async fn receive_packet(
        &mut self,
        event: &RxEventRef<'_>,
        packet_index: usize,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, ProductionError<B::Error>> {
        self.ensure_ready()?;
        let result = self.inner.receive_packet(event, packet_index, output).await;
        let frame = self.finish_receive(result, output)?;
        self.enforce_received_frame(frame, output)
    }

    fn finish_receive(
        &mut self,
        result: Result<ReceivedFrame, DriverError<B::Error>>,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, ProductionError<B::Error>> {
        match result {
            Ok(frame) => Ok(frame),
            Err(DriverError::ControlledPortClosed { ether_type, .. }) => {
                // The portable layer has already consumed the firmware RX
                // buffer. Normalize this expected fail-closed drop so WPA2
                // callers do not mistake pre-authorization ARP/IP traffic for
                // a hardware fault, and wipe any copied caller bytes.
                output.fill(0);
                Err(ProductionError::ControlledPortClosed { ether_type })
            }
            Err(error) => {
                if receive_error_requires_recovery(&error) {
                    self.inner.enter_recovery();
                }
                Err(ProductionError::Driver(error))
            }
        }
    }

    fn enforce_received_frame(
        &mut self,
        frame: ReceivedFrame,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, ProductionError<B::Error>> {
        if self.frame_allowed(frame.ether_type) {
            return Ok(frame);
        }
        output[..frame.len].fill(0);
        Err(ProductionError::ControlledPortClosed {
            ether_type: frame.ether_type,
        })
    }

    /// Sends one Ethernet frame only when the controlled port permits it.
    pub async fn transmit(
        &mut self,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, ProductionError<B::Error>> {
        self.ensure_ready()?;
        let ether_type = ethernet_type(frame)?;
        if !self.frame_allowed(ether_type) {
            return Err(ProductionError::ControlledPortClosed { ether_type });
        }
        let result = self.inner.transmit(wdev_id, frame, dscp_tos).await;
        self.finish_driver(result, DriverOperation::Transmit)
    }

    /// Checks the firmware watchdog status.
    pub async fn watchdog_pending(&mut self) -> Result<bool, ProductionError<B::Error>> {
        let result = self.inner.watchdog_pending().await;
        self.finish_driver(result, DriverOperation::Watchdog)
    }

    /// Acknowledges the watchdog and enters recovery.
    pub async fn acknowledge_watchdog(&mut self) -> Result<(), ProductionError<B::Error>> {
        let result = self.inner.acknowledge_watchdog().await;
        self.finish_driver(result, DriverOperation::Watchdog)
    }

    fn ensure_ready(&self) -> Result<(), ProductionError<B::Error>> {
        if self.inner.state() == DriverState::Ready {
            Ok(())
        } else {
            Err(ProductionError::Driver(DriverError::InvalidState {
                current: self.inner.state(),
                required: DriverState::Ready,
            }))
        }
    }

    fn frame_allowed(&mut self, ether_type: u16) -> bool {
        let station = self.inner.station_mut();
        if station.controlled_port_open() {
            return true;
        }
        ether_type == EAPOL_ETHERTYPE && station.eapol_required()
    }

    fn finish_station<T>(
        &mut self,
        result: Result<T, StationError<B::Error>>,
    ) -> Result<T, ProductionError<B::Error>> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if station_error_requires_recovery(&error) {
                    self.inner.enter_recovery();
                }
                Err(ProductionError::Station(error))
            }
        }
    }

    fn finish_driver<T>(
        &mut self,
        result: Result<T, DriverError<B::Error>>,
        operation: DriverOperation,
    ) -> Result<T, ProductionError<B::Error>> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if driver_error_requires_recovery(&error, operation) {
                    self.inner.enter_recovery();
                }
                Err(ProductionError::Driver(error))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum DriverOperation {
    Control,
    Event,
    Receive,
    Transmit,
    Watchdog,
}

fn ethernet_type<E>(frame: &[u8]) -> Result<u16, ProductionError<E>> {
    if frame.len() < 14 {
        return Err(ProductionError::InvalidEthernetFrame);
    }
    Ok(u16::from_be_bytes([frame[12], frame[13]]))
}

fn station_error_requires_recovery<E>(error: &StationError<E>) -> bool {
    match error {
        StationError::Device(error) => device_error_requires_recovery(error),
        StationError::Fault(_) => true,
        StationError::Protocol(_)
        | StationError::InvalidState { .. }
        | StationError::InterfaceAlreadyCreated
        | StationError::InterfaceNotCreated => false,
    }
}

fn device_error_requires_recovery<E>(error: &DeviceError<E>) -> bool {
    matches!(
        error,
        DeviceError::Rpu(_)
            | DeviceError::NotInitialized
            | DeviceError::InvalidQueueMap
            | DeviceError::CommandDeliveryUncertain
            | DeviceError::RecoveryRequired
            | DeviceError::EventTooLarge { .. }
    )
}

fn data_error_requires_recovery<E>(error: &DataError<E>, operation: DriverOperation) -> bool {
    match error {
        DataError::Device(error) => device_error_requires_recovery(error),
        DataError::Rpu(_) | DataError::QueueOwnershipUncertain(_) => true,
        DataError::ReceiveDescriptorBusy(_) => true,
        DataError::Protocol(_) => input_protocol_error_requires_recovery(operation),
        DataError::NoTransmitToken | DataError::OutputTooSmall { .. } => false,
    }
}

fn driver_error_requires_recovery<E>(error: &DriverError<E>, operation: DriverOperation) -> bool {
    match error {
        DriverError::Device(error) => device_error_requires_recovery(error),
        DriverError::Data(error) => data_error_requires_recovery(error, operation),
        DriverError::Station(error) => station_error_requires_recovery(error),
        other => simple_driver_error_requires_recovery(other, operation),
    }
}

fn simple_driver_error_requires_recovery<E>(
    error: &DriverError<E>,
    operation: DriverOperation,
) -> bool {
    match error {
        DriverError::DataProtocol(_)
        | DriverError::Firmware(_)
        | DriverError::Protocol(_)
        | DriverError::UnexpectedEventForState { .. }
        | DriverError::InvalidWatchdogStatus => true,
        DriverError::WrongInterface { .. } => input_protocol_error_requires_recovery(operation),
        DriverError::InvalidState { .. }
        | DriverError::InvalidStationState { .. }
        | DriverError::ConfigurationMismatch
        | DriverError::FrameTooShort
        | DriverError::ControlledPortClosed { .. } => false,
        DriverError::Device(_) | DriverError::Data(_) | DriverError::Station(_) => {
            unreachable!("nested driver errors are handled first")
        }
    }
}

fn input_protocol_error_requires_recovery(operation: DriverOperation) -> bool {
    matches!(operation, DriverOperation::Receive | DriverOperation::Event)
}

fn receive_error_requires_recovery<E>(error: &DriverError<E>) -> bool {
    driver_error_requires_recovery(error, DriverOperation::Receive)
}

#[cfg(feature = "wpa2")]
/// One driver event and its WPA2 progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureDriverEvent<'a> {
    pub event: DriverEvent<'a>,
    pub security: Wpa2Progress,
}

#[cfg(feature = "wpa2")]
/// Result of one received packet in a WPA2 station session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureReceive {
    /// Normal Ethernet data permitted by the controlled port.
    Data(ReceivedFrame),
    /// EAPOL data consumed by the WPA2 state machine.
    Eapol(Wpa2Progress),
}

#[cfg(feature = "wpa2")]
/// Error from the integrated WPA2 station runtime.
#[derive(Debug)]
pub enum SecureProductionError<E> {
    Production(ProductionError<E>),
    Wpa2(Wpa2RuntimeError<E>),
    Supplicant(Wpa2Error),
}

#[cfg(feature = "wpa2")]
impl<E> From<ProductionError<E>> for SecureProductionError<E> {
    fn from(value: ProductionError<E>) -> Self {
        Self::Production(value)
    }
}

#[cfg(feature = "wpa2")]
impl<E> From<Wpa2RuntimeError<E>> for SecureProductionError<E> {
    fn from(value: Wpa2RuntimeError<E>) -> Self {
        Self::Wpa2(value)
    }
}

#[cfg(feature = "wpa2")]
/// Integrated fail-closed WPA2-Personal station runtime.
pub struct Wpa2StationDriver<B, const RX: usize, const TX: usize> {
    driver: MissionCriticalDriver<B, RX, TX>,
    security: Wpa2Runtime,
}

#[cfg(feature = "wpa2")]
impl<B, const RX: usize, const TX: usize> Wpa2StationDriver<B, RX, TX> {
    /// Joins one fail-closed driver and one configured WPA2 supplicant.
    pub fn new(
        driver: MissionCriticalDriver<B, RX, TX>,
        supplicant: Wpa2Supplicant,
        wdev_id: u8,
    ) -> Self {
        Self {
            driver,
            security: Wpa2Runtime::new(supplicant, wdev_id),
        }
    }

    /// Returns the driver lifecycle state.
    pub const fn state(&self) -> DriverState {
        self.driver.state()
    }

    /// Returns the WPA2 phase state.
    pub const fn security_state(&self) -> Wpa2RuntimeState {
        self.security.state()
    }

    /// Replaces WPA2 phase deadlines.
    pub fn set_wpa2_timeouts(&mut self, timeouts: Wpa2Timeouts) {
        self.security.set_timeouts(timeouts);
    }

    /// Returns the fail-closed driver API.
    pub const fn driver(&self) -> &MissionCriticalDriver<B, RX, TX> {
        &self.driver
    }

    /// Returns the fail-closed driver API for safe high-level commands.
    pub fn driver_mut(&mut self) -> &mut MissionCriticalDriver<B, RX, TX> {
        &mut self.driver
    }

    /// Consumes the WPA2 coordinator and returns the fail-closed driver.
    pub fn into_driver(self) -> MissionCriticalDriver<B, RX, TX> {
        self.driver
    }
}

#[cfg(feature = "wpa2")]
impl<B, const RX: usize, const TX: usize> Wpa2StationDriver<B, RX, TX>
where
    B: Bus,
{
    /// Starts a new pairwise exchange with a fresh CSPRNG nonce.
    pub fn restart_pairwise(
        &mut self,
        supplicant_nonce: [u8; 32],
    ) -> Result<(), SecureProductionError<B::Error>> {
        self.security
            .restart_pairwise(supplicant_nonce)
            .map_err(SecureProductionError::Supplicant)
    }

    /// Advances both station and WPA2 deadlines.
    pub fn advance_time(&mut self, elapsed_ms: u32) -> Result<(), SecureProductionError<B::Error>> {
        self.driver.advance_time(elapsed_ms)?;
        self.security
            .advance_time(&mut self.driver.inner, elapsed_ms)?;
        Ok(())
    }

    /// Polls one firmware event and applies all relevant WPA2 transitions.
    pub async fn poll_event<'a, D>(
        &mut self,
        delay: &mut D,
        scratch: &'a mut [u8],
    ) -> Result<Option<SecureDriverEvent<'a>>, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        let Some(event) = self.driver.poll_event(scratch).await? else {
            return Ok(None);
        };

        let security = self.apply_security_event(delay, event).await?;

        Ok(Some(SecureDriverEvent { event, security }))
    }

    async fn apply_security_event<D>(
        &mut self,
        delay: &mut D,
        event: DriverEvent<'_>,
    ) -> Result<Wpa2Progress, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        match event {
            DriverEvent::Control(control) => self.apply_control_event(delay, control).await,
            DriverEvent::TransmitDone(done) => self.apply_transmit_done(delay, done).await,
            DriverEvent::Data(_) => Ok(self.security.refresh_carrier(&mut self.driver.inner)),
            _ => Ok(Wpa2Progress::NoChange),
        }
    }

    async fn apply_control_event<D>(
        &mut self,
        delay: &mut D,
        control: ControlEvent<'_>,
    ) -> Result<Wpa2Progress, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        if !control_event_is_expected(self.security.state(), control) {
            return Ok(Wpa2Progress::NoChange);
        }
        Ok(self
            .security
            .on_control_event(&mut self.driver.inner, delay, control)
            .await?)
    }

    async fn apply_transmit_done<D>(
        &mut self,
        delay: &mut D,
        done: TxDoneEventRef<'_>,
    ) -> Result<Wpa2Progress, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        if !transmit_done_is_expected(self.security.state(), done) {
            return Ok(Wpa2Progress::NoChange);
        }
        Ok(self
            .security
            .on_transmit_done(&mut self.driver.inner, delay, done)
            .await?)
    }

    /// Reads one packet. EAPOL packets are consumed by the WPA2 state machine.
    pub async fn receive_packet<D>(
        &mut self,
        delay: &mut D,
        event: &RxEventRef<'_>,
        packet_index: usize,
        output: &mut [u8],
    ) -> Result<SecureReceive, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        let frame = self
            .driver
            .receive_packet(event, packet_index, output)
            .await?;
        self.finish_received_packet(delay, frame, output).await
    }

    async fn finish_received_packet<D>(
        &mut self,
        delay: &mut D,
        frame: ReceivedFrame,
        output: &mut [u8],
    ) -> Result<SecureReceive, SecureProductionError<B::Error>>
    where
        D: DelayNs,
    {
        if frame.ether_type != EAPOL_ETHERTYPE {
            return Ok(SecureReceive::Data(frame));
        }

        let result = self
            .security
            .on_ethernet_frame(&mut self.driver.inner, delay, &output[..frame.len])
            .await;
        output[..frame.len].fill(0);
        Ok(SecureReceive::Eapol(result?))
    }

    /// Sends one normal Ethernet frame through the authorized port.
    pub async fn transmit(
        &mut self,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, SecureProductionError<B::Error>> {
        Ok(self.driver.transmit(wdev_id, frame, dscp_tos).await?)
    }
}

#[cfg(feature = "wpa2")]
fn control_event_is_expected(state: Wpa2RuntimeState, event: ControlEvent<'_>) -> bool {
    let ControlEvent::CommandStatus { command, .. } = event else {
        return false;
    };
    expected_security_command(state) == Some(command)
}

#[cfg(feature = "wpa2")]
fn expected_security_command(state: Wpa2RuntimeState) -> Option<u32> {
    match state {
        Wpa2RuntimeState::AwaitingPairwiseKeyStatus
        | Wpa2RuntimeState::AwaitingGroupKeyStatus
        | Wpa2RuntimeState::AwaitingGroupRekeyStatus => Some(UmacCommand::NewKey as u32),
        Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus
        | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => Some(UmacCommand::SetKey as u32),
        Wpa2RuntimeState::AwaitingAuthorizationStatus => Some(UmacCommand::SetStation as u32),
        _ => None,
    }
}

#[cfg(feature = "wpa2")]
fn transmit_done_is_expected(state: Wpa2RuntimeState, event: TxDoneEventRef<'_>) -> bool {
    matches!(
        state,
        Wpa2RuntimeState::AwaitingEapolTransmit { token, .. } if token == event.token
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::Bus;
    use crate::data::DataProtocolError;
    use crate::memory::RpuError;
    #[cfg(feature = "wpa2")]
    use crate::protocol::UmacHeader;
    use crate::protocol::{HostMessageRef, HostMessageType, ProtocolError};
    use crate::station::StationFault;
    #[cfg(feature = "wpa2")]
    use crate::system::SystemEvent;
    use crate::test_support::block_on;

    #[cfg(feature = "wpa2")]
    use crate::data::DataEvent;
    #[cfg(feature = "wpa2")]
    use crate::wpa2::Pmk;
    #[cfg(feature = "wpa2")]
    use crate::wpa2_runtime::EapolTransmitPurpose;

    #[derive(Default)]
    struct NullBus;

    impl Bus for NullBus {
        type Error = ();

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, _address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            data.fill(0);
            Ok(())
        }

        async fn write(&mut self, _address: u32, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[cfg(feature = "wpa2")]
    struct NoDelay;

    #[cfg(feature = "wpa2")]
    impl DelayNs for NoDelay {
        async fn delay_ns(&mut self, _ns: u32) {}
    }

    fn driver() -> MissionCriticalDriver<NullBus, 1, 1> {
        MissionCriticalDriver::new(NullBus, 64, 64, 1, 0, 0).unwrap()
    }

    fn ready_driver() -> MissionCriticalDriver<NullBus, 1, 1> {
        let mut driver = driver();
        driver.inner.prepare_ready_for_test();
        driver
    }

    fn received(ether_type: u16) -> ReceivedFrame {
        ReceivedFrame {
            len: 14,
            ether_type,
            descriptor_id: 0,
            signal_dbm: -40,
            frequency_mhz: 2412,
        }
    }

    #[cfg(feature = "wpa2")]
    fn umac_header() -> UmacHeader {
        UmacHeader {
            port_id: 0,
            sequence: 1,
            command_event: 0,
            result: 0,
            valid_ids: 0,
            ifaceindex: 1,
            wiphy_index: 0,
            wdev_id: 0,
        }
    }

    fn rx_event_payload() -> [u8; 37] {
        let mut payload = [0u8; 37];
        payload[..4]
            .copy_from_slice(&(crate::data::DataCommand::ReceiveBuffer as u32).to_le_bytes());
        let len = payload.len() as u32;
        payload[4..8].copy_from_slice(&len.to_le_bytes());
        payload[13] = 1;
        payload[15] = 24;
        payload
    }

    #[cfg(feature = "wpa2")]
    fn secure_driver() -> Wpa2StationDriver<NullBus, 1, 1> {
        const RSN_IE: [u8; 22] = [
            0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
        ];
        let supplicant = Wpa2Supplicant::new(
            [2, 0, 0, 0, 0, 1],
            [2, 0, 0, 0, 0, 2],
            [0x11; 32],
            Pmk::from_bytes([0x33; 32]),
            &RSN_IE,
        )
        .unwrap();
        Wpa2StationDriver::new(driver(), supplicant, 0)
    }

    #[test]
    fn mission_driver_is_fail_closed_until_ready_and_validates_ethernet_first() {
        let mut cold = driver();
        assert_eq!(cold.state(), DriverState::Cold);
        assert!(!cold.controlled_port_open());
        assert!(matches!(
            block_on(cold.transmit(0, &[0; 14], 0)),
            Err(ProductionError::Driver(DriverError::InvalidState { .. }))
        ));
        let payload = rx_event_payload();
        let event = RxEventRef::parse(HostMessageRef {
            resubmit: false,
            message_type: HostMessageType::Data,
            payload: &payload,
        })
        .unwrap();
        assert!(matches!(
            block_on(cold.receive_packet(&event, 0, &mut [0; 64])),
            Err(ProductionError::Driver(DriverError::InvalidState { .. }))
        ));

        let mut ready = ready_driver();
        assert!(matches!(
            block_on(ready.transmit(0, &[0; 13], 0)),
            Err(ProductionError::InvalidEthernetFrame)
        ));
        let mut ipv4 = [0u8; 14];
        ipv4[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(matches!(
            block_on(ready.transmit(0, &ipv4, 0)),
            Err(ProductionError::ControlledPortClosed { ether_type: 0x0800 })
        ));
    }

    #[test]
    fn receive_result_normalization_wipes_closed_port_frames_and_recovers_faults() {
        let mut driver = ready_driver();
        let mut output = [7u8; 32];
        assert!(matches!(
            driver.finish_receive(
                Err(DriverError::ControlledPortClosed {
                    state: StationState::Down,
                    ether_type: 0x0800,
                }),
                &mut output,
            ),
            Err(ProductionError::ControlledPortClosed { ether_type: 0x0800 })
        ));
        assert_eq!(output, [0; 32]);
        assert_eq!(driver.state(), DriverState::Ready);

        output.fill(7);
        assert!(matches!(
            driver.finish_receive(
                Err(DriverError::Data(DataError::OutputTooSmall {
                    needed: 64,
                    capacity: 32,
                })),
                &mut output,
            ),
            Err(ProductionError::Driver(DriverError::Data(
                DataError::OutputTooSmall { .. }
            )))
        ));
        assert_eq!(driver.state(), DriverState::Ready);

        assert!(matches!(
            driver.finish_receive(
                Err(DriverError::DataProtocol(DataProtocolError::InvalidLength)),
                &mut output,
            ),
            Err(ProductionError::Driver(DriverError::DataProtocol(_)))
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn received_frame_policy_allows_only_the_active_controlled_port() {
        let mut driver = ready_driver();
        let mut output = [9u8; 32];
        assert!(!driver.frame_allowed(EAPOL_ETHERTYPE));
        assert!(matches!(
            driver.enforce_received_frame(received(0x0800), &mut output),
            Err(ProductionError::ControlledPortClosed { ether_type: 0x0800 })
        ));
        assert_eq!(&output[..14], &[0; 14]);

        driver
            .inner
            .station_mut()
            .prepare_security_for_test([1, 2, 3, 4, 5, 6]);
        assert!(driver.frame_allowed(EAPOL_ETHERTYPE));
        assert!(!driver.frame_allowed(0x0800));
        assert!(
            driver
                .enforce_received_frame(received(EAPOL_ETHERTYPE), &mut output)
                .is_ok()
        );

        driver
            .inner
            .station_mut()
            .prepare_connected_for_test([1, 2, 3, 4, 5, 6]);
        assert!(driver.frame_allowed(0x0800));
        assert!(
            driver
                .enforce_received_frame(received(0x0800), &mut output)
                .is_ok()
        );
    }

    #[test]
    fn finish_helpers_enter_recovery_only_for_hardware_and_station_faults() {
        let mut driver = ready_driver();
        assert_eq!(driver.finish_station::<u8>(Ok(7)).unwrap(), 7);
        assert!(matches!(
            driver.finish_station::<()>(Err(StationError::Protocol(ProtocolError::LimitExceeded))),
            Err(ProductionError::Station(StationError::Protocol(_)))
        ));
        assert_eq!(driver.state(), DriverState::Ready);
        assert!(matches!(
            driver.finish_station::<()>(Err(StationError::Fault(StationFault::UnexpectedEvent))),
            Err(ProductionError::Station(StationError::Fault(_)))
        ));
        assert_eq!(driver.state(), DriverState::Recovering);

        let mut driver = ready_driver();
        assert_eq!(
            driver
                .finish_driver::<u8>(Ok(9), DriverOperation::Control)
                .unwrap(),
            9
        );
        assert!(matches!(
            driver.finish_driver::<()>(Err(DriverError::FrameTooShort), DriverOperation::Transmit),
            Err(ProductionError::Driver(DriverError::FrameTooShort))
        ));
        assert_eq!(driver.state(), DriverState::Ready);
        assert!(matches!(
            driver.finish_driver::<()>(
                Err(DriverError::InvalidWatchdogStatus),
                DriverOperation::Watchdog
            ),
            Err(ProductionError::Driver(DriverError::InvalidWatchdogStatus))
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn all_recovery_policy_categories_are_explicit() {
        for error in [
            DeviceError::<()>::Rpu(RpuError::Timeout),
            DeviceError::NotInitialized,
            DeviceError::InvalidQueueMap,
            DeviceError::CommandDeliveryUncertain,
            DeviceError::RecoveryRequired,
            DeviceError::EventTooLarge {
                declared: 2,
                capacity: 1,
            },
        ] {
            assert!(device_error_requires_recovery(&error));
        }
        for error in [
            DeviceError::<()>::Protocol(ProtocolError::InvalidLength),
            DeviceError::CommandQueueEmpty,
            DeviceError::CommandNeedsWait,
            DeviceError::CommandQueueTimeout,
            DeviceError::EventBufferChanged,
        ] {
            assert!(!device_error_requires_recovery(&error));
        }

        assert!(data_error_requires_recovery(
            &DataError::<()>::Rpu(RpuError::Timeout),
            DriverOperation::Transmit
        ));
        assert!(data_error_requires_recovery(
            &DataError::<()>::Device(DeviceError::NotInitialized),
            DriverOperation::Control
        ));
        assert!(data_error_requires_recovery(
            &DataError::<()>::QueueOwnershipUncertain(DeviceError::CommandDeliveryUncertain),
            DriverOperation::Transmit
        ));
        assert!(data_error_requires_recovery(
            &DataError::<()>::ReceiveDescriptorBusy(1),
            DriverOperation::Receive
        ));
        assert!(data_error_requires_recovery(
            &DataError::<()>::Protocol(DataProtocolError::InvalidLength),
            DriverOperation::Event
        ));
        assert!(!data_error_requires_recovery(
            &DataError::<()>::Protocol(DataProtocolError::InvalidLength),
            DriverOperation::Transmit
        ));
        assert!(!data_error_requires_recovery(
            &DataError::<()>::NoTransmitToken,
            DriverOperation::Transmit
        ));
        assert!(!data_error_requires_recovery(
            &DataError::<()>::OutputTooSmall {
                needed: 2,
                capacity: 1,
            },
            DriverOperation::Receive
        ));
    }

    #[test]
    fn simple_driver_error_policy_distinguishes_input_context() {
        assert!(simple_driver_error_requires_recovery(
            &DriverError::<()>::DataProtocol(DataProtocolError::InvalidLength),
            DriverOperation::Control
        ));
        assert!(simple_driver_error_requires_recovery(
            &DriverError::<()>::Protocol(ProtocolError::InvalidLength),
            DriverOperation::Control
        ));
        assert!(simple_driver_error_requires_recovery(
            &DriverError::<()>::Firmware(crate::firmware::LoadError::Firmware(
                crate::firmware::FirmwareError::TruncatedHeader,
            )),
            DriverOperation::Control
        ));
        let wrong = DriverError::<()>::WrongInterface {
            expected: 0,
            received: 1,
        };
        assert!(simple_driver_error_requires_recovery(
            &wrong,
            DriverOperation::Receive
        ));
        assert!(!simple_driver_error_requires_recovery(
            &wrong,
            DriverOperation::Transmit
        ));
        assert!(simple_driver_error_requires_recovery(
            &DriverError::<()>::UnexpectedEventForState {
                state: DriverState::Ready,
            },
            DriverOperation::Event
        ));
        assert!(!simple_driver_error_requires_recovery(
            &DriverError::<()>::ConfigurationMismatch,
            DriverOperation::Control
        ));
    }

    #[cfg(feature = "wpa2")]
    #[test]
    fn expected_wpa2_commands_and_transmit_tokens_are_state_specific() {
        for state in [
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus,
            Wpa2RuntimeState::AwaitingGroupKeyStatus,
            Wpa2RuntimeState::AwaitingGroupRekeyStatus,
        ] {
            assert_eq!(
                expected_security_command(state),
                Some(UmacCommand::NewKey as u32)
            );
        }
        for state in [
            Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus,
            Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus,
        ] {
            assert_eq!(
                expected_security_command(state),
                Some(UmacCommand::SetKey as u32)
            );
        }
        assert_eq!(
            expected_security_command(Wpa2RuntimeState::AwaitingAuthorizationStatus),
            Some(UmacCommand::SetStation as u32)
        );
        assert_eq!(
            expected_security_command(Wpa2RuntimeState::AwaitingAuthenticator),
            None
        );

        let status = ControlEvent::CommandStatus {
            header: umac_header(),
            command: UmacCommand::NewKey as u32,
            status: 0,
        };
        assert!(control_event_is_expected(
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus,
            status
        ));
        assert!(!control_event_is_expected(
            Wpa2RuntimeState::AwaitingAuthorizationStatus,
            status
        ));
        assert!(!control_event_is_expected(
            Wpa2RuntimeState::AwaitingPairwiseKeyStatus,
            ControlEvent::InterfaceState {
                header: umac_header(),
                status: 0,
            }
        ));

        let done = TxDoneEventRef {
            token: 7,
            statuses: &[0],
        };
        assert!(transmit_done_is_expected(
            Wpa2RuntimeState::AwaitingEapolTransmit {
                token: 7,
                purpose: EapolTransmitPurpose::Message2,
            },
            done
        ));
        assert!(!transmit_done_is_expected(
            Wpa2RuntimeState::AwaitingEapolTransmit {
                token: 8,
                purpose: EapolTransmitPurpose::Message2,
            },
            done
        ));
    }

    #[cfg(feature = "wpa2")]
    #[test]
    fn secure_event_routing_ignores_unexpected_events_fail_closed() {
        let mut secure = secure_driver();
        let mut delay = NoDelay;
        assert_eq!(
            block_on(
                secure
                    .apply_security_event(&mut delay, DriverEvent::System(SystemEvent::InitDone),)
            )
            .unwrap(),
            Wpa2Progress::NoChange
        );
        assert_eq!(
            block_on(secure.apply_security_event(
                &mut delay,
                DriverEvent::Control(ControlEvent::InterfaceState {
                    header: umac_header(),
                    status: 0,
                }),
            ))
            .unwrap(),
            Wpa2Progress::NoChange
        );
        assert_eq!(
            block_on(secure.apply_security_event(
                &mut delay,
                DriverEvent::TransmitDone(TxDoneEventRef {
                    token: 7,
                    statuses: &[0],
                }),
            ))
            .unwrap(),
            Wpa2Progress::NoChange
        );
        assert_eq!(
            block_on(secure.apply_security_event(
                &mut delay,
                DriverEvent::Data(DataEvent::CarrierOn { wdev_id: 0 }),
            ))
            .unwrap(),
            Wpa2Progress::NoChange
        );

        assert!(matches!(
            block_on(secure.poll_event(&mut delay, &mut [0; 64])),
            Err(SecureProductionError::Production(ProductionError::Driver(
                DriverError::Device(DeviceError::NotInitialized)
            )))
        ));
    }

    #[cfg(feature = "wpa2")]
    #[test]
    fn secure_receive_classifies_data_and_wipes_rejected_eapol() {
        let mut secure = secure_driver();
        let mut delay = NoDelay;
        let mut output = [9u8; 32];

        assert_eq!(
            block_on(secure.finish_received_packet(&mut delay, received(0x0800), &mut output,))
                .unwrap(),
            SecureReceive::Data(received(0x0800))
        );
        assert_eq!(output, [9; 32]);

        assert!(matches!(
            block_on(secure.finish_received_packet(
                &mut delay,
                received(EAPOL_ETHERTYPE),
                &mut output,
            )),
            Err(SecureProductionError::Wpa2(_))
        ));
        assert_eq!(&output[..14], &[0; 14]);
        assert_eq!(secure.state(), DriverState::Recovering);
    }

    #[cfg(feature = "wpa2")]
    #[test]
    fn secure_deadlines_advance_and_expire_fail_closed() {
        let mut secure = secure_driver();
        assert!(secure.advance_time(1).is_ok());
        assert_eq!(secure.security.remaining_time_ms(), Some(4_999));

        assert!(matches!(
            secure.advance_time(4_999),
            Err(SecureProductionError::Wpa2(Wpa2RuntimeError::Timeout(
                Wpa2RuntimeState::AwaitingAuthenticator
            )))
        ));
        assert_eq!(secure.state(), DriverState::Recovering);
        assert_eq!(secure.security_state(), Wpa2RuntimeState::Failed);
    }

    #[test]
    fn short_ethernet_frame_is_rejected() {
        assert!(matches!(
            ethernet_type::<()>(&[0; 13]),
            Err(ProductionError::InvalidEthernetFrame)
        ));
    }

    #[test]
    fn ethernet_type_is_big_endian() {
        let mut frame = [0u8; 14];
        frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE.to_be_bytes());
        assert_eq!(ethernet_type::<()>(&frame).unwrap(), EAPOL_ETHERTYPE);
    }

    #[test]
    fn caller_buffer_error_does_not_require_hardware_recovery() {
        let error = DriverError::<()>::Data(DataError::OutputTooSmall {
            needed: 64,
            capacity: 32,
        });
        assert!(!receive_error_requires_recovery(&error));
    }

    #[test]
    fn uncertain_queue_ownership_requires_recovery() {
        let error = DriverError::<()>::Data(DataError::QueueOwnershipUncertain(
            DeviceError::CommandDeliveryUncertain,
        ));
        assert!(driver_error_requires_recovery(
            &error,
            DriverOperation::Transmit
        ));
    }

    #[test]
    fn malformed_firmware_data_requires_recovery() {
        let error = DriverError::<()>::DataProtocol(DataProtocolError::InvalidLength);
        assert!(driver_error_requires_recovery(
            &error,
            DriverOperation::Event
        ));
    }

    #[test]
    fn invalid_state_is_not_a_hardware_recovery_reason() {
        let error = DriverError::<()>::InvalidState {
            current: DriverState::Cold,
            required: DriverState::Ready,
        };
        assert!(!driver_error_requires_recovery(
            &error,
            DriverOperation::Control
        ));
    }

    #[test]
    fn station_fault_requires_recovery() {
        let error = StationError::<()>::Fault(StationFault::UnexpectedEvent);
        assert!(station_error_requires_recovery(&error));
    }

    #[test]
    fn protocol_input_error_does_not_require_hardware_recovery() {
        let error = StationError::<()>::Protocol(ProtocolError::LimitExceeded);
        assert!(!station_error_requires_recovery(&error));
    }
}
