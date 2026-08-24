//! Fail-closed high-level runtime for production integration.
//!
//! This module does not make hardware validation optional. It provides one
//! controlled API that closes the data port before authorization, routes
//! uncertain ownership to recovery, and does not expose mutable low-level
//! device state.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::{
    AssociationRequest, AuthenticationRequest, EAPOL_ETHERTYPE, PowerSaveState,
};
use super::data::{DataError, DataLayoutError, DataProtocolError, ReceivedFrame, RxEventRef};
use super::device::{DeviceError, FragmentLimitError};
use super::firmware::{FirmwareBundle, FirmwareReport, FirmwareTrustPolicy};
use super::protocol::{ProtocolError, ScanReason, ScanRequest, SystemInitConfig};
use super::runtime::{
    DriverError, DriverEvent, DriverState, NativeDriver, Platform, RecoveryError,
};
use super::station::{StationError, StationFault, StationState, StationTimeouts};

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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station
                .create_interface(device, delay, mac_address, interface_name)
                .await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station
                .set_regulatory(device, delay, country, user_hint_type, force)
                .await
        };
        self.finish_station(result)
    }

    /// Brings the station interface up.
    pub async fn bring_up<D>(&mut self, delay: &mut D) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.bring_up(device, delay).await
        };
        self.finish_station(result)
    }

    /// Brings the station interface down.
    pub async fn bring_down<D>(&mut self, delay: &mut D) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.bring_down(device, delay).await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.start_scan(device, delay, request).await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.request_scan_results(device, delay, reason).await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.authenticate(device, delay, request).await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.associate(device, delay, request).await
        };
        self.finish_station(result)
    }

    /// Applies a sequenced firmware power-save update.
    pub async fn set_power_save<D>(
        &mut self,
        delay: &mut D,
        state: PowerSaveState,
        timeout_ms: Option<i32>,
    ) -> Result<(), ProductionError<B::Error>>
    where
        D: DelayNs,
    {
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station
                .set_power_save(device, delay, state, timeout_ms)
                .await
        };
        self.finish_station(result)
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
        self.ensure_ready()?;
        let result = {
            let (device, station) = self.inner.security_parts_mut();
            station.disconnect(device, delay, reason_code).await
        };
        self.finish_station(result)
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
        let result = self
            .inner
            .receive_packet(event, packet_index, output)
            .await;
        let frame = match result {
            Ok(frame) => frame,
            Err(error) => {
                if receive_error_requires_recovery(&error) {
                    self.inner.enter_recovery();
                }
                return Err(ProductionError::Driver(error));
            }
        };

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
        StationError::Protocol(_) | StationError::InvalidState { .. } => false,
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
        DataError::Protocol(_) => matches!(operation, DriverOperation::Receive | DriverOperation::Event),
        DataError::NoTransmitToken | DataError::OutputTooSmall { .. } => false,
    }
}

fn driver_error_requires_recovery<E>(error: &DriverError<E>, operation: DriverOperation) -> bool {
    match error {
        DriverError::Device(error) => {
            if matches!(operation, DriverOperation::Event)
                && matches!(error, DeviceError::EventBufferChanged)
            {
                return false;
            }
            device_error_requires_recovery(error)
        }
        DriverError::Data(error) => data_error_requires_recovery(error, operation),
        DriverError::DataProtocol(_) => true,
        DriverError::Firmware(_) | DriverError::Protocol(_) | DriverError::InvalidWatchdogStatus => {
            true
        }
        DriverError::Station(error) => station_error_requires_recovery(error),
        DriverError::InvalidState { .. } => false,
    }
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
    pub fn advance_time(
        &mut self,
        elapsed_ms: u32,
    ) -> Result<(), SecureProductionError<B::Error>> {
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

        let security = match event {
            DriverEvent::Control(control)
                if control_event_is_expected(self.security.state(), control) =>
            {
                self.security
                    .on_control_event(&mut self.driver.inner, delay, control)
                    .await?
            }
            DriverEvent::TransmitDone(done)
                if transmit_done_is_expected(self.security.state(), done) =>
            {
                self.security
                    .on_transmit_done(&mut self.driver.inner, delay, done)
                    .await?
            }
            DriverEvent::Data(_) => self.security.refresh_carrier(&mut self.driver.inner),
            _ => Wpa2Progress::NoChange,
        };

        Ok(Some(SecureDriverEvent { event, security }))
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
        if frame.ether_type != EAPOL_ETHERTYPE {
            return Ok(SecureReceive::Data(frame));
        }

        let progress = self
            .security
            .on_ethernet_frame(
                &mut self.driver.inner,
                delay,
                &output[..frame.len],
            )
            .await?;
        output[..frame.len].fill(0);
        Ok(SecureReceive::Eapol(progress))
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
    match state {
        Wpa2RuntimeState::AwaitingPairwiseKeyStatus
        | Wpa2RuntimeState::AwaitingGroupKeyStatus
        | Wpa2RuntimeState::AwaitingGroupRekeyStatus => command == UmacCommand::NewKey as u32,
        Wpa2RuntimeState::AwaitingDefaultGroupKeyStatus
        | Wpa2RuntimeState::AwaitingDefaultGroupRekeyStatus => command == UmacCommand::SetKey as u32,
        Wpa2RuntimeState::AwaitingAuthorizationStatus => command == UmacCommand::SetStation as u32,
        _ => false,
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
