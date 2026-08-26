//! Top-level boot, event dispatch, watchdog, recovery, and controlled-port runtime.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::{
    AssociationRequest, AuthenticationRequest, ControlEvent, PowerSaveState, parse_control_event,
};
use super::data::{
    DataError, DataEvent, DataLayoutError, DataPath, DataProtocolError, EAPOL_ETHERTYPE,
    ETHERNET_HEADER_LEN, ReceivedFrame, RxEventRef, TxDoneEventRef, classify_data_event,
};
use super::device::{Device, DeviceError};
use super::firmware::{self, FirmwareBundle, FirmwareReport, FirmwareTrustPolicy, LoadError};
use super::protocol::{
    HOST_MESSAGE_HEADER_LEN, HostMessageRef, HostMessageType, ProtocolError, SYSTEM_INIT_LEN,
    ScanReason, ScanRequest, SystemInitConfig, encode_system_init,
};
use super::station::{StationController, StationError, StationState};
use super::system::{SystemEvent, parse_system_event};

/// Default wake-status polls after a board reset.
pub const DEFAULT_WAKE_ATTEMPTS: u16 = 1000;
/// LMAC watchdog status register.
pub const RPU_REG_WATCHDOG_STATUS: u32 = 0xa400_0004;
/// LMAC watchdog clear register.
pub const RPU_REG_WATCHDOG_CLEAR: u32 = 0xa400_000c;
/// LMAC watchdog timer register.
pub const RPU_REG_WATCHDOG_TIMER: u32 = 0xa400_004c;
/// Watchdog status and clear bit.
pub const RPU_WATCHDOG_BIT: u32 = 1 << 1;
/// Watchdog timer reload value.
pub const RPU_WATCHDOG_RELOAD: u32 = 0x00ff_ffff;
const SYSTEM_INIT_MESSAGE_LEN: usize = SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN;

/// Top-level driver lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverState {
    Cold,
    Recovering,
    WaitingForSystemInit,
    Ready,
    Fault,
}

/// Event returned after host-message dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverEvent<'a> {
    System(SystemEvent<'a>),
    Control(ControlEvent<'a>),
    Data(DataEvent),
    TransmitDone(TxDoneEventRef<'a>),
    Receive(RxEventRef<'a>),
    Supplicant(&'a [u8]),
}

/// Runtime operation failure.
#[derive(Debug)]
pub enum DriverError<E> {
    Device(DeviceError<E>),
    Data(DataError<E>),
    DataProtocol(DataProtocolError),
    Firmware(LoadError<E>),
    Protocol(ProtocolError),
    Station(StationError<E>),
    InvalidState {
        current: DriverState,
        required: DriverState,
    },
    InvalidStationState {
        current: StationState,
        required: StationState,
    },
    ConfigurationMismatch,
    WrongInterface {
        expected: u8,
        received: u8,
    },
    FrameTooShort,
    ControlledPortClosed {
        state: StationState,
        ether_type: u16,
    },
    UnexpectedEventForState {
        state: DriverState,
    },
    InvalidWatchdogStatus,
}

impl<E> From<DeviceError<E>> for DriverError<E> {
    fn from(value: DeviceError<E>) -> Self {
        Self::Device(value)
    }
}

impl<E> From<DataError<E>> for DriverError<E> {
    fn from(value: DataError<E>) -> Self {
        Self::Data(value)
    }
}

impl<E> From<LoadError<E>> for DriverError<E> {
    fn from(value: LoadError<E>) -> Self {
        Self::Firmware(value)
    }
}

impl<E> From<ProtocolError> for DriverError<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl<E> From<StationError<E>> for DriverError<E> {
    fn from(value: StationError<E>) -> Self {
        Self::Station(value)
    }
}

/// Board or driver recovery failure.
#[derive(Debug)]
pub enum RecoveryError<E, P> {
    Platform(P),
    Driver(DriverError<E>),
}

impl<E, P> From<DriverError<E>> for RecoveryError<E, P> {
    fn from(value: DriverError<E>) -> Self {
        Self::Driver(value)
    }
}

/// Board services that the portable driver cannot implement.
#[allow(async_fn_in_trait)]
pub trait Platform {
    type Error;

    /// Performs the complete nRF7002 power and hard-reset sequence.
    async fn hard_reset<D>(&mut self, delay: &mut D) -> Result<(), Self::Error>
    where
        D: DelayNs;

    /// Selects a bus configuration of 8 MHz or less for wake access.
    async fn prepare_wake_bus(&mut self) -> Result<(), Self::Error>;

    /// Selects the board-qualified bus configuration for normal traffic.
    async fn prepare_data_bus(&mut self) -> Result<(), Self::Error>;

    /// Waits for the nRF7002 host-interrupt signal.
    async fn wait_for_interrupt(&mut self) -> Result<(), Self::Error>;
}

/// Owns one complete native nRF7002 driver instance.
pub struct NativeDriver<B, const RX: usize, const TX: usize> {
    device: Device<B>,
    data: DataPath<RX, TX>,
    station: StationController,
    state: DriverState,
    ifaceindex: i32,
    wdev_id: u8,
    configured_mac: Option<[u8; 6]>,
}

macro_rules! recovery_step {
    ($result:expr, $map_error:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return Err($map_error(error)),
        }
    };
}

macro_rules! run_native_station_command {
    ($driver:ident, $delay:expr, $method:ident $(, $argument:expr)* $(,)?) => {{
        $driver.require_state(DriverState::Ready)?;
        $driver
            .station
            .$method(&mut $driver.device, $delay $(, $argument)*)
            .await?;
        Ok(())
    }};
}

impl<B, const RX: usize, const TX: usize> NativeDriver<B, RX, TX> {
    /// Creates one cold driver instance.
    pub fn new(
        bus: B,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        ifaceindex: i32,
        firmware_index: i8,
        wdev_id: u32,
    ) -> Result<Self, DataLayoutError> {
        let wdev_id_u8 = u8::try_from(wdev_id).map_err(|_| DataLayoutError::InvalidCapacity)?;
        Ok(Self {
            device: Device::new(bus),
            data: DataPath::new(rx_buffer_size, tx_buffer_size)?,
            station: StationController::new(ifaceindex, firmware_index, wdev_id),
            state: DriverState::Cold,
            ifaceindex,
            wdev_id: wdev_id_u8,
            configured_mac: None,
        })
    }

    /// Returns the current top-level state.
    pub const fn state(&self) -> DriverState {
        self.state
    }

    /// Returns the configured Linux-style interface index.
    pub const fn ifaceindex(&self) -> i32 {
        self.ifaceindex
    }

    /// Returns the firmware data-path interface identifier.
    pub const fn wdev_id(&self) -> u8 {
        self.wdev_id
    }

    /// Borrows the low-level device.
    pub fn device_mut(&mut self) -> &mut Device<B> {
        &mut self.device
    }

    /// Borrows packet-RAM ownership state.
    pub fn data_mut(&mut self) -> &mut DataPath<RX, TX> {
        &mut self.data
    }

    /// Borrows the station state machine.
    pub const fn station(&self) -> &StationController {
        &self.station
    }

    /// Mutably borrows the station state machine.
    pub fn station_mut(&mut self) -> &mut StationController {
        &mut self.station
    }

    /// Splits the device and station fields for coordinated control operations.
    pub(crate) fn security_parts_mut(&mut self) -> (&mut Device<B>, &mut StationController) {
        (&mut self.device, &mut self.station)
    }

    /// Moves the complete runtime into recovery.
    pub(crate) fn enter_recovery(&mut self) {
        self.station.begin_recovery();
        self.configured_mac = None;
        self.state = DriverState::Recovering;
    }

    #[cfg(test)]
    pub(crate) fn prepare_ready_for_test(&mut self) {
        self.state = DriverState::Ready;
    }

    /// Releases the low-level bus.
    pub fn into_inner(self) -> B {
        self.device.into_inner()
    }
}

impl<B, const RX: usize, const TX: usize> NativeDriver<B, RX, TX>
where
    B: Bus,
{
    /// Performs a hard reset, loads firmware, initializes queues, and sends system init.
    ///
    /// The driver enters [`DriverState::WaitingForSystemInit`]. It becomes
    /// ready only after [`SystemEvent::InitDone`] is received and dispatched.
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
        self.state = DriverState::Recovering;
        self.station.begin_recovery();
        self.configured_mac = None;

        let result = async {
            recovery_step!(self.validate_system_config(config), RecoveryError::Driver);
            let _ = self.device.disable_interrupts().await;
            recovery_step!(platform.hard_reset(delay).await, RecoveryError::Platform);
            self.device.reset_queue_state();
            self.data.reset_after_rpu_reset();

            recovery_step!(platform.prepare_wake_bus().await, RecoveryError::Platform);
            recovery_step!(
                self.device
                    .rpu_mut()
                    .wake(delay, DEFAULT_WAKE_ATTEMPTS)
                    .await,
                |error| RecoveryError::Driver(DriverError::Device(DeviceError::from(error)))
            );
            recovery_step!(platform.prepare_data_bus().await, RecoveryError::Platform);

            recovery_step!(self.device.rpu_mut().enable_clocks().await, |error| {
                RecoveryError::Driver(DriverError::Device(DeviceError::from(error)))
            });

            let report = recovery_step!(
                firmware::load(self.device.rpu_mut(), delay, bundle, trust).await,
                |error| RecoveryError::Driver(DriverError::Firmware(error))
            );
            recovery_step!(self.device.initialize_queues().await, |error| {
                RecoveryError::Driver(DriverError::Device(error))
            });
            recovery_step!(self.data.post_all_rx(&mut self.device).await, |error| {
                RecoveryError::Driver(DriverError::Data(error))
            });
            recovery_step!(self.device.enable_interrupts().await, |error| {
                RecoveryError::Driver(DriverError::Device(error))
            });

            let mut message = [0u8; SYSTEM_INIT_MESSAGE_LEN];
            let len = recovery_step!(encode_system_init(&mut message, config), |error| {
                RecoveryError::Driver(DriverError::Protocol(error))
            });
            recovery_step!(
                self.device
                    .send_control_reliable(&message[..len], delay)
                    .await,
                |error| RecoveryError::Driver(DriverError::Device(error))
            );
            Ok(report)
        }
        .await;

        match result {
            Ok(report) => {
                self.configured_mac = Some(config.mac_address);
                self.state = DriverState::WaitingForSystemInit;
                Ok(report)
            }
            Err(error) => {
                self.state = DriverState::Fault;
                Err(error)
            }
        }
    }

    /// Creates the configured station interface after system initialization succeeds.
    pub async fn create_station_interface<D>(
        &mut self,
        delay: &mut D,
        ifaceindex: i32,
        mac_address: [u8; 6],
        interface_name: &[u8],
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        self.require_state(DriverState::Ready)?;
        if ifaceindex != self.ifaceindex || self.configured_mac != Some(mac_address) {
            return Err(DriverError::ConfigurationMismatch);
        }
        run_native_station_command!(self, delay, create_interface, mac_address, interface_name)
    }

    /// Requests a regulatory country code.
    pub async fn set_regulatory<D>(
        &mut self,
        delay: &mut D,
        country: [u8; 2],
        user_hint_type: u32,
        force: bool,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, set_regulatory, country, user_hint_type, force)
    }

    /// Brings the configured station interface up.
    pub async fn bring_up<D>(&mut self, delay: &mut D) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, bring_up)
    }

    /// Brings the configured station interface down.
    pub async fn bring_down<D>(&mut self, delay: &mut D) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, bring_down)
    }

    /// Starts one bounded station scan.
    pub async fn start_scan<D>(
        &mut self,
        delay: &mut D,
        request: &ScanRequest<'_>,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, start_scan, request)
    }

    /// Requests the result stream after scan completion.
    pub async fn request_scan_results<D>(
        &mut self,
        delay: &mut D,
        reason: ScanReason,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, request_scan_results, reason)
    }

    /// Starts station authentication.
    pub async fn authenticate<D>(
        &mut self,
        delay: &mut D,
        request: &AuthenticationRequest<'_>,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, authenticate, request)
    }

    /// Starts station association.
    pub async fn associate<D>(
        &mut self,
        delay: &mut D,
        request: &AssociationRequest<'_>,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, associate, request)
    }

    /// Enables or disables firmware power save.
    pub async fn set_power_save<D>(
        &mut self,
        delay: &mut D,
        state: PowerSaveState,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, set_power_save, state)
    }

    /// Changes the firmware power-save timeout.
    pub async fn set_power_save_timeout<D>(
        &mut self,
        delay: &mut D,
        timeout_ms: i32,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, set_power_save_timeout, timeout_ms)
    }

    /// Starts a station deauthentication sequence.
    pub async fn disconnect<D>(
        &mut self,
        delay: &mut D,
        reason_code: u16,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        run_native_station_command!(self, delay, disconnect, reason_code)
    }

    /// Waits for one host interrupt through the board layer.
    pub async fn wait_for_interrupt<P>(
        &mut self,
        platform: &mut P,
    ) -> Result<(), RecoveryError<B::Error, P::Error>>
    where
        P: Platform,
    {
        platform
            .wait_for_interrupt()
            .await
            .map_err(RecoveryError::Platform)
    }

    /// Advances station-control deadlines.
    pub fn advance_time(&mut self, elapsed_ms: u32) -> Result<(), DriverError<B::Error>> {
        match self.station.advance_time(elapsed_ms) {
            Ok(()) => Ok(()),
            Err(fault) => {
                self.enter_recovery();
                Err(DriverError::Station(StationError::Fault(fault)))
            }
        }
    }

    /// Polls, parses, and applies one complete RPU event.
    pub async fn poll_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<DriverEvent<'a>>, DriverError<B::Error>> {
        if self.device.recovery_required() {
            self.enter_recovery();
            return Err(DriverError::Device(DeviceError::RecoveryRequired));
        }
        let Some(message) = self.device.try_read_event(scratch).await? else {
            return Ok(None);
        };
        Ok(Some(self.dispatch_message(message)?))
    }

    /// Dispatches one already parsed host message.
    pub fn dispatch_message<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        match message.message_type {
            HostMessageType::System => self.dispatch_system_message(message),
            HostMessageType::Umac => self.dispatch_control_message(message),
            HostMessageType::Data => self.dispatch_data_message(message),
            HostMessageType::Supplicant => self.dispatch_supplicant_message(message),
        }
    }

    fn dispatch_system_message<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        let event = parse_system_event(message)?;
        match event {
            SystemEvent::InitDone if self.state == DriverState::WaitingForSystemInit => {
                self.station.recovery_complete();
                self.state = DriverState::Ready;
            }
            SystemEvent::InitDone | SystemEvent::DeinitDone => {
                let state = self.state;
                self.enter_recovery();
                return Err(DriverError::UnexpectedEventForState { state });
            }
            _ => {}
        }
        Ok(DriverEvent::System(event))
    }

    fn dispatch_control_message<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        self.require_state(DriverState::Ready)?;
        let event = parse_control_event(message)?;
        if let Err(error) = self.station.handle_control_event(event) {
            self.enter_recovery();
            return Err(DriverError::Station(error));
        }
        Ok(DriverEvent::Control(event))
    }

    fn dispatch_data_message<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        self.require_state(DriverState::Ready)?;
        let event = classify_data_event(message).map_err(DriverError::DataProtocol)?;
        match event {
            DataEvent::TransmitDone { .. } => self.dispatch_transmit_done(message),
            DataEvent::Receive => self.dispatch_receive(message),
            _ => self.dispatch_station_data(event),
        }
    }

    fn dispatch_transmit_done<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        let event = TxDoneEventRef::parse(message).map_err(DriverError::DataProtocol)?;
        self.data
            .complete_tx(event.token)
            .map_err(DriverError::DataProtocol)?;
        Ok(DriverEvent::TransmitDone(event))
    }

    fn dispatch_receive<'a>(
        &mut self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        let event = RxEventRef::parse(message).map_err(DriverError::DataProtocol)?;
        Ok(DriverEvent::Receive(event))
    }

    fn dispatch_station_data<'a>(
        &mut self,
        event: DataEvent,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        if let Err(error) = self.station.handle_data_event(event) {
            self.enter_recovery();
            return Err(DriverError::Station(error));
        }
        Ok(DriverEvent::Data(event))
    }

    fn dispatch_supplicant_message<'a>(
        &self,
        message: HostMessageRef<'a>,
    ) -> Result<DriverEvent<'a>, DriverError<B::Error>> {
        self.require_state(DriverState::Ready)?;
        Ok(DriverEvent::Supplicant(message.payload))
    }

    /// Copies one received packet into caller storage and enforces the controlled port.
    pub async fn receive_packet(
        &mut self,
        event: &RxEventRef<'_>,
        packet_index: usize,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, DriverError<B::Error>> {
        let frame = self
            .data
            .receive_packet(&mut self.device, event, packet_index, output)
            .await?;
        self.validate_received_frame(event, frame)
    }

    fn validate_received_frame(
        &mut self,
        event: &RxEventRef<'_>,
        frame: ReceivedFrame,
    ) -> Result<ReceivedFrame, DriverError<B::Error>> {
        if event.wdev_id != self.wdev_id {
            let received = event.wdev_id;
            self.enter_recovery();
            return Err(DriverError::WrongInterface {
                expected: self.wdev_id,
                received,
            });
        }
        self.require_controlled_port(frame.ether_type)?;
        Ok(frame)
    }

    /// Sends one Ethernet frame and enforces the controlled port.
    pub async fn transmit(
        &mut self,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, DriverError<B::Error>> {
        if wdev_id != self.wdev_id {
            return Err(DriverError::WrongInterface {
                expected: self.wdev_id,
                received: wdev_id,
            });
        }
        let ether_type = ethernet_type(frame).ok_or(DriverError::FrameTooShort)?;
        self.require_controlled_port(ether_type)?;
        Ok(self
            .data
            .transmit(&mut self.device, wdev_id, frame, dscp_tos)
            .await?)
    }

    /// Sends one Ethernet frame on the configured station interface.
    pub async fn transmit_frame(
        &mut self,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, DriverError<B::Error>> {
        self.transmit(self.wdev_id, frame, dscp_tos).await
    }

    /// Checks the watchdog status with Nordic's sentinel-read rule.
    pub async fn watchdog_pending(&mut self) -> Result<bool, DriverError<B::Error>> {
        for _ in 0..10 {
            let value = self
                .device
                .rpu_mut()
                .read_register(RPU_REG_WATCHDOG_STATUS)
                .await
                .map_err(DeviceError::from)?;
            if value != 0xaaaa_aaaa {
                return Ok(value & RPU_WATCHDOG_BIT != 0);
            }
        }
        self.state = DriverState::Fault;
        Err(DriverError::InvalidWatchdogStatus)
    }

    /// Acknowledges and rearms a watchdog interrupt, then requires recovery.
    pub async fn acknowledge_watchdog(&mut self) -> Result<(), DriverError<B::Error>> {
        self.device
            .rpu_mut()
            .write_register(RPU_REG_WATCHDOG_CLEAR, RPU_WATCHDOG_BIT)
            .await
            .map_err(DeviceError::from)?;
        self.device
            .rpu_mut()
            .write_register(RPU_REG_WATCHDOG_TIMER, RPU_WATCHDOG_RELOAD)
            .await
            .map_err(DeviceError::from)?;
        self.enter_recovery();
        Ok(())
    }

    fn validate_system_config(
        &self,
        config: &SystemInitConfig,
    ) -> Result<(), DriverError<B::Error>> {
        let mac = config.mac_address;
        let mac_is_valid = [mac != [0; 6], mac != [0xff; 6], mac[0] & 1 == 0]
            .into_iter()
            .all(core::convert::identity);
        let pool0 = config.rx_pools[0];
        let extra_pools_are_empty = config.rx_pools[1..]
            .iter()
            .all(|pool| pool.buffer_size | pool.buffer_count == 0);
        let valid = [
            config.wdev_id == self.wdev_id as u32,
            mac_is_valid,
            pool0.buffer_size as usize == self.data.rx_buffer_size(),
            pool0.buffer_count as usize == RX,
            extra_pools_are_empty,
        ]
        .into_iter()
        .all(core::convert::identity);
        if valid {
            Ok(())
        } else {
            Err(DriverError::ConfigurationMismatch)
        }
    }

    fn require_controlled_port(&self, ether_type: u16) -> Result<(), DriverError<B::Error>> {
        let state = self.station.state();
        let allowed = if ether_type == EAPOL_ETHERTYPE {
            self.station.eapol_required()
        } else {
            self.station.controlled_port_open()
        };
        if allowed {
            Ok(())
        } else {
            Err(DriverError::ControlledPortClosed { state, ether_type })
        }
    }

    fn require_state(&self, required: DriverState) -> Result<(), DriverError<B::Error>> {
        if self.state == required {
            Ok(())
        } else {
            Err(DriverError::InvalidState {
                current: self.state,
                required,
            })
        }
    }
}

fn ethernet_type(frame: &[u8]) -> Option<u16> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    Some(u16::from_be_bytes([frame[12], frame[13]]))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::vec::Vec;

    use sha2::{Digest, Sha256};

    use super::super::firmware::{
        FEATURE_SYSTEM_MODE, FirmwareError, IMAGE_HEADER_LEN, PATCH_HEADER_LEN, PATCH_IMAGE_COUNT,
        PATCH_SIGNATURE, PINNED_PATCH_VERSION,
    };
    use super::super::protocol::{
        RF_PARAMS_LEN, UMAC_HEADER_LEN, encode_host_message, parse_host_message,
    };
    use super::super::system::{SYSTEM_HEADER_LEN, SystemEventId};
    use super::super::test_support::block_on;
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[derive(Default)]
    struct TestBus {
        reads: VecDeque<u32>,
        writes: Vec<(u32, Vec<u8>)>,
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
            let value = self.reads.pop_front().unwrap_or(0).to_le_bytes();
            data.copy_from_slice(&value[..data.len()]);
            Ok(())
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    struct NoDelay;

    impl DelayNs for NoDelay {
        async fn delay_ns(&mut self, _ns: u32) {}
    }

    #[derive(Default)]
    struct TestPlatform {
        fail_hard_reset: bool,
        hard_reset_calls: usize,
    }

    impl Platform for TestPlatform {
        type Error = ();

        async fn hard_reset<D>(&mut self, _delay: &mut D) -> Result<(), Self::Error>
        where
            D: DelayNs,
        {
            self.hard_reset_calls += 1;
            if self.fail_hard_reset {
                Err(())
            } else {
                Ok(())
            }
        }

        async fn prepare_wake_bus(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn prepare_data_bus(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn wait_for_interrupt(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct AllowFirmware;

    impl FirmwareTrustPolicy for AllowFirmware {
        fn verify(&self, _bundle: &FirmwareBundle<'_>) -> Result<(), FirmwareError> {
            Ok(())
        }
    }

    fn make_driver() -> NativeDriver<(), 1, 1> {
        NativeDriver::new((), 64, 64, 1, 0, 0).unwrap()
    }

    fn test_bus_driver(bus: TestBus) -> NativeDriver<TestBus, 1, 1> {
        NativeDriver::new(bus, 64, 64, 1, 0, 0).unwrap()
    }

    fn valid_config() -> SystemInitConfig {
        let mut config = SystemInitConfig::new(MAC, [0; RF_PARAMS_LEN]);
        config.rx_pools[0].buffer_size = 64;
        config.rx_pools[0].buffer_count = 1;
        config
    }

    fn bundle_bytes() -> [u8; PATCH_HEADER_LEN + 4 * IMAGE_HEADER_LEN + 4] {
        let mut bytes = [0u8; PATCH_HEADER_LEN + 4 * IMAGE_HEADER_LEN + 4];
        bytes[0..4].copy_from_slice(&PATCH_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&PATCH_IMAGE_COUNT.to_le_bytes());
        bytes[8..12].copy_from_slice(&PINNED_PATCH_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&FEATURE_SYSTEM_MODE.to_le_bytes());
        let payload_len = (bytes.len() - PATCH_HEADER_LEN) as u32;
        bytes[16..20].copy_from_slice(&payload_len.to_le_bytes());
        let mut offset = PATCH_HEADER_LEN;
        for kind in 0u32..4 {
            bytes[offset..offset + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&1u32.to_le_bytes());
            bytes[offset + 8] = kind as u8;
            offset += IMAGE_HEADER_LEN + 1;
        }
        let digest = Sha256::digest(&bytes[PATCH_HEADER_LEN..]);
        bytes[20..PATCH_HEADER_LEN].copy_from_slice(&digest);
        bytes
    }

    fn message<'a>(message_type: HostMessageType, payload: &'a [u8]) -> HostMessageRef<'a> {
        HostMessageRef {
            resubmit: false,
            message_type,
            payload,
        }
    }

    fn data_payload<const N: usize>(command: u32) -> [u8; N] {
        let mut payload = [0u8; N];
        payload[..4].copy_from_slice(&command.to_le_bytes());
        payload[4..8].copy_from_slice(&(N as u32).to_le_bytes());
        payload
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

    #[test]
    fn init_done_moves_runtime_to_ready() {
        let mut driver = make_driver();
        driver.state = DriverState::WaitingForSystemInit;
        let mut payload = [0u8; SYSTEM_HEADER_LEN];
        payload[0..4].copy_from_slice(&(SystemEventId::InitDone as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&(SYSTEM_HEADER_LEN as u32).to_le_bytes());
        let mut bytes = [0u8; 32];
        let len = encode_host_message(&mut bytes, HostMessageType::System, true, &payload).unwrap();
        let message = parse_host_message(&bytes[..len]).unwrap();
        assert!(driver.dispatch_message(message).is_ok());
        assert_eq!(driver.state(), DriverState::Ready);
        assert_eq!(driver.station.state(), StationState::Down);
    }

    #[test]
    fn system_events_are_state_checked_and_other_events_are_preserved() {
        let mut driver = make_driver();
        let mut payload = [0u8; SYSTEM_HEADER_LEN];
        payload[0..4].copy_from_slice(&(SystemEventId::DeinitDone as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&(SYSTEM_HEADER_LEN as u32).to_le_bytes());
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::System, &payload)),
            Err(DriverError::UnexpectedEventForState {
                state: DriverState::Cold
            })
        ));
        assert_eq!(driver.state(), DriverState::Recovering);

        let mut driver = make_driver();
        payload[0..4].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::System, &payload)),
            Ok(DriverEvent::System(SystemEvent::Other { id: 999, .. }))
        ));
        assert_eq!(driver.state(), DriverState::Cold);
    }

    #[test]
    fn control_data_and_supplicant_dispatch_cover_success_and_fail_closed_paths() {
        let mut driver = make_driver();
        let supplicant = [1, 2, 3];
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Supplicant, &supplicant)),
            Err(DriverError::InvalidState { .. })
        ));
        driver.prepare_ready_for_test();
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Supplicant, &supplicant)),
            Ok(DriverEvent::Supplicant([1, 2, 3]))
        ));

        let control = [0u8; UMAC_HEADER_LEN];
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Umac, &control)),
            Ok(DriverEvent::Control(ControlEvent::Other { .. }))
        ));

        let other = data_payload::<8>(99);
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Data, &other)),
            Ok(DriverEvent::Data(DataEvent::Other(99)))
        ));

        let receive = data_payload::<24>(3);
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Data, &receive)),
            Ok(DriverEvent::Receive(_))
        ));

        let mut done = data_payload::<23>(2);
        done[9] = 1;
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Data, &done)),
            Err(DriverError::DataProtocol(_))
        ));

        let mut mismatched_carrier = data_payload::<12>(4);
        mismatched_carrier[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            driver.dispatch_message(message(HostMessageType::Data, &mismatched_carrier)),
            Err(DriverError::Station(StationError::Fault(_)))
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn receive_policy_checks_interface_and_controlled_port_after_data_copy() {
        let mut driver = make_driver();
        let event_bytes = data_payload::<24>(3);
        let event = RxEventRef::parse(message(HostMessageType::Data, &event_bytes)).unwrap();
        assert!(matches!(
            driver.validate_received_frame(&event, received(0x0800)),
            Err(DriverError::ControlledPortClosed {
                ether_type: 0x0800,
                ..
            })
        ));

        driver.station.prepare_security_for_test(MAC);
        assert_eq!(
            driver
                .validate_received_frame(&event, received(EAPOL_ETHERTYPE))
                .unwrap(),
            received(EAPOL_ETHERTYPE)
        );

        let mut wrong_interface = data_payload::<24>(3);
        wrong_interface[12] = 1;
        let event = RxEventRef::parse(message(HostMessageType::Data, &wrong_interface)).unwrap();
        assert!(matches!(
            driver.validate_received_frame(&event, received(EAPOL_ETHERTYPE)),
            Err(DriverError::WrongInterface {
                expected: 0,
                received: 1
            })
        ));
        assert_eq!(driver.state(), DriverState::Recovering);
    }

    #[test]
    fn transmit_rejects_wrong_interface_short_frames_and_closed_port() {
        let mut driver = make_driver();
        assert!(matches!(
            block_on(driver.transmit(1, &[0; 14], 0)),
            Err(DriverError::WrongInterface {
                expected: 0,
                received: 1
            })
        ));
        assert!(matches!(
            block_on(driver.transmit(0, &[0; 13], 0)),
            Err(DriverError::FrameTooShort)
        ));
        assert!(matches!(
            block_on(driver.transmit(0, &[0; 14], 0)),
            Err(DriverError::ControlledPortClosed { .. })
        ));
        assert_eq!(ethernet_type(&[0; 13]), None);
        let mut frame = [0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(ethernet_type(&frame), Some(0x0800));
    }

    #[test]
    fn station_interface_configuration_requires_ready_exact_identity() {
        let mut driver = make_driver();
        let mut delay = NoDelay;
        assert!(matches!(
            block_on(driver.create_station_interface(&mut delay, 1, MAC, b"wlan0")),
            Err(DriverError::InvalidState { .. })
        ));

        driver.prepare_ready_for_test();
        driver.configured_mac = Some(MAC);
        assert!(matches!(
            block_on(driver.create_station_interface(&mut delay, 2, MAC, b"wlan0")),
            Err(DriverError::ConfigurationMismatch)
        ));
        assert!(matches!(
            block_on(driver.create_station_interface(&mut delay, 1, [4; 6], b"wlan0")),
            Err(DriverError::ConfigurationMismatch)
        ));
        assert!(block_on(driver.create_station_interface(&mut delay, 1, MAC, b"wlan0")).is_ok());
    }

    #[test]
    fn system_configuration_checks_each_runtime_identity_boundary() {
        let driver = make_driver();
        assert_eq!(
            SYSTEM_INIT_MESSAGE_LEN,
            SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN
        );
        let valid = valid_config();
        assert!(driver.validate_system_config(&valid).is_ok());

        for invalid in [
            {
                let mut value = valid.clone();
                value.wdev_id = 1;
                value
            },
            {
                let mut value = valid.clone();
                value.mac_address = [0; 6];
                value
            },
            {
                let mut value = valid.clone();
                value.mac_address = [0xff; 6];
                value
            },
            {
                let mut value = valid.clone();
                value.mac_address = [3, 0, 0, 0, 0, 1];
                value
            },
            {
                let mut value = valid.clone();
                value.rx_pools[0].buffer_size = 65;
                value
            },
            {
                let mut value = valid.clone();
                value.rx_pools[0].buffer_count = 2;
                value
            },
            {
                let mut value = valid.clone();
                value.rx_pools[1].buffer_size = 1;
                value
            },
            {
                let mut value = valid.clone();
                value.rx_pools[2].buffer_count = 1;
                value
            },
        ] {
            assert!(matches!(
                driver.validate_system_config(&invalid),
                Err(DriverError::ConfigurationMismatch)
            ));
        }
    }

    #[test]
    fn recovery_validation_and_platform_failures_end_in_fault() {
        let bytes = bundle_bytes();
        let bundle = FirmwareBundle::parse(&bytes).unwrap();
        let mut delay = NoDelay;

        let mut driver = test_bus_driver(TestBus::default());
        let mut platform = TestPlatform::default();
        let invalid = SystemInitConfig::new(MAC, [0; RF_PARAMS_LEN]);
        assert!(matches!(
            block_on(driver.recover(&mut platform, &mut delay, &bundle, &AllowFirmware, &invalid,)),
            Err(RecoveryError::Driver(DriverError::ConfigurationMismatch))
        ));
        assert_eq!(driver.state(), DriverState::Fault);
        assert_eq!(platform.hard_reset_calls, 0);

        let mut driver = test_bus_driver(TestBus::default());
        let mut platform = TestPlatform {
            fail_hard_reset: true,
            hard_reset_calls: 0,
        };
        assert!(matches!(
            block_on(driver.recover(
                &mut platform,
                &mut delay,
                &bundle,
                &AllowFirmware,
                &valid_config(),
            )),
            Err(RecoveryError::Platform(()))
        ));
        assert_eq!(driver.state(), DriverState::Fault);
        assert_eq!(platform.hard_reset_calls, 1);
    }

    #[test]
    fn watchdog_sentinel_rule_and_acknowledgement_are_exact() {
        let mut bus = TestBus::default();
        bus.reads.extend([0xaaaa_aaaa, RPU_WATCHDOG_BIT, 0]);
        let mut driver = test_bus_driver(bus);
        assert!(block_on(driver.watchdog_pending()).unwrap());
        assert!(!block_on(driver.watchdog_pending()).unwrap());
        assert!(block_on(driver.acknowledge_watchdog()).is_ok());
        assert_eq!(driver.state(), DriverState::Recovering);
        let bus = driver.into_inner();
        assert_eq!(bus.writes.len(), 2);
        assert_eq!(bus.writes[0].1, RPU_WATCHDOG_BIT.to_le_bytes());
        assert_eq!(bus.writes[1].1, RPU_WATCHDOG_RELOAD.to_le_bytes());

        let mut bus = TestBus::default();
        bus.reads.extend([0xaaaa_aaaa; 10]);
        let mut driver = test_bus_driver(bus);
        assert!(matches!(
            block_on(driver.watchdog_pending()),
            Err(DriverError::InvalidWatchdogStatus)
        ));
        assert_eq!(driver.state(), DriverState::Fault);
    }

    #[test]
    fn controlled_port_blocks_normal_data_before_connection() {
        let driver = make_driver();
        assert!(matches!(
            driver.require_controlled_port(0x0800),
            Err(DriverError::ControlledPortClosed {
                state: StationState::Down,
                ether_type: 0x0800,
            })
        ));
    }

    #[test]
    fn controlled_port_allows_eapol_during_key_exchange() {
        let mut driver = make_driver();
        driver.station.prepare_security_for_test([1, 2, 3, 4, 5, 6]);
        assert!(driver.require_controlled_port(EAPOL_ETHERTYPE).is_ok());
        assert!(driver.require_controlled_port(0x0800).is_err());
    }
}
