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
    HOST_MESSAGE_HEADER_LEN, HostMessageRef, HostMessageType, InterfaceType, ProtocolError,
    SYSTEM_INIT_LEN, ScanReason, ScanRequest, SystemInitConfig, encode_new_interface,
    encode_system_init,
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

    /// Splits the device and station fields for an in-crate security coordinator.
    pub(crate) fn security_parts_mut(&mut self) -> (&mut Device<B>, &mut StationController) {
        (&mut self.device, &mut self.station)
    }

    /// Moves the complete runtime into recovery.
    pub(crate) fn enter_recovery(&mut self) {
        self.station.begin_recovery();
        self.configured_mac = None;
        self.state = DriverState::Recovering;
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
            self.validate_system_config(config)
                .map_err(RecoveryError::Driver)?;
            let _ = self.device.disable_interrupts().await;
            platform
                .hard_reset(delay)
                .await
                .map_err(RecoveryError::Platform)?;
            self.device.reset_queue_state();
            self.data.reset_after_rpu_reset();

            platform
                .prepare_wake_bus()
                .await
                .map_err(RecoveryError::Platform)?;
            self.device
                .rpu_mut()
                .wake(delay, DEFAULT_WAKE_ATTEMPTS)
                .await
                .map_err(DeviceError::from)
                .map_err(DriverError::from)?;
            platform
                .prepare_data_bus()
                .await
                .map_err(RecoveryError::Platform)?;

            let report = firmware::load(self.device.rpu_mut(), delay, bundle, trust)
                .await
                .map_err(DriverError::from)?;
            self.device
                .initialize_queues()
                .await
                .map_err(DriverError::from)?;
            self.data
                .post_all_rx(&mut self.device)
                .await
                .map_err(DriverError::from)?;
            self.device
                .enable_interrupts()
                .await
                .map_err(DriverError::from)?;

            let mut message = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
            let len = encode_system_init(&mut message, config).map_err(DriverError::from)?;
            self.device
                .send_control_reliable(&message[..len], delay)
                .await
                .map_err(DriverError::from)?;
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
        if self.station.state() != StationState::Down {
            return Err(DriverError::InvalidStationState {
                current: self.station.state(),
                required: StationState::Down,
            });
        }
        let mut message = [0u8; 128];
        let len = encode_new_interface(
            &mut message,
            ifaceindex,
            InterfaceType::Station,
            mac_address,
            interface_name,
        )?;
        self.device
            .send_control_reliable(&message[..len], delay)
            .await?;
        Ok(())
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
        self.require_state(DriverState::Ready)?;
        self.station
            .set_regulatory(&mut self.device, delay, country, user_hint_type, force)
            .await?;
        Ok(())
    }

    /// Brings the configured station interface up.
    pub async fn bring_up<D>(&mut self, delay: &mut D) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        self.require_state(DriverState::Ready)?;
        self.station.bring_up(&mut self.device, delay).await?;
        Ok(())
    }

    /// Brings the configured station interface down.
    pub async fn bring_down<D>(&mut self, delay: &mut D) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        self.require_state(DriverState::Ready)?;
        self.station.bring_down(&mut self.device, delay).await?;
        Ok(())
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
        self.require_state(DriverState::Ready)?;
        self.station
            .start_scan(&mut self.device, delay, request)
            .await?;
        Ok(())
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
        self.require_state(DriverState::Ready)?;
        self.station
            .request_scan_results(&mut self.device, delay, reason)
            .await?;
        Ok(())
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
        self.require_state(DriverState::Ready)?;
        self.station
            .authenticate(&mut self.device, delay, request)
            .await?;
        Ok(())
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
        self.require_state(DriverState::Ready)?;
        self.station
            .associate(&mut self.device, delay, request)
            .await?;
        Ok(())
    }

    /// Enables or disables firmware power save without changing its timeout.
    pub async fn set_power_save<D>(
        &mut self,
        delay: &mut D,
        state: PowerSaveState,
    ) -> Result<(), DriverError<B::Error>>
    where
        D: DelayNs,
    {
        self.require_state(DriverState::Ready)?;
        self.station
            .set_power_save(&mut self.device, delay, state, None)
            .await?;
        Ok(())
    }

    /// Starts a station deauthentication sequence.
    pub async fn disconnect(&mut self, reason_code: u16) -> Result<(), DriverError<B::Error>> {
        self.require_state(DriverState::Ready)?;
        self.station
            .disconnect(&mut self.device, reason_code)
            .await?;
        Ok(())
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
            HostMessageType::System => {
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
            HostMessageType::Umac => {
                self.require_state(DriverState::Ready)?;
                let event = parse_control_event(message)?;
                if let Err(error) = self.station.handle_control_event(event) {
                    self.enter_recovery();
                    return Err(DriverError::Station(error));
                }
                Ok(DriverEvent::Control(event))
            }
            HostMessageType::Data => {
                self.require_state(DriverState::Ready)?;
                let event = classify_data_event(message).map_err(DriverError::DataProtocol)?;
                match event {
                    DataEvent::TransmitDone { .. } => {
                        let transmit_done =
                            TxDoneEventRef::parse(message).map_err(DriverError::DataProtocol)?;
                        self.data
                            .complete_tx(transmit_done.token)
                            .map_err(DriverError::DataProtocol)?;
                        return Ok(DriverEvent::TransmitDone(transmit_done));
                    }
                    DataEvent::Receive => {
                        let receive =
                            RxEventRef::parse(message).map_err(DriverError::DataProtocol)?;
                        return Ok(DriverEvent::Receive(receive));
                    }
                    _ => {
                        if let Err(error) = self.station.handle_data_event(event) {
                            self.enter_recovery();
                            return Err(DriverError::Station(error));
                        }
                    }
                }
                Ok(DriverEvent::Data(event))
            }
            HostMessageType::Supplicant => {
                self.require_state(DriverState::Ready)?;
                Ok(DriverEvent::Supplicant(message.payload))
            }
        }
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
        let mac_is_valid = mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0;
        let pool0 = config.rx_pools[0];
        let extra_pools_are_empty = config.rx_pools[1..]
            .iter()
            .all(|pool| pool.buffer_size == 0 && pool.buffer_count == 0);
        if config.wdev_id != self.wdev_id as u32
            || !mac_is_valid
            || pool0.buffer_size as usize != self.data.rx_buffer_size()
            || pool0.buffer_count as usize != RX
            || !extra_pools_are_empty
        {
            return Err(DriverError::ConfigurationMismatch);
        }
        Ok(())
    }

    fn require_controlled_port(&self, ether_type: u16) -> Result<(), DriverError<B::Error>> {
        let state = self.station.state();
        let allowed = if ether_type == EAPOL_ETHERTYPE {
            matches!(
                state,
                StationState::Securing
                    | StationState::Authorizing
                    | StationState::AwaitingCarrier
                    | StationState::Connected
            )
        } else {
            state == StationState::Connected
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
    use super::super::protocol::{encode_host_message, parse_host_message};
    use super::super::system::{SYSTEM_HEADER_LEN, SystemEventId};
    use super::*;

    #[test]
    fn init_done_moves_runtime_to_ready() {
        let mut driver = NativeDriver::<(), 1, 1>::new((), 64, 64, 1, 0, 0).unwrap();
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
    fn controlled_port_blocks_normal_data_before_connection() {
        let driver = NativeDriver::<(), 1, 1>::new((), 64, 64, 1, 0, 0).unwrap();
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
        let mut driver = NativeDriver::<(), 1, 1>::new((), 64, 64, 1, 0, 0).unwrap();
        driver.station.prepare_security_for_test([1, 2, 3, 4, 5, 6]);
        assert!(driver.require_controlled_port(EAPOL_ETHERTYPE).is_ok());
        assert!(driver.require_controlled_port(0x0800).is_err());
    }
}
