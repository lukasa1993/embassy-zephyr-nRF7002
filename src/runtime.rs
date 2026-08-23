//! Top-level boot, event dispatch, watchdog, and recovery runtime.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::{ControlEvent, parse_control_event};
use super::data::{
    DataError, DataEvent, DataLayoutError, DataPath, DataProtocolError, ReceivedFrame, RxEventRef,
    classify_data_event,
};
use super::device::{Device, DeviceError};
use super::firmware::{self, FirmwareBundle, FirmwareReport, LoadError};
use super::protocol::{HostMessageRef, HostMessageType, ProtocolError, SystemInitConfig};
use super::station::{StationController, StationError};
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
        Ok(Self {
            device: Device::new(bus),
            data: DataPath::new(rx_buffer_size, tx_buffer_size)?,
            station: StationController::new(ifaceindex, firmware_index, wdev_id),
            state: DriverState::Cold,
        })
    }

    /// Returns the current top-level state.
    pub const fn state(&self) -> DriverState {
        self.state
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
    pub fn station_mut(&mut self) -> &mut StationController {
        &mut self.station
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
    pub async fn recover<P, D>(
        &mut self,
        platform: &mut P,
        delay: &mut D,
        bundle: &FirmwareBundle<'_>,
        config: &SystemInitConfig,
    ) -> Result<FirmwareReport, RecoveryError<B::Error, P::Error>>
    where
        P: Platform,
        D: DelayNs,
    {
        self.state = DriverState::Recovering;
        self.station.begin_recovery();

        let result = async {
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

            let report = firmware::load(self.device.rpu_mut(), delay, bundle)
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
            self.device
                .send_system_init(config)
                .await
                .map_err(DriverError::from)?;
            Ok(report)
        }
        .await;

        match result {
            Ok(report) => {
                self.state = DriverState::WaitingForSystemInit;
                Ok(report)
            }
            Err(error) => {
                self.state = DriverState::Fault;
                Err(error)
            }
        }
    }

    /// Creates the station interface after system initialization succeeds.
    pub async fn create_station_interface(
        &mut self,
        ifaceindex: i32,
        mac_address: [u8; 6],
        interface_name: &[u8],
    ) -> Result<(), DriverError<B::Error>> {
        self.require_state(DriverState::Ready)?;
        self.device
            .add_station_interface(ifaceindex, mac_address, interface_name)
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

    /// Polls, parses, and applies one complete RPU event.
    pub async fn poll_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<DriverEvent<'a>>, DriverError<B::Error>> {
        if self.device.recovery_required() {
            self.state = DriverState::Recovering;
            self.station.begin_recovery();
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
                    SystemEvent::DeinitDone => {
                        self.station.begin_recovery();
                        self.state = DriverState::Cold;
                    }
                    _ => {}
                }
                Ok(DriverEvent::System(event))
            }
            HostMessageType::Umac => {
                let event = parse_control_event(message)?;
                self.station.handle_control_event(event)?;
                Ok(DriverEvent::Control(event))
            }
            HostMessageType::Data => {
                let event = classify_data_event(message).map_err(DriverError::DataProtocol)?;
                match event {
                    DataEvent::TransmitDone { token, .. } => {
                        self.data
                            .complete_tx(token)
                            .map_err(DriverError::DataProtocol)?;
                    }
                    DataEvent::Receive => {
                        let receive =
                            RxEventRef::parse(message).map_err(DriverError::DataProtocol)?;
                        return Ok(DriverEvent::Receive(receive));
                    }
                    _ => self.station.handle_data_event(event)?,
                }
                Ok(DriverEvent::Data(event))
            }
            HostMessageType::Supplicant => Ok(DriverEvent::Supplicant(message.payload)),
        }
    }

    /// Copies one received packet into caller storage and returns Ethernet metadata.
    pub async fn receive_packet(
        &mut self,
        event: &RxEventRef<'_>,
        packet_index: usize,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, DriverError<B::Error>> {
        Ok(self
            .data
            .receive_packet(&mut self.device, event, packet_index, output)
            .await?)
    }

    /// Sends one Ethernet frame.
    pub async fn transmit(
        &mut self,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, DriverError<B::Error>> {
        Ok(self
            .data
            .transmit(&mut self.device, wdev_id, frame, dscp_tos)
            .await?)
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
        self.station.begin_recovery();
        self.state = DriverState::Recovering;
        Ok(())
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
        assert_eq!(
            driver.station.state(),
            super::super::station::StationState::Down
        );
    }
}
