use crate::{
    ConnectRequest, Device, DeviceError, FirmwareImage, Hardware, WifiEvent, WifiState,
};

/// Nordic RPU command, event, and Ethernet data implementation.
///
/// A pure-Rust implementation maps these calls to the Nordic host/RPU ABI and
/// shared descriptor rings. The trait does not contain Zephyr types or OS
/// callbacks.
pub trait RpuInterface<H>
where
    H: Hardware,
{
    /// RPU protocol error.
    type Error;

    /// Initialize command, event, transmit, and receive queues.
    async fn initialize(&mut self, hardware: &mut H) -> Result<(), Self::Error>;

    /// Start an active scan.
    async fn start_scan(&mut self, hardware: &mut H) -> Result<(), Self::Error>;

    /// Start station association and authentication.
    async fn connect(
        &mut self,
        hardware: &mut H,
        request: &ConnectRequest<'_>,
    ) -> Result<(), Self::Error>;

    /// Request a station disconnect.
    async fn disconnect(&mut self, hardware: &mut H) -> Result<(), Self::Error>;

    /// Wait for and decode one firmware event.
    async fn next_event(&mut self, hardware: &mut H) -> Result<WifiEvent, Self::Error>;

    /// Submit one complete Ethernet frame.
    async fn transmit(&mut self, hardware: &mut H, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive one complete Ethernet frame.
    ///
    /// The returned length is never larger than `destination.len()`.
    async fn receive(
        &mut self,
        hardware: &mut H,
        destination: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Return the station MAC address assigned by firmware or board data.
    fn mac_address(&self) -> [u8; 6];
}

/// Complete native nRF7002 error.
#[derive(Debug, PartialEq, Eq)]
pub enum Nrf7002Error<HardwareError, RpuError> {
    /// Power, reset, status, or firmware loader error.
    Device(DeviceError<HardwareError>),
    /// Nordic host/RPU protocol error.
    Rpu(RpuError),
    /// The connect request failed host-side validation.
    InvalidConnectRequest,
    /// An operation is not valid in the current Wi-Fi state.
    InvalidState,
    /// The RPU returned a frame length larger than the destination buffer.
    InvalidReceiveLength,
}

/// Native nRF7002 device composed from board hardware and an RPU ABI engine.
pub struct Nrf7002<H, R, const VERIFY_BUFFER: usize = 1024>
where
    H: Hardware,
    R: RpuInterface<H>,
{
    device: Device<H, VERIFY_BUFFER>,
    rpu: R,
    wifi_state: WifiState,
}

impl<H, R, const VERIFY_BUFFER: usize> Nrf7002<H, R, VERIFY_BUFFER>
where
    H: Hardware,
    R: RpuInterface<H>,
{
    /// Create a native device from the firmware loader and RPU implementation.
    #[must_use]
    pub const fn new(device: Device<H, VERIFY_BUFFER>, rpu: R) -> Self {
        Self {
            device,
            rpu,
            wifi_state: WifiState::Down,
        }
    }

    /// Return the high-level Wi-Fi state.
    #[must_use]
    pub const fn wifi_state(&self) -> WifiState {
        self.wifi_state
    }

    /// Return the station MAC address.
    #[must_use]
    pub fn mac_address(&self) -> [u8; 6] {
        self.rpu.mac_address()
    }

    /// Return the firmware-loader device.
    #[must_use]
    pub const fn device(&self) -> &Device<H, VERIFY_BUFFER> {
        &self.device
    }

    /// Initialize RPU firmware and all shared queues.
    ///
    /// # Errors
    ///
    /// Returns [`Nrf7002Error::Device`] for board or firmware-load failures and
    /// [`Nrf7002Error::Rpu`] for command/data interface failures.
    pub async fn initialize(
        &mut self,
        image: &FirmwareImage<'_>,
    ) -> Result<(), Nrf7002Error<H::Error, R::Error>> {
        self.device
            .initialize(image)
            .await
            .map_err(Nrf7002Error::Device)?;
        self.rpu
            .initialize(self.device.hardware_mut())
            .await
            .map_err(Nrf7002Error::Rpu)?;
        self.wifi_state = WifiState::Idle;
        Ok(())
    }

    /// Start a network scan.
    ///
    /// # Errors
    ///
    /// Returns [`Nrf7002Error::InvalidState`] unless the interface is idle, or
    /// [`Nrf7002Error::Rpu`] when command submission fails.
    pub async fn start_scan(&mut self) -> Result<(), Nrf7002Error<H::Error, R::Error>> {
        if self.wifi_state != WifiState::Idle {
            return Err(Nrf7002Error::InvalidState);
        }
        self.rpu
            .start_scan(self.device.hardware_mut())
            .await
            .map_err(Nrf7002Error::Rpu)?;
        self.wifi_state = WifiState::Scanning;
        Ok(())
    }

    /// Start station connection.
    ///
    /// # Errors
    ///
    /// Returns an input, state, or RPU error.
    pub async fn connect(
        &mut self,
        request: &ConnectRequest<'_>,
    ) -> Result<(), Nrf7002Error<H::Error, R::Error>> {
        if !request.is_valid() {
            return Err(Nrf7002Error::InvalidConnectRequest);
        }
        if !matches!(self.wifi_state, WifiState::Idle | WifiState::Scanning) {
            return Err(Nrf7002Error::InvalidState);
        }
        self.rpu
            .connect(self.device.hardware_mut(), request)
            .await
            .map_err(Nrf7002Error::Rpu)?;
        self.wifi_state = WifiState::Associating;
        Ok(())
    }

    /// Request disconnection from the active network.
    ///
    /// # Errors
    ///
    /// Returns a state or RPU error.
    pub async fn disconnect(&mut self) -> Result<(), Nrf7002Error<H::Error, R::Error>> {
        if !matches!(
            self.wifi_state,
            WifiState::Associating | WifiState::Authenticating | WifiState::Connected { .. }
        ) {
            return Err(Nrf7002Error::InvalidState);
        }
        self.rpu
            .disconnect(self.device.hardware_mut())
            .await
            .map_err(Nrf7002Error::Rpu)?;
        self.wifi_state = WifiState::Disconnecting;
        Ok(())
    }

    /// Wait for and apply one firmware event.
    ///
    /// # Errors
    ///
    /// Returns an RPU decoding or transport error.
    pub async fn next_event(
        &mut self,
    ) -> Result<WifiEvent, Nrf7002Error<H::Error, R::Error>> {
        let event = self
            .rpu
            .next_event(self.device.hardware_mut())
            .await
            .map_err(Nrf7002Error::Rpu)?;
        self.apply_event(event);
        Ok(event)
    }

    /// Transmit one complete Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns [`Nrf7002Error::InvalidState`] until the station is connected,
    /// or an RPU error when descriptor submission fails.
    pub async fn transmit(
        &mut self,
        frame: &[u8],
    ) -> Result<(), Nrf7002Error<H::Error, R::Error>> {
        if !matches!(self.wifi_state, WifiState::Connected { .. }) {
            return Err(Nrf7002Error::InvalidState);
        }
        self.rpu
            .transmit(self.device.hardware_mut(), frame)
            .await
            .map_err(Nrf7002Error::Rpu)
    }

    /// Receive one complete Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns a state, RPU, or returned-length error.
    pub async fn receive(
        &mut self,
        destination: &mut [u8],
    ) -> Result<usize, Nrf7002Error<H::Error, R::Error>> {
        if !matches!(self.wifi_state, WifiState::Connected { .. }) {
            return Err(Nrf7002Error::InvalidState);
        }
        let length = self
            .rpu
            .receive(self.device.hardware_mut(), destination)
            .await
            .map_err(Nrf7002Error::Rpu)?;
        if length > destination.len() {
            return Err(Nrf7002Error::InvalidReceiveLength);
        }
        Ok(length)
    }

    fn apply_event(&mut self, event: WifiEvent) {
        match event {
            WifiEvent::Ready | WifiEvent::ScanComplete | WifiEvent::Disconnected { .. } => {
                self.wifi_state = WifiState::Idle;
            }
            WifiEvent::ScanStarted => self.wifi_state = WifiState::Scanning,
            WifiEvent::Connected { bssid, channel } => {
                self.wifi_state = WifiState::Connected { bssid, channel };
            }
            WifiEvent::FirmwareFault { .. } => self.wifi_state = WifiState::Fault,
            WifiEvent::ScanResult { .. }
            | WifiEvent::ReceiveReady
            | WifiEvent::TransmitComplete { .. } => {}
        }
    }
}
