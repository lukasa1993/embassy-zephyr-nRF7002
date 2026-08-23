use crate::{
    FirmwareError, FirmwareImage, Hardware, RpuStatus, StatusRegister, WakeControl,
};

/// Native driver configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Delay after power is enabled.
    pub power_settle_us: u32,
    /// Delay after the reset sequence.
    pub reset_settle_us: u32,
    /// Delay between status reads.
    pub poll_interval_us: u32,
    /// Maximum status reads while the boot ROM starts.
    pub boot_status_polls: u32,
    /// Maximum status reads while the RPU wakes.
    pub wake_status_polls: u32,
    /// Maximum status reads after firmware start.
    pub firmware_status_polls: u32,
    /// Maximum bytes in one QSPI transfer.
    pub transfer_size: usize,
    /// Read each firmware chunk back before firmware start.
    pub verify_download: bool,
    /// Register that reports the RPU awake and ready bits.
    pub status_register: StatusRegister,
    /// Register that accepts the immediate-wake bit.
    pub wake_register: StatusRegister,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            power_settle_us: 5_000,
            reset_settle_us: 5_000,
            poll_interval_us: 100,
            boot_status_polls: 10_000,
            wake_status_polls: 10_000,
            firmware_status_polls: 50_000,
            transfer_size: 1_024,
            verify_download: true,
            status_register: StatusRegister::Rpu2,
            wake_register: StatusRegister::Rpu2,
        }
    }
}

/// Observable native-driver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Power is disabled.
    Off,
    /// Power is enabled and reset has not completed.
    Powered,
    /// The boot ROM responds to status reads.
    BootRom,
    /// Firmware bytes are being transferred.
    LoadingFirmware,
    /// The RPU entry point was released.
    StartingFirmware,
    /// Firmware reports ready.
    Ready,
    /// Initialization or shutdown failed.
    Fault,
}

/// Operation that expired while the driver polled RPU status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutStage {
    /// Initial boot-ROM readiness.
    BootRom,
    /// RPU wake acknowledgement.
    Wake,
    /// Firmware readiness after start.
    Firmware,
}

/// Native-device error.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceError<E> {
    /// A board-operation failed.
    Hardware(E),
    /// The firmware image failed validation.
    Firmware(FirmwareError),
    /// One or more configuration values are invalid.
    InvalidConfiguration,
    /// RPU status did not reach the required state.
    Timeout(TimeoutStage),
    /// A firmware byte changed between write and readback.
    Verification {
        /// RPU byte address.
        address: u32,
        /// Byte supplied by the firmware image.
        expected: u8,
        /// Byte read from RPU memory.
        actual: u8,
    },
    /// An address calculation exceeded the RPU address space.
    AddressOverflow,
}

/// nRF7002 power, reset, wake, and firmware loader.
pub struct Device<H, const VERIFY_BUFFER: usize = 1024> {
    hardware: H,
    config: Config,
    state: DeviceState,
    verify_buffer: [u8; VERIFY_BUFFER],
}

impl<H, const VERIFY_BUFFER: usize> Device<H, VERIFY_BUFFER>
where
    H: Hardware,
{
    /// Create a powered-off device.
    #[must_use]
    pub const fn new(hardware: H, config: Config) -> Self {
        Self {
            hardware,
            config,
            state: DeviceState::Off,
            verify_buffer: [0; VERIFY_BUFFER],
        }
    }

    /// Return the current driver state.
    #[must_use]
    pub const fn state(&self) -> DeviceState {
        self.state
    }

    /// Return the active configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Borrow the hardware implementation for board-specific diagnostics.
    pub fn hardware(&self) -> &H {
        &self.hardware
    }

    /// Mutably borrow the hardware implementation.
    ///
    /// Board code must not change RPU state while a driver operation is active.
    pub fn hardware_mut(&mut self) -> &mut H {
        &mut self.hardware
    }

    /// Consume the driver and return the hardware implementation.
    #[must_use]
    pub fn into_hardware(self) -> H {
        self.hardware
    }

    /// Power, reset, wake, load, verify, and start the RPU firmware.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid input, hardware failure, timeout, or
    /// readback mismatch. Any failure puts the device in [`DeviceState::Fault`].
    pub async fn initialize(
        &mut self,
        image: &FirmwareImage<'_>,
    ) -> Result<(), DeviceError<H::Error>> {
        let result = self.initialize_inner(image).await;
        if result.is_err() {
            self.state = DeviceState::Fault;
        }
        result
    }

    /// Disable nRF7002 power.
    ///
    /// # Errors
    ///
    /// Returns the board error when the power control fails.
    pub async fn shutdown(&mut self) -> Result<(), DeviceError<H::Error>> {
        match self.hardware.set_power(false).await {
            Ok(()) => {
                self.state = DeviceState::Off;
                Ok(())
            }
            Err(error) => {
                self.state = DeviceState::Fault;
                Err(DeviceError::Hardware(error))
            }
        }
    }

    /// Wait for the nRF7002 interrupt signal.
    ///
    /// # Errors
    ///
    /// Returns the board error from the interrupt implementation.
    pub async fn wait_for_interrupt(&mut self) -> Result<(), DeviceError<H::Error>> {
        self.hardware
            .wait_for_interrupt()
            .await
            .map_err(DeviceError::Hardware)
    }

    async fn initialize_inner(
        &mut self,
        image: &FirmwareImage<'_>,
    ) -> Result<(), DeviceError<H::Error>> {
        self.validate_configuration()?;
        image.validate().map_err(DeviceError::Firmware)?;

        self.hardware
            .set_power(true)
            .await
            .map_err(DeviceError::Hardware)?;
        self.state = DeviceState::Powered;
        self.hardware.delay_us(self.config.power_settle_us).await;

        self.hardware
            .reset()
            .await
            .map_err(DeviceError::Hardware)?;
        self.hardware.delay_us(self.config.reset_settle_us).await;

        self.wait_ready(self.config.boot_status_polls, TimeoutStage::BootRom)
            .await?;
        self.state = DeviceState::BootRom;

        let current = self
            .hardware
            .read_status(self.config.wake_register)
            .await
            .map_err(DeviceError::Hardware)?;
        self.hardware
            .write_status(
                self.config.wake_register,
                WakeControl::request_wake(current).raw(),
            )
            .await
            .map_err(DeviceError::Hardware)?;
        self.wait_awake(self.config.wake_status_polls).await?;

        self.state = DeviceState::LoadingFirmware;
        self.download(image).await?;

        self.state = DeviceState::StartingFirmware;
        self.hardware
            .start_firmware(image.entry_point)
            .await
            .map_err(DeviceError::Hardware)?;
        self.wait_ready(
            self.config.firmware_status_polls,
            TimeoutStage::Firmware,
        )
        .await?;
        self.state = DeviceState::Ready;
        Ok(())
    }

    fn validate_configuration(&self) -> Result<(), DeviceError<H::Error>> {
        if self.config.transfer_size == 0
            || self.config.transfer_size > VERIFY_BUFFER
            || self.config.boot_status_polls == 0
            || self.config.wake_status_polls == 0
            || self.config.firmware_status_polls == 0
        {
            return Err(DeviceError::InvalidConfiguration);
        }
        Ok(())
    }

    async fn wait_ready(
        &mut self,
        polls: u32,
        stage: TimeoutStage,
    ) -> Result<(), DeviceError<H::Error>> {
        for _ in 0..polls {
            let raw = self
                .hardware
                .read_status(self.config.status_register)
                .await
                .map_err(DeviceError::Hardware)?;
            if RpuStatus::from_raw(raw).is_ready() {
                return Ok(());
            }
            self.hardware.delay_us(self.config.poll_interval_us).await;
        }
        Err(DeviceError::Timeout(stage))
    }

    async fn wait_awake(&mut self, polls: u32) -> Result<(), DeviceError<H::Error>> {
        for _ in 0..polls {
            let raw = self
                .hardware
                .read_status(self.config.status_register)
                .await
                .map_err(DeviceError::Hardware)?;
            if RpuStatus::from_raw(raw).is_awake() {
                return Ok(());
            }
            self.hardware.delay_us(self.config.poll_interval_us).await;
        }
        Err(DeviceError::Timeout(TimeoutStage::Wake))
    }

    async fn download(
        &mut self,
        image: &FirmwareImage<'_>,
    ) -> Result<(), DeviceError<H::Error>> {
        for segment in image.segments {
            let mut offset = 0_usize;
            while offset < segment.data.len() {
                let remaining = segment.data.len() - offset;
                let length = remaining.min(self.config.transfer_size);
                let chunk = &segment.data[offset..offset + length];
                let offset_u32 =
                    u32::try_from(offset).map_err(|_| DeviceError::AddressOverflow)?;
                let address = segment
                    .address
                    .checked_add(offset_u32)
                    .ok_or(DeviceError::AddressOverflow)?;

                self.hardware
                    .write_memory(address, chunk)
                    .await
                    .map_err(DeviceError::Hardware)?;

                if self.config.verify_download {
                    let (hardware, verify_buffer) =
                        (&mut self.hardware, &mut self.verify_buffer);
                    let readback = &mut verify_buffer[..length];
                    hardware
                        .read_memory(address, readback)
                        .await
                        .map_err(DeviceError::Hardware)?;
                    if let Some((relative, (&expected, &actual))) = chunk
                        .iter()
                        .zip(readback.iter())
                        .enumerate()
                        .find(|(_, (expected, actual))| expected != actual)
                    {
                        let relative_u32 = u32::try_from(relative)
                            .map_err(|_| DeviceError::AddressOverflow)?;
                        let mismatch_address = address
                            .checked_add(relative_u32)
                            .ok_or(DeviceError::AddressOverflow)?;
                        return Err(DeviceError::Verification {
                            address: mismatch_address,
                            expected,
                            actual,
                        });
                    }
                }

                offset += length;
            }
        }
        Ok(())
    }
}
