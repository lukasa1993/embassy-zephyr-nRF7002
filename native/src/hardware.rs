/// nRF7002 status register selected by the bus implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRegister {
    /// First RPU status register.
    Rpu0,
    /// Second RPU status register.
    Rpu1,
    /// Third RPU status register. Nordic uses this register for wake control.
    Rpu2,
}

/// Board operations required by the native driver.
///
/// An nRF5340 implementation normally maps these methods to Embassy QSPI,
/// GPIO, GPIOTE, and timer drivers. The trait has one error type so that the
/// state machine can preserve the first hardware failure without allocation.
pub trait Hardware {
    /// Board-specific hardware error.
    type Error;

    /// Enable or disable power for the nRF7002.
    async fn set_power(&mut self, enabled: bool) -> Result<(), Self::Error>;

    /// Apply the board reset sequence.
    async fn reset(&mut self) -> Result<(), Self::Error>;

    /// Read one RPU status register.
    async fn read_status(&mut self, register: StatusRegister) -> Result<u8, Self::Error>;

    /// Write one RPU status register.
    async fn write_status(
        &mut self,
        register: StatusRegister,
        value: u8,
    ) -> Result<(), Self::Error>;

    /// Read from the nRF7002 address space.
    async fn read_memory(
        &mut self,
        address: u32,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Write to the nRF7002 address space.
    async fn write_memory(&mut self, address: u32, source: &[u8]) -> Result<(), Self::Error>;

    /// Set the firmware entry point and release the RPU from its boot state.
    async fn start_firmware(&mut self, entry_point: u32) -> Result<(), Self::Error>;

    /// Wait for the nRF7002 interrupt line.
    async fn wait_for_interrupt(&mut self) -> Result<(), Self::Error>;

    /// Delay without blocking the executor.
    async fn delay_us(&mut self, microseconds: u32);
}
