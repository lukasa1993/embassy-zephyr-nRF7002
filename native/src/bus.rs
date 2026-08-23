//! Direct nRF7002 SPI transport.
//!
//! The framing follows Nordic's `nrf70-bm` SPI shim. The SPI device must keep
//! chip select active for every `transaction` call.

use embedded_hal_async::spi::{Operation, SpiDevice};

/// Fast-read command used by the nRF70 host interface.
pub const OPCODE_FAST_READ: u8 = 0x0b;
/// Page-program command used by the nRF70 host interface.
pub const OPCODE_WRITE: u8 = 0x02;
/// Read status register 1.
pub const OPCODE_READ_STATUS_1: u8 = 0x1f;
/// Read status register 2.
pub const OPCODE_READ_STATUS_2: u8 = 0x2f;
/// Write status register 2.
pub const OPCODE_WRITE_STATUS_2: u8 = 0x3f;
/// Incrementing-address flag used by Nordic's SPI and QSPI shims.
pub const INCREMENTING_ADDRESS_MASK: u32 = 0x80_0000;
/// RPU wake request bit in status register 2.
pub const RPU_WAKE_REQUEST: u8 = 1 << 0;
/// RPU awake indication in status register 1.
pub const RPU_AWAKE: u8 = 1 << 1;
/// RPU firmware-ready indication in status register 1.
pub const RPU_READY: u8 = 1 << 2;

const MAX_SLAVE_LATENCY_WORDS: usize = 8;
const MAX_SLAVE_LATENCY_BYTES: usize = MAX_SLAVE_LATENCY_WORDS * 4;

/// Bus operations needed by the native driver.
#[allow(async_fn_in_trait)]
pub trait Bus {
    /// Error returned by the host bus implementation.
    type Error;

    /// Reads one nRF70 status register.
    async fn read_status(&mut self, opcode: u8) -> Result<u8, Self::Error>;

    /// Writes one nRF70 status register.
    async fn write_status(&mut self, opcode: u8, value: u8) -> Result<(), Self::Error>;

    /// Reads bytes from the 24-bit nRF70 host address space.
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Self::Error>;

    /// Writes bytes to the 24-bit nRF70 host address space.
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error>;
}

/// Static SPI framing settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpiConfig {
    /// Address bits ORed into every block transfer.
    pub address_mask: u32,
    /// Extra 32-bit latency words discarded after a fast-read header.
    pub slave_latency_words: u8,
}

impl SpiConfig {
    /// Nordic's default SPI configuration.
    pub const NORDIC_DEFAULT: Self = Self {
        address_mask: INCREMENTING_ADDRESS_MASK,
        slave_latency_words: 0,
    };

    /// Creates validated settings.
    pub const fn new(address_mask: u32, slave_latency_words: u8) -> Option<Self> {
        if address_mask > 0x00ff_ffff
            || slave_latency_words as usize > MAX_SLAVE_LATENCY_WORDS
        {
            return None;
        }
        Some(Self {
            address_mask,
            slave_latency_words,
        })
    }
}

impl Default for SpiConfig {
    fn default() -> Self {
        Self::NORDIC_DEFAULT
    }
}

/// Native nRF7002 transport over an async Embassy-compatible SPI device.
pub struct SpiTransport<SPI> {
    spi: SPI,
    config: SpiConfig,
}

impl<SPI> SpiTransport<SPI> {
    /// Creates a transport with Nordic's incrementing-address mode enabled.
    pub const fn new(spi: SPI) -> Self {
        Self {
            spi,
            config: SpiConfig::NORDIC_DEFAULT,
        }
    }

    /// Creates a transport with explicit framing settings.
    pub const fn with_config(spi: SPI, config: SpiConfig) -> Self {
        Self { spi, config }
    }

    /// Returns the framing settings.
    pub const fn config(&self) -> SpiConfig {
        self.config
    }

    /// Borrows the underlying SPI device.
    pub fn spi_mut(&mut self) -> &mut SPI {
        &mut self.spi
    }

    /// Releases the underlying SPI device.
    pub fn into_inner(self) -> SPI {
        self.spi
    }

    fn wire_address(&self, address: u32) -> u32 {
        (address | self.config.address_mask) & 0x00ff_ffff
    }
}

impl<SPI> Bus for SpiTransport<SPI>
where
    SPI: SpiDevice<u8>,
{
    type Error = SPI::Error;

    async fn read_status(&mut self, opcode: u8) -> Result<u8, Self::Error> {
        // Nordic's shim sends six bytes and consumes the second received byte.
        let mut transfer = [opcode, 0, 0, 0, 0, 0];
        self.spi.transfer_in_place(&mut transfer).await?;
        Ok(transfer[1])
    }

    async fn write_status(&mut self, opcode: u8, value: u8) -> Result<(), Self::Error> {
        self.spi.write(&[opcode, value]).await
    }

    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
        if data.is_empty() {
            return Ok(());
        }

        let address = self.wire_address(address);
        let header = [
            OPCODE_FAST_READ,
            (address >> 16) as u8,
            (address >> 8) as u8,
            address as u8,
            0,
        ];
        let latency_len = self.config.slave_latency_words as usize * 4;
        let mut latency = [0u8; MAX_SLAVE_LATENCY_BYTES];

        if latency_len == 0 {
            let mut operations = [Operation::Write(&header), Operation::Read(data)];
            self.spi.transaction(&mut operations).await
        } else {
            let mut operations = [
                Operation::Write(&header),
                Operation::Read(&mut latency[..latency_len]),
                Operation::Read(data),
            ];
            self.spi.transaction(&mut operations).await
        }
    }

    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        if data.is_empty() {
            return Ok(());
        }

        let address = self.wire_address(address);
        let header = [
            OPCODE_WRITE,
            (address >> 16) as u8,
            (address >> 8) as u8,
            address as u8,
        ];
        let mut operations = [Operation::Write(&header), Operation::Write(data)];
        self.spi.transaction(&mut operations).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nordic_defaults_are_exact() {
        assert_eq!(SpiConfig::NORDIC_DEFAULT.address_mask, 0x80_0000);
        assert_eq!(SpiConfig::NORDIC_DEFAULT.slave_latency_words, 0);
    }

    #[test]
    fn invalid_latency_is_rejected() {
        assert!(SpiConfig::new(0x80_0000, 8).is_some());
        assert!(SpiConfig::new(0x80_0000, 9).is_none());
        assert!(SpiConfig::new(0x0100_0000, 0).is_none());
    }
}
