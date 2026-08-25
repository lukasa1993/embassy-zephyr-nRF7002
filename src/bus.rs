//! Direct nRF7002 SPI transport.
//!
//! The framing follows Nordic's `nrf70-bm` SPI shim. The SPI device must keep
//! chip select active for every `transaction` call.

use embedded_hal_async::spi::SpiDevice;

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
const READ_HEADER_LEN: usize = 5;
const HIGH_LATENCY_READ_WORD_LEN: usize = 4;
/// Largest payload copied into the transport's reusable EasyDMA buffer.
///
/// This matches `NRF70_PATCH_DL_CHUNK_SIZE` in the pinned Nordic host
/// interface. Keeping a complete 4 KiB firmware chunk in one SPI transaction
/// is important: chip select must not toggle in the middle of a chunk.
pub const MAX_SPI_DATA_LEN: usize = 4096;
const SPI_IO_BUFFER_LEN: usize = READ_HEADER_LEN + MAX_SLAVE_LATENCY_BYTES + MAX_SPI_DATA_LEN;

// Nordic's SPI shim requires EasyDMA buffers to be word aligned.
#[repr(align(4))]
struct SpiIoBuffer {
    bytes: [u8; SPI_IO_BUFFER_LEN],
}

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
///
/// Use [`SpiConfig::new`] for custom settings. The fields stay private so an
/// invalid latency cannot create an out-of-bounds transfer slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpiConfig {
    address_mask: u32,
    slave_latency_words: u8,
    nordic_memory_map_latency: bool,
}

impl SpiConfig {
    /// Nordic's default SPI configuration.
    pub const NORDIC_DEFAULT: Self = Self {
        address_mask: INCREMENTING_ADDRESS_MASK,
        slave_latency_words: 0,
        nordic_memory_map_latency: false,
    };

    /// Nordic's per-memory-region latency table used by the pinned bus shim.
    pub const NORDIC_MEMORY_MAP: Self = Self {
        address_mask: INCREMENTING_ADDRESS_MASK,
        slave_latency_words: 0,
        nordic_memory_map_latency: true,
    };

    /// Creates validated settings.
    pub const fn new(address_mask: u32, slave_latency_words: u8) -> Option<Self> {
        if address_mask > 0x00ff_ffff || slave_latency_words as usize > MAX_SLAVE_LATENCY_WORDS {
            return None;
        }
        Some(Self {
            address_mask,
            slave_latency_words,
            nordic_memory_map_latency: false,
        })
    }

    /// Returns the address bits added to each block transfer.
    pub const fn address_mask(self) -> u32 {
        self.address_mask
    }

    /// Returns the number of 32-bit read-latency words.
    pub const fn slave_latency_words(self) -> u8 {
        self.slave_latency_words
    }

    /// Returns true when reads use Nordic's region-specific latency table.
    pub const fn uses_nordic_memory_map_latency(self) -> bool {
        self.nordic_memory_map_latency
    }

    fn read_latency_words(self, address: u32) -> u8 {
        if !self.nordic_memory_map_latency {
            return self.slave_latency_words;
        }
        match address & !self.address_mask {
            0x000000..=0x008fff => 1,
            0x009000..=0x03ffff => 2,
            0x040000..=0x07ffff => 1,
            0x080000..=0x092000 => 1,
            0x0c0000..=0x0f0fff => 0,
            0x100000..=0x134000
            | 0x140000..=0x14c000
            | 0x180000..=0x190000
            | 0x200000..=0x261800
            | 0x280000..=0x2a4000
            | 0x300000..=0x338000 => 1,
            _ => 0,
        }
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
    io_buffer: SpiIoBuffer,
}

impl<SPI> SpiTransport<SPI> {
    /// Creates a transport with Nordic's incrementing-address mode enabled.
    pub const fn new(spi: SPI) -> Self {
        Self {
            spi,
            config: SpiConfig::NORDIC_DEFAULT,
            io_buffer: SpiIoBuffer {
                bytes: [0; SPI_IO_BUFFER_LEN],
            },
        }
    }

    /// Creates a transport with explicit framing settings.
    pub const fn with_config(spi: SPI, config: SpiConfig) -> Self {
        Self {
            spi,
            config,
            io_buffer: SpiIoBuffer {
                bytes: [0; SPI_IO_BUFFER_LEN],
            },
        }
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

        if self.config.nordic_memory_map_latency && self.config.read_latency_words(address) != 0 {
            for (index, word) in data.chunks_mut(4).enumerate() {
                let word_address = address + index as u32 * 4;
                self.read_one(word_address, word, false).await?;
            }
            return Ok(());
        }

        let mut done = 0usize;
        while done < data.len() {
            let count = core::cmp::min(MAX_SPI_DATA_LEN, data.len() - done);
            self.read_one(address + done as u32, &mut data[done..done + count], true)
                .await?;
            done += count;
        }
        Ok(())
    }

    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        if data.is_empty() {
            return Ok(());
        }

        let mut done = 0usize;
        while done < data.len() {
            let count = core::cmp::min(MAX_SPI_DATA_LEN, data.len() - done);
            let address = self.wire_address(address + done as u32);
            self.io_buffer.bytes[0] = OPCODE_WRITE;
            self.io_buffer.bytes[1] = (address >> 16) as u8;
            self.io_buffer.bytes[2] = (address >> 8) as u8;
            self.io_buffer.bytes[3] = address as u8;
            self.io_buffer.bytes[4..4 + count].copy_from_slice(&data[done..done + count]);
            self.spi.write(&self.io_buffer.bytes[..4 + count]).await?;
            self.io_buffer.bytes[..4 + count].fill(0);
            done += count;
        }
        Ok(())
    }
}

impl<SPI> SpiTransport<SPI>
where
    SPI: SpiDevice<u8>,
{
    async fn read_one(
        &mut self,
        address: u32,
        data: &mut [u8],
        incrementing: bool,
    ) -> Result<(), SPI::Error> {
        let latency_len = self.config.read_latency_words(address) as usize * 4;
        let address = if incrementing {
            self.wire_address(address)
        } else {
            address & 0x00ff_ffff
        };
        debug_assert!(latency_len == 0 || data.len() <= HIGH_LATENCY_READ_WORD_LEN);
        debug_assert!(data.len() <= MAX_SPI_DATA_LEN);
        self.io_buffer.bytes[0] = OPCODE_FAST_READ;
        self.io_buffer.bytes[1] = (address >> 16) as u8;
        self.io_buffer.bytes[2] = (address >> 8) as u8;
        self.io_buffer.bytes[3] = address as u8;
        self.io_buffer.bytes[4] = 0;
        let data_start = READ_HEADER_LEN + latency_len;
        let transfer_len = data_start + data.len();
        // Nordic's SPI shim clocks reads with a null TX buffer. The nRF SPIM
        // peripheral emits its 0xff over-read character for those clocks, so
        // reproduce that wire traffic instead of transmitting stale/zero RAM.
        self.io_buffer.bytes[READ_HEADER_LEN..transfer_len].fill(0xff);
        self.spi
            .transfer_in_place(&mut self.io_buffer.bytes[..transfer_len])
            .await?;
        data.copy_from_slice(&self.io_buffer.bytes[data_start..transfer_len]);
        self.io_buffer.bytes[..transfer_len].fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nordic_defaults_are_exact() {
        assert_eq!(SpiConfig::NORDIC_DEFAULT.address_mask(), 0x80_0000);
        assert_eq!(SpiConfig::NORDIC_DEFAULT.slave_latency_words(), 0);
        assert!(!SpiConfig::NORDIC_DEFAULT.uses_nordic_memory_map_latency());
        assert!(SpiConfig::NORDIC_MEMORY_MAP.uses_nordic_memory_map_latency());
    }

    #[test]
    fn nordic_memory_map_latency_matches_the_pinned_bus_shim() {
        let config = SpiConfig::NORDIC_MEMORY_MAP;
        assert_eq!(config.read_latency_words(0x000018), 1);
        assert_eq!(config.read_latency_words(0x009000), 2);
        assert_eq!(config.read_latency_words(0x048c20), 1);
        assert_eq!(config.read_latency_words(0x080000), 1);
        assert_eq!(config.read_latency_words(0x0c5000), 0);
        assert_eq!(config.read_latency_words(0x143a80), 1);
        assert_eq!(config.read_latency_words(0x28c000), 1);
    }

    #[test]
    fn invalid_latency_is_rejected() {
        assert!(SpiConfig::new(0x80_0000, 8).is_some());
        assert!(SpiConfig::new(0x80_0000, 9).is_none());
        assert!(SpiConfig::new(0x0100_0000, 0).is_none());
    }

    #[test]
    fn spi_io_buffer_is_word_aligned() {
        let buffer = SpiIoBuffer {
            bytes: [0; SPI_IO_BUFFER_LEN],
        };
        assert_eq!(buffer.bytes.as_ptr() as usize & 3, 0);
    }
}
