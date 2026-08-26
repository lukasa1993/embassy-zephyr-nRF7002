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
        memory_map_latency_words(address & !self.address_mask)
    }
}

fn memory_map_latency_words(address: u32) -> u8 {
    if address <= 0x0f0fff {
        return low_memory_latency_words(address);
    }
    if is_high_one_word_region(address) {
        return 1;
    }
    0
}

fn low_memory_latency_words(address: u32) -> u8 {
    if address <= 0x07ffff {
        return lowest_memory_latency_words(address);
    }
    upper_low_memory_latency_words(address)
}

fn lowest_memory_latency_words(address: u32) -> u8 {
    match address {
        0x000000..=0x008fff => 1,
        0x009000..=0x03ffff => 2,
        0x040000..=0x07ffff => 1,
        _ => 0,
    }
}

fn upper_low_memory_latency_words(address: u32) -> u8 {
    match address {
        0x080000..=0x092000 => 2,
        0x0c0000..=0x0f0fff => 0,
        _ => 0,
    }
}

fn is_high_one_word_region(address: u32) -> bool {
    is_first_high_one_word_region(address) || is_second_high_one_word_region(address)
}

fn is_first_high_one_word_region(address: u32) -> bool {
    matches!(
        address,
        0x100000..=0x134000 | 0x140000..=0x14c000 | 0x180000..=0x190000
    )
}

fn is_second_high_one_word_region(address: u32) -> bool {
    matches!(
        address,
        0x200000..=0x261800 | 0x280000..=0x2a4000 | 0x300000..=0x338000
    )
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
            return self.read_word_at_a_time(address, data).await;
        }

        self.read_incrementing(address, data).await
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
    async fn read_incrementing(&mut self, address: u32, data: &mut [u8]) -> Result<(), SPI::Error> {
        let mut done = 0usize;
        while done < data.len() {
            let count = core::cmp::min(MAX_SPI_DATA_LEN, data.len() - done);
            self.read_one(address + done as u32, &mut data[done..done + count], true)
                .await?;
            done += count;
        }
        Ok(())
    }

    async fn read_word_at_a_time(
        &mut self,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), SPI::Error> {
        for (index, word) in data.chunks_mut(HIGH_LATENCY_READ_WORD_LEN).enumerate() {
            let word_address = address + index as u32 * HIGH_LATENCY_READ_WORD_LEN as u32;
            self.read_one(word_address, word, false).await?;
        }
        Ok(())
    }

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
        // Match Nordic's two-buffer transfer exactly: latency clocks extend a
        // zero-filled header, then the null TX data buffer uses SPIM's 0xff
        // over-read character while the payload is received.
        self.io_buffer.bytes[READ_HEADER_LEN..data_start].fill(0);
        self.io_buffer.bytes[data_start..transfer_len].fill(0xff);
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
    use core::convert::Infallible;
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    use embedded_hal_async::spi::{ErrorType, Operation};

    use crate::test_support::block_on;

    use super::*;

    #[derive(Default)]
    struct FakeSpi {
        sent: Vec<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
    }

    impl FakeSpi {
        fn with_responses(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                sent: Vec::new(),
                responses: responses.into_iter().collect(),
            }
        }
    }

    impl ErrorType for FakeSpi {
        type Error = Infallible;
    }

    impl SpiDevice<u8> for FakeSpi {
        async fn transaction(
            &mut self,
            operations: &mut [Operation<'_, u8>],
        ) -> Result<(), Self::Error> {
            assert_eq!(operations.len(), 1);
            match &mut operations[0] {
                Operation::Write(bytes) => self.sent.push(bytes.to_vec()),
                Operation::TransferInPlace(bytes) => {
                    self.sent.push(bytes.to_vec());
                    let response = self.responses.pop_front().expect("missing SPI response");
                    assert_eq!(response.len(), bytes.len());
                    bytes.copy_from_slice(&response);
                }
                operation => panic!("unexpected SPI operation: {operation:?}"),
            }
            Ok(())
        }
    }

    fn read_response(payload: &[u8], latency_words: usize) -> Vec<u8> {
        let mut response = vec![0; READ_HEADER_LEN + latency_words * 4];
        response.extend_from_slice(payload);
        response
    }

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
        for (address, latency) in [
            (0x000000, 1),
            (0x008fff, 1),
            (0x009000, 2),
            (0x03ffff, 2),
            (0x040000, 1),
            (0x07ffff, 1),
            (0x080000, 2),
            (0x092000, 2),
            (0x092001, 0),
            (0x0bffff, 0),
            (0x0c0000, 0),
            (0x0f0fff, 0),
            (0x0f1000, 0),
            (0x100000, 1),
            (0x134000, 1),
            (0x134001, 0),
            (0x140000, 1),
            (0x14c000, 1),
            (0x180000, 1),
            (0x190000, 1),
            (0x200000, 1),
            (0x261800, 1),
            (0x280000, 1),
            (0x2a4000, 1),
            (0x300000, 1),
            (0x338000, 1),
            (0x338001, 0),
            (0xffffff, 0),
            (INCREMENTING_ADDRESS_MASK | 0x009000, 2),
        ] {
            assert_eq!(config.read_latency_words(address), latency, "{address:#x}");
        }
    }

    #[test]
    fn invalid_latency_is_rejected() {
        let config = SpiConfig::new(0x80_0000, 8).expect("maximum latency is valid");
        assert_eq!(config.address_mask(), 0x80_0000);
        assert_eq!(config.slave_latency_words(), 8);
        assert!(!config.uses_nordic_memory_map_latency());
        assert!(SpiConfig::new(0x80_0000, 9).is_none());
        assert!(SpiConfig::new(0x0100_0000, 0).is_none());
    }

    #[test]
    fn status_register_frames_are_exact() {
        let mut status_response = vec![0; 6];
        status_response[1] = 0xa5;
        let spi = FakeSpi::with_responses([status_response]);
        let mut transport = SpiTransport::new(spi);

        assert_eq!(
            block_on(transport.read_status(OPCODE_READ_STATUS_1)),
            Ok(0xa5)
        );
        assert_eq!(
            block_on(transport.write_status(OPCODE_WRITE_STATUS_2, 0x5a)),
            Ok(())
        );
        assert_eq!(transport.config(), SpiConfig::NORDIC_DEFAULT);
        assert_eq!(transport.spi_mut().sent.len(), 2);

        let spi = transport.into_inner();
        assert_eq!(spi.sent[0], [OPCODE_READ_STATUS_1, 0, 0, 0, 0, 0]);
        assert_eq!(spi.sent[1], [OPCODE_WRITE_STATUS_2, 0x5a]);
        assert!(spi.responses.is_empty());
    }

    #[test]
    fn incrementing_reads_use_exact_headers_and_chunk_boundaries() {
        let first_payload: Vec<u8> = (0..MAX_SPI_DATA_LEN).map(|index| index as u8).collect();
        let second_payload = vec![0xde, 0xad];
        let spi = FakeSpi::with_responses([
            read_response(&first_payload, 0),
            read_response(&second_payload, 0),
        ]);
        let mut transport = SpiTransport::new(spi);
        let mut output = vec![0; MAX_SPI_DATA_LEN + second_payload.len()];

        assert_eq!(block_on(transport.read(0x12_3456, &mut output)), Ok(()));
        assert_eq!(&output[..MAX_SPI_DATA_LEN], first_payload);
        assert_eq!(&output[MAX_SPI_DATA_LEN..], second_payload);

        let spi = transport.into_inner();
        assert_eq!(spi.sent.len(), 2);
        assert_eq!(&spi.sent[0][..5], [OPCODE_FAST_READ, 0x92, 0x34, 0x56, 0]);
        assert_eq!(spi.sent[0].len(), READ_HEADER_LEN + MAX_SPI_DATA_LEN);
        assert!(
            spi.sent[0][READ_HEADER_LEN..]
                .iter()
                .all(|byte| *byte == 0xff)
        );
        assert_eq!(&spi.sent[1][..5], [OPCODE_FAST_READ, 0x92, 0x44, 0x56, 0]);
        assert_eq!(spi.sent[1].len(), READ_HEADER_LEN + 2);
        assert_eq!(&spi.sent[1][READ_HEADER_LEN..], [0xff, 0xff]);
    }

    #[test]
    fn memory_map_reads_clock_latency_for_each_nonincrementing_word() {
        let spi =
            FakeSpi::with_responses([read_response(&[1, 2, 3, 4], 2), read_response(&[5, 6], 2)]);
        let mut transport = SpiTransport::with_config(spi, SpiConfig::NORDIC_MEMORY_MAP);
        let mut output = [0; 6];

        assert_eq!(block_on(transport.read(0x009000, &mut output)), Ok(()));
        assert_eq!(output, [1, 2, 3, 4, 5, 6]);

        let spi = transport.into_inner();
        assert_eq!(spi.sent.len(), 2);
        assert_eq!(&spi.sent[0][..5], [OPCODE_FAST_READ, 0x00, 0x90, 0x00, 0]);
        assert_eq!(spi.sent[0].len(), READ_HEADER_LEN + 8 + 4);
        assert!(
            spi.sent[0][READ_HEADER_LEN..READ_HEADER_LEN + 8]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(&spi.sent[0][READ_HEADER_LEN + 8..], [0xff; 4]);
        assert_eq!(&spi.sent[1][..5], [OPCODE_FAST_READ, 0x00, 0x90, 0x04, 0]);
        assert_eq!(spi.sent[1].len(), READ_HEADER_LEN + 8 + 2);
    }

    #[test]
    fn fixed_maximum_latency_keeps_one_incrementing_word_transfer() {
        let payload = vec![0x5a; HIGH_LATENCY_READ_WORD_LEN];
        let config = SpiConfig::new(INCREMENTING_ADDRESS_MASK, MAX_SLAVE_LATENCY_WORDS as u8)
            .expect("maximum fixed latency is valid");
        let spi = FakeSpi::with_responses([read_response(&payload, MAX_SLAVE_LATENCY_WORDS)]);
        let mut transport = SpiTransport::with_config(spi, config);
        let mut output = vec![0; HIGH_LATENCY_READ_WORD_LEN];

        assert_eq!(block_on(transport.read(0x12_3456, &mut output)), Ok(()));
        assert_eq!(output, payload);

        let spi = transport.into_inner();
        assert_eq!(spi.sent.len(), 1);
        assert_eq!(&spi.sent[0][..5], [OPCODE_FAST_READ, 0x92, 0x34, 0x56, 0]);
        assert_eq!(
            spi.sent[0].len(),
            READ_HEADER_LEN + MAX_SLAVE_LATENCY_BYTES + HIGH_LATENCY_READ_WORD_LEN
        );
        assert!(
            spi.sent[0][READ_HEADER_LEN..READ_HEADER_LEN + MAX_SLAVE_LATENCY_BYTES]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            spi.sent[0][READ_HEADER_LEN + MAX_SLAVE_LATENCY_BYTES..]
                .iter()
                .all(|byte| *byte == 0xff)
        );
    }

    #[test]
    fn writes_use_exact_headers_and_chunk_boundaries() {
        let mut data: Vec<u8> = (0..MAX_SPI_DATA_LEN).map(|index| index as u8).collect();
        data.extend_from_slice(&[0xde, 0xad]);
        let mut transport = SpiTransport::new(FakeSpi::default());

        assert_eq!(block_on(transport.write(0x12_3456, &data)), Ok(()));

        let spi = transport.into_inner();
        assert_eq!(spi.sent.len(), 2);
        assert_eq!(&spi.sent[0][..4], [OPCODE_WRITE, 0x92, 0x34, 0x56]);
        assert_eq!(&spi.sent[0][4..], &data[..MAX_SPI_DATA_LEN]);
        assert_eq!(&spi.sent[1][..4], [OPCODE_WRITE, 0x92, 0x44, 0x56]);
        assert_eq!(&spi.sent[1][4..], [0xde, 0xad]);
    }

    #[test]
    fn empty_transfers_do_not_touch_spi() {
        let mut transport = SpiTransport::new(FakeSpi::default());
        assert_eq!(block_on(transport.read(0x1234, &mut [])), Ok(()));
        assert_eq!(block_on(transport.write(0x1234, &[])), Ok(()));
        assert!(transport.into_inner().sent.is_empty());
    }

    #[test]
    fn spi_io_buffer_is_word_aligned() {
        assert_eq!(
            SPI_IO_BUFFER_LEN,
            READ_HEADER_LEN + MAX_SLAVE_LATENCY_WORDS * 4 + MAX_SPI_DATA_LEN
        );
        let buffer = SpiIoBuffer {
            bytes: [0; SPI_IO_BUFFER_LEN],
        };
        assert_eq!(buffer.bytes.as_ptr() as usize & 3, 0);
    }
}
