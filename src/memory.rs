//! nRF7002 RPU address translation, power control, and memory access.

use embedded_hal_async::delay::DelayNs;

use super::bus::{Bus, OPCODE_READ_STATUS_1, OPCODE_READ_STATUS_2, OPCODE_WRITE_STATUS_2};
use super::bus::{RPU_AWAKE, RPU_READY, RPU_WAKE_REQUEST};

/// Largest transfer emitted by the memory layer.
///
/// [`crate::SpiTransport`] owns a reusable RAM EasyDMA buffer, so firmware
/// image bytes can remain in flash while preserving Nordic's 4 KiB download
/// transaction size.
pub const MAX_BUS_CHUNK: usize = super::bus::MAX_SPI_DATA_LEN;

pub const RPU_ADDR_GRAM_START: u32 = 0xb700_0000;
pub const RPU_ADDR_GRAM_END: u32 = 0xb701_01ff;
pub const RPU_ADDR_SBUS_START: u32 = 0xa400_0000;
pub const RPU_ADDR_SBUS_END: u32 = 0xa400_7fff;
pub const RPU_ADDR_PBUS_START: u32 = 0xa500_0000;
pub const RPU_ADDR_PBUS_END: u32 = 0xa503_ffff;
pub const RPU_ADDR_PKTRAM_START: u32 = 0xb000_0000;
pub const RPU_ADDR_PKTRAM_END: u32 = 0xb003_0fff;

pub const RPU_ADDR_LMAC_ROM_START: u32 = 0x8000_0000;
pub const RPU_ADDR_LMAC_ROM_END: u32 = 0x8003_3fff;
pub const RPU_ADDR_LMAC_RET_START: u32 = 0x8004_0000;
pub const RPU_ADDR_LMAC_RET_END: u32 = 0x8004_bfff;
pub const RPU_ADDR_LMAC_SCRATCH_START: u32 = 0x8008_0000;
pub const RPU_ADDR_LMAC_SCRATCH_END: u32 = 0x8008_ffff;

pub const RPU_ADDR_UMAC_ROM_START: u32 = 0x8000_0000;
pub const RPU_ADDR_UMAC_ROM_END: u32 = 0x8006_17ff;
pub const RPU_ADDR_UMAC_RET_START: u32 = 0x8008_0000;
pub const RPU_ADDR_UMAC_RET_END: u32 = 0x800a_3fff;
pub const RPU_ADDR_UMAC_SCRATCH_START: u32 = 0x8010_0000;
pub const RPU_ADDR_UMAC_SCRATCH_END: u32 = 0x8013_7fff;

pub const HOST_SBUS_BASE: u32 = 0x0000_0000;
pub const HOST_PBUS_BASE: u32 = 0x0004_0000;
pub const HOST_GRAM_BASE: u32 = 0x0008_0000;
pub const HOST_PKTRAM_BASE: u32 = 0x000c_0000;
pub const HOST_LMAC_DIRECT_BASE: u32 = 0x0010_0000;
pub const HOST_UMAC_DIRECT_BASE: u32 = 0x0020_0000;
pub const RPU_ADDR_MASK_OFFSET: u32 = 0x00ff_ffff;
pub const RPU_MCU_CORE_INDIRECT_BASE: u32 = 0xc000_0000;

pub const RPU_REG_MIPS_MCU_CONTROL: u32 = 0xa400_0000;
pub const RPU_REG_MIPS_MCU2_CONTROL: u32 = 0xa400_0100;
pub const RPU_REG_MIPS_MCU_SYS_CORE_MEM_CTRL: u32 = 0xa400_0030;
pub const RPU_REG_MIPS_MCU_SYS_CORE_MEM_WDATA: u32 = 0xa400_0034;
pub const RPU_REG_MIPS_MCU2_SYS_CORE_MEM_CTRL: u32 = 0xa400_0130;
pub const RPU_REG_MIPS_MCU2_SYS_CORE_MEM_WDATA: u32 = 0xa400_0134;
pub const RPU_REG_MIPS_MCU_WAIT_STATUS: u32 = 0xa400_0018;
pub const RPU_REG_MIPS_MCU2_WAIT_STATUS: u32 = 0xa400_0118;
/// PBUS register used by Nordic's bus initialization to enable RPU clocks.
pub const RPU_REG_CLOCK_ENABLE: u32 = 0xa500_8c20;
/// Clock-enable value required before either MIPS core can leave reset.
pub const RPU_CLOCK_ENABLE: u32 = 0x100;

/// One of the two MIPS processors in the nRF7002 RPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Processor {
    /// Lower MAC processor.
    Lmac,
    /// Upper MAC processor.
    Umac,
}

impl Processor {
    pub(crate) const fn control_register(self) -> u32 {
        match self {
            Self::Lmac => RPU_REG_MIPS_MCU_CONTROL,
            Self::Umac => RPU_REG_MIPS_MCU2_CONTROL,
        }
    }

    pub(crate) const fn wait_register(self) -> u32 {
        match self {
            Self::Lmac => RPU_REG_MIPS_MCU_WAIT_STATUS,
            Self::Umac => RPU_REG_MIPS_MCU2_WAIT_STATUS,
        }
    }

    pub(crate) const fn indirect_control_register(self) -> u32 {
        match self {
            Self::Lmac => RPU_REG_MIPS_MCU_SYS_CORE_MEM_CTRL,
            Self::Umac => RPU_REG_MIPS_MCU2_SYS_CORE_MEM_CTRL,
        }
    }

    pub(crate) const fn indirect_data_register(self) -> u32 {
        match self {
            Self::Lmac => RPU_REG_MIPS_MCU_SYS_CORE_MEM_WDATA,
            Self::Umac => RPU_REG_MIPS_MCU2_SYS_CORE_MEM_WDATA,
        }
    }
}

/// Address translation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    /// The address is outside every supported nRF70 host-visible region.
    Unsupported(u32),
    /// A range crosses the end of its mapped region.
    Range,
}

/// Native RPU access failure.
#[derive(Debug)]
pub enum RpuError<E> {
    /// The SPI or QSPI implementation failed.
    Bus(E),
    /// The RPU address cannot be mapped.
    Address(AddressError),
    /// An operation that requires word alignment received an invalid value.
    Unaligned,
    /// A bounded poll did not reach its expected state.
    Timeout,
    /// A register poll exhausted its deadline without reaching the mask/value.
    PollTimeout {
        address: u32,
        mask: u32,
        expected: u32,
        last: u32,
    },
    /// An input length or encoded address was invalid.
    InvalidArgument,
}

impl<E> From<AddressError> for RpuError<E> {
    fn from(value: AddressError) -> Self {
        Self::Address(value)
    }
}

/// Maps an RPU address into the 24-bit host bus window.
pub const fn host_offset(processor: Processor, address: u32) -> Result<u32, AddressError> {
    let low = address & RPU_ADDR_MASK_OFFSET;
    if let Some(base) = shared_region_base(address) {
        return Ok(base + low);
    }
    match processor_region_base(processor, address) {
        Some(base) => Ok(base + low),
        None => Err(AddressError::Unsupported(address)),
    }
}

const fn shared_region_base(address: u32) -> Option<u32> {
    match address {
        RPU_ADDR_SBUS_START..=RPU_ADDR_SBUS_END => Some(HOST_SBUS_BASE),
        RPU_ADDR_PBUS_START..=RPU_ADDR_PBUS_END => Some(HOST_PBUS_BASE),
        RPU_ADDR_GRAM_START..=RPU_ADDR_GRAM_END => Some(HOST_GRAM_BASE),
        RPU_ADDR_PKTRAM_START..=RPU_ADDR_PKTRAM_END => Some(HOST_PKTRAM_BASE),
        _ => None,
    }
}

const fn processor_region_base(processor: Processor, address: u32) -> Option<u32> {
    match processor {
        Processor::Lmac => lmac_region_base(address),
        Processor::Umac => umac_region_base(address),
    }
}

const fn lmac_region_base(address: u32) -> Option<u32> {
    match address {
        RPU_ADDR_LMAC_ROM_START..=RPU_ADDR_LMAC_ROM_END
        | RPU_ADDR_LMAC_RET_START..=RPU_ADDR_LMAC_RET_END
        | RPU_ADDR_LMAC_SCRATCH_START..=RPU_ADDR_LMAC_SCRATCH_END => Some(HOST_LMAC_DIRECT_BASE),
        _ => None,
    }
}

const fn umac_region_base(address: u32) -> Option<u32> {
    match address {
        RPU_ADDR_UMAC_ROM_START..=RPU_ADDR_UMAC_ROM_END
        | RPU_ADDR_UMAC_RET_START..=RPU_ADDR_UMAC_RET_END
        | RPU_ADDR_UMAC_SCRATCH_START..=RPU_ADDR_UMAC_SCRATCH_END => Some(HOST_UMAC_DIRECT_BASE),
        _ => None,
    }
}

/// Owns the host bus and performs RPU memory operations.
pub struct Rpu<B> {
    bus: B,
}

impl<B> Rpu<B> {
    /// Creates an RPU memory interface.
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Borrows the low-level bus.
    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    /// Releases the low-level bus.
    pub fn into_inner(self) -> B {
        self.bus
    }
}

impl<B> Rpu<B>
where
    B: Bus,
{
    /// Requests RPU wake and waits for the hardware awake indication.
    ///
    /// Nordic requires the wake transaction to run at no more than 8 MHz.
    /// The SPI peripheral configuration remains the caller's responsibility.
    pub async fn wake<D>(&mut self, delay: &mut D, attempts: u16) -> Result<(), RpuError<B::Error>>
    where
        D: DelayNs,
    {
        self.bus
            .write_status(OPCODE_WRITE_STATUS_2, RPU_WAKE_REQUEST)
            .await
            .map_err(RpuError::Bus)?;
        self.wait_status_bit(OPCODE_READ_STATUS_2, RPU_WAKE_REQUEST, delay, attempts)
            .await?;
        self.wait_status_bit(OPCODE_READ_STATUS_1, RPU_AWAKE, delay, attempts)
            .await
    }

    async fn wait_status_bit<D>(
        &mut self,
        opcode: u8,
        mask: u8,
        delay: &mut D,
        attempts: u16,
    ) -> Result<(), RpuError<B::Error>>
    where
        D: DelayNs,
    {
        for _ in 0..attempts {
            let status = self.bus.read_status(opcode).await.map_err(RpuError::Bus)?;
            if status & mask != 0 {
                return Ok(());
            }
            delay.delay_ms(1).await;
        }
        Err(RpuError::Timeout)
    }

    /// Reads the firmware-ready status bit.
    pub async fn firmware_ready(&mut self) -> Result<bool, RpuError<B::Error>> {
        let state = self
            .bus
            .read_status(OPCODE_READ_STATUS_1)
            .await
            .map_err(RpuError::Bus)?;
        Ok(state & RPU_READY != 0)
    }

    /// Reads bytes from one RPU memory region.
    ///
    /// The nRF7002 host bus operates on aligned words. The final short word is
    /// read into local scratch storage and only the requested bytes are copied
    /// to the caller.
    pub async fn read(
        &mut self,
        processor: Processor,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), RpuError<B::Error>> {
        validate_access(processor, address, data.len())?;
        let aligned_len = data.len() & !3;
        self.read_aligned(processor, address, &mut data[..aligned_len])
            .await?;
        self.read_tail(processor, address, aligned_len, data).await
    }

    async fn read_aligned(
        &mut self,
        processor: Processor,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), RpuError<B::Error>> {
        for (index, chunk) in data.chunks_mut(MAX_BUS_CHUNK).enumerate() {
            let offset = chunk_host_offset(processor, address, index)?;
            self.bus.read(offset, chunk).await.map_err(RpuError::Bus)?;
        }
        Ok(())
    }

    async fn read_tail(
        &mut self,
        processor: Processor,
        address: u32,
        aligned_len: usize,
        data: &mut [u8],
    ) -> Result<(), RpuError<B::Error>> {
        let tail_len = data.len() - aligned_len;
        if tail_len == 0 {
            return Ok(());
        }
        let mut tail = [0u8; 4];
        let offset = host_offset(processor, address + aligned_len as u32)?;
        self.bus
            .read(offset, &mut tail)
            .await
            .map_err(RpuError::Bus)?;
        data[aligned_len..].copy_from_slice(&tail[..tail_len]);
        Ok(())
    }

    /// Writes bytes to one RPU memory region.
    ///
    /// The nRF7002 host bus operates on aligned words. The final short word is
    /// zero-padded before the transfer. Every caller must own the complete
    /// destination word when it uses a non-word-sized write.
    pub async fn write(
        &mut self,
        processor: Processor,
        address: u32,
        data: &[u8],
    ) -> Result<(), RpuError<B::Error>> {
        validate_access(processor, address, data.len())?;
        let aligned_len = data.len() & !3;
        self.write_aligned(processor, address, &data[..aligned_len])
            .await?;
        self.write_tail(processor, address, aligned_len, data).await
    }

    async fn write_aligned(
        &mut self,
        processor: Processor,
        address: u32,
        data: &[u8],
    ) -> Result<(), RpuError<B::Error>> {
        for (index, chunk) in data.chunks(MAX_BUS_CHUNK).enumerate() {
            let offset = chunk_host_offset(processor, address, index)?;
            self.bus.write(offset, chunk).await.map_err(RpuError::Bus)?;
        }
        Ok(())
    }

    async fn write_tail(
        &mut self,
        processor: Processor,
        address: u32,
        aligned_len: usize,
        data: &[u8],
    ) -> Result<(), RpuError<B::Error>> {
        let tail_len = data.len() - aligned_len;
        if tail_len == 0 {
            return Ok(());
        }
        let mut tail = [0u8; 4];
        tail[..tail_len].copy_from_slice(&data[aligned_len..]);
        let offset = host_offset(processor, address + aligned_len as u32)?;
        self.bus.write(offset, &tail).await.map_err(RpuError::Bus)?;
        Ok(())
    }

    /// Reads a little-endian word.
    pub async fn read_u32(
        &mut self,
        processor: Processor,
        address: u32,
    ) -> Result<u32, RpuError<B::Error>> {
        if address & 3 != 0 {
            return Err(RpuError::Unaligned);
        }
        let mut bytes = [0u8; 4];
        self.read(processor, address, &mut bytes).await?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Writes a little-endian word.
    pub async fn write_u32(
        &mut self,
        processor: Processor,
        address: u32,
        value: u32,
    ) -> Result<(), RpuError<B::Error>> {
        if address & 3 != 0 {
            return Err(RpuError::Unaligned);
        }
        self.write(processor, address, &value.to_le_bytes()).await
    }

    /// Reads an RPU system or peripheral register.
    pub async fn read_register(&mut self, address: u32) -> Result<u32, RpuError<B::Error>> {
        self.read_u32(Processor::Lmac, address).await
    }

    /// Writes an RPU system or peripheral register.
    pub async fn write_register(
        &mut self,
        address: u32,
        value: u32,
    ) -> Result<(), RpuError<B::Error>> {
        self.write_u32(Processor::Lmac, address, value).await
    }

    /// Writes words through a processor's indirect core-memory port.
    pub async fn write_indirect(
        &mut self,
        processor: Processor,
        encoded_address: u32,
        data: &[u8],
    ) -> Result<(), RpuError<B::Error>> {
        validate_indirect_access(encoded_address, data.len())?;
        let word_address = (encoded_address & RPU_ADDR_MASK_OFFSET) >> 2;
        self.write_register(processor.indirect_control_register(), word_address)
            .await?;
        self.write_indirect_words(processor, data).await
    }

    async fn write_indirect_words(
        &mut self,
        processor: Processor,
        data: &[u8],
    ) -> Result<(), RpuError<B::Error>> {
        for word in data.chunks_exact(4) {
            let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            self.write_register(processor.indirect_data_register(), value)
                .await?;
        }
        Ok(())
    }

    /// Enables the RPU clocks required before processor reset and firmware load.
    pub async fn enable_clocks(&mut self) -> Result<(), RpuError<B::Error>> {
        self.write_register(RPU_REG_CLOCK_ENABLE, RPU_CLOCK_ENABLE)
            .await
    }

    /// Performs Nordic's pulsed processor reset and waits for the MIPS wait state.
    pub async fn reset_processor<D>(
        &mut self,
        processor: Processor,
        delay: &mut D,
    ) -> Result<(), RpuError<B::Error>>
    where
        D: DelayNs,
    {
        self.write_register(processor.control_register(), 1).await?;
        self.poll_register(processor.control_register(), 1, 0, delay, 50, 10)
            .await?;
        self.poll_register(processor.wait_register(), 1, 1, delay, 50, 10)
            .await
    }

    /// Polls a register with a bounded delay.
    pub async fn poll_register<D>(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        delay: &mut D,
        attempts: u16,
        delay_ms: u32,
    ) -> Result<(), RpuError<B::Error>>
    where
        D: DelayNs,
    {
        let mut last = 0;
        for _ in 0..attempts {
            last = self.read_register(address).await?;
            if last & mask == expected {
                return Ok(());
            }
            delay.delay_ms(delay_ms).await;
        }
        Err(RpuError::PollTimeout {
            address,
            mask,
            expected,
            last,
        })
    }
}

const fn align4(len: usize) -> Option<usize> {
    match len.checked_add(3) {
        Some(value) => Some(value & !3),
        None => None,
    }
}

fn checked_range<E>(processor: Processor, address: u32, len: usize) -> Result<(), RpuError<E>> {
    if len == 0 {
        host_offset(processor, address)?;
        return Ok(());
    }
    let (span, end) = checked_access_end(address, len)?;
    let (first, last) = mapped_access_bounds(processor, address, end)?;
    if last.checked_sub(first) != Some(span) {
        return Err(RpuError::Address(AddressError::Range));
    }
    Ok(())
}

fn checked_access_end<E>(address: u32, len: usize) -> Result<(u32, u32), RpuError<E>> {
    let span = checked_span(len)?;
    let end = address
        .checked_add(span)
        .ok_or(RpuError::Address(AddressError::Range))?;
    Ok((span, end))
}

fn mapped_access_bounds<E>(
    processor: Processor,
    address: u32,
    end: u32,
) -> Result<(u32, u32), RpuError<E>> {
    Ok((
        host_offset(processor, address)?,
        host_offset(processor, end)?,
    ))
}

fn validate_access<E>(processor: Processor, address: u32, len: usize) -> Result<(), RpuError<E>> {
    if address & 3 != 0 {
        return Err(RpuError::Unaligned);
    }
    let padded_len = align4(len).ok_or(RpuError::InvalidArgument)?;
    checked_range(processor, address, padded_len)
}

fn validate_indirect_access<E>(encoded_address: u32, len: usize) -> Result<(), RpuError<E>> {
    if encoded_address & 0xff00_0000 != RPU_MCU_CORE_INDIRECT_BASE {
        return Err(RpuError::Unaligned);
    }
    if encoded_address & 3 != 0 || len & 3 != 0 {
        return Err(RpuError::Unaligned);
    }
    Ok(())
}

fn checked_span<E>(len: usize) -> Result<u32, RpuError<E>> {
    u32::try_from(len - 1).map_err(|_| RpuError::Address(AddressError::Range))
}

fn chunk_host_offset<E>(
    processor: Processor,
    address: u32,
    index: usize,
) -> Result<u32, RpuError<E>> {
    let byte_offset = index
        .checked_mul(MAX_BUS_CHUNK)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RpuError::InvalidArgument)?;
    let address = address
        .checked_add(byte_offset)
        .ok_or(RpuError::InvalidArgument)?;
    Ok(host_offset(processor, address)?)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    use crate::test_support::block_on;

    use super::*;

    #[derive(Default)]
    struct TestBus {
        status_1: VecDeque<u8>,
        status_2: VecDeque<u8>,
        status_writes: Vec<(u8, u8)>,
        read_responses: VecDeque<Vec<u8>>,
        register_values: Vec<(u32, u32)>,
        reads: Vec<(u32, usize)>,
        writes: Vec<(u32, Vec<u8>)>,
    }

    impl Bus for TestBus {
        type Error = ();

        async fn read_status(&mut self, opcode: u8) -> Result<u8, Self::Error> {
            let queue = if opcode == OPCODE_READ_STATUS_1 {
                &mut self.status_1
            } else {
                &mut self.status_2
            };
            Ok(queue.pop_front().unwrap_or(0))
        }

        async fn write_status(&mut self, opcode: u8, value: u8) -> Result<(), Self::Error> {
            self.status_writes.push((opcode, value));
            Ok(())
        }

        async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            self.reads.push((address, data.len()));
            if let Some(response) = self.read_responses.pop_front() {
                assert_eq!(response.len(), data.len());
                data.copy_from_slice(&response);
                return Ok(());
            }
            let value = self
                .register_values
                .iter()
                .find_map(|(candidate, value)| (*candidate == address).then_some(*value))
                .unwrap_or(0);
            data.copy_from_slice(&value.to_le_bytes()[..data.len()]);
            Ok(())
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingDelay(usize);

    impl DelayNs for CountingDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            self.0 += 1;
        }
    }

    #[test]
    fn bus_chunks_match_the_pinned_nordic_loader() {
        let chunk = core::hint::black_box(MAX_BUS_CHUNK);
        assert_eq!(chunk, 4096);
        assert_eq!(chunk & 3, 0);
    }

    #[test]
    fn maps_all_public_regions() {
        for (start, end, base) in [
            (RPU_ADDR_SBUS_START, RPU_ADDR_SBUS_END, HOST_SBUS_BASE),
            (RPU_ADDR_PBUS_START, RPU_ADDR_PBUS_END, HOST_PBUS_BASE),
            (RPU_ADDR_GRAM_START, RPU_ADDR_GRAM_END, HOST_GRAM_BASE),
            (RPU_ADDR_PKTRAM_START, RPU_ADDR_PKTRAM_END, HOST_PKTRAM_BASE),
        ] {
            assert_eq!(
                host_offset(Processor::Lmac, start),
                Ok(base + (start & RPU_ADDR_MASK_OFFSET))
            );
            assert_eq!(
                host_offset(Processor::Umac, end),
                Ok(base + (end & RPU_ADDR_MASK_OFFSET))
            );
        }

        for (processor, start, end, base) in [
            (
                Processor::Lmac,
                RPU_ADDR_LMAC_ROM_START,
                RPU_ADDR_LMAC_ROM_END,
                HOST_LMAC_DIRECT_BASE,
            ),
            (
                Processor::Lmac,
                RPU_ADDR_LMAC_RET_START,
                RPU_ADDR_LMAC_RET_END,
                HOST_LMAC_DIRECT_BASE,
            ),
            (
                Processor::Lmac,
                RPU_ADDR_LMAC_SCRATCH_START,
                RPU_ADDR_LMAC_SCRATCH_END,
                HOST_LMAC_DIRECT_BASE,
            ),
            (
                Processor::Umac,
                RPU_ADDR_UMAC_ROM_START,
                RPU_ADDR_UMAC_ROM_END,
                HOST_UMAC_DIRECT_BASE,
            ),
            (
                Processor::Umac,
                RPU_ADDR_UMAC_RET_START,
                RPU_ADDR_UMAC_RET_END,
                HOST_UMAC_DIRECT_BASE,
            ),
            (
                Processor::Umac,
                RPU_ADDR_UMAC_SCRATCH_START,
                RPU_ADDR_UMAC_SCRATCH_END,
                HOST_UMAC_DIRECT_BASE,
            ),
        ] {
            assert_eq!(
                host_offset(processor, start),
                Ok(base + (start & RPU_ADDR_MASK_OFFSET))
            );
            assert_eq!(
                host_offset(processor, end),
                Ok(base + (end & RPU_ADDR_MASK_OFFSET))
            );
        }
    }

    #[test]
    fn processor_local_ranges_do_not_alias() {
        assert!(host_offset(Processor::Lmac, 0x8010_0000).is_err());
        assert!(host_offset(Processor::Umac, 0x8007_0000).is_err());
        assert_eq!(
            host_offset(Processor::Lmac, 0),
            Err(AddressError::Unsupported(0))
        );
        assert_eq!(Processor::Lmac.control_register(), RPU_REG_MIPS_MCU_CONTROL);
        assert_eq!(
            Processor::Umac.control_register(),
            RPU_REG_MIPS_MCU2_CONTROL
        );
        assert_eq!(
            Processor::Lmac.wait_register(),
            RPU_REG_MIPS_MCU_WAIT_STATUS
        );
        assert_eq!(
            Processor::Umac.wait_register(),
            RPU_REG_MIPS_MCU2_WAIT_STATUS
        );
        assert_eq!(
            Processor::Lmac.indirect_control_register(),
            RPU_REG_MIPS_MCU_SYS_CORE_MEM_CTRL
        );
        assert_eq!(
            Processor::Umac.indirect_control_register(),
            RPU_REG_MIPS_MCU2_SYS_CORE_MEM_CTRL
        );
        assert_eq!(
            Processor::Lmac.indirect_data_register(),
            RPU_REG_MIPS_MCU_SYS_CORE_MEM_WDATA
        );
        assert_eq!(
            Processor::Umac.indirect_data_register(),
            RPU_REG_MIPS_MCU2_SYS_CORE_MEM_WDATA
        );
    }

    #[test]
    fn wake_and_firmware_ready_poll_exact_status_bits() {
        let bus = TestBus {
            status_1: [0, RPU_AWAKE, RPU_READY].into(),
            status_2: [0, RPU_WAKE_REQUEST].into(),
            ..TestBus::default()
        };
        let mut rpu = Rpu::new(bus);
        let mut delay = CountingDelay::default();
        assert!(block_on(rpu.wake(&mut delay, 3)).is_ok());
        assert_eq!(delay.0, 2);
        assert!(block_on(rpu.firmware_ready()).unwrap());
        assert_eq!(
            rpu.bus_mut().status_writes,
            [(OPCODE_WRITE_STATUS_2, RPU_WAKE_REQUEST)]
        );

        let mut rpu = Rpu::new(TestBus::default());
        let mut delay = CountingDelay::default();
        assert!(matches!(
            block_on(rpu.wake(&mut delay, 2)),
            Err(RpuError::Timeout)
        ));
        assert_eq!(delay.0, 2);

        let bus = TestBus {
            status_2: [RPU_WAKE_REQUEST].into(),
            ..TestBus::default()
        };
        let mut rpu = Rpu::new(bus);
        let mut delay = CountingDelay::default();
        assert!(matches!(
            block_on(rpu.wake(&mut delay, 2)),
            Err(RpuError::Timeout)
        ));
        assert_eq!(delay.0, 2);
    }

    #[test]
    fn reads_and_writes_chunked_words_and_zero_padded_tails() {
        let first: Vec<u8> = (0..MAX_BUS_CHUNK).map(|index| index as u8).collect();
        let second = vec![0x10, 0x20, 0x30, 0x40];
        let bus = TestBus {
            read_responses: [first.clone(), second.clone(), vec![0xaa, 0xbb, 0xcc, 0xdd]].into(),
            ..TestBus::default()
        };
        let mut rpu = Rpu::new(bus);
        let mut output = vec![0; MAX_BUS_CHUNK + 7];
        assert!(block_on(rpu.read(Processor::Lmac, RPU_ADDR_LMAC_RET_START, &mut output)).is_ok());
        assert_eq!(&output[..MAX_BUS_CHUNK], first);
        assert_eq!(&output[MAX_BUS_CHUNK..MAX_BUS_CHUNK + 4], second);
        assert_eq!(&output[MAX_BUS_CHUNK + 4..], &[0xaa, 0xbb, 0xcc]);
        let expected_base =
            HOST_LMAC_DIRECT_BASE + (RPU_ADDR_LMAC_RET_START & RPU_ADDR_MASK_OFFSET);
        assert_eq!(
            rpu.bus_mut().reads,
            [
                (expected_base, MAX_BUS_CHUNK),
                (expected_base + MAX_BUS_CHUNK as u32, 4),
                (expected_base + MAX_BUS_CHUNK as u32 + 4, 4)
            ]
        );

        let mut input = first;
        input.extend_from_slice(&[1, 2, 3, 4, 0x11, 0x22, 0x33]);
        assert!(block_on(rpu.write(Processor::Lmac, RPU_ADDR_LMAC_RET_START, &input)).is_ok());
        let bus = rpu.into_inner();
        assert_eq!(bus.writes.len(), 3);
        assert_eq!(
            bus.writes[0],
            (expected_base, input[..MAX_BUS_CHUNK].to_vec())
        );
        assert_eq!(
            bus.writes[1],
            (expected_base + MAX_BUS_CHUNK as u32, vec![1, 2, 3, 4])
        );
        assert_eq!(
            bus.writes[2],
            (
                expected_base + MAX_BUS_CHUNK as u32 + 4,
                vec![0x11, 0x22, 0x33, 0]
            )
        );
    }

    #[test]
    fn memory_access_rejects_alignment_and_region_crossings() {
        let mut rpu = Rpu::new(TestBus::default());
        assert!(matches!(
            block_on(rpu.read(Processor::Lmac, RPU_ADDR_LMAC_RET_START + 1, &mut [0; 4])),
            Err(RpuError::Unaligned)
        ));
        assert!(matches!(
            block_on(rpu.write(Processor::Lmac, RPU_ADDR_LMAC_RET_END - 3, &[0; 8])),
            Err(RpuError::Address(AddressError::Unsupported(_)))
        ));
        assert!(matches!(
            block_on(rpu.read(Processor::Lmac, 0, &mut [])),
            Err(RpuError::Address(AddressError::Unsupported(0)))
        ));
        assert!(block_on(rpu.read(Processor::Lmac, RPU_ADDR_LMAC_RET_START, &mut [])).is_ok());
        assert!(block_on(rpu.write(Processor::Lmac, RPU_ADDR_LMAC_RET_START, &[])).is_ok());
        assert_eq!(align4(0), Some(0));
        assert_eq!(align4(1), Some(4));
        assert_eq!(align4(4), Some(4));
        assert_eq!(align4(usize::MAX), None);
        assert!(matches!(
            checked_range::<()>(Processor::Lmac, RPU_ADDR_LMAC_RET_START, usize::MAX),
            Err(RpuError::Address(AddressError::Range))
        ));
        let discontinuous_start = RPU_ADDR_SBUS_END - 3;
        let discontinuous_len = (RPU_ADDR_PBUS_START - discontinuous_start + 1) as usize;
        assert!(matches!(
            checked_range::<()>(Processor::Lmac, discontinuous_start, discontinuous_len),
            Err(RpuError::Address(AddressError::Range))
        ));
    }

    #[test]
    fn word_register_and_indirect_accesses_are_exact() {
        let bus = TestBus {
            read_responses: [0x1234_5678u32.to_le_bytes().to_vec()].into(),
            ..TestBus::default()
        };
        let mut rpu = Rpu::new(bus);
        assert_eq!(
            block_on(rpu.read_u32(Processor::Lmac, RPU_ADDR_LMAC_RET_START)).unwrap(),
            0x1234_5678
        );
        assert!(
            block_on(rpu.write_u32(Processor::Lmac, RPU_ADDR_LMAC_RET_START, 0xaabb_ccdd)).is_ok()
        );
        assert!(block_on(rpu.enable_clocks()).is_ok());
        assert!(
            block_on(rpu.write_indirect(
                Processor::Lmac,
                RPU_MCU_CORE_INDIRECT_BASE | 4,
                &[1, 0, 0, 0, 2, 0, 0, 0],
            ))
            .is_ok()
        );
        let bus = rpu.into_inner();
        assert!(bus.writes.contains(&(
            HOST_LMAC_DIRECT_BASE + (RPU_ADDR_LMAC_RET_START & RPU_ADDR_MASK_OFFSET),
            0xaabb_ccddu32.to_le_bytes().to_vec()
        )));
        assert!(bus.writes.contains(&(
            HOST_PBUS_BASE + (RPU_REG_CLOCK_ENABLE & RPU_ADDR_MASK_OFFSET),
            RPU_CLOCK_ENABLE.to_le_bytes().to_vec()
        )));
        assert!(bus.writes.contains(&(
            HOST_SBUS_BASE + (RPU_REG_MIPS_MCU_SYS_CORE_MEM_CTRL & RPU_ADDR_MASK_OFFSET),
            1u32.to_le_bytes().to_vec()
        )));
        let data_port =
            HOST_SBUS_BASE + (RPU_REG_MIPS_MCU_SYS_CORE_MEM_WDATA & RPU_ADDR_MASK_OFFSET);
        assert!(
            bus.writes
                .contains(&(data_port, 1u32.to_le_bytes().to_vec()))
        );
        assert!(
            bus.writes
                .contains(&(data_port, 2u32.to_le_bytes().to_vec()))
        );

        for (address, data) in [
            (0x8000_0000, &[0u8; 4][..]),
            (RPU_MCU_CORE_INDIRECT_BASE | 1, &[0u8; 4][..]),
            (RPU_MCU_CORE_INDIRECT_BASE, &[0u8; 3][..]),
        ] {
            let mut rpu = Rpu::new(TestBus::default());
            assert!(matches!(
                block_on(rpu.write_indirect(Processor::Lmac, address, data)),
                Err(RpuError::Unaligned)
            ));
        }
    }

    #[test]
    fn processor_reset_and_register_poll_are_bounded() {
        let control = host_offset(Processor::Lmac, RPU_REG_MIPS_MCU_CONTROL).unwrap();
        let wait = host_offset(Processor::Lmac, RPU_REG_MIPS_MCU_WAIT_STATUS).unwrap();
        let bus = TestBus {
            register_values: vec![(control, 0), (wait, 1)],
            ..TestBus::default()
        };
        let mut rpu = Rpu::new(bus);
        let mut delay = CountingDelay::default();
        assert!(block_on(rpu.reset_processor(Processor::Lmac, &mut delay)).is_ok());
        assert_eq!(delay.0, 0);

        let mut rpu = Rpu::new(TestBus {
            register_values: vec![(control, 5)],
            ..TestBus::default()
        });
        let mut delay = CountingDelay::default();
        assert!(matches!(
            block_on(rpu.poll_register(RPU_REG_MIPS_MCU_CONTROL, 1, 0, &mut delay, 2, 7)),
            Err(RpuError::PollTimeout {
                address: RPU_REG_MIPS_MCU_CONTROL,
                mask: 1,
                expected: 0,
                last: 5,
            })
        ));
        assert_eq!(delay.0, 2);
    }
}
