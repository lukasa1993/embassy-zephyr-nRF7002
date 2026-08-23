//! nRF7002 RPU address translation, power control, and memory access.

use embedded_hal_async::delay::DelayNs;

use super::bus::{Bus, OPCODE_READ_STATUS_1, OPCODE_READ_STATUS_2, OPCODE_WRITE_STATUS_2};
use super::bus::{RPU_AWAKE, RPU_READY, RPU_WAKE_REQUEST};

/// Largest transfer emitted by the memory layer.
pub const MAX_BUS_CHUNK: usize = 4096;

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

pub const HOST_SBUS_BASE: u32 = 0x0000_00;
pub const HOST_PBUS_BASE: u32 = 0x0400_00;
pub const HOST_GRAM_BASE: u32 = 0x0800_00;
pub const HOST_PKTRAM_BASE: u32 = 0x0c00_00;
pub const HOST_LMAC_DIRECT_BASE: u32 = 0x1000_00;
pub const HOST_UMAC_DIRECT_BASE: u32 = 0x2000_00;
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
    if address >= RPU_ADDR_SBUS_START && address <= RPU_ADDR_SBUS_END {
        return Ok(HOST_SBUS_BASE + low);
    }
    if address >= RPU_ADDR_PBUS_START && address <= RPU_ADDR_PBUS_END {
        return Ok(HOST_PBUS_BASE + low);
    }
    if address >= RPU_ADDR_GRAM_START && address <= RPU_ADDR_GRAM_END {
        return Ok(HOST_GRAM_BASE + low);
    }
    if address >= RPU_ADDR_PKTRAM_START && address <= RPU_ADDR_PKTRAM_END {
        return Ok(HOST_PKTRAM_BASE + low);
    }

    let direct = match processor {
        Processor::Lmac
            if (address >= RPU_ADDR_LMAC_ROM_START && address <= RPU_ADDR_LMAC_ROM_END)
                || (address >= RPU_ADDR_LMAC_RET_START && address <= RPU_ADDR_LMAC_RET_END)
                || (address >= RPU_ADDR_LMAC_SCRATCH_START
                    && address <= RPU_ADDR_LMAC_SCRATCH_END) =>
        {
            Some(HOST_LMAC_DIRECT_BASE)
        }
        Processor::Umac
            if (address >= RPU_ADDR_UMAC_ROM_START && address <= RPU_ADDR_UMAC_ROM_END)
                || (address >= RPU_ADDR_UMAC_RET_START && address <= RPU_ADDR_UMAC_RET_END)
                || (address >= RPU_ADDR_UMAC_SCRATCH_START
                    && address <= RPU_ADDR_UMAC_SCRATCH_END) =>
        {
            Some(HOST_UMAC_DIRECT_BASE)
        }
        _ => None,
    };

    match direct {
        Some(base) => Ok(base + low),
        None => Err(AddressError::Unsupported(address)),
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

        let mut wake_accepted = false;
        for _ in 0..attempts {
            let accepted = self
                .bus
                .read_status(OPCODE_READ_STATUS_2)
                .await
                .map_err(RpuError::Bus)?;
            if accepted & RPU_WAKE_REQUEST != 0 {
                wake_accepted = true;
                break;
            }
            delay.delay_ms(1).await;
        }
        if !wake_accepted {
            return Err(RpuError::Timeout);
        }

        for _ in 0..attempts {
            let state = self
                .bus
                .read_status(OPCODE_READ_STATUS_1)
                .await
                .map_err(RpuError::Bus)?;
            if state & RPU_AWAKE != 0 {
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
        if address & 3 != 0 {
            return Err(RpuError::Unaligned);
        }
        let padded_len = align4(data.len()).ok_or(RpuError::InvalidArgument)?;
        checked_range(processor, address, padded_len)?;

        let aligned_len = data.len() & !3;
        let mut done = 0usize;
        while done < aligned_len {
            let count = core::cmp::min(MAX_BUS_CHUNK, aligned_len - done);
            let offset = host_offset(processor, address + done as u32)?;
            self.bus
                .read(offset, &mut data[done..done + count])
                .await
                .map_err(RpuError::Bus)?;
            done += count;
        }

        let tail_len = data.len() - aligned_len;
        if tail_len != 0 {
            let mut tail = [0u8; 4];
            let offset = host_offset(processor, address + aligned_len as u32)?;
            self.bus
                .read(offset, &mut tail)
                .await
                .map_err(RpuError::Bus)?;
            data[aligned_len..].copy_from_slice(&tail[..tail_len]);
        }
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
        if address & 3 != 0 {
            return Err(RpuError::Unaligned);
        }
        let padded_len = align4(data.len()).ok_or(RpuError::InvalidArgument)?;
        checked_range(processor, address, padded_len)?;

        let aligned_len = data.len() & !3;
        let mut done = 0usize;
        while done < aligned_len {
            let count = core::cmp::min(MAX_BUS_CHUNK, aligned_len - done);
            let offset = host_offset(processor, address + done as u32)?;
            self.bus
                .write(offset, &data[done..done + count])
                .await
                .map_err(RpuError::Bus)?;
            done += count;
        }

        let tail_len = data.len() - aligned_len;
        if tail_len != 0 {
            let mut tail = [0u8; 4];
            tail[..tail_len].copy_from_slice(&data[aligned_len..]);
            let offset = host_offset(processor, address + aligned_len as u32)?;
            self.bus.write(offset, &tail).await.map_err(RpuError::Bus)?;
        }
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
        if encoded_address & 0xff00_0000 != RPU_MCU_CORE_INDIRECT_BASE
            || encoded_address & 3 != 0
            || data.len() & 3 != 0
        {
            return Err(RpuError::Unaligned);
        }
        let word_address = (encoded_address & RPU_ADDR_MASK_OFFSET) >> 2;
        self.write_register(processor.indirect_control_register(), word_address)
            .await?;
        for word in data.chunks_exact(4) {
            let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            self.write_register(processor.indirect_data_register(), value)
                .await?;
        }
        Ok(())
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
        for _ in 0..attempts {
            if self.read_register(address).await? & mask == expected {
                return Ok(());
            }
            delay.delay_ms(delay_ms).await;
        }
        Err(RpuError::Timeout)
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
    let span = u32::try_from(len - 1).map_err(|_| RpuError::Address(AddressError::Range))?;
    let end = address
        .checked_add(span)
        .ok_or(RpuError::Address(AddressError::Range))?;
    let first = host_offset(processor, address)?;
    let last = host_offset(processor, end)?;
    if last.checked_sub(first) != Some(span) {
        return Err(RpuError::Address(AddressError::Range));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_public_regions() {
        assert_eq!(host_offset(Processor::Lmac, 0xa400_1234), Ok(0x001234));
        assert_eq!(host_offset(Processor::Lmac, 0xa500_1234), Ok(0x041234));
        assert_eq!(host_offset(Processor::Lmac, 0xb700_1234), Ok(0x081234));
        assert_eq!(host_offset(Processor::Lmac, 0xb000_5000), Ok(0x0c5000));
        assert_eq!(host_offset(Processor::Lmac, 0x8004_3a80), Ok(0x143a80));
        assert_eq!(host_offset(Processor::Umac, 0x8008_c000), Ok(0x28c000));
    }

    #[test]
    fn processor_local_ranges_do_not_alias() {
        assert!(host_offset(Processor::Lmac, 0x8010_0000).is_err());
        assert!(host_offset(Processor::Umac, 0x8007_0000).is_err());
    }
}
