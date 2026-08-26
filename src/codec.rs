//! Shared bounded little-endian codec primitives.

use crate::protocol::ProtocolError;

pub(crate) struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.position
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.bytes(&[value])
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn i32(&mut self, value: i32) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(ProtocolError::BufferTooSmall)?;
        let target = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProtocolError::BufferTooSmall)?;
        target.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    pub(crate) fn zeros(&mut self, count: usize) -> Result<(), ProtocolError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ProtocolError::BufferTooSmall)?;
        let target = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProtocolError::BufferTooSmall)?;
        target.fill(0);
        self.position = end;
        Ok(())
    }

    pub(crate) fn fixed(&mut self, value: &[u8], width: usize) -> Result<(), ProtocolError> {
        if value.len() > width {
            return Err(ProtocolError::LimitExceeded);
        }
        self.bytes(value)?;
        self.zeros(width - value.len())
    }

    pub(crate) fn fixed_u32(&mut self, value: &[u32], count: usize) -> Result<(), ProtocolError> {
        if value.len() > count {
            return Err(ProtocolError::LimitExceeded);
        }
        for item in value {
            self.u32(*item)?;
        }
        self.zeros((count - value.len()) * 4)
    }
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(crate) fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_u32_writes_exact_values_and_zero_padding() {
        let mut bytes = [0xaa; 16];
        let mut writer = Writer::new(&mut bytes);
        writer.fixed_u32(&[0x0102_0304], 3).unwrap();
        assert_eq!(writer.len(), 12);
        assert_eq!(&bytes[..4], &[4, 3, 2, 1]);
        assert_eq!(&bytes[4..12], &[0; 8]);
        assert_eq!(&bytes[12..], &[0xaa; 4]);
    }

    #[test]
    fn integer_readers_honor_nonzero_offsets_and_little_endian_order() {
        let bytes = [0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 0xbb];
        assert_eq!(read_u16(&bytes, 1), 0x0201);
        assert_eq!(read_u32(&bytes, 1), 0x0403_0201);
        assert_eq!(read_i32(&bytes, 1), 0x0403_0201);
        assert_eq!(read_u64(&bytes, 1), 0x0807_0605_0403_0201);
    }
}
