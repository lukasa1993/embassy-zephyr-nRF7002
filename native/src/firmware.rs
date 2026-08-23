/// Firmware version recorded by the image provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FirmwareVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

/// One contiguous firmware region in RPU memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSegment<'a> {
    /// Destination address in the nRF7002 address space.
    pub address: u32,
    /// Bytes to transfer.
    pub data: &'a [u8],
    /// Optional IEEE CRC-32 of `data`.
    pub crc32: Option<u32>,
}

/// Complete firmware image supplied to the loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareImage<'a> {
    /// Firmware release version.
    pub version: FirmwareVersion,
    /// RPU entry point after all segments are loaded.
    pub entry_point: u32,
    /// Ordered, non-overlapping image segments.
    pub segments: &'a [FirmwareSegment<'a>],
}

/// Static firmware-image validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareError {
    /// The image has no segments.
    NoSegments,
    /// The entry point is not inside a supplied segment.
    EntryPointOutsideImage,
    /// A segment has no data.
    EmptySegment {
        /// Segment index.
        index: usize,
    },
    /// A segment length cannot fit in the 32-bit RPU address space.
    SegmentTooLarge {
        /// Segment index.
        index: usize,
    },
    /// The last byte of a segment is outside the 32-bit address space.
    AddressOverflow {
        /// Segment index.
        index: usize,
    },
    /// Two ordered segments overlap or are not in ascending order.
    Overlap {
        /// Earlier segment index.
        first: usize,
        /// Later segment index.
        second: usize,
    },
    /// A supplied segment checksum is wrong.
    CrcMismatch {
        /// Segment index.
        index: usize,
        /// Checksum declared by the image.
        expected: u32,
        /// Checksum calculated by the loader.
        actual: u32,
    },
}

impl FirmwareImage<'_> {
    /// Validate lengths, addresses, ordering, entry point, and checksums.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError`] when the image is unsafe to transfer.
    pub fn validate(&self) -> Result<(), FirmwareError> {
        if self.segments.is_empty() {
            return Err(FirmwareError::NoSegments);
        }

        let mut previous_end = None;
        let mut entry_point_is_mapped = false;

        for (index, segment) in self.segments.iter().enumerate() {
            if segment.data.is_empty() {
                return Err(FirmwareError::EmptySegment { index });
            }

            let length = u32::try_from(segment.data.len())
                .map_err(|_| FirmwareError::SegmentTooLarge { index })?;
            let end = segment
                .address
                .checked_add(length)
                .ok_or(FirmwareError::AddressOverflow { index })?;

            if let Some(previous) = previous_end {
                if segment.address < previous {
                    return Err(FirmwareError::Overlap {
                        first: index - 1,
                        second: index,
                    });
                }
            }
            previous_end = Some(end);

            if self.entry_point >= segment.address && self.entry_point < end {
                entry_point_is_mapped = true;
            }

            if let Some(expected) = segment.crc32 {
                let actual = crc32(segment.data);
                if actual != expected {
                    return Err(FirmwareError::CrcMismatch {
                        index,
                        expected,
                        actual,
                    });
                }
            }
        }

        if !entry_point_is_mapped {
            return Err(FirmwareError::EntryPointOutsideImage);
        }

        Ok(())
    }
}

/// Calculate an IEEE CRC-32 without a lookup table or allocation.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::{FirmwareError, FirmwareImage, FirmwareSegment, FirmwareVersion, crc32};

    #[test]
    fn crc_matches_standard_test_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn valid_image_is_accepted() {
        let first = [1, 2, 3, 4];
        let second = [5, 6];
        let segments = [
            FirmwareSegment {
                address: 0x1000,
                data: &first,
                crc32: Some(crc32(&first)),
            },
            FirmwareSegment {
                address: 0x2000,
                data: &second,
                crc32: None,
            },
        ];
        let image = FirmwareImage {
            version: FirmwareVersion::default(),
            entry_point: 0x1000,
            segments: &segments,
        };
        assert_eq!(image.validate(), Ok(()));
    }

    #[test]
    fn overlap_is_rejected() {
        let bytes = [0; 8];
        let segments = [
            FirmwareSegment {
                address: 0x1000,
                data: &bytes,
                crc32: None,
            },
            FirmwareSegment {
                address: 0x1004,
                data: &bytes,
                crc32: None,
            },
        ];
        let image = FirmwareImage {
            version: FirmwareVersion::default(),
            entry_point: 0x1000,
            segments: &segments,
        };
        assert_eq!(
            image.validate(),
            Err(FirmwareError::Overlap {
                first: 0,
                second: 1
            })
        );
    }

    #[test]
    fn entry_point_must_be_loaded() {
        let bytes = [0; 4];
        let segments = [FirmwareSegment {
            address: 0x1000,
            data: &bytes,
            crc32: None,
        }];
        let image = FirmwareImage {
            version: FirmwareVersion::default(),
            entry_point: 0x2000,
            segments: &segments,
        };
        assert_eq!(
            image.validate(),
            Err(FirmwareError::EntryPointOutsideImage)
        );
    }
}
