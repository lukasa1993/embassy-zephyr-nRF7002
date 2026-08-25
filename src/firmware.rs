//! Parser and loader for Nordic's combined nRF70 firmware patch bundle.

use embedded_hal_async::delay::DelayNs;
use sha2::{Digest, Sha256};

use super::bus::Bus;
use super::memory::{Processor, Rpu, RpuError};

/// Signature at the start of `nrf70.bin`.
pub const PATCH_SIGNATURE: u32 = 0xdead_1eaf;
/// Number of images in the combined system-mode bundle.
pub const PATCH_IMAGE_COUNT: u32 = 4;
/// Version required by the NCS v3.4.0 host interface: 1.2.14.9.
pub const PINNED_PATCH_VERSION: u32 = 0x0102_0e09;
/// System-mode feature bit.
pub const FEATURE_SYSTEM_MODE: u32 = 1 << 0;
/// System-mode with raw-frame support feature bit.
pub const FEATURE_SYSTEM_WITH_RAW: u32 = 1 << 3;
/// Header bytes before the hashed image payload.
pub const PATCH_HEADER_LEN: usize = 52;
/// Per-image header bytes.
pub const IMAGE_HEADER_LEN: usize = 8;
/// Fixed memory used for firmware download readback.
pub const FIRMWARE_READBACK_CHUNK: usize = 256;
/// Bounded read attempts for each firmware verification chunk.
pub const FIRMWARE_READBACK_ATTEMPTS: usize = 3;

pub const RPU_MEM_LMAC_PATCH_BIN: u32 = 0x8004_3a80;
pub const RPU_MEM_LMAC_PATCH_BIMG: u32 = 0x8004_bbc0;
pub const RPU_MEM_UMAC_PATCH_BIN: u32 = 0x8008_c000;
pub const RPU_MEM_UMAC_PATCH_BIMG: u32 = 0x8009_b800;
pub const RPU_MEM_LMAC_BOOT_SIG: u32 = 0xb700_0d50;
pub const RPU_MEM_UMAC_BOOT_SIG: u32 = 0xb000_0000;
pub const BOOT_SIGNATURE: u32 = 0x5a5a_5a5a;

pub const RPU_REG_UCC_SLEEP_CTRL_DATA_0: u32 = 0xa400_2c2c;
pub const RPU_REG_UCC_SLEEP_CTRL_DATA_1: u32 = 0xa400_2c30;
pub const RPU_REG_MIPS_MCU_CONTROL: u32 = 0xa400_0000;
pub const RPU_REG_MIPS_MCU2_CONTROL: u32 = 0xa400_0100;

const LMAC_BOOT_VECTOR_REGISTERS: [u32; 4] = [0xa400_0050, 0xa400_0054, 0xa400_0058, 0xa400_005c];
const UMAC_BOOT_VECTOR_REGISTERS: [u32; 4] = [0xa400_0150, 0xa400_0154, 0xa400_0158, 0xa400_015c];
const BOOT_VECTOR_VALUES: [u32; 4] = [0x3c1a_8000, 0x275a_0000, 0x0340_0008, 0];

/// External policy that authorizes one complete firmware file.
///
/// The policy is separate from the digest stored inside the bundle. Thus, an
/// attacker cannot replace both the firmware bytes and the bundle-owned digest
/// and still pass authorization.
pub trait FirmwareTrustPolicy {
    /// Authorizes the exact complete file supplied to the parser.
    fn verify(&self, bundle: &FirmwareBundle<'_>) -> Result<(), FirmwareError>;
}

/// Trust policy for one externally pinned complete-file SHA-256 value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedFirmwareSha256 {
    expected: [u8; 32],
}

impl PinnedFirmwareSha256 {
    /// Creates a policy from a digest stored outside `nrf70.bin`.
    pub const fn new(expected: [u8; 32]) -> Self {
        Self { expected }
    }

    /// Returns the configured complete-file digest.
    pub const fn expected(&self) -> [u8; 32] {
        self.expected
    }
}

impl FirmwareTrustPolicy for PinnedFirmwareSha256 {
    fn verify(&self, bundle: &FirmwareBundle<'_>) -> Result<(), FirmwareError> {
        let actual = bundle.full_sha256();
        let mut difference = 0u8;
        for (actual_byte, expected_byte) in actual.iter().zip(self.expected.iter()) {
            difference |= *actual_byte ^ *expected_byte;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(FirmwareError::UntrustedImage)
        }
    }
}

/// Structural or compatibility failure in a firmware bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareError {
    /// The slice is shorter than the fixed bundle header.
    TruncatedHeader,
    /// The header signature is not Nordic's nRF70 signature.
    BadSignature(u32),
    /// The bundle does not contain exactly four images.
    BadImageCount(u32),
    /// The firmware host-interface version does not match NCS v3.4.0.
    IncompatibleVersion(u32),
    /// The bundle is not the exact system-mode image supported by this driver.
    IncompatibleFeatures(u32),
    /// The declared payload length does not fit the supplied slice.
    TruncatedPayload,
    /// An image header or image body is truncated.
    TruncatedImage,
    /// An image type is invalid or repeated.
    InvalidImageType(u32),
    /// Bytes remain or are missing after parsing all declared images.
    LengthMismatch,
    /// SHA-256 integrity verification failed.
    HashMismatch,
    /// The complete file did not match the external trust policy.
    UntrustedImage,
}

/// Failure while downloading or starting firmware.
#[derive(Debug)]
pub enum LoadError<E> {
    /// The bundle is invalid or incompatible.
    Firmware(FirmwareError),
    /// The RPU bus or memory operation failed at a defined load stage.
    Rpu {
        stage: LoadStage,
        error: RpuError<E>,
    },
    /// A required image was not present.
    MissingImage(ImageKind),
    /// Download readback did not match the trusted image bytes.
    ReadbackMismatch {
        kind: ImageKind,
        offset: usize,
        expected: [u8; 4],
        actual: [u8; 4],
    },
}

/// Firmware operation active when an RPU access failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadStage {
    Reset(Processor),
    Download(ImageKind),
    Verify(ImageKind),
    Boot(Processor),
}

impl<E> From<FirmwareError> for LoadError<E> {
    fn from(value: FirmwareError) -> Self {
        Self::Firmware(value)
    }
}

/// One image in the combined bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ImageKind {
    /// UMAC boot image, loaded at `RPU_MEM_UMAC_PATCH_BIMG`.
    UmacPrimary = 0,
    /// UMAC binary image, loaded at `RPU_MEM_UMAC_PATCH_BIN`.
    UmacSecondary = 1,
    /// LMAC boot image, loaded at `RPU_MEM_LMAC_PATCH_BIMG`.
    LmacPrimary = 2,
    /// LMAC binary image, loaded at `RPU_MEM_LMAC_PATCH_BIN`.
    LmacSecondary = 3,
}

impl ImageKind {
    const fn from_u32(value: u32) -> Result<Self, FirmwareError> {
        match value {
            0 => Ok(Self::UmacPrimary),
            1 => Ok(Self::UmacSecondary),
            2 => Ok(Self::LmacPrimary),
            3 => Ok(Self::LmacSecondary),
            other => Err(FirmwareError::InvalidImageType(other)),
        }
    }

    const fn destination(self) -> (Processor, u32) {
        match self {
            Self::UmacPrimary => (Processor::Umac, RPU_MEM_UMAC_PATCH_BIMG),
            Self::UmacSecondary => (Processor::Umac, RPU_MEM_UMAC_PATCH_BIN),
            Self::LmacPrimary => (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIMG),
            Self::LmacSecondary => (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIN),
        }
    }
}

/// Fixed bundle metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareHeader {
    /// Packed firmware interface version.
    pub version: u32,
    /// Feature bitmap.
    pub feature_flags: u32,
    /// Hashed payload length after the fixed header.
    pub payload_len: u32,
    /// Expected SHA-256 digest of the image payload.
    pub hash: [u8; 32],
}

/// Borrowed view of one firmware image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareImage<'a> {
    /// Image role.
    pub kind: ImageKind,
    /// Image bytes.
    pub data: &'a [u8],
}

/// Validated, allocation-free view of `nrf70.bin`.
pub struct FirmwareBundle<'a> {
    bytes: &'a [u8],
    header: FirmwareHeader,
    payload_end: usize,
}

impl<'a> FirmwareBundle<'a> {
    /// Parses the structure and checks the exact pinned system-mode interface.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FirmwareError> {
        if bytes.len() < PATCH_HEADER_LEN {
            return Err(FirmwareError::TruncatedHeader);
        }
        let signature = word(bytes, 0);
        if signature != PATCH_SIGNATURE {
            return Err(FirmwareError::BadSignature(signature));
        }
        let image_count = word(bytes, 4);
        if image_count != PATCH_IMAGE_COUNT {
            return Err(FirmwareError::BadImageCount(image_count));
        }
        let version = word(bytes, 8);
        if version != PINNED_PATCH_VERSION {
            return Err(FirmwareError::IncompatibleVersion(version));
        }
        let feature_flags = word(bytes, 12);
        if feature_flags != FEATURE_SYSTEM_MODE {
            return Err(FirmwareError::IncompatibleFeatures(feature_flags));
        }
        let payload_len = word(bytes, 16);
        let payload_end = PATCH_HEADER_LEN
            .checked_add(payload_len as usize)
            .ok_or(FirmwareError::TruncatedPayload)?;
        if payload_end > bytes.len() {
            return Err(FirmwareError::TruncatedPayload);
        }
        if payload_end != bytes.len() {
            return Err(FirmwareError::LengthMismatch);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[20..PATCH_HEADER_LEN]);
        let bundle = Self {
            bytes,
            header: FirmwareHeader {
                version,
                feature_flags,
                payload_len,
                hash,
            },
            payload_end,
        };
        bundle.validate_images()?;
        Ok(bundle)
    }

    /// Returns fixed metadata.
    pub const fn header(&self) -> FirmwareHeader {
        self.header
    }

    /// Returns the exact complete file supplied to the parser.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Computes SHA-256 over the exact complete file.
    pub fn full_sha256(&self) -> [u8; 32] {
        let digest = Sha256::digest(self.bytes);
        let mut output = [0u8; 32];
        output.copy_from_slice(&digest);
        output
    }

    /// Verifies the SHA-256 digest stored in the bundle.
    pub fn verify_hash(&self) -> Result<(), FirmwareError> {
        let digest = Sha256::digest(&self.bytes[PATCH_HEADER_LEN..self.payload_end]);
        if digest[..] == self.header.hash[..] {
            Ok(())
        } else {
            Err(FirmwareError::HashMismatch)
        }
    }

    /// Returns one image by role.
    pub fn image(&self, wanted: ImageKind) -> Result<FirmwareImage<'a>, FirmwareError> {
        let mut offset = PATCH_HEADER_LEN;
        for _ in 0..PATCH_IMAGE_COUNT {
            let kind = ImageKind::from_u32(word(self.bytes, offset))?;
            let len = word(self.bytes, offset + 4) as usize;
            let start = offset + IMAGE_HEADER_LEN;
            let end = start
                .checked_add(len)
                .ok_or(FirmwareError::TruncatedImage)?;
            if end > self.payload_end {
                return Err(FirmwareError::TruncatedImage);
            }
            if kind == wanted {
                return Ok(FirmwareImage {
                    kind,
                    data: &self.bytes[start..end],
                });
            }
            offset = end;
        }
        Err(FirmwareError::InvalidImageType(wanted as u32))
    }

    fn validate_images(&self) -> Result<(), FirmwareError> {
        let mut offset = PATCH_HEADER_LEN;
        let mut seen = 0u8;
        for _ in 0..PATCH_IMAGE_COUNT {
            if offset + IMAGE_HEADER_LEN > self.payload_end {
                return Err(FirmwareError::TruncatedImage);
            }
            let kind = ImageKind::from_u32(word(self.bytes, offset))?;
            let mask = 1u8 << kind as u8;
            if seen & mask != 0 {
                return Err(FirmwareError::InvalidImageType(kind as u32));
            }
            seen |= mask;
            let len = word(self.bytes, offset + 4) as usize;
            offset = offset
                .checked_add(IMAGE_HEADER_LEN)
                .and_then(|value| value.checked_add(len))
                .ok_or(FirmwareError::TruncatedImage)?;
            if offset > self.payload_end {
                return Err(FirmwareError::TruncatedImage);
            }
        }
        if seen != 0b1111 || offset != self.payload_end {
            return Err(FirmwareError::LengthMismatch);
        }
        Ok(())
    }
}

/// Successful firmware start report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareReport {
    /// Bundle version loaded into the RPU.
    pub version: u32,
    /// Feature flags accepted by the loader.
    pub feature_flags: u32,
}

/// Resets both processors, downloads and verifies all images, boots LMAC then UMAC, and checks signatures.
pub async fn load<B, D, T>(
    rpu: &mut Rpu<B>,
    delay: &mut D,
    bundle: &FirmwareBundle<'_>,
    trust: &T,
) -> Result<FirmwareReport, LoadError<B::Error>>
where
    B: Bus,
    D: DelayNs,
    T: FirmwareTrustPolicy + ?Sized,
{
    trust.verify(bundle)?;
    bundle.verify_hash()?;
    rpu.reset_processor(Processor::Lmac, delay)
        .await
        .map_err(|error| LoadError::Rpu {
            stage: LoadStage::Reset(Processor::Lmac),
            error,
        })?;
    rpu.reset_processor(Processor::Umac, delay)
        .await
        .map_err(|error| LoadError::Rpu {
            stage: LoadStage::Reset(Processor::Umac),
            error,
        })?;

    // Nordic downloads UMAC first and LMAC second.
    for kind in [
        ImageKind::UmacPrimary,
        ImageKind::UmacSecondary,
        ImageKind::LmacPrimary,
        ImageKind::LmacSecondary,
    ] {
        let image = bundle.image(kind).map_err(LoadError::Firmware)?;
        let (processor, destination) = kind.destination();
        rpu.write(processor, destination, image.data)
            .await
            .map_err(|error| LoadError::Rpu {
                stage: LoadStage::Download(kind),
                error,
            })?;
        // The RPU direct-memory bridge can return a stale first word when a
        // high-latency read follows the final write immediately.
        delay.delay_ms(1).await;
        verify_download(rpu, delay, processor, destination, image).await?;
    }

    boot_processor(rpu, delay, Processor::Lmac)
        .await
        .map_err(|error| LoadError::Rpu {
            stage: LoadStage::Boot(Processor::Lmac),
            error,
        })?;
    boot_processor(rpu, delay, Processor::Umac)
        .await
        .map_err(|error| LoadError::Rpu {
            stage: LoadStage::Boot(Processor::Umac),
            error,
        })?;

    let header = bundle.header();
    Ok(FirmwareReport {
        version: header.version,
        feature_flags: header.feature_flags,
    })
}

async fn verify_download<B, D>(
    rpu: &mut Rpu<B>,
    delay: &mut D,
    processor: Processor,
    destination: u32,
    image: FirmwareImage<'_>,
) -> Result<(), LoadError<B::Error>>
where
    B: Bus,
    D: DelayNs,
{
    let mut readback = [0u8; FIRMWARE_READBACK_CHUNK];
    let mut offset = 0usize;
    while offset < image.data.len() {
        let count = core::cmp::min(FIRMWARE_READBACK_CHUNK, image.data.len() - offset);
        let stage = LoadStage::Verify(image.kind);
        let offset_u32 = u32::try_from(offset).map_err(|_| LoadError::Rpu {
            stage,
            error: RpuError::InvalidArgument,
        })?;
        let address = destination.checked_add(offset_u32).ok_or(LoadError::Rpu {
            stage,
            error: RpuError::InvalidArgument,
        })?;
        let mut matched = false;
        for attempt in 0..FIRMWARE_READBACK_ATTEMPTS {
            rpu.read(processor, address, &mut readback[..count])
                .await
                .map_err(|error| LoadError::Rpu { stage, error })?;
            if readback[..count] == image.data[offset..offset + count] {
                matched = true;
                break;
            }
            if attempt + 1 < FIRMWARE_READBACK_ATTEMPTS {
                delay.delay_ms(1).await;
            }
        }
        if !matched {
            let mismatch = readback[..count]
                .iter()
                .zip(&image.data[offset..offset + count])
                .position(|(actual, expected)| actual != expected)
                .unwrap_or(0);
            let mut expected = [0u8; 4];
            let mut actual = [0u8; 4];
            let diagnostic_len = core::cmp::min(4, count - mismatch);
            expected[..diagnostic_len].copy_from_slice(
                &image.data[offset + mismatch..offset + mismatch + diagnostic_len],
            );
            actual[..diagnostic_len]
                .copy_from_slice(&readback[mismatch..mismatch + diagnostic_len]);
            readback[..count].fill(0);
            return Err(LoadError::ReadbackMismatch {
                kind: image.kind,
                offset: offset + mismatch,
                expected,
                actual,
            });
        }
        readback[..count].fill(0);
        offset += count;
    }
    Ok(())
}

async fn boot_processor<B, D>(
    rpu: &mut Rpu<B>,
    delay: &mut D,
    processor: Processor,
) -> Result<(), RpuError<B::Error>>
where
    B: Bus,
    D: DelayNs,
{
    let (signature_address, sleep_control, patch_offset, run_register, vectors) = match processor {
        Processor::Lmac => (
            RPU_MEM_LMAC_BOOT_SIG,
            RPU_REG_UCC_SLEEP_CTRL_DATA_0,
            RPU_MEM_LMAC_PATCH_BIMG - 0x8004_0000,
            RPU_REG_MIPS_MCU_CONTROL,
            LMAC_BOOT_VECTOR_REGISTERS,
        ),
        Processor::Umac => (
            RPU_MEM_UMAC_BOOT_SIG,
            RPU_REG_UCC_SLEEP_CTRL_DATA_1,
            RPU_MEM_UMAC_PATCH_BIMG - 0x8008_0000,
            RPU_REG_MIPS_MCU2_CONTROL,
            UMAC_BOOT_VECTOR_REGISTERS,
        ),
    };

    rpu.write_u32(processor, signature_address, 0).await?;
    rpu.write_register(sleep_control, patch_offset).await?;
    for (address, value) in vectors.into_iter().zip(BOOT_VECTOR_VALUES) {
        rpu.write_register(address, value).await?;
    }
    rpu.write_register(run_register, 1).await?;

    for _ in 0..100 {
        if rpu.read_u32(processor, signature_address).await? == BOOT_SIGNATURE {
            return Ok(());
        }
        delay.delay_ms(10).await;
    }
    Err(RpuError::Timeout)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_bytes() -> [u8; PATCH_HEADER_LEN + 4 * IMAGE_HEADER_LEN + 4] {
        let mut bytes = [0u8; PATCH_HEADER_LEN + 4 * IMAGE_HEADER_LEN + 4];
        bytes[0..4].copy_from_slice(&PATCH_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&PATCH_IMAGE_COUNT.to_le_bytes());
        bytes[8..12].copy_from_slice(&PINNED_PATCH_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&FEATURE_SYSTEM_MODE.to_le_bytes());
        let payload_len = (bytes.len() - PATCH_HEADER_LEN) as u32;
        bytes[16..20].copy_from_slice(&payload_len.to_le_bytes());
        let mut offset = PATCH_HEADER_LEN;
        for kind in 0u32..4 {
            bytes[offset..offset + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&1u32.to_le_bytes());
            bytes[offset + 8] = kind as u8;
            offset += 9;
        }
        let digest = Sha256::digest(&bytes[PATCH_HEADER_LEN..]);
        bytes[20..PATCH_HEADER_LEN].copy_from_slice(&digest);
        bytes
    }

    #[test]
    fn parses_and_verifies_all_images() {
        let bytes = bundle_bytes();
        let bundle = FirmwareBundle::parse(&bytes).unwrap();
        bundle.verify_hash().unwrap();
        assert_eq!(bundle.image(ImageKind::UmacPrimary).unwrap().data, &[0]);
        assert_eq!(bundle.image(ImageKind::LmacSecondary).unwrap().data, &[3]);
    }

    #[test]
    fn detects_modified_payload() {
        let mut bytes = bundle_bytes();
        bytes[PATCH_HEADER_LEN + IMAGE_HEADER_LEN] ^= 0x80;
        let bundle = FirmwareBundle::parse(&bytes).unwrap();
        assert_eq!(bundle.verify_hash(), Err(FirmwareError::HashMismatch));
    }

    #[test]
    fn externally_pinned_digest_accepts_exact_file() {
        let bytes = bundle_bytes();
        let bundle = FirmwareBundle::parse(&bytes).unwrap();
        let policy = PinnedFirmwareSha256::new(bundle.full_sha256());
        assert_eq!(policy.verify(&bundle), Ok(()));
    }

    #[test]
    fn rejects_a_raw_mode_bundle() {
        let mut bytes = bundle_bytes();
        bytes[12..16].copy_from_slice(&FEATURE_SYSTEM_WITH_RAW.to_le_bytes());
        assert!(matches!(
            FirmwareBundle::parse(&bytes),
            Err(FirmwareError::IncompatibleFeatures(FEATURE_SYSTEM_WITH_RAW))
        ));
    }

    #[test]
    fn rejects_bytes_after_the_declared_payload() {
        let original = bundle_bytes();
        let mut bytes = [0u8; PATCH_HEADER_LEN + 4 * IMAGE_HEADER_LEN + 5];
        bytes[..original.len()].copy_from_slice(&original);
        assert!(matches!(
            FirmwareBundle::parse(&bytes),
            Err(FirmwareError::LengthMismatch)
        ));
    }

    #[test]
    fn external_digest_covers_header_not_only_payload() {
        let original = bundle_bytes();
        let original_bundle = FirmwareBundle::parse(&original).unwrap();
        let policy = PinnedFirmwareSha256::new(original_bundle.full_sha256());

        let mut substituted = original;
        substituted[12..16].copy_from_slice(&FEATURE_SYSTEM_WITH_RAW.to_le_bytes());
        assert!(matches!(
            FirmwareBundle::parse(&substituted),
            Err(FirmwareError::IncompatibleFeatures(FEATURE_SYSTEM_WITH_RAW))
        ));
        assert_eq!(policy.verify(&original_bundle), Ok(()));
    }
}
