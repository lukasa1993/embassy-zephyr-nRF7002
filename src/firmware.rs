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
}

/// Firmware operation active when an RPU access failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadStage {
    Reset(Processor),
    Download(ImageKind),
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
        let header = parse_compatible_header(bytes)?;
        let payload_end = exact_payload_end(bytes, header.payload_len)?;
        let bundle = Self {
            bytes,
            header,
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
            let (kind, start, end) = self.image_extent(offset)?;
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

    fn image_extent(&self, offset: usize) -> Result<(ImageKind, usize, usize), FirmwareError> {
        let header_end = offset
            .checked_add(IMAGE_HEADER_LEN)
            .ok_or(FirmwareError::TruncatedImage)?;
        if header_end > self.payload_end {
            return Err(FirmwareError::TruncatedImage);
        }
        let kind = ImageKind::from_u32(word(self.bytes, offset))?;
        let len = word(self.bytes, offset + 4) as usize;
        let end = header_end
            .checked_add(len)
            .ok_or(FirmwareError::TruncatedImage)?;
        if end > self.payload_end {
            return Err(FirmwareError::TruncatedImage);
        }
        Ok((kind, header_end, end))
    }

    fn validate_images(&self) -> Result<(), FirmwareError> {
        let mut offset = PATCH_HEADER_LEN;
        let mut seen = 0u8;
        for _ in 0..PATCH_IMAGE_COUNT {
            let (kind, _, end) = self.image_extent(offset)?;
            let mask = 1u8 << kind as u8;
            if seen & mask != 0 {
                return Err(FirmwareError::InvalidImageType(kind as u32));
            }
            seen |= mask;
            offset = end;
        }
        if seen != 0b1111 || offset != self.payload_end {
            return Err(FirmwareError::LengthMismatch);
        }
        Ok(())
    }
}

fn parse_compatible_header(bytes: &[u8]) -> Result<FirmwareHeader, FirmwareError> {
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
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[20..PATCH_HEADER_LEN]);
    Ok(FirmwareHeader {
        version,
        feature_flags,
        payload_len,
        hash,
    })
}

fn exact_payload_end(bytes: &[u8], payload_len: u32) -> Result<usize, FirmwareError> {
    let payload_end = PATCH_HEADER_LEN
        .checked_add(payload_len as usize)
        .ok_or(FirmwareError::TruncatedPayload)?;
    if payload_end > bytes.len() {
        return Err(FirmwareError::TruncatedPayload);
    }
    if payload_end != bytes.len() {
        return Err(FirmwareError::LengthMismatch);
    }
    Ok(payload_end)
}

/// Successful firmware start report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareReport {
    /// Bundle version loaded into the RPU.
    pub version: u32,
    /// Feature flags accepted by the loader.
    pub feature_flags: u32,
}

/// Validates the trusted bundle, resets both processors, downloads all images,
/// boots LMAC then UMAC, and checks both boot signatures.
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
    run_processor_operation(rpu, delay, ProcessorOperation::Reset).await?;
    download_images(rpu, bundle).await?;
    run_processor_operation(rpu, delay, ProcessorOperation::Boot).await?;

    let header = bundle.header();
    Ok(FirmwareReport {
        version: header.version,
        feature_flags: header.feature_flags,
    })
}

#[derive(Clone, Copy)]
enum ProcessorOperation {
    Reset,
    Boot,
}

impl ProcessorOperation {
    fn stage(self, processor: Processor) -> LoadStage {
        match self {
            Self::Reset => LoadStage::Reset(processor),
            Self::Boot => LoadStage::Boot(processor),
        }
    }
}

async fn run_processor_operation<B, D>(
    rpu: &mut Rpu<B>,
    delay: &mut D,
    operation: ProcessorOperation,
) -> Result<(), LoadError<B::Error>>
where
    B: Bus,
    D: DelayNs,
{
    for processor in [Processor::Lmac, Processor::Umac] {
        let result = match operation {
            ProcessorOperation::Reset => rpu.reset_processor(processor, delay).await,
            ProcessorOperation::Boot => boot_processor(rpu, delay, processor).await,
        };
        result.map_err(|error| LoadError::Rpu {
            stage: operation.stage(processor),
            error,
        })?;
    }
    Ok(())
}

async fn download_images<B: Bus>(
    rpu: &mut Rpu<B>,
    bundle: &FirmwareBundle<'_>,
) -> Result<(), LoadError<B::Error>> {
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
        // Match Nordic's pinned loader: the high-latency direct-memory read
        // path is not a reliable write verifier. Both processors must still
        // publish their boot signatures below, which fails a bad download.
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
    let config = boot_config(processor);

    program_boot(rpu, processor, config).await?;
    wait_for_boot_signature(rpu, delay, processor, config.signature_address).await
}

#[derive(Clone, Copy)]
struct BootConfig {
    signature_address: u32,
    sleep_control: u32,
    patch_offset: u32,
    run_register: u32,
    vectors: [u32; 4],
}

const fn boot_config(processor: Processor) -> BootConfig {
    match processor {
        Processor::Lmac => BootConfig {
            signature_address: RPU_MEM_LMAC_BOOT_SIG,
            sleep_control: RPU_REG_UCC_SLEEP_CTRL_DATA_0,
            patch_offset: RPU_MEM_LMAC_PATCH_BIMG - 0x8004_0000,
            run_register: RPU_REG_MIPS_MCU_CONTROL,
            vectors: LMAC_BOOT_VECTOR_REGISTERS,
        },
        Processor::Umac => BootConfig {
            signature_address: RPU_MEM_UMAC_BOOT_SIG,
            sleep_control: RPU_REG_UCC_SLEEP_CTRL_DATA_1,
            patch_offset: RPU_MEM_UMAC_PATCH_BIMG - 0x8008_0000,
            run_register: RPU_REG_MIPS_MCU2_CONTROL,
            vectors: UMAC_BOOT_VECTOR_REGISTERS,
        },
    }
}

async fn program_boot<B: Bus>(
    rpu: &mut Rpu<B>,
    processor: Processor,
    config: BootConfig,
) -> Result<(), RpuError<B::Error>> {
    rpu.write_u32(processor, config.signature_address, 0)
        .await?;
    rpu.write_register(config.sleep_control, config.patch_offset)
        .await?;
    for (address, value) in config.vectors.into_iter().zip(BOOT_VECTOR_VALUES) {
        rpu.write_register(address, value).await?;
    }
    rpu.write_register(config.run_register, 1).await
}

async fn wait_for_boot_signature<B, D>(
    rpu: &mut Rpu<B>,
    delay: &mut D,
    processor: Processor,
    signature_address: u32,
) -> Result<(), RpuError<B::Error>>
where
    B: Bus,
    D: DelayNs,
{
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
    use std::vec::Vec;

    use crate::memory::{RPU_REG_MIPS_MCU_WAIT_STATUS, RPU_REG_MIPS_MCU2_WAIT_STATUS, host_offset};
    use crate::test_support::block_on;

    use super::*;

    #[derive(Default)]
    struct FirmwareBus {
        writes: Vec<(u32, Vec<u8>)>,
        boot_ready: bool,
    }

    impl Bus for FirmwareBus {
        type Error = ();

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            data.fill(0);
            let lmac_wait = host_offset(Processor::Lmac, RPU_REG_MIPS_MCU_WAIT_STATUS).unwrap();
            let umac_wait = host_offset(Processor::Lmac, RPU_REG_MIPS_MCU2_WAIT_STATUS).unwrap();
            let lmac_signature = host_offset(Processor::Lmac, RPU_MEM_LMAC_BOOT_SIG).unwrap();
            let umac_signature = host_offset(Processor::Umac, RPU_MEM_UMAC_BOOT_SIG).unwrap();
            let value = if address == lmac_wait || address == umac_wait {
                1
            } else if self.boot_ready && (address == lmac_signature || address == umac_signature) {
                BOOT_SIGNATURE
            } else {
                0
            };
            data.copy_from_slice(&value.to_le_bytes()[..data.len()]);
            Ok(())
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingDelay {
        calls: usize,
    }

    impl DelayNs for CountingDelay {
        async fn delay_ns(&mut self, _ns: u32) {
            self.calls += 1;
        }
    }

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
        assert_eq!(bundle.as_bytes(), bytes);
        assert_eq!(bundle.header().version, PINNED_PATCH_VERSION);
        for (kind, expected, destination) in [
            (
                ImageKind::UmacPrimary,
                0,
                (Processor::Umac, RPU_MEM_UMAC_PATCH_BIMG),
            ),
            (
                ImageKind::UmacSecondary,
                1,
                (Processor::Umac, RPU_MEM_UMAC_PATCH_BIN),
            ),
            (
                ImageKind::LmacPrimary,
                2,
                (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIMG),
            ),
            (
                ImageKind::LmacSecondary,
                3,
                (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIN),
            ),
        ] {
            assert_eq!(bundle.image(kind).unwrap().data, &[expected]);
            assert_eq!(kind.destination(), destination);
            assert_eq!(ImageKind::from_u32(kind as u32), Ok(kind));
        }
        assert_eq!(
            ImageKind::from_u32(4),
            Err(FirmwareError::InvalidImageType(4))
        );
    }

    #[test]
    fn rejects_every_fixed_header_mismatch() {
        assert_eq!(
            FirmwareBundle::parse(&bundle_bytes()[..PATCH_HEADER_LEN - 1]).err(),
            Some(FirmwareError::TruncatedHeader)
        );
        for (offset, replacement, expected) in [
            (0, 0u32, FirmwareError::BadSignature(0)),
            (4, 3u32, FirmwareError::BadImageCount(3)),
            (8, 0u32, FirmwareError::IncompatibleVersion(0)),
            (
                12,
                FEATURE_SYSTEM_WITH_RAW,
                FirmwareError::IncompatibleFeatures(FEATURE_SYSTEM_WITH_RAW),
            ),
        ] {
            let mut bytes = bundle_bytes();
            bytes[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
            assert_eq!(FirmwareBundle::parse(&bytes).err(), Some(expected));
        }
    }

    #[test]
    fn rejects_truncated_repeated_and_trailing_images() {
        let mut short_header = bundle_bytes().to_vec();
        short_header.truncate(PATCH_HEADER_LEN + IMAGE_HEADER_LEN - 1);
        let payload_len = (short_header.len() - PATCH_HEADER_LEN) as u32;
        short_header[16..20].copy_from_slice(&payload_len.to_le_bytes());
        assert_eq!(
            FirmwareBundle::parse(&short_header).err(),
            Some(FirmwareError::TruncatedImage)
        );

        let mut short_body = bundle_bytes();
        short_body[PATCH_HEADER_LEN + 4..PATCH_HEADER_LEN + 8]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            FirmwareBundle::parse(&short_body).err(),
            Some(FirmwareError::TruncatedImage)
        );

        let mut repeated = bundle_bytes();
        repeated[PATCH_HEADER_LEN + 9..PATCH_HEADER_LEN + 13].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            FirmwareBundle::parse(&repeated).err(),
            Some(FirmwareError::InvalidImageType(0))
        );

        let mut trailing = bundle_bytes().to_vec();
        trailing.push(0xaa);
        let payload_len = (trailing.len() - PATCH_HEADER_LEN) as u32;
        trailing[16..20].copy_from_slice(&payload_len.to_le_bytes());
        assert_eq!(
            FirmwareBundle::parse(&trailing).err(),
            Some(FirmwareError::LengthMismatch)
        );
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

    #[test]
    fn loads_images_and_programs_both_exact_boot_configs() {
        assert_eq!(
            ProcessorOperation::Reset.stage(Processor::Lmac),
            LoadStage::Reset(Processor::Lmac)
        );
        assert_eq!(
            ProcessorOperation::Boot.stage(Processor::Umac),
            LoadStage::Boot(Processor::Umac)
        );
        let bytes = bundle_bytes();
        let bundle = FirmwareBundle::parse(&bytes).unwrap();
        let trust = PinnedFirmwareSha256::new(bundle.full_sha256());
        assert_eq!(trust.expected(), bundle.full_sha256());
        let mut rpu = Rpu::new(FirmwareBus {
            boot_ready: true,
            ..FirmwareBus::default()
        });
        let mut delay = CountingDelay::default();

        let report = block_on(load(&mut rpu, &mut delay, &bundle, &trust)).unwrap();
        assert_eq!(
            report,
            FirmwareReport {
                version: PINNED_PATCH_VERSION,
                feature_flags: FEATURE_SYSTEM_MODE,
            }
        );
        assert_eq!(delay.calls, 0);

        let bus = rpu.into_inner();
        for (processor, address, expected) in [
            (Processor::Umac, RPU_MEM_UMAC_PATCH_BIMG, 0),
            (Processor::Umac, RPU_MEM_UMAC_PATCH_BIN, 1),
            (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIMG, 2),
            (Processor::Lmac, RPU_MEM_LMAC_PATCH_BIN, 3),
        ] {
            let host = host_offset(processor, address).unwrap();
            assert!(
                bus.writes
                    .iter()
                    .any(|(written_address, data)| *written_address == host
                        && data == &[expected, 0, 0, 0])
            );
        }
        for (address, expected) in [
            (RPU_REG_UCC_SLEEP_CTRL_DATA_0, 0x0000_bbc0u32),
            (RPU_REG_UCC_SLEEP_CTRL_DATA_1, 0x0001_b800u32),
        ] {
            let host = host_offset(Processor::Lmac, address).unwrap();
            assert!(bus.writes.iter().any(|(written_address, data)| {
                *written_address == host && data == &expected.to_le_bytes()
            }));
        }
    }

    #[test]
    fn boot_signature_wait_is_bounded() {
        let mut rpu = Rpu::new(FirmwareBus::default());
        let mut delay = CountingDelay::default();
        assert!(matches!(
            block_on(boot_processor(&mut rpu, &mut delay, Processor::Lmac)),
            Err(RpuError::Timeout)
        ));
        assert_eq!(delay.calls, 100);
    }
}
