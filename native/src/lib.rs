//! Native, allocation-free nRF7002 driver core for Embassy.
//!
//! This crate talks to the nRF7002 RPU directly. It does not link Zephyr,
//! Nordic's C host driver, or a C ABI. The packed interface is pinned to the
//! nRF Connect SDK v3.4.0 `nrf_wifi` revision.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod bus;
pub mod data;
pub mod device;
pub mod firmware;
pub mod memory;
pub mod protocol;

#[cfg(feature = "embassy-net")]
pub mod embassy;

pub use bus::{Bus, SpiConfig, SpiTransport};
pub use data::{DataPath, ReceivedFrame, RxEventRef};
pub use device::Device;
pub use firmware::{FirmwareBundle, FirmwareReport};
pub use memory::{Processor, Rpu};
pub use protocol::{ScanRequest, SystemInitConfig};

/// Pinned host-driver source revision used for every packed interface value.
pub const NRF_WIFI_SOURCE_REVISION: &str = "5046744cb4c9640eb8b11cb92f1ea0b9554c20cf";
/// Pinned firmware bundle release.
pub const NRFXLIB_FIRMWARE_RELEASE: &str = "v3.4.0";
