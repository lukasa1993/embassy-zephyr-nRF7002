#![no_std]
#![allow(async_fn_in_trait)]

//! Zephyr-free nRF7002 driver core for Embassy.
//!
//! The crate keeps all Nordic RPU access behind [`Hardware`] and
//! [`RpuInterface`]. Board code supplies the QSPI, GPIO, interrupt, and timer
//! operations. The driver supplies deterministic firmware loading, state
//! management, fixed-size Ethernet buffers, and an `embassy-net-driver`
//! adapter.

#[cfg(test)]
extern crate std;

mod control;
mod device;
mod firmware;
mod hardware;
mod net_driver;
mod ring;
mod rpu;
mod status;

pub use control::{ConnectRequest, Credentials, Security, Ssid, WifiEvent, WifiState};
pub use device::{Config, Device, DeviceError, DeviceState, TimeoutStage};
pub use firmware::{FirmwareError, FirmwareImage, FirmwareSegment, FirmwareVersion, crc32};
pub use hardware::{Hardware, StatusRegister};
pub use net_driver::{EmbassyNetDevice, PacketIo};
pub use ring::{RingCursor, RingError};
pub use rpu::{Nrf7002, Nrf7002Error, RpuInterface};
pub use status::{RpuStatus, WakeControl};
