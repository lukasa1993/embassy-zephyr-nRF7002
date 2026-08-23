# Native Embassy nRF7002 driver

This crate is a `no_std` Rust driver core for the Nordic nRF7002. It talks to
the radio processor directly. It does not link Zephyr, the Nordic C host
driver, a C ABI, or a C runtime.

## Current native path

The crate contains these parts:

- the nRF70 SPI host framing and status-register access;
- RPU address translation, register access, indirect LMAC writes, reset, and
  power control;
- parsing, SHA-256 checking, download, and start of the Nordic `nrf70.bin`
  firmware bundle;
- the firmware host-port queue manager, command fragmentation, event
  reassembly, and interrupt control;
- packed system, UMAC, scan, interface, RX, and TX message codecs;
- a fixed packet-RAM allocator with RX descriptor recycling and TX tokens;
- conversion of firmware RX formats to Ethernet II frames; and
- an allocation-free `embassy-net-driver` queue behind the `embassy-net`
  feature.

All wire values are pinned to Nordic nRF Connect SDK v3.4.0 and
`nrf_wifi` revision `5046744cb4c9640eb8b11cb92f1ea0b9554c20cf`.

## Firmware input

Use the default system-mode firmware bundle from `sdk-nrfxlib` v3.4.0:

```text
nrf_wifi/bin/zephyr/default/nrf70.bin
```

The crate does not copy that binary into this repository. The application can
embed the file with `include_bytes!` after it accepts Nordic's firmware
license.

## Hardware contract

The application supplies:

- one async `embedded-hal-async` SPI device;
- the nRF7002 host-interrupt GPIO future or interrupt handler;
- a delay provider;
- the board RF parameter block and valid TX power ceilings; and
- the nRF7002 power and coexistence GPIO sequence for its board.

The wake status-register transaction must use 8 MHz or less. Normal data
traffic can use the board-qualified SPI frequency and latency setting.

## Build checks

```sh
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --no-default-features
```

Repository CI also compiles the pinned Nordic C headers with static assertions.
This checks the sizes and key offsets used by the Rust codecs.

## Verification limit

Host tests and C layout checks prove compilation, bounds, hashes, and packed
formats. They do not prove RF operation. A board test must still confirm
firmware start, scan, association, controlled-port operation, DHCP, data
traffic, reconnect, and error recovery.
