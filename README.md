# embassy-nrf7002

`embassy-nrf7002` is a native, allocation-free, `no_std` Rust driver core for the Nordic nRF7002 Wi-Fi companion IC.

The driver talks to the nRF7002 radio processor directly. It does not link Zephyr, the Nordic C host driver, a C ABI, or a C run-time library.

## Status

This branch is an alpha implementation. Host tests and packed-interface layout checks cover compilation, bounds, firmware parsing, queue logic, and message formats. These checks do not prove RF operation. Use the hardware test plan before a production release.

The host interface is pinned to:

- nRF Connect SDK firmware release `v3.4.0`;
- `nrf_wifi` revision `5046744cb4c9640eb8b11cb92f1ea0b9554c20cf`.

Do not use another firmware or host-interface revision without a full ABI review.

## Driver contents

The crate provides:

- nRF70 SPI framing and status-register access;
- RPU address translation, reset, power, register, and memory access;
- firmware bundle parsing, SHA-256 checks, patch download, and processor start;
- host-port queue management, command fragmentation, event reassembly, and interrupt control;
- packed system, UMAC, scan, interface, RX, and TX messages;
- fixed packet-RAM allocation, RX descriptor recycling, and TX tokens;
- Ethernet II frame conversion; and
- an allocation-free `embassy-net-driver` adapter behind the `embassy-net` feature.

## Firmware input

Use the system-mode firmware bundle from `sdk-nrfxlib` `v3.4.0`:

```text
nrf_wifi/bin/zephyr/default/nrf70.bin
```

The path name comes from the Nordic firmware package. The driver does not use Zephyr. The firmware file is not stored in this repository. The application can include it after it accepts the Nordic firmware license.

## Board contract

Board code must supply:

- one asynchronous `embedded-hal-async` SPI device;
- the host-interrupt GPIO handler or future;
- a delay provider;
- valid board RF parameters and TX power ceilings; and
- the correct nRF7002 power, reset, and coexistence GPIO sequence.

Use 8 MHz or less for the wake status-register transaction. Use only a board-qualified frequency for normal traffic.

## Build

The repository pins Rust `1.95.0`.

```sh
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --lib --no-default-features --target thumbv8m.main-none-eabihf
cargo check --lib --features embassy-net --target thumbv8m.main-none-eabihf
```

CI also compiles the pinned Nordic C headers with static assertions. This test checks the sizes and offsets that the Rust codecs use.

## Documents

- [`docs/PORTING.md`](docs/PORTING.md): board and OS-service port map.
- [`docs/ABI_REQUIREMENTS.md`](docs/ABI_REQUIREMENTS.md): host/RPU ABI completion gate.
- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md): hardware acceptance tests.

Licensed under Apache-2.0 or MIT, at your option.
