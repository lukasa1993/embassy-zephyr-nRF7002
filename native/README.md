# Native Embassy nRF7002 driver

This directory contains the Zephyr-free nRF7002 driver work.

The runtime code is `no_std` Rust. It separates the Nordic RPU transport, firmware loading, command/event queues, and the `embassy-net-driver` adapter. The low-level bus is a trait so that an nRF5340 QSPI implementation can use Embassy interrupts and DMA without a Zephyr compatibility layer.

## Verification

Run:

```sh
cargo test --manifest-path native/Cargo.toml --all-features
cargo clippy --manifest-path native/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path native/Cargo.toml --all -- --check
```

Hardware association tests require an nRF7002 board, the matching Nordic firmware image, and a Wi-Fi access point. Static tests do not replace those tests.
