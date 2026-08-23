# Proof firmware

This is the Rust static-library application for the real nRF7002 proof. It is
an independent Cargo workspace below `rust/app/`; the reusable crate workspace never
discovers Zephyr's generated `zephyr-sys`, bindgen, or CMake dependencies.

The proof application does all application policy in Rust:

1. takes the exclusive `WifiController`;
2. verifies STA, SoftAP, concurrent dual-VIF, and runtime-credential support;
3. explicitly enables STA while leaving SoftAP disabled;
4. explicitly selects the regulatory domain;
5. collects SSID, security, and passphrase over the bounded Rust provisioning console;
6. borrows those credentials for one synchronous connect call and zeroizes the Rust buffers;
7. runs DHCP, TCP, and a `Hello from embassy-zephyr-nRF7002` HTTP server with `embassy-net`;
8. drains and logs the Rust Wi-Fi control events, resynchronizing role status if the fixed queue reports drops.

There are no credentials, automatic interface start, Zephyr DHCP/IP/TCP, or
Zephyr application decisions in this image. Automatic supplicant reconnect and
roaming are the explicit exceptions.

The Zephyr build invokes `rust_cargo_application()` from the local
`CMakeLists.txt`. It supplies the official `zephyr` crate and the matching
Embassy versions:

- `embassy-executor = 0.7.0` with a bounded task arena;
- `embassy-time = 0.4.0` at the foundation's 1 kHz tick;
- `embassy-net` over the reusable `embassy-zephyr-nrf7002` L2 driver;
- `zephyr = 0.1.0` with `executor-zephyr` and `time-driver`.

Build the C/Kconfig foundation once, then live in Rust:

```sh
scripts/build.sh
scripts/rust-rebuild.sh
```

The latter rebuilds the Rust archive and performs only Zephyr's required
generated-metadata/final-link passes. It fails if checked-out Zephyr, Nordic,
or application C sources are recompiled.
