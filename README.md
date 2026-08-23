# embassy-zephyr-nRF7002

A reusable, `no_std` Rust control and raw-Ethernet boundary for the Nordic
nRF7002 Wi-Fi companion on `nrf7002dk/nrf5340/cpuapp`. Embassy owns DHCP,
IP, TCP, and application logic. A pinned NCS/Zephyr foundation owns device
initialization, the nRF70 driver, WPA supplicant, automatic reconnect/roaming,
and the final firmware link.

> **Alpha status:** host tests and the complete pinned Zephyr build/link pass.
> The included firmware has not yet completed an on-device association, DHCP,
> and HTTP request gate. Use the prerelease for evaluation, not production.

## What Rust controls

The safe `WifiController` API exposes all supported runtime choices:

- enable or disable STA and SoftAP independently;
- scan on 2.4 GHz and/or 5 GHz;
- connect one STA association using credentials supplied by Rust at runtime;
- start one SoftAP, with one officially supported connected client;
- run concurrent STA + SoftAP through two nRF70 virtual interfaces;
- select SSID, security, MFP, BSSID, band, channel, bandwidth, timeout, hidden
  SSID behavior, regulatory country/domain, power-save settings, and TWT;
- read role status, link details, regulatory channels, statistics, and Wi-Fi
  events; and
- disconnect roles, stop SoftAP, reset statistics, or remove the AP client.

Credentials are borrowed for a synchronous call, copied into bounded bridge
storage, submitted to the supplicant, and wiped. No SSID or passphrase is
compiled into the Zephyr foundation. Automatic reconnect and roaming are the
only mechanism-side policy; Rust receives their resulting events and status.

The current frozen capability limits are one STA association, one officially
supported SoftAP client, two virtual interfaces, and both 2.4 GHz and 5 GHz.
`WifiController::capabilities()` validates these limits at runtime.

## Add the Rust crate

Use the matching Git tag so the Rust API, C ABI, Zephyr configuration, and
toolchain pins cannot drift independently:

```toml
[dependencies]
embassy-zephyr-nrf7002 = {
  git = "https://github.com/lukasa1993/embassy-zephyr-nRF7002",
  tag = "v0.1.0-alpha.1",
  default-features = false,
  features = ["zephyr", "embassy-net"],
}
```

```rust,ignore
use embassy_zephyr_nrf7002::{
    ConnectRequest, CountryCode, InterfaceRole, Security, WifiController,
};

let mut wifi = WifiController::take()?;
wifi.set_enabled(InterfaceRole::Station, true)?;
wifi.set_country(InterfaceRole::Station, CountryCode::new(*b"US")?, false)?;
wifi.connect(ConnectRequest::new(
    runtime_ssid,
    Security::Wpa2Psk,
    runtime_passphrase,
))?;
```

The `zephyr` feature calls the repository's private C ABI and therefore must
be linked inside the matching Zephyr wrapper. A Cargo dependency by itself
does not replace Zephyr's generated linker passes. See
[the crate API guide](docs/crate-api.md) for the Rust-only surface and data
plane.

## Prebuilt proof firmware

The GitHub prerelease provides:

- a flashable `.hex`, plus matching `.elf` and `.bin` files;
- a SHA-256 checksum file; and
- a verified foundation archive for inspection and reproducible caching.

The proof image asks for the SSID, security mode, and passphrase through its
Rust provisioning console, then runs Embassy DHCP/TCP and serves:

```text
Hello from embassy-zephyr-nRF7002
```

No credentials are present in the release image. The foundation archive is an
auditable cache, not a standalone firmware linker SDK: Zephyr's persistent
CMake/Ninja tree is still required to link changed Rust firmware.

## Build once, then rebuild Rust

Only Docker is required on the host. NCS, Zephyr, west, CMake, the Nordic
toolchain, the Rust target toolchain, generated files, and caches remain in
this repository's ignored directories.

```sh
scripts/bootstrap.sh
scripts/build.sh
```

After that, edit the Rust application under `rust/app/` and run:

```sh
scripts/rust-rebuild.sh
```

That command invokes the existing inner Ninja graph directly. Cargo rebuilds
the Rust static library and Zephyr performs its required metadata/final-link
passes; it does not run west update, CMake reconfiguration, or rebuild the
checked-out C foundation.

Package and verify the frozen foundation explicitly:

```sh
scripts/package.sh
scripts/verify.sh --for-rust
scripts/status.sh
```

Host-side crate tests do not need Docker or Zephyr:

```sh
rustup run 1.95.0 cargo test --features embassy-net \
  --target aarch64-apple-darwin
```

## Isolation and pins

All non-Rust integration lives in this repository. It is not a Cargo member of
any consuming product repository. `.workspace/`, `.build/`, `artifacts/`,
`target/`, and `release/` are ignored.

The wrapper currently pins NCS v3.4.0, Zephyr `ncs-v3.4.0`,
`zephyr-lang-rust` commit `dd73abc242e995784da62352fe8c70d9a6c7ac2e`,
Rust 1.95.0, and the Nordic v3.4.0 toolchain image by immutable digest. The
build fails closed if Zephyr IPv4/IPv6, DHCP, DNS, TCP, or UDP is enabled;
ordinary Ethernet frames cross into `embassy-net` instead.

Licensed under Apache-2.0 or MIT, at your option.
