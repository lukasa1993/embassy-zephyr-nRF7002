# embassy-zephyr-nrf7002

`embassy-zephyr-nrf7002` is the reusable, `no_std`, allocation-free Rust
boundary for the frozen Zephyr/nRF7002 foundation. Product code sees Rust
types only; no
Zephyr enum, pointer, socket descriptor, packet, errno, C header, CMake file, or
generated binding is public.

The crate has three surfaces:

- `WifiController` is the exclusive management/control owner. It enables and
  disables roles, supplies runtime credentials, starts scans and SoftAP, reads
  status/capabilities/statistics, configures regulatory and power behavior, and
  drains management events.
- `Platform` owns one role-specific raw Ethernet endpoint. Use
  `Platform::open_endpoint_for(InterfaceRole::Station)` or `AccessPoint`.
- `SharedDevice`, `NetworkDriver`, and `NetworkReactor` adapt a `Platform`
  endpoint to `embassy-net` with fixed-capacity RX/TX queues.

## Frozen capability contract

The current `nrf7002dk/nrf5340/cpuapp` foundation reports:

| Capability | Contract |
| --- | --- |
| STA | One upstream AP association |
| SoftAP | One officially supported connected client |
| Concurrent mode | STA + SoftAP, two nRF70 virtual interfaces |
| Bands | 2.4 GHz and 5 GHz |
| Credentials | Borrowed from Rust at runtime; never compiled into Zephyr |
| L2 | Role-addressed complete Ethernet frames |
| Other controls | Scan, BSSID/band/channel/width/MFP, country/domain, power save, TWT, statistics, AP client kick |

`WifiController::capabilities()` is still the runtime source of truth. The
adapter verifies the ABI, wire layout, band flags, and advertised role limits
before returning the controller.

## Rust owns runtime decisions

Zephyr auto-start is disabled. Rust must explicitly enable a role, choose the
regulatory domain, and issue STA/SoftAP requests:

```rust,ignore
use embassy_zephyr_nrf7002::{
    ConnectRequest, CountryCode, InterfaceRole, Security, WifiController,
};

let mut wifi = WifiController::take()?;
wifi.set_enabled(InterfaceRole::Station, true)?;
wifi.set_country(InterfaceRole::Station, CountryCode::new(*b"US")?, false)?;

// Both slices are borrowed only for this synchronous call. The bridge copies
// them into bounded scratch space, submits them, then wipes that scratch.
wifi.connect(ConnectRequest::new(
    runtime_ssid,
    Security::Wpa2Psk,
    runtime_passphrase,
))?;
```

The only deliberate mechanism-side policy is automatic supplicant reconnect
and roaming. Rust does not drive their step-by-step state machine. Their link
effects are observable through connection/disconnection events and
`WifiController::status()`, including the current BSSID, channel, band, RSSI,
and PHY mode.

## Events

`WifiController::poll_event()` is nonblocking and returns stable Rust enums for:

- station connected, connection failed, and disconnected;
- interface administrative up/down;
- SoftAP started/stopped;
- SoftAP client joined/left, including peer MAC, link generation, and TWT capability;
- TWT completion/failure.

The C-to-Rust event queue has 16 fixed slots and never blocks the Zephyr event
thread. Every returned event includes the cumulative drop counter. If it
changes, product code should query `status()` for both roles and rebuild its
observed state. Scan results use a separate 16-slot queue with their own drop
counter.

## Embassy data plane

Put the shared device in static storage, open the Rust-selected endpoint, then
split ownership between `embassy-net` and one reactor task:

```rust,ignore
use embassy_zephyr_nrf7002::{
    initialize_network, DefaultSharedDevice, InterfaceRole, Platform,
};

static DEVICE: DefaultSharedDevice = DefaultSharedDevice::new();

let endpoint = Platform::open_endpoint_for(InterfaceRole::Station)?;
let split = initialize_network(endpoint, &DEVICE)?;
let driver = split.driver;       // move into embassy-net::Stack
let mut reactor = split.reactor; // move into one Embassy service task
let _report = reactor.service_once()?;
```

The reactor is queue-only and nonblocking. A TX `WouldBlock` retains the same
lease and bytes for retry. Disconnect advances the link epoch and retires stale
frames. EAPOL belongs to Zephyr's supplicant and is filtered at this boundary;
Rust owns ordinary Ethernet data frames and `embassy-net` owns DHCP/IP/TCP.

## Verification

Host tests need no Docker, West, CMake, Zephyr, or target linker:

```sh
rustup run 1.95.0 cargo test \
  --features embassy-net \
  --target aarch64-apple-darwin
```

The target path is validated by the one-time foundation build and subsequent
`scripts/rust-rebuild.sh` link-only loop.
