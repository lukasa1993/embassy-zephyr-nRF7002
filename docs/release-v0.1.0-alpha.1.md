# v0.1.0-alpha.1

First public build-verified prerelease of `embassy-zephyr-nRF7002`.

Included:

- safe `no_std` Rust Wi-Fi control, event, status, and raw-L2 APIs;
- allocation-free `embassy-net-driver` adapter;
- runtime Rust credentials with bounded bridge buffers and explicit wiping;
- one STA association and one officially supported SoftAP client;
- concurrent STA + SoftAP with two virtual interfaces;
- 2.4 GHz and 5 GHz control;
- scans, regulatory control, power save, TWT, statistics, and AP client removal;
- Rust provisioning, Embassy DHCP/TCP, and HTTP proof firmware; and
- prebuilt `.hex`, `.elf`, `.bin`, verified foundation archive, and SHA-256
  checksums for `nrf7002dk/nrf5340/cpuapp`.

Automatic WPA-supplicant reconnect and roaming remain enabled. Rust observes
their resulting events and status; all other runtime decisions are Rust-owned.

This prerelease passes host tests, configuration invariants, and the full
pinned NCS/Zephyr link. Physical association, DHCP, and HTTP response have not
yet been certified, so this is not a production release.
