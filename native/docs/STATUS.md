# Native driver status

## Statically verified

- `no_std` Rust core builds without the Embassy adapter.
- The Embassy network-driver feature builds.
- Firmware segment validation and CRC-32 tests pass.
- Firmware chunk transfer, readback, timeout, and fault-state tests pass with mock hardware.
- Descriptor ring full, empty, and wrap tests pass.
- Formatting and Clippy checks pass with warnings denied.

## Not yet hardware verified

- nRF5340 QSPI register transactions.
- Nordic firmware patch addresses and release sequence.
- Nordic host/RPU command and event encoding.
- Scan, association, WPA2, WPA3, DHCP, and sustained Ethernet traffic.
- Recovery after a real RPU fault or interrupt loss.

No hardware result is claimed until these tests run on a physical nRF7002 target.
