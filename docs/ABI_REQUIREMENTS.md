# Nordic host/RPU ABI completion gate

This crate targets one exact Nordic host interface and firmware release:

- nRF Connect SDK `v3.4.0`;
- `nrf_wifi` revision `5046744cb4c9640eb8b11cb92f1ea0b9554c20cf`.

A green host build proves that the Rust types compile and that selected packed layouts match the pinned C headers. It does not prove that the radio works on a board.

## Current feature state

| Area | State | Required work |
|---|---|---|
| SPI transport and RPU address map | Implemented in Rust | Verify timing and bus errors on each board. |
| Firmware bundle parse and patch boot | Implemented in Rust | Verify licensed firmware on hardware. |
| Queue map and interrupt registers | Implemented in Rust | Verify queue recovery after RPU faults. |
| Command fragmentation | Implemented in Rust | Test queue saturation and partial bus failures. |
| Event fragmentation | Implemented in Rust | Test delayed fragments, changed scratch buffers, and oversized events. |
| System initialization command | Implemented encoder | Decode and verify all initialization results and capabilities. |
| Station interface creation | Implemented encoder | Add interface status handling and deletion. |
| Scan request and result request | Implemented encoders | Complete scan-event decoding and board tests. |
| RX and TX data descriptors | Implemented basic path | Test saturation, ownership errors, aggregation, and recovery. |
| Ethernet conversion | Implemented basic path | Test all 802.11 address modes and payload forms on hardware. |
| Authentication | Not implemented | Add command and event codecs and state handling. |
| Association | Not implemented | Add command and event codecs and state handling. |
| WPA2 key flow | Not implemented | Add EAPOL flow and key installation. |
| WPA3 SAE flow | Not implemented | Add SAE flow and key installation. |
| Regulatory and channel control | Not implemented | Add country, channel, and regulatory event handling. |
| Disconnect state | Partial | Deauthentication command exists. Complete all result and reason handling. |
| Power save and TWT | Not implemented | Add wake, sleep, timeout, and TWT state handling. |
| Firmware watchdog and recovery | Not implemented | Add fault detection, reset, queue reset, and network-state recovery. |
| Statistics and diagnostics | Not implemented | Add bounded event decoders and public status data. |
| Board-ready runner | Not implemented | Join power, firmware, queue, event, data, and Embassy tasks. |

## Release gate

Do not remove the alpha status until all required items below are complete:

1. Every used command, event, and packed field has a test against the pinned Nordic headers.
2. Authentication, association, key installation, disconnect, and recovery have complete state machines.
3. The board runner has bounded timeouts and a clear reset path.
4. The tests in [`TEST_PLAN.md`](TEST_PLAN.md) pass on the target nRF5340 and nRF7002 board.
5. The exact firmware file and its license are documented for the release.
6. A new Nordic revision gets a new ABI review. Do not change the revision without that review.
