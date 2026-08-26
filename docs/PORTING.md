# nRF7002 native board integration

This crate contains a low-level driver core. It does not contain a complete board runner.

## Service map

| Board need | Crate API |
|---|---|
| SPI device with chip select | `SpiTransport<SPI>` and the `Bus` trait |
| RPU register and memory access | `Rpu<B>` |
| Delay for reset, wake, and boot | `embedded_hal_async::delay::DelayNs` |
| Firmware parse, trust, and boot | `FirmwareBundle::parse`, `PinnedFirmwareSha256`, and `firmware::load` |
| Queue and interrupt control | `Device<B>` |
| RX and TX packet RAM | `DataPath<RX, TX>` |
| Embassy network queue | `NetworkState`, `NetworkDriver`, and `NetworkRunner` with the `embassy-net` feature |
| Host interrupt wait | Board GPIO interrupt future or task |
| Power, reset, and coexistence pins | Board code |

## Required board sequence

Use this order as the integration baseline:

1. Apply the board power, reset, and coexistence GPIO sequence.
2. Create an asynchronous `embedded-hal-async` SPI device that keeps chip select active for one transaction.
3. Create `SpiTransport::new(spi)` and then `Rpu::new(transport)`.
4. Use the RPU wake and status methods with a bounded delay policy.
5. Parse the pinned Nordic firmware with `FirmwareBundle::parse`.
6. Create a `PinnedFirmwareSha256` value from a complete-file digest stored outside the firmware file.
7. Call `firmware::load` with the trust policy to reset both processors, write all four images, start LMAC and UMAC, and check their boot signatures.
7. Move the bus into `Device::new`, then call `initialize_queues` and `enable_interrupts`.
8. Create a `DataPath<RX, TX>` that matches the RX pool and frame sizes in `SystemInitConfig`.
9. Send system initialization and wait for a successful firmware result before you post normal traffic.
10. Add the station interface and post all RX descriptors.
11. Start an interrupt task. After each host interrupt, call `try_read_event` until it returns `Ok(None)`.
12. Decode UMAC and data events. Return completed TX tokens and deliver RX frames to `NetworkRunner`.

## Event scratch buffer rule

A fragmented event can continue after a later interrupt. Keep the same scratch buffer unchanged until `try_read_event` returns a complete event.

If the buffer cannot stay in place, call `Device::discard_pending_event`. Later calls to `try_read_event` will remove the remaining fragments before they read a new event.

Size the scratch buffer for the largest event that the application accepts. An event fragment is at most 1000 bytes for the pinned Nordic interface, but one complete event can use more than one fragment.

## SPI rule

Use 8 MHz or less for the wake status-register transaction. Use only a frequency that is qualified for the board for normal traffic.

`SpiConfig` validates its 24-bit mask and slave-latency limit. Board code is still responsible for the SPI mode, frequency changes, chip-select timing, and power-state timing.

## RX and TX configuration rule

The `DataPath` sizes and counts must match the values sent in `SystemInitConfig`.

The fixed TX command area ends when packet data starts. The crate limits TX tokens to the slots that fit before `RPU_MEM_PACKET_BASE`. Do not create another packet-RAM allocator for the same device.

## Missing top-level work

A production board runner still needs these parts:

- authentication and association state;
- key installation and EAPOL handling;
- regulatory and channel control;
- connection-state and disconnect handling;
- power-save state;
- watchdog and reset recovery;
- bounded command-queue wait or retry policy; and
- board hardware tests.

See [`ABI_REQUIREMENTS.md`](ABI_REQUIREMENTS.md) and [`TEST_PLAN.md`](TEST_PLAN.md).
