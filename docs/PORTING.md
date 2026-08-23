# nRF7002 native port map

The Nordic bare-metal driver separates its Wi-Fi core from operating-system and bus services. The native Rust path uses the same separation, but it does not add a Zephyr shim.

| Nordic port need | Native Embassy implementation |
|---|---|
| RPU interrupt | GPIOTE or GPIO interrupt future |
| Deferred tasklet | Embassy task and bounded channel |
| Heap allocation | Fixed arrays, frame slots, and descriptor rings |
| Linked lists | Checked ring cursors and fixed queues |
| Sleep and delay | Embassy timer future |
| Spin lock | Embassy mutex or critical-section raw mutex |
| Timer callback | Embassy timer task |
| Random data | Board RNG implementation |
| SPI or QSPI transport | `Hardware` implementation using Embassy peripherals |
| Firmware patch transfer | `Device::initialize` with checked `FirmwareImage` segments |
| Ethernet integration | `EmbassyNetDevice` and `PacketIo` |

## Required next hardware layer

The board-specific `Hardware` implementation must provide these exact operations:

1. Power and reset sequencing for the board.
2. RPU status-register reads and writes.
3. QSPI reads and writes to the nRF7002 address space.
4. Firmware entry-point release.
5. Interrupt-line wait.
6. Non-blocking delay.

The RPU ABI implementation must provide command, event, transmit, and receive rings. It must use the same Nordic firmware and host-interface version. A mismatched host ABI and firmware image is not accepted as a valid test configuration.
