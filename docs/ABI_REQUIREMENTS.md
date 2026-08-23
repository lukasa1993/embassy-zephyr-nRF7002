# Nordic host/RPU ABI completion gate

The `ControlCodec` implementation is firmware-release specific. It is complete only when it implements and tests all items below against the exact Nordic headers and firmware image used by the board.

- Firmware system initialization and capability response
- Virtual-interface creation and deletion
- Regulatory-domain and channel configuration
- Scan request, result stream, and completion
- Authentication and association commands and events
- WPA2 four-way handshake data and key installation
- WPA3 SAE exchange and key installation
- Disconnect request and reason event
- Transmit descriptor submission and completion
- Receive descriptor ownership and refill
- Power-save wake and sleep transitions
- Firmware fault, recovery, and statistics events

The generic Rust mailbox engine does not invent command identifiers or structure layouts. A codec must take them from Nordic's official host/RPU interface for the selected firmware release. This prevents a build from passing while using a mismatched ABI.
