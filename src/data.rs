//! Native packet-RAM allocator and nRF70 data descriptors.

use super::bus::Bus;
use super::device::{Device, DeviceError, RPU_MEM_TX_CMD_BASE};
use super::memory::{Processor, RPU_ADDR_MASK_OFFSET, RPU_MCU_CORE_INDIRECT_BASE, RpuError};
pub use super::protocol::DataCommand;
use super::protocol::{HOST_MESSAGE_HEADER_LEN, HostMessageRef, HostMessageType};

/// First packet byte available to the host driver.
pub const RPU_MEM_PACKET_BASE: u32 = 0xb000_5000;
/// Last byte in the nRF7002 packet RAM.
pub const RPU_MEM_PACKET_END: u32 = 0xb003_0fff;
/// Packet RAM bytes available to host RX and TX buffers.
pub const RPU_PACKET_RAM_SIZE: usize = 180_224;
/// Headroom stored before each RX packet.
pub const RX_BUFFER_HEADROOM: usize = 4;
/// Spacing reserved by Nordic after each TX packet.
pub const TX_BUFFER_HEADROOM: usize = 52;
/// Bytes between LMAC RX command slots.
pub const RX_COMMAND_SLOT_SIZE: u32 = 8;
/// Bytes between UMAC TX command slots.
pub const TX_COMMAND_SLOT_SIZE: u32 = 148;
/// Maximum number of TX command slots before packet data starts.
pub const MAX_TX_TOKENS: usize =
    ((RPU_MEM_PACKET_BASE - RPU_MEM_TX_CMD_BASE) / TX_COMMAND_SLOT_SIZE) as usize;
/// Ethernet header bytes.
pub const ETHERNET_HEADER_LEN: usize = 14;
/// EAPOL EtherType.
pub const EAPOL_ETHERTYPE: u16 = 0x888e;

const RX_EVENT_FIXED_LEN: usize = 20;
const RX_INFO_LEN: usize = 17;
const TX_COMMAND_PAYLOAD_LEN: usize = 47;
const TX_COMMAND_TOTAL_LEN: usize = HOST_MESSAGE_HEADER_LEN + TX_COMMAND_PAYLOAD_LEN;

/// RX payload representation selected by firmware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RxPayloadType {
    /// 802.11 MPDU with MAC and LLC headers.
    Mpdu = 0,
    /// MSDU with a MAC header before the A-MSDU header.
    MsduWithMac = 1,
    /// A-MSDU style Ethernet payload.
    Msdu = 2,
}

impl RxPayloadType {
    fn from_u8(value: u8) -> Result<Self, DataProtocolError> {
        match value {
            0 => Ok(Self::Mpdu),
            1 => Ok(Self::MsduWithMac),
            2 => Ok(Self::Msdu),
            _ => Err(DataProtocolError::InvalidRxPayloadType(value)),
        }
    }
}

/// Data-path configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataLayoutError {
    /// A pool has zero capacity or exceeds a wire or command-area limit.
    InvalidCapacity,
    /// Configured TX and RX storage overlap in packet RAM.
    PacketRamExhausted,
}

/// Malformed data event or Ethernet frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataProtocolError {
    WrongMessageType,
    InvalidLength,
    InvalidCommand(u32),
    InvalidDescriptor(u16),
    InvalidPacketIndex,
    InvalidRxPayloadType(u8),
    FrameTooShort,
    FrameTooLarge,
}

/// Native data operation failure.
#[derive(Debug)]
pub enum DataError<E> {
    Device(DeviceError<E>),
    Rpu(RpuError<E>),
    Protocol(DataProtocolError),
    /// A queue write failed after firmware ownership could have changed.
    QueueOwnershipUncertain(DeviceError<E>),
    NoTransmitToken,
    ReceiveDescriptorBusy(u16),
    OutputTooSmall { needed: usize, capacity: usize },
}

impl<E> From<DeviceError<E>> for DataError<E> {
    fn from(value: DeviceError<E>) -> Self {
        Self::Device(value)
    }
}

impl<E> From<RpuError<E>> for DataError<E> {
    fn from(value: RpuError<E>) -> Self {
        Self::Rpu(value)
    }
}

/// One RX packet reference inside a data event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxPacketInfo {
    pub descriptor_id: u16,
    pub packet_len: u16,
    pub payload_type: RxPayloadType,
}

/// Borrowed view of one firmware RX event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxEventRef<'a> {
    payload: &'a [u8],
    pub rx_packet_type: i16,
    pub rate_flags: u8,
    pub rate: u8,
    pub wdev_id: u8,
    pub packet_count: u8,
    pub mac_header_len: u8,
    pub frequency_mhz: u16,
    pub signal_dbm: i16,
}

impl<'a> RxEventRef<'a> {
    /// Parses `NRF_WIFI_CMD_RX_BUFF`.
    pub fn parse(message: HostMessageRef<'a>) -> Result<Self, DataProtocolError> {
        if message.message_type != HostMessageType::Data {
            return Err(DataProtocolError::WrongMessageType);
        }
        let payload = message.payload;
        if payload.len() < RX_EVENT_FIXED_LEN {
            return Err(DataProtocolError::InvalidLength);
        }
        let command = read_u32(payload, 0);
        if command != DataCommand::ReceiveBuffer as u32 {
            return Err(DataProtocolError::InvalidCommand(command));
        }
        let declared = read_u32(payload, 4) as usize;
        if declared < RX_EVENT_FIXED_LEN || declared > payload.len() {
            return Err(DataProtocolError::InvalidLength);
        }
        let packet_count = payload[13];
        let required = RX_EVENT_FIXED_LEN
            .checked_add(packet_count as usize * RX_INFO_LEN)
            .ok_or(DataProtocolError::InvalidLength)?;
        if required > declared {
            return Err(DataProtocolError::InvalidLength);
        }
        Ok(Self {
            payload: &payload[..declared],
            rx_packet_type: read_i16(payload, 8),
            rate_flags: payload[10],
            rate: payload[11],
            wdev_id: payload[12],
            packet_count,
            mac_header_len: payload[15],
            frequency_mhz: read_u16(payload, 16),
            signal_dbm: read_i16(payload, 18),
        })
    }

    /// Returns one packet descriptor.
    pub fn packet(&self, index: usize) -> Result<RxPacketInfo, DataProtocolError> {
        if index >= self.packet_count as usize {
            return Err(DataProtocolError::InvalidPacketIndex);
        }
        let offset = RX_EVENT_FIXED_LEN + index * RX_INFO_LEN;
        Ok(RxPacketInfo {
            descriptor_id: read_u16(self.payload, offset),
            packet_len: read_u16(self.payload, offset + 2),
            payload_type: RxPayloadType::from_u8(self.payload[offset + 4])?,
        })
    }
}

/// Data event category that does not require an RX-packet parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataEvent {
    TransmitDone { token: u8, status_count: u8 },
    CarrierOn { wdev_id: u32 },
    CarrierOff { wdev_id: u32 },
    Receive,
    Other(u32),
}

/// Classifies one data event.
pub fn classify_data_event(message: HostMessageRef<'_>) -> Result<DataEvent, DataProtocolError> {
    if message.message_type != HostMessageType::Data {
        return Err(DataProtocolError::WrongMessageType);
    }
    if message.payload.len() < 8 {
        return Err(DataProtocolError::InvalidLength);
    }
    let command = read_u32(message.payload, 0);
    let declared = read_u32(message.payload, 4) as usize;
    if declared < 8 || declared > message.payload.len() {
        return Err(DataProtocolError::InvalidLength);
    }
    match command {
        value if value == DataCommand::TransmitDone as u32 => {
            if declared < 10 {
                return Err(DataProtocolError::InvalidLength);
            }
            Ok(DataEvent::TransmitDone {
                token: message.payload[8],
                status_count: message.payload[9],
            })
        }
        value if value == DataCommand::ReceiveBuffer as u32 => Ok(DataEvent::Receive),
        value if value == DataCommand::CarrierOn as u32 => {
            if declared < 12 {
                return Err(DataProtocolError::InvalidLength);
            }
            Ok(DataEvent::CarrierOn {
                wdev_id: read_u32(message.payload, 8),
            })
        }
        value if value == DataCommand::CarrierOff as u32 => {
            if declared < 12 {
                return Err(DataProtocolError::InvalidLength);
            }
            Ok(DataEvent::CarrierOff {
                wdev_id: read_u32(message.payload, 8),
            })
        }
        other => Ok(DataEvent::Other(other)),
    }
}

/// Static packet-RAM ownership for native RX and TX descriptors.
pub struct DataPath<const RX: usize, const TX: usize> {
    rx_buffer_size: usize,
    tx_buffer_size: usize,
    rx_stride: usize,
    tx_stride: usize,
    rx_base: u32,
    tx_in_flight: [bool; TX],
    rx_posted: [bool; RX],
    next_tx: usize,
}

impl<const RX: usize, const TX: usize> DataPath<RX, TX> {
    /// Builds a non-overlapping packet-RAM layout.
    pub fn new(rx_buffer_size: usize, tx_buffer_size: usize) -> Result<Self, DataLayoutError> {
        if RX == 0
            || TX == 0
            || RX > u16::MAX as usize
            || TX > MAX_TX_TOKENS
            || rx_buffer_size == 0
            || tx_buffer_size < ETHERNET_HEADER_LEN
            || rx_buffer_size > u16::MAX as usize
            || tx_buffer_size > u16::MAX as usize
        {
            return Err(DataLayoutError::InvalidCapacity);
        }
        let rx_stride = align4(
            rx_buffer_size
                .checked_add(RX_BUFFER_HEADROOM)
                .ok_or(DataLayoutError::InvalidCapacity)?,
        );
        let tx_stride = align4(
            tx_buffer_size
                .checked_add(TX_BUFFER_HEADROOM)
                .ok_or(DataLayoutError::InvalidCapacity)?,
        );
        let rx_bytes = rx_stride
            .checked_mul(RX)
            .ok_or(DataLayoutError::PacketRamExhausted)?;
        let tx_bytes = tx_stride
            .checked_mul(TX)
            .ok_or(DataLayoutError::PacketRamExhausted)?;
        if rx_bytes
            .checked_add(tx_bytes)
            .ok_or(DataLayoutError::PacketRamExhausted)?
            > RPU_PACKET_RAM_SIZE
        {
            return Err(DataLayoutError::PacketRamExhausted);
        }
        let rx_base = RPU_MEM_PACKET_END + 1 - rx_bytes as u32;
        Ok(Self {
            rx_buffer_size,
            tx_buffer_size,
            rx_stride,
            tx_stride,
            rx_base,
            tx_in_flight: [false; TX],
            rx_posted: [false; RX],
            next_tx: 0,
        })
    }

    /// Returns the RX payload capacity.
    pub const fn rx_buffer_size(&self) -> usize {
        self.rx_buffer_size
    }

    /// Returns the TX frame capacity.
    pub const fn tx_buffer_size(&self) -> usize {
        self.tx_buffer_size
    }

    /// Returns one RX packet-RAM slot, including the four-byte headroom.
    pub fn rx_slot_address(&self, descriptor: usize) -> Option<u32> {
        (descriptor < RX).then_some(self.rx_base + descriptor as u32 * self.rx_stride as u32)
    }

    /// Returns one TX packet-RAM slot.
    pub fn tx_slot_address(&self, token: usize) -> Option<u32> {
        (token < TX).then_some(RPU_MEM_PACKET_BASE + token as u32 * self.tx_stride as u32)
    }

    /// Releases local ownership state after a confirmed RPU reset.
    ///
    /// Call this only after the RPU can no longer access packet RAM and after
    /// its hardware queues are reset. RX descriptors must be posted again.
    pub fn reset_after_rpu_reset(&mut self) {
        self.tx_in_flight.fill(false);
        self.rx_posted.fill(false);
        self.next_tx = 0;
    }

    /// Posts every RX descriptor to firmware pool zero.
    pub async fn post_all_rx<B>(
        &mut self,
        device: &mut Device<B>,
    ) -> Result<(), DataError<B::Error>>
    where
        B: Bus,
    {
        for descriptor in 0..RX {
            if !self.rx_posted[descriptor] {
                self.post_rx(device, descriptor as u16, 0).await?;
            }
        }
        Ok(())
    }

    /// Posts one RX descriptor to a firmware RX queue.
    pub async fn post_rx<B>(
        &mut self,
        device: &mut Device<B>,
        descriptor: u16,
        pool_id: usize,
    ) -> Result<(), DataError<B::Error>>
    where
        B: Bus,
    {
        let index = descriptor as usize;
        if index >= RX {
            return Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                descriptor,
            )));
        }
        if self.rx_posted[index] {
            return Err(DataError::ReceiveDescriptorBusy(descriptor));
        }
        let queues = device
            .queues()
            .ok_or(DataError::Device(DeviceError::NotInitialized))?;
        if pool_id >= queues.rx_buffer_busy.len() {
            return Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                descriptor,
            )));
        }
        let command_base = device
            .rx_command_base()
            .ok_or(DataError::Device(DeviceError::NotInitialized))?;
        let slot = self.rx_slot_address(index).ok_or(DataError::Protocol(
            DataProtocolError::InvalidDescriptor(descriptor),
        ))?;
        device
            .rpu_mut()
            .write_u32(Processor::Lmac, slot, descriptor as u32)
            .await?;
        // Firmware writes at the DMA pointer. The first four bytes remain
        // host-owned descriptor headroom, as in Nordic's native HAL.
        let dma_pointer = (slot + RX_BUFFER_HEADROOM as u32) & RPU_ADDR_MASK_OFFSET;
        let command_address = command_base + RX_COMMAND_SLOT_SIZE * descriptor as u32;
        let indirect = RPU_MCU_CORE_INDIRECT_BASE | (command_address & RPU_ADDR_MASK_OFFSET);
        device
            .rpu_mut()
            .write_indirect(Processor::Lmac, indirect, &dma_pointer.to_le_bytes())
            .await?;

        // A bus error during the queue write does not prove that the write did
        // not reach hardware. Keep the descriptor unavailable until an RPU
        // reset confirms that firmware cannot own it.
        self.rx_posted[index] = true;
        if let Err(error) = device
            .enqueue(queues.rx_buffer_busy[pool_id], command_address)
            .await
        {
            return Err(DataError::QueueOwnershipUncertain(error));
        }
        Ok(())
    }

    /// Copies and converts one RX packet to an Ethernet frame, then reposts its descriptor.
    pub async fn receive_packet<B>(
        &mut self,
        device: &mut Device<B>,
        event: &RxEventRef<'_>,
        packet_index: usize,
        output: &mut [u8],
    ) -> Result<ReceivedFrame, DataError<B::Error>>
    where
        B: Bus,
    {
        let info = event.packet(packet_index).map_err(DataError::Protocol)?;
        let descriptor = info.descriptor_id as usize;
        if descriptor >= RX || !self.rx_posted[descriptor] {
            return Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                info.descriptor_id,
            )));
        }

        // Firmware consumed this descriptor when it emitted the RX event.
        self.rx_posted[descriptor] = false;
        let raw_len = info.packet_len as usize;
        if raw_len > self.rx_buffer_size {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::Protocol(DataProtocolError::FrameTooLarge));
        }
        if raw_len > output.len() {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::OutputTooSmall {
                needed: raw_len,
                capacity: output.len(),
            });
        }

        let slot = self.rx_slot_address(descriptor).ok_or(DataError::Protocol(
            DataProtocolError::InvalidDescriptor(info.descriptor_id),
        ))?;
        if let Err(error) = device
            .rpu_mut()
            .read(
                Processor::Lmac,
                slot + RX_BUFFER_HEADROOM as u32,
                &mut output[..raw_len],
            )
            .await
        {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::Rpu(error));
        }

        let conversion = convert_to_ethernet(
            &mut output[..raw_len],
            info.payload_type,
            event.mac_header_len as usize,
        );
        self.post_rx(device, info.descriptor_id, 0).await?;
        let frame_len = conversion.map_err(DataError::Protocol)?;
        let ether_type = u16::from_be_bytes([output[12], output[13]]);
        Ok(ReceivedFrame {
            len: frame_len,
            ether_type,
            descriptor_id: info.descriptor_id,
            signal_dbm: event.signal_dbm,
            frequency_mhz: event.frequency_mhz,
        })
    }

    /// Sends one complete Ethernet frame through one native TX token.
    pub async fn transmit<B>(
        &mut self,
        device: &mut Device<B>,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<u8, DataError<B::Error>>
    where
        B: Bus,
    {
        if frame.len() < ETHERNET_HEADER_LEN {
            return Err(DataError::Protocol(DataProtocolError::FrameTooShort));
        }
        if frame.len() > self.tx_buffer_size || frame.len() > u16::MAX as usize {
            return Err(DataError::Protocol(DataProtocolError::FrameTooLarge));
        }
        let token = self.reserve_tx().ok_or(DataError::NoTransmitToken)?;
        let packet_address = self
            .tx_slot_address(token as usize)
            .ok_or(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                token as u16,
            )))?;

        if let Err(error) = write_packet(device, packet_address, frame).await {
            self.tx_in_flight[token as usize] = false;
            return Err(error);
        }

        let command_base = device
            .tx_command_base()
            .ok_or(DataError::Device(DeviceError::NotInitialized))?;
        let queues = device
            .queues()
            .ok_or(DataError::Device(DeviceError::NotInitialized))?;
        let command_address = command_base + TX_COMMAND_SLOT_SIZE * token as u32;
        let command = encode_tx_command(
            wdev_id,
            token,
            frame,
            dscp_tos,
            packet_address & RPU_ADDR_MASK_OFFSET,
        );
        if let Err(error) = device
            .rpu_mut()
            .write(Processor::Umac, command_address, &command)
            .await
        {
            self.tx_in_flight[token as usize] = false;
            return Err(DataError::Rpu(error));
        }

        // After the command is written, a queue or trigger bus error can leave
        // firmware ownership uncertain. Do not release the token for reuse.
        if let Err(error) = device.enqueue(queues.command_busy, command_address).await {
            return Err(DataError::QueueOwnershipUncertain(error));
        }
        if let Err(error) = device.trigger_command().await {
            return Err(DataError::QueueOwnershipUncertain(error));
        }
        Ok(token)
    }

    /// Releases a token after `NRF_WIFI_CMD_TX_BUFF_DONE`.
    pub fn complete_tx(&mut self, token: u8) -> Result<(), DataProtocolError> {
        let index = token as usize;
        if index >= TX {
            return Err(DataProtocolError::InvalidDescriptor(token as u16));
        }
        if !self.tx_in_flight[index] {
            return Err(DataProtocolError::InvalidDescriptor(token as u16));
        }
        self.tx_in_flight[index] = false;
        Ok(())
    }

    fn reserve_tx(&mut self) -> Option<u8> {
        for offset in 0..TX {
            let index = (self.next_tx + offset) % TX;
            if !self.tx_in_flight[index] {
                self.tx_in_flight[index] = true;
                self.next_tx = (index + 1) % TX;
                return Some(index as u8);
            }
        }
        None
    }
}

/// Metadata for one delivered Ethernet frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedFrame {
    pub len: usize,
    pub ether_type: u16,
    pub descriptor_id: u16,
    pub signal_dbm: i16,
    pub frequency_mhz: u16,
}

async fn write_packet<B>(
    device: &mut Device<B>,
    address: u32,
    frame: &[u8],
) -> Result<(), DataError<B::Error>>
where
    B: Bus,
{
    let aligned = frame.len() & !3;
    if aligned != 0 {
        device
            .rpu_mut()
            .write(Processor::Umac, address, &frame[..aligned])
            .await?;
    }
    if aligned != frame.len() {
        let mut tail = [0u8; 4];
        tail[..frame.len() - aligned].copy_from_slice(&frame[aligned..]);
        device
            .rpu_mut()
            .write(Processor::Umac, address + aligned as u32, &tail)
            .await?;
    }
    Ok(())
}

fn encode_tx_command(
    wdev_id: u8,
    token: u8,
    frame: &[u8],
    dscp_tos: u16,
    dma_pointer: u32,
) -> [u8; TX_COMMAND_TOTAL_LEN] {
    let mut out = [0u8; TX_COMMAND_TOTAL_LEN];
    put_u32(&mut out, 0, TX_COMMAND_TOTAL_LEN as u32);
    put_u32(&mut out, 4, 0);
    put_i32(&mut out, 8, HostMessageType::Data as i32);
    let payload = &mut out[HOST_MESSAGE_HEADER_LEN..];
    put_u32(payload, 0, DataCommand::TransmitBuffer as u32);
    put_u32(payload, 4, TX_COMMAND_PAYLOAD_LEN as u32);
    payload[8] = wdev_id;
    payload[9] = token;
    put_i32(payload, 10, 0); // umac_fill_flags
    put_u16(payload, 14, 0); // frame control
    payload[16..22].copy_from_slice(&frame[0..6]);
    payload[22..28].copy_from_slice(&frame[6..12]);
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    put_u16(payload, 28, ether_type);
    put_u32(payload, 30, dscp_tos as u32);
    payload[34] = 0; // more_data
    payload[35] = 0; // eosp
    put_u32(payload, 36, 0); // pending buffer size
    payload[40] = 1; // packet count
    put_u16(payload, 41, frame.len() as u16);
    put_u32(payload, 43, dma_pointer);
    out
}

fn convert_to_ethernet(
    frame: &mut [u8],
    payload_type: RxPayloadType,
    mac_header_len: usize,
) -> Result<usize, DataProtocolError> {
    match payload_type {
        RxPayloadType::Mpdu => convert_mpdu(frame, mac_header_len),
        RxPayloadType::MsduWithMac => convert_msdu(frame, mac_header_len),
        RxPayloadType::Msdu => convert_msdu(frame, 0),
    }
}

fn convert_mpdu(frame: &mut [u8], mac_header_len: usize) -> Result<usize, DataProtocolError> {
    if mac_header_len < 24 || frame.len() < mac_header_len + 2 {
        return Err(DataProtocolError::FrameTooShort);
    }
    let fc = read_u16(frame, 0);
    let (destination, source) = ieee80211_addresses(frame, fc)?;
    let ether_type = llc_ether_type(frame, mac_header_len)?;
    let skip = llc_skip(ether_type);
    let payload_offset = mac_header_len
        .checked_add(skip)
        .ok_or(DataProtocolError::InvalidLength)?;
    rebuild_ethernet(frame, payload_offset, destination, source, ether_type)
}

fn convert_msdu(frame: &mut [u8], mac_header_len: usize) -> Result<usize, DataProtocolError> {
    let amsdu = mac_header_len;
    if frame.len() < amsdu + 14 + 2 {
        return Err(DataProtocolError::FrameTooShort);
    }
    let mut destination = [0u8; 6];
    let mut source = [0u8; 6];
    destination.copy_from_slice(&frame[amsdu..amsdu + 6]);
    source.copy_from_slice(&frame[amsdu + 6..amsdu + 12]);
    let llc = amsdu + 14;
    let ether_type = llc_ether_type(frame, llc)?;
    let payload_offset = llc
        .checked_add(llc_skip(ether_type))
        .ok_or(DataProtocolError::InvalidLength)?;
    rebuild_ethernet(frame, payload_offset, destination, source, ether_type)
}

fn ieee80211_addresses(
    frame: &[u8],
    frame_control: u16,
) -> Result<([u8; 6], [u8; 6]), DataProtocolError> {
    if frame.len() < 24 {
        return Err(DataProtocolError::FrameTooShort);
    }
    let mut address1 = [0u8; 6];
    let mut address2 = [0u8; 6];
    let mut address3 = [0u8; 6];
    address1.copy_from_slice(&frame[4..10]);
    address2.copy_from_slice(&frame[10..16]);
    address3.copy_from_slice(&frame[16..22]);
    let to_ds = frame_control & 0x0100 != 0;
    let from_ds = frame_control & 0x0200 != 0;
    match (to_ds, from_ds) {
        (true, true) => {
            if frame.len() < 30 {
                return Err(DataProtocolError::FrameTooShort);
            }
            let mut address4 = [0u8; 6];
            address4.copy_from_slice(&frame[24..30]);
            Ok((address3, address4))
        }
        (false, true) => Ok((address1, address3)),
        (true, false) => Ok((address3, address2)),
        (false, false) => Ok((address1, address2)),
    }
}

fn llc_ether_type(frame: &[u8], offset: usize) -> Result<u16, DataProtocolError> {
    let end = offset
        .checked_add(8)
        .ok_or(DataProtocolError::InvalidLength)?;
    if end > frame.len() {
        return Err(DataProtocolError::FrameTooShort);
    }
    Ok(u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]))
}

fn llc_skip(ether_type: u16) -> usize {
    if ether_type == 0x80f3 || ether_type == 0x8137 || ether_type >= 0x0600 {
        8
    } else {
        2
    }
}

fn rebuild_ethernet(
    frame: &mut [u8],
    payload_offset: usize,
    destination: [u8; 6],
    source: [u8; 6],
    ether_type: u16,
) -> Result<usize, DataProtocolError> {
    if payload_offset > frame.len() {
        return Err(DataProtocolError::FrameTooShort);
    }
    let payload_len = frame.len() - payload_offset;
    let new_len = ETHERNET_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DataProtocolError::InvalidLength)?;
    if new_len > frame.len() {
        return Err(DataProtocolError::FrameTooLarge);
    }
    frame.copy_within(payload_offset.., ETHERNET_HEADER_LEN);
    frame[0..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
    Ok(new_len)
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_i16(bytes: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{HostMessageType, encode_host_message, parse_host_message};
    use super::*;

    #[test]
    fn packet_ram_layout_does_not_overlap() {
        let layout = DataPath::<8, 4>::new(1600, 1514).unwrap();
        let tx_end = layout.tx_slot_address(3).unwrap() + layout.tx_stride as u32;
        assert!(tx_end <= layout.rx_base);
        assert_eq!(
            layout.rx_slot_address(7).unwrap() + layout.rx_stride as u32,
            RPU_MEM_PACKET_END + 1
        );
    }

    #[test]
    fn tx_command_slots_stop_before_packet_data() {
        assert_eq!(MAX_TX_TOKENS, 137);
        assert!(DataPath::<137, 137>::new(1, ETHERNET_HEADER_LEN).is_ok());
        assert_eq!(
            DataPath::<1, 138>::new(1, ETHERNET_HEADER_LEN).err(),
            Some(DataLayoutError::InvalidCapacity)
        );
    }

    #[test]
    fn reset_releases_local_ownership_after_rpu_reset() {
        let mut layout = DataPath::<2, 2>::new(1600, 1514).unwrap();
        layout.tx_in_flight = [true, true];
        layout.rx_posted = [true, true];
        layout.next_tx = 1;
        layout.reset_after_rpu_reset();
        assert_eq!(layout.tx_in_flight, [false, false]);
        assert_eq!(layout.rx_posted, [false, false]);
        assert_eq!(layout.next_tx, 0);
    }

    #[test]
    fn tx_command_has_exact_packed_layout() {
        let mut frame = [0u8; ETHERNET_HEADER_LEN];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let command = encode_tx_command(0, 2, &frame, 7, 0x5000);
        assert_eq!(read_u32(&command, 0) as usize, TX_COMMAND_TOTAL_LEN);
        assert_eq!(read_u32(&command, 12), DataCommand::TransmitBuffer as u32);
        assert_eq!(command[20], 0);
        assert_eq!(command[21], 2);
        assert_eq!(read_u16(&command, 40), 0x0800);
        assert_eq!(read_u16(&command, 53), ETHERNET_HEADER_LEN as u16);
        assert_eq!(read_u32(&command, 55), 0x5000);
    }

    #[test]
    fn converts_from_ds_mpdu_to_ethernet() {
        let mut frame = [0u8; 64];
        frame[0..2].copy_from_slice(&0x0208u16.to_le_bytes());
        frame[4..10].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        frame[10..16].copy_from_slice(&[2, 2, 2, 2, 2, 2]);
        frame[16..22].copy_from_slice(&[3, 3, 3, 3, 3, 3]);
        frame[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]);
        frame[32..36].copy_from_slice(&[9, 8, 7, 6]);
        let len = convert_mpdu(&mut frame[..36], 24).unwrap();
        assert_eq!(len, 18);
        assert_eq!(&frame[0..6], &[1; 6]);
        assert_eq!(&frame[6..12], &[3; 6]);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[14..18], &[9, 8, 7, 6]);
    }

    #[test]
    fn converts_four_address_mpdu_to_ethernet() {
        let mut frame = [0u8; 64];
        frame[0..2].copy_from_slice(&0x0308u16.to_le_bytes());
        frame[4..10].copy_from_slice(&[1; 6]);
        frame[10..16].copy_from_slice(&[2; 6]);
        frame[16..22].copy_from_slice(&[3; 6]);
        frame[24..30].copy_from_slice(&[4; 6]);
        frame[30..38].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]);
        frame[38..42].copy_from_slice(&[9, 8, 7, 6]);
        let len = convert_mpdu(&mut frame[..42], 30).unwrap();
        assert_eq!(len, 18);
        assert_eq!(&frame[0..6], &[3; 6]);
        assert_eq!(&frame[6..12], &[4; 6]);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[14..18], &[9, 8, 7, 6]);
    }

    #[test]
    fn classifies_data_message() {
        let mut payload = [0u8; 12];
        put_u32(&mut payload, 0, DataCommand::CarrierOn as u32);
        put_u32(&mut payload, 4, 12);
        put_u32(&mut payload, 8, 1);
        let mut message = [0u8; 32];
        let len = encode_host_message(&mut message, HostMessageType::Data, true, &payload).unwrap();
        let parsed = parse_host_message(&message[..len]).unwrap();
        assert_eq!(
            classify_data_event(parsed),
            Ok(DataEvent::CarrierOn { wdev_id: 1 })
        );
    }

    #[test]
    fn protocol_error_type_is_independent() {
        let _ = super::super::protocol::ProtocolError::InvalidLength;
    }
}
