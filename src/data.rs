//! Native packet-RAM allocator and nRF70 data descriptors.

use super::bus::Bus;
use super::device::{Device, DeviceError, RPU_MEM_TX_CMD_BASE};
use super::memory::{Processor, RPU_ADDR_MASK_OFFSET, RPU_MCU_CORE_INDIRECT_BASE, RpuError};
pub use super::protocol::DataCommand;
use super::protocol::{HOST_MESSAGE_HEADER_LEN, HostMessageRef, HostMessageType, Hpq};

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
const TX_DONE_FIXED_LEN: usize = 22;
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
    OutputTooSmall {
        needed: usize,
        capacity: usize,
    },
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
        let (payload, declared) =
            validated_data_payload(message, DataCommand::ReceiveBuffer, RX_EVENT_FIXED_LEN)?;
        let packet_count = payload[13];
        validate_rx_packet_array(declared, packet_count)?;
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

/// Borrowed view of one firmware TX-done event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxDoneEventRef<'a> {
    /// Descriptor token released by firmware.
    pub token: u8,
    /// Per-packet firmware status bytes. Zero means success.
    pub statuses: &'a [u8],
}

impl<'a> TxDoneEventRef<'a> {
    /// Parses `NRF_WIFI_CMD_TX_BUFF_DONE` and validates its status array.
    pub fn parse(message: HostMessageRef<'a>) -> Result<Self, DataProtocolError> {
        let (payload, declared) =
            validated_data_payload(message, DataCommand::TransmitDone, TX_DONE_FIXED_LEN)?;
        let status_count = payload[9] as usize;
        let required = TX_DONE_FIXED_LEN
            .checked_add(status_count)
            .ok_or(DataProtocolError::InvalidLength)?;
        if declared != required {
            return Err(DataProtocolError::InvalidLength);
        }
        Ok(Self {
            token: payload[8],
            statuses: &payload[TX_DONE_FIXED_LEN..required],
        })
    }

    /// Returns true only when all packet status bytes report success.
    pub fn all_succeeded(&self) -> bool {
        !self.statuses.is_empty() && self.statuses.iter().all(|status| *status == 0)
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
    classify_data_command(message, command, declared)
}

fn validated_data_payload(
    message: HostMessageRef<'_>,
    expected_command: DataCommand,
    minimum_len: usize,
) -> Result<(&[u8], usize), DataProtocolError> {
    if message.message_type != HostMessageType::Data {
        return Err(DataProtocolError::WrongMessageType);
    }
    let payload = message.payload;
    if payload.len() < minimum_len {
        return Err(DataProtocolError::InvalidLength);
    }
    let command = read_u32(payload, 0);
    if command != expected_command as u32 {
        return Err(DataProtocolError::InvalidCommand(command));
    }
    let declared = read_u32(payload, 4) as usize;
    if declared < minimum_len || declared > payload.len() {
        return Err(DataProtocolError::InvalidLength);
    }
    Ok((payload, declared))
}

fn validate_rx_packet_array(declared: usize, packet_count: u8) -> Result<(), DataProtocolError> {
    let packet_bytes = (packet_count as usize)
        .checked_mul(RX_INFO_LEN)
        .ok_or(DataProtocolError::InvalidLength)?;
    let required = RX_EVENT_FIXED_LEN
        .checked_add(packet_bytes)
        .ok_or(DataProtocolError::InvalidLength)?;
    if required > declared {
        return Err(DataProtocolError::InvalidLength);
    }
    Ok(())
}

fn classify_data_command(
    message: HostMessageRef<'_>,
    command: u32,
    declared: usize,
) -> Result<DataEvent, DataProtocolError> {
    match command {
        2 => classify_transmit_done(message),
        3 => Ok(DataEvent::Receive),
        4 => classify_carrier(message.payload, declared, true),
        5 => classify_carrier(message.payload, declared, false),
        other => Ok(DataEvent::Other(other)),
    }
}

fn classify_transmit_done(message: HostMessageRef<'_>) -> Result<DataEvent, DataProtocolError> {
    let event = TxDoneEventRef::parse(message)?;
    Ok(DataEvent::TransmitDone {
        token: event.token,
        status_count: event.statuses.len() as u8,
    })
}

fn classify_carrier(
    payload: &[u8],
    declared: usize,
    on: bool,
) -> Result<DataEvent, DataProtocolError> {
    if declared < 12 {
        return Err(DataProtocolError::InvalidLength);
    }
    let wdev_id = read_u32(payload, 8);
    if on {
        Ok(DataEvent::CarrierOn { wdev_id })
    } else {
        Ok(DataEvent::CarrierOff { wdev_id })
    }
}

fn validate_layout_capacity<const RX: usize, const TX: usize>(
    rx_buffer_size: usize,
    tx_buffer_size: usize,
) -> Result<(), DataLayoutError> {
    validate_descriptor_counts::<RX, TX>()?;
    validate_buffer_sizes(rx_buffer_size, tx_buffer_size)
}

fn validate_descriptor_counts<const RX: usize, const TX: usize>() -> Result<(), DataLayoutError> {
    if RX == 0 || TX == 0 {
        return Err(DataLayoutError::InvalidCapacity);
    }
    if RX > u16::MAX as usize || TX > MAX_TX_TOKENS {
        return Err(DataLayoutError::InvalidCapacity);
    }
    Ok(())
}

fn validate_buffer_sizes(
    rx_buffer_size: usize,
    tx_buffer_size: usize,
) -> Result<(), DataLayoutError> {
    if rx_buffer_size == 0 || tx_buffer_size < ETHERNET_HEADER_LEN {
        return Err(DataLayoutError::InvalidCapacity);
    }
    if rx_buffer_size > u16::MAX as usize || tx_buffer_size > u16::MAX as usize {
        return Err(DataLayoutError::InvalidCapacity);
    }
    Ok(())
}

fn layout_strides(
    rx_buffer_size: usize,
    tx_buffer_size: usize,
) -> Result<(usize, usize), DataLayoutError> {
    let rx_with_headroom = rx_buffer_size
        .checked_add(RX_BUFFER_HEADROOM)
        .ok_or(DataLayoutError::InvalidCapacity)?;
    let tx_with_headroom = tx_buffer_size
        .checked_add(TX_BUFFER_HEADROOM)
        .ok_or(DataLayoutError::InvalidCapacity)?;
    Ok((align4(rx_with_headroom), align4(tx_with_headroom)))
}

fn validated_layout_bytes<const RX: usize, const TX: usize>(
    rx_stride: usize,
    tx_stride: usize,
) -> Result<usize, DataLayoutError> {
    let rx_bytes = rx_stride
        .checked_mul(RX)
        .ok_or(DataLayoutError::PacketRamExhausted)?;
    let tx_bytes = tx_stride
        .checked_mul(TX)
        .ok_or(DataLayoutError::PacketRamExhausted)?;
    let total = rx_bytes
        .checked_add(tx_bytes)
        .ok_or(DataLayoutError::PacketRamExhausted)?;
    if total > RPU_PACKET_RAM_SIZE {
        return Err(DataLayoutError::PacketRamExhausted);
    }
    Ok(rx_bytes)
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
        validate_layout_capacity::<RX, TX>(rx_buffer_size, tx_buffer_size)?;
        let (rx_stride, tx_stride) = layout_strides(rx_buffer_size, tx_buffer_size)?;
        let rx_bytes = validated_layout_bytes::<RX, TX>(rx_stride, tx_stride)?;
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
        let index = self.available_rx_index(descriptor)?;
        let (queue, command_base) = rx_queue_context(device, pool_id, descriptor)?;
        let slot = self.rx_slot_address(index).ok_or(DataError::Protocol(
            DataProtocolError::InvalidDescriptor(descriptor),
        ))?;
        let command_address = prepare_rx_descriptor(device, slot, command_base, descriptor).await?;

        // A bus error during the queue write does not prove that the write did
        // not reach hardware. Keep the descriptor unavailable until an RPU
        // reset confirms that firmware cannot own it.
        self.rx_posted[index] = true;
        device
            .enqueue(queue, command_address)
            .await
            .map_err(DataError::QueueOwnershipUncertain)
    }

    fn available_rx_index<E>(&self, descriptor: u16) -> Result<usize, DataError<E>> {
        let index = descriptor as usize;
        if index >= RX {
            return Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                descriptor,
            )));
        }
        if self.rx_posted[index] {
            return Err(DataError::ReceiveDescriptorBusy(descriptor));
        }
        Ok(index)
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
        let (info, descriptor, raw_len) = self.take_rx_descriptor(event, packet_index)?;
        self.ensure_receive_capacity(device, info, raw_len, output.len())
            .await?;
        let slot = self.rx_slot_address(descriptor).ok_or(DataError::Protocol(
            DataProtocolError::InvalidDescriptor(info.descriptor_id),
        ))?;
        self.read_rx_or_repost(device, info, slot, &mut output[..raw_len])
            .await?;
        let conversion = convert_to_ethernet(
            &mut output[..raw_len],
            info.payload_type,
            event.mac_header_len as usize,
        );
        self.post_rx(device, info.descriptor_id, 0).await?;
        received_frame(conversion, output, info, event)
    }

    fn take_rx_descriptor<E>(
        &mut self,
        event: &RxEventRef<'_>,
        packet_index: usize,
    ) -> Result<(RxPacketInfo, usize, usize), DataError<E>> {
        let info = event.packet(packet_index).map_err(DataError::Protocol)?;
        let descriptor = info.descriptor_id as usize;
        if descriptor >= RX || !self.rx_posted[descriptor] {
            return Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(
                info.descriptor_id,
            )));
        }
        self.rx_posted[descriptor] = false;
        Ok((info, descriptor, info.packet_len as usize))
    }

    async fn ensure_receive_capacity<B>(
        &mut self,
        device: &mut Device<B>,
        info: RxPacketInfo,
        raw_len: usize,
        output_len: usize,
    ) -> Result<(), DataError<B::Error>>
    where
        B: Bus,
    {
        if raw_len > self.rx_buffer_size {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::Protocol(DataProtocolError::FrameTooLarge));
        }
        if raw_len > output_len {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::OutputTooSmall {
                needed: raw_len,
                capacity: output_len,
            });
        }
        Ok(())
    }

    async fn read_rx_or_repost<B>(
        &mut self,
        device: &mut Device<B>,
        info: RxPacketInfo,
        slot: u32,
        output: &mut [u8],
    ) -> Result<(), DataError<B::Error>>
    where
        B: Bus,
    {
        if let Err(error) = device
            .rpu_mut()
            .read(Processor::Lmac, slot + RX_BUFFER_HEADROOM as u32, output)
            .await
        {
            self.post_rx(device, info.descriptor_id, 0).await?;
            return Err(DataError::Rpu(error));
        }
        Ok(())
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
        let (token, packet_address) = self.prepare_transmit(device, frame).await?;
        self.submit_transmit(device, token, packet_address, wdev_id, frame, dscp_tos)
            .await?;
        Ok(token)
    }

    async fn prepare_transmit<B>(
        &mut self,
        device: &mut Device<B>,
        frame: &[u8],
    ) -> Result<(u8, u32), DataError<B::Error>>
    where
        B: Bus,
    {
        validate_transmit_frame(frame, self.tx_buffer_size)?;
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
        Ok((token, packet_address))
    }

    async fn submit_transmit<B>(
        &mut self,
        device: &mut Device<B>,
        token: u8,
        packet_address: u32,
        wdev_id: u8,
        frame: &[u8],
        dscp_tos: u16,
    ) -> Result<(), DataError<B::Error>>
    where
        B: Bus,
    {
        let (command_base, command_queue) = transmit_queue_context(device)?;
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
        deliver_transmit_command(device, command_queue, command_address).await
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

fn rx_queue_context<B: Bus>(
    device: &Device<B>,
    pool_id: usize,
    descriptor: u16,
) -> Result<(Hpq, u32), DataError<B::Error>> {
    let queues = device
        .queues()
        .ok_or(DataError::Device(DeviceError::NotInitialized))?;
    let queue = queues
        .rx_buffer_busy
        .get(pool_id)
        .copied()
        .ok_or(DataError::Protocol(DataProtocolError::InvalidDescriptor(
            descriptor,
        )))?;
    let command_base = device
        .rx_command_base()
        .ok_or(DataError::Device(DeviceError::NotInitialized))?;
    Ok((queue, command_base))
}

async fn prepare_rx_descriptor<B: Bus>(
    device: &mut Device<B>,
    slot: u32,
    command_base: u32,
    descriptor: u16,
) -> Result<u32, DataError<B::Error>> {
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
    Ok(command_address)
}

fn received_frame<E>(
    conversion: Result<usize, DataProtocolError>,
    output: &[u8],
    info: RxPacketInfo,
    event: &RxEventRef<'_>,
) -> Result<ReceivedFrame, DataError<E>> {
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

fn validate_transmit_frame<E>(frame: &[u8], capacity: usize) -> Result<(), DataError<E>> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(DataError::Protocol(DataProtocolError::FrameTooShort));
    }
    if frame.len() > capacity || frame.len() > u16::MAX as usize {
        return Err(DataError::Protocol(DataProtocolError::FrameTooLarge));
    }
    Ok(())
}

fn transmit_queue_context<B: Bus>(device: &Device<B>) -> Result<(u32, Hpq), DataError<B::Error>> {
    let command_base = device
        .tx_command_base()
        .ok_or(DataError::Device(DeviceError::NotInitialized))?;
    let queues = device
        .queues()
        .ok_or(DataError::Device(DeviceError::NotInitialized))?;
    Ok((command_base, queues.command_busy))
}

async fn deliver_transmit_command<B: Bus>(
    device: &mut Device<B>,
    command_queue: Hpq,
    command_address: u32,
) -> Result<(), DataError<B::Error>> {
    // After the command is written, a queue or trigger bus error can leave
    // firmware ownership uncertain. Do not release the token for reuse.
    if let Err(error) = device.enqueue(command_queue, command_address).await {
        return Err(DataError::QueueOwnershipUncertain(error));
    }
    if let Err(error) = device.trigger_command().await {
        return Err(DataError::QueueOwnershipUncertain(error));
    }
    Ok(())
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
    if mac_header_len < 24 {
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
    let header_end = amsdu
        .checked_add(14)
        .ok_or(DataProtocolError::InvalidLength)?;
    if frame.len() < header_end {
        return Err(DataProtocolError::FrameTooShort);
    }
    let mut destination = [0u8; 6];
    let mut source = [0u8; 6];
    destination.copy_from_slice(&frame[amsdu..amsdu + 6]);
    source.copy_from_slice(&frame[amsdu + 6..amsdu + 12]);
    let llc = header_end;
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
    if to_ds && from_ds {
        return four_address_mapping(frame, address3);
    }
    Ok(three_address_mapping(
        address1, address2, address3, to_ds, from_ds,
    ))
}

fn four_address_mapping(
    frame: &[u8],
    destination: [u8; 6],
) -> Result<([u8; 6], [u8; 6]), DataProtocolError> {
    if frame.len() < 30 {
        return Err(DataProtocolError::FrameTooShort);
    }
    let mut source = [0u8; 6];
    source.copy_from_slice(&frame[24..30]);
    Ok((destination, source))
}

fn three_address_mapping(
    address1: [u8; 6],
    address2: [u8; 6],
    address3: [u8; 6],
    to_ds: bool,
    from_ds: bool,
) -> ([u8; 6], [u8; 6]) {
    if to_ds {
        (address3, address2)
    } else if from_ds {
        (address1, address3)
    } else {
        (address1, address2)
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
    if ether_type >= 0x0600 { 8 } else { 2 }
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
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    use super::super::memory::host_offset;
    use super::super::protocol::{
        HostMessageType, Hpq, HpqmInfo, encode_host_message, parse_host_message,
    };
    use super::*;
    use crate::test_support::block_on;

    #[derive(Default)]
    struct TestBus {
        read_responses: VecDeque<Vec<u8>>,
        reads: Vec<(u32, usize)>,
        writes: Vec<(u32, Vec<u8>)>,
    }

    impl Bus for TestBus {
        type Error = ();

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            self.reads.push((address, data.len()));
            let response = self
                .read_responses
                .pop_front()
                .unwrap_or_else(|| vec![0; data.len()]);
            assert_eq!(response.len(), data.len());
            data.copy_from_slice(&response);
            Ok(())
        }

        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailingBusError {
        Read,
        Write,
    }

    #[derive(Default)]
    struct FailingBus {
        fail_read: bool,
        fail_write_at: Option<usize>,
        write_attempts: usize,
    }

    impl Bus for FailingBus {
        type Error = FailingBusError;

        async fn read_status(&mut self, _opcode: u8) -> Result<u8, Self::Error> {
            Ok(0)
        }

        async fn write_status(&mut self, _opcode: u8, _value: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read(&mut self, _address: u32, data: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(FailingBusError::Read);
            }
            data.fill(0);
            Ok(())
        }

        async fn write(&mut self, _address: u32, _data: &[u8]) -> Result<(), Self::Error> {
            let attempt = self.write_attempts;
            self.write_attempts += 1;
            if self.fail_write_at == Some(attempt) {
                return Err(FailingBusError::Write);
            }
            Ok(())
        }
    }

    fn queues() -> HpqmInfo {
        HpqmInfo {
            event_busy: Hpq {
                enqueue_address: 0xa400_6004,
                dequeue_address: 0xa400_6000,
            },
            event_available: Hpq {
                enqueue_address: 0xa400_6014,
                dequeue_address: 0xa400_6010,
            },
            command_busy: Hpq {
                enqueue_address: 0xa400_6024,
                dequeue_address: 0xa400_6020,
            },
            command_available: Hpq {
                enqueue_address: 0xa400_7004,
                dequeue_address: 0xa400_7000,
            },
            rx_buffer_busy: [
                Hpq {
                    enqueue_address: 0xa400_6034,
                    dequeue_address: 0xa400_6030,
                },
                Hpq {
                    enqueue_address: 0xa400_6044,
                    dequeue_address: 0xa400_6040,
                },
                Hpq {
                    enqueue_address: 0xa400_6054,
                    dequeue_address: 0xa400_6050,
                },
            ],
        }
    }

    fn device(bus: TestBus) -> Device<TestBus> {
        let mut device = Device::new(bus);
        device.initialize_for_test(queues(), 0xb000_2000);
        device
    }

    fn failing_device(bus: FailingBus) -> Device<FailingBus> {
        let mut device = Device::new(bus);
        device.initialize_for_test(queues(), 0xb000_2000);
        device
    }

    fn data_message<'a>(payload: &'a [u8]) -> HostMessageRef<'a> {
        HostMessageRef {
            resubmit: false,
            message_type: HostMessageType::Data,
            payload,
        }
    }

    fn rx_event_payload(descriptor: u16, packet_len: u16, payload_type: u8) -> Vec<u8> {
        let mut payload = vec![0; RX_EVENT_FIXED_LEN + RX_INFO_LEN];
        put_u32(&mut payload, 0, DataCommand::ReceiveBuffer as u32);
        let len = payload.len() as u32;
        put_u32(&mut payload, 4, len);
        payload[13] = 1;
        payload[15] = 24;
        put_u16(&mut payload, 16, 2412);
        payload[18..20].copy_from_slice(&(-42i16).to_le_bytes());
        put_u16(&mut payload, RX_EVENT_FIXED_LEN, descriptor);
        put_u16(&mut payload, RX_EVENT_FIXED_LEN + 2, packet_len);
        payload[RX_EVENT_FIXED_LEN + 4] = payload_type;
        payload
    }

    fn ethernet_frame(len: usize) -> Vec<u8> {
        let mut frame = vec![0; len];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame
    }

    #[test]
    fn packet_ram_layout_does_not_overlap() {
        let layout = DataPath::<8, 4>::new(1600, 1514).unwrap();
        assert_eq!(layout.rx_buffer_size(), 1600);
        assert_eq!(layout.tx_buffer_size(), 1514);
        assert_eq!(layout.rx_slot_address(8), None);
        assert_eq!(layout.tx_slot_address(4), None);
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
        assert_eq!(
            DataPath::<0, 1>::new(1, ETHERNET_HEADER_LEN).err(),
            Some(DataLayoutError::InvalidCapacity)
        );
        assert_eq!(
            DataPath::<1, 0>::new(1, ETHERNET_HEADER_LEN).err(),
            Some(DataLayoutError::InvalidCapacity)
        );
        assert_eq!(
            DataPath::<65536, 1>::new(1, ETHERNET_HEADER_LEN).err(),
            Some(DataLayoutError::InvalidCapacity)
        );
        for (rx_size, tx_size) in [
            (0, ETHERNET_HEADER_LEN),
            (1, ETHERNET_HEADER_LEN - 1),
            (u16::MAX as usize + 1, ETHERNET_HEADER_LEN),
            (1, u16::MAX as usize + 1),
        ] {
            assert_eq!(
                DataPath::<1, 1>::new(rx_size, tx_size).err(),
                Some(DataLayoutError::InvalidCapacity)
            );
        }
        assert_eq!(
            DataPath::<137, 137>::new(u16::MAX as usize, u16::MAX as usize).err(),
            Some(DataLayoutError::PacketRamExhausted)
        );
        assert_eq!(
            layout_strides(usize::MAX, 14),
            Err(DataLayoutError::InvalidCapacity)
        );
        assert_eq!(
            validated_layout_bytes::<2, 1>(usize::MAX, 1),
            Err(DataLayoutError::PacketRamExhausted)
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
        assert_eq!(command[52], 1);
    }

    #[test]
    fn rx_and_tx_event_parsers_reject_every_invalid_boundary() {
        for value in 0..=2 {
            assert_eq!(RxPayloadType::from_u8(value).unwrap() as u8, value);
        }
        assert_eq!(
            RxPayloadType::from_u8(3),
            Err(DataProtocolError::InvalidRxPayloadType(3))
        );

        let payload = rx_event_payload(7, 100, RxPayloadType::Msdu as u8);
        let event = RxEventRef::parse(data_message(&payload)).unwrap();
        assert_eq!(event.packet_count, 1);
        assert_eq!(
            event.packet(0),
            Ok(RxPacketInfo {
                descriptor_id: 7,
                packet_len: 100,
                payload_type: RxPayloadType::Msdu,
            })
        );
        assert_eq!(event.packet(1), Err(DataProtocolError::InvalidPacketIndex));

        let mut two_packets = vec![0; RX_EVENT_FIXED_LEN + 2 * RX_INFO_LEN];
        put_u32(&mut two_packets, 0, DataCommand::ReceiveBuffer as u32);
        let two_packet_len = two_packets.len() as u32;
        put_u32(&mut two_packets, 4, two_packet_len);
        two_packets[13] = 2;
        let second = RX_EVENT_FIXED_LEN + RX_INFO_LEN;
        put_u16(&mut two_packets, second, 9);
        put_u16(&mut two_packets, second + 2, 321);
        two_packets[second + 4] = RxPayloadType::MsduWithMac as u8;
        assert_eq!(
            RxEventRef::parse(data_message(&two_packets))
                .unwrap()
                .packet(1),
            Ok(RxPacketInfo {
                descriptor_id: 9,
                packet_len: 321,
                payload_type: RxPayloadType::MsduWithMac,
            })
        );

        let mut invalid_type = payload.clone();
        invalid_type[RX_EVENT_FIXED_LEN + 4] = 3;
        let event = RxEventRef::parse(data_message(&invalid_type)).unwrap();
        assert_eq!(
            event.packet(0),
            Err(DataProtocolError::InvalidRxPayloadType(3))
        );
        assert_eq!(
            RxEventRef::parse(HostMessageRef {
                message_type: HostMessageType::System,
                ..data_message(&payload)
            }),
            Err(DataProtocolError::WrongMessageType)
        );
        assert_eq!(
            RxEventRef::parse(data_message(&payload[..RX_EVENT_FIXED_LEN - 1])),
            Err(DataProtocolError::InvalidLength)
        );
        let mut wrong_command = payload.clone();
        put_u32(&mut wrong_command, 0, 99);
        assert_eq!(
            RxEventRef::parse(data_message(&wrong_command)),
            Err(DataProtocolError::InvalidCommand(99))
        );
        for declared in [
            RX_EVENT_FIXED_LEN - 1,
            payload.len() + 1,
            RX_EVENT_FIXED_LEN,
        ] {
            let mut invalid = payload.clone();
            put_u32(&mut invalid, 4, declared as u32);
            assert_eq!(
                RxEventRef::parse(data_message(&invalid)),
                Err(DataProtocolError::InvalidLength)
            );
        }

        let mut tx = vec![0; TX_DONE_FIXED_LEN + 2];
        put_u32(&mut tx, 0, DataCommand::TransmitDone as u32);
        let tx_len = tx.len() as u32;
        put_u32(&mut tx, 4, tx_len);
        tx[8] = 4;
        tx[9] = 2;
        let event = TxDoneEventRef::parse(data_message(&tx)).unwrap();
        assert!(event.all_succeeded());
        tx[TX_DONE_FIXED_LEN] = 1;
        assert!(
            !TxDoneEventRef::parse(data_message(&tx))
                .unwrap()
                .all_succeeded()
        );
        tx[9] = 0;
        put_u32(&mut tx, 4, TX_DONE_FIXED_LEN as u32);
        assert!(
            !TxDoneEventRef::parse(data_message(&tx))
                .unwrap()
                .all_succeeded()
        );
        put_u32(&mut tx, 4, (TX_DONE_FIXED_LEN + 1) as u32);
        assert_eq!(
            TxDoneEventRef::parse(data_message(&tx)),
            Err(DataProtocolError::InvalidLength)
        );
    }

    #[test]
    fn classifies_every_data_event_and_rejects_bad_headers() {
        let mut payload = vec![0; TX_DONE_FIXED_LEN + 1];
        put_u32(&mut payload, 0, DataCommand::TransmitDone as u32);
        let len = payload.len() as u32;
        put_u32(&mut payload, 4, len);
        payload[8] = 3;
        payload[9] = 1;
        assert_eq!(
            classify_data_event(data_message(&payload)),
            Ok(DataEvent::TransmitDone {
                token: 3,
                status_count: 1,
            })
        );
        for (command, expected) in [
            (DataCommand::ReceiveBuffer as u32, DataEvent::Receive),
            (99, DataEvent::Other(99)),
        ] {
            let mut payload = [0; 8];
            put_u32(&mut payload, 0, command);
            put_u32(&mut payload, 4, 8);
            assert_eq!(classify_data_event(data_message(&payload)), Ok(expected));
        }
        for (command, expected) in [
            (
                DataCommand::CarrierOn as u32,
                DataEvent::CarrierOn { wdev_id: 7 },
            ),
            (
                DataCommand::CarrierOff as u32,
                DataEvent::CarrierOff { wdev_id: 7 },
            ),
        ] {
            let mut payload = [0; 12];
            put_u32(&mut payload, 0, command);
            put_u32(&mut payload, 4, 12);
            put_u32(&mut payload, 8, 7);
            assert_eq!(classify_data_event(data_message(&payload)), Ok(expected));
            put_u32(&mut payload, 4, 8);
            assert_eq!(
                classify_data_event(data_message(&payload)),
                Err(DataProtocolError::InvalidLength)
            );
        }
        assert_eq!(
            classify_data_event(HostMessageRef {
                message_type: HostMessageType::System,
                ..data_message(&[0; 8])
            }),
            Err(DataProtocolError::WrongMessageType)
        );
        assert_eq!(
            classify_data_event(data_message(&[0; 7])),
            Err(DataProtocolError::InvalidLength)
        );
        for declared in [7, 9] {
            let mut payload = [0; 8];
            put_u32(&mut payload, 4, declared);
            assert_eq!(
                classify_data_event(data_message(&payload)),
                Err(DataProtocolError::InvalidLength)
            );
        }
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
    fn converts_all_address_modes_and_msdu_payloads() {
        for (flags, destination, source) in [
            (0x0000u16, [1; 6], [2; 6]),
            (0x0100, [3; 6], [2; 6]),
            (0x0200, [1; 6], [3; 6]),
        ] {
            let mut frame = [0u8; 40];
            frame[0..2].copy_from_slice(&flags.to_le_bytes());
            frame[4..10].copy_from_slice(&[1; 6]);
            frame[10..16].copy_from_slice(&[2; 6]);
            frame[16..22].copy_from_slice(&[3; 6]);
            frame[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x06]);
            frame[32..34].copy_from_slice(&[9, 8]);
            let len = convert_to_ethernet(&mut frame[..34], RxPayloadType::Mpdu, 24).unwrap();
            assert_eq!(len, 16);
            assert_eq!(&frame[..6], &destination);
            assert_eq!(&frame[6..12], &source);
            assert_eq!(&frame[12..14], &[0x08, 0x06]);
        }

        for (payload_type, mac_header_len, amsdu) in [
            (RxPayloadType::Msdu, 0, 0),
            (RxPayloadType::MsduWithMac, 4, 4),
        ] {
            let mut frame = [0u8; 40];
            frame[amsdu..amsdu + 6].copy_from_slice(&[1; 6]);
            frame[amsdu + 6..amsdu + 12].copy_from_slice(&[2; 6]);
            let llc = amsdu + 14;
            frame[llc..llc + 8].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]);
            frame[llc + 8..llc + 10].copy_from_slice(&[7, 6]);
            let raw_len = llc + 10;
            let len =
                convert_to_ethernet(&mut frame[..raw_len], payload_type, mac_header_len).unwrap();
            assert_eq!(len, 16);
            assert_eq!(&frame[..6], &[1; 6]);
            assert_eq!(&frame[6..12], &[2; 6]);
            assert_eq!(&frame[14..16], &[7, 6]);
        }
        assert_eq!(llc_skip(0x80f3), 8);
        assert_eq!(llc_skip(0x8137), 8);
        assert_eq!(llc_skip(0x0600), 8);
        assert_eq!(llc_skip(0x05ff), 2);
    }

    #[test]
    fn conversion_rejects_every_short_or_expanding_frame() {
        assert_eq!(
            convert_mpdu(&mut [0; 30], 23),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            convert_mpdu(&mut [0; 25], 24),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            ieee80211_addresses(&[0; 23], 0),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            ieee80211_addresses(&[0; 29], 0x0300),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            convert_msdu(&mut [0; 15], 0),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            convert_msdu(&mut [0; 17], 4),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            llc_ether_type(&[0; 8], usize::MAX),
            Err(DataProtocolError::InvalidLength)
        );
        assert_eq!(
            llc_ether_type(&[0; 7], 0),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            rebuild_ethernet(&mut [0; 10], 11, [0; 6], [0; 6], 0),
            Err(DataProtocolError::FrameTooShort)
        );
        assert_eq!(
            rebuild_ethernet(&mut [0; 20], 2, [0; 6], [0; 6], 0),
            Err(DataProtocolError::FrameTooLarge)
        );
    }

    #[test]
    fn posts_receives_and_reposts_an_rx_descriptor() {
        let mut raw = [0u8; 36];
        raw[0..2].copy_from_slice(&0x0208u16.to_le_bytes());
        raw[4..10].copy_from_slice(&[1; 6]);
        raw[10..16].copy_from_slice(&[2; 6]);
        raw[16..22].copy_from_slice(&[3; 6]);
        raw[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]);
        raw[32..36].copy_from_slice(&[9, 8, 7, 6]);
        let bus = TestBus {
            read_responses: [raw.to_vec()].into(),
            ..TestBus::default()
        };
        let mut device = device(bus);
        let mut path = DataPath::<2, 2>::new(1600, 1514).unwrap();
        assert!(block_on(path.post_all_rx(&mut device)).is_ok());
        assert_eq!(path.rx_posted, [true, true]);
        let payload = rx_event_payload(0, raw.len() as u16, RxPayloadType::Mpdu as u8);
        let event = RxEventRef::parse(data_message(&payload)).unwrap();
        let mut output = [0u8; 64];
        let received = block_on(path.receive_packet(&mut device, &event, 0, &mut output)).unwrap();
        assert_eq!(
            received,
            ReceivedFrame {
                len: 18,
                ether_type: 0x0800,
                descriptor_id: 0,
                signal_dbm: -42,
                frequency_mhz: 2412,
            }
        );
        assert_eq!(&output[..6], &[1; 6]);
        assert_eq!(&output[6..12], &[3; 6]);
        assert!(path.rx_posted[0]);

        assert!(matches!(
            block_on(path.post_rx(&mut device, 0, 0)),
            Err(DataError::ReceiveDescriptorBusy(0))
        ));
        assert!(matches!(
            block_on(path.post_rx(&mut device, 2, 0)),
            Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(2)))
        ));
        path.rx_posted[1] = false;
        assert!(matches!(
            block_on(path.post_rx(&mut device, 1, 3)),
            Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(1)))
        ));
        let bus = device.into_inner();
        let packet_address = path.rx_slot_address(0).unwrap() + RX_BUFFER_HEADROOM as u32;
        assert_eq!(
            bus.reads,
            [(
                host_offset(Processor::Lmac, packet_address).unwrap(),
                raw.len()
            )]
        );
    }

    #[test]
    fn rx_descriptor_offsets_and_addresses_are_exact() {
        let payload = rx_event_payload(1, 16, RxPayloadType::Msdu as u8);
        let event = RxEventRef::parse(data_message(&payload)).unwrap();
        let mut path = DataPath::<1, 1>::new(64, 64).unwrap();
        assert!(matches!(
            path.take_rx_descriptor::<()>(&event, 0),
            Err(DataError::Protocol(DataProtocolError::InvalidDescriptor(1)))
        ));

        let mut device = device(TestBus::default());
        let slot = RPU_MEM_PACKET_BASE + 0x100;
        let command_base = 0xb000_2000;
        let command = block_on(prepare_rx_descriptor(&mut device, slot, command_base, 2)).unwrap();
        assert_eq!(command, command_base + 2 * RX_COMMAND_SLOT_SIZE);
        let bus = device.into_inner();
        let expected_dma =
            ((slot + RX_BUFFER_HEADROOM as u32) & RPU_ADDR_MASK_OFFSET).to_le_bytes();
        assert!(bus.writes.iter().any(|(_, data)| data == &expected_dma));
    }

    #[test]
    fn receive_capacity_errors_repost_the_descriptor() {
        let mut device = device(TestBus::default());
        let payload = rx_event_payload(0, 36, RxPayloadType::Mpdu as u8);
        let event = RxEventRef::parse(data_message(&payload)).unwrap();

        let mut path = DataPath::<1, 1>::new(32, 64).unwrap();
        block_on(path.post_all_rx(&mut device)).unwrap();
        assert!(matches!(
            block_on(path.receive_packet(&mut device, &event, 0, &mut [0; 64])),
            Err(DataError::Protocol(DataProtocolError::FrameTooLarge))
        ));
        assert!(path.rx_posted[0]);

        let mut path = DataPath::<1, 1>::new(64, 64).unwrap();
        block_on(path.post_all_rx(&mut device)).unwrap();
        assert!(matches!(
            block_on(path.receive_packet(&mut device, &event, 0, &mut [0; 20])),
            Err(DataError::OutputTooSmall {
                needed: 36,
                capacity: 20,
            })
        ));
        assert!(path.rx_posted[0]);
    }

    #[test]
    fn transmit_cycles_tokens_and_writes_tail_command_and_trigger() {
        let mut device = device(TestBus::default());
        let mut path = DataPath::<1, 2>::new(64, 64).unwrap();
        let frame = ethernet_frame(15);
        assert_eq!(
            block_on(path.transmit(&mut device, 4, &frame, 7)).unwrap(),
            0
        );
        assert_eq!(path.next_tx, 1);
        assert_eq!(
            block_on(path.transmit(&mut device, 4, &frame, 7)).unwrap(),
            1
        );
        assert_eq!(path.next_tx, 0);
        assert!(matches!(
            block_on(path.transmit(&mut device, 4, &frame, 7)),
            Err(DataError::NoTransmitToken)
        ));
        assert_eq!(path.complete_tx(0), Ok(()));
        assert_eq!(
            block_on(path.transmit(&mut device, 4, &frame, 7)).unwrap(),
            0
        );
        assert_eq!(path.next_tx, 1);
        assert_eq!(
            path.complete_tx(2),
            Err(DataProtocolError::InvalidDescriptor(2))
        );
        assert_eq!(path.complete_tx(1), Ok(()));
        assert_eq!(
            path.complete_tx(1),
            Err(DataProtocolError::InvalidDescriptor(1))
        );

        let bus = device.into_inner();
        assert!(bus.writes.iter().any(|(_, data)| data == &frame[..12]));
        assert!(
            bus.writes
                .iter()
                .any(|(_, data)| data == &[frame[12], frame[13], frame[14], 0])
        );
        let tail_address = host_offset(
            Processor::Umac,
            path.tx_slot_address(0).unwrap() + (frame.len() & !3) as u32,
        )
        .unwrap();
        assert!(bus.writes.iter().any(|(address, data)| {
            *address == tail_address && data == &[frame[12], frame[13], frame[14], 0]
        }));
        assert!(bus.writes.iter().any(|(_, data)| {
            data.len() == TX_COMMAND_TOTAL_LEN & !3
                && read_u32(data, HOST_MESSAGE_HEADER_LEN) == DataCommand::TransmitBuffer as u32
        }));
        let command_queue_host = queues().command_busy.enqueue_address & RPU_ADDR_MASK_OFFSET;
        assert!(
            bus.writes
                .iter()
                .any(|(address, _)| *address == command_queue_host)
        );
        let second_command =
            host_offset(Processor::Umac, RPU_MEM_TX_CMD_BASE + TX_COMMAND_SLOT_SIZE).unwrap();
        assert!(
            bus.writes
                .iter()
                .any(|(address, data)| *address == second_command
                    && read_u32(data, HOST_MESSAGE_HEADER_LEN)
                        == DataCommand::TransmitBuffer as u32)
        );
    }

    #[test]
    fn layout_alignment_and_slot_offsets_are_exact() {
        assert_eq!(
            [align4(1), align4(2), align4(3), align4(4), align4(5)],
            [4, 4, 4, 4, 8]
        );
        let path = DataPath::<2, 3>::new(33, 65).unwrap();
        assert_eq!(
            path.rx_slot_address(1),
            Some(path.rx_base + path.rx_stride as u32)
        );
        assert_eq!(
            path.tx_slot_address(2),
            Some(RPU_MEM_PACKET_BASE + 2 * path.tx_stride as u32)
        );
    }

    #[test]
    fn transmit_validation_does_not_consume_tokens() {
        let mut device = device(TestBus::default());
        let mut path = DataPath::<1, 1>::new(64, 14).unwrap();
        assert!(matches!(
            block_on(path.transmit(&mut device, 0, &[0; 13], 0)),
            Err(DataError::Protocol(DataProtocolError::FrameTooShort))
        ));
        assert!(matches!(
            block_on(path.transmit(&mut device, 0, &[0; 15], 0)),
            Err(DataError::Protocol(DataProtocolError::FrameTooLarge))
        ));
        assert_eq!(path.tx_in_flight, [false]);

        let mut closed = Device::new(TestBus::default());
        assert!(matches!(
            block_on(path.post_rx(&mut closed, 0, 0)),
            Err(DataError::Device(DeviceError::NotInitialized))
        ));
    }

    #[test]
    fn packet_and_command_write_failures_release_the_reserved_token() {
        let frame = ethernet_frame(16);
        let mut path = DataPath::<1, 1>::new(64, 64).unwrap();
        let mut device = failing_device(FailingBus {
            fail_write_at: Some(0),
            ..FailingBus::default()
        });
        assert!(matches!(
            block_on(path.transmit(&mut device, 0, &frame, 0)),
            Err(DataError::Rpu(RpuError::Bus(FailingBusError::Write)))
        ));
        assert_eq!(path.tx_in_flight, [false]);

        let mut device = failing_device(FailingBus {
            fail_write_at: Some(1),
            ..FailingBus::default()
        });
        assert!(matches!(
            block_on(path.transmit(&mut device, 0, &frame, 0)),
            Err(DataError::Rpu(RpuError::Bus(FailingBusError::Write)))
        ));
        assert_eq!(path.tx_in_flight, [false]);
    }

    #[test]
    fn receive_read_failure_reposts_the_descriptor() {
        let mut device = failing_device(FailingBus {
            fail_read: true,
            ..FailingBus::default()
        });
        let mut path = DataPath::<1, 1>::new(64, 64).unwrap();
        block_on(path.post_all_rx(&mut device)).unwrap();
        let payload = rx_event_payload(0, 32, RxPayloadType::Mpdu as u8);
        let event = RxEventRef::parse(data_message(&payload)).unwrap();
        assert!(matches!(
            block_on(path.receive_packet(&mut device, &event, 0, &mut [0; 64])),
            Err(DataError::Rpu(RpuError::Bus(FailingBusError::Read)))
        ));
        assert_eq!(path.rx_posted, [true]);
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
    fn tx_done_status_array_is_validated() {
        let mut payload = [0u8; TX_DONE_FIXED_LEN + 1];
        put_u32(&mut payload, 0, DataCommand::TransmitDone as u32);
        let payload_len = payload.len() as u32;
        put_u32(&mut payload, 4, payload_len);
        payload[8] = 3;
        payload[9] = 1;
        payload[TX_DONE_FIXED_LEN] = 0;
        let mut message = [0u8; 64];
        let len = encode_host_message(&mut message, HostMessageType::Data, true, &payload).unwrap();
        let parsed = parse_host_message(&message[..len]).unwrap();
        let event = TxDoneEventRef::parse(parsed).unwrap();
        assert_eq!(event.token, 3);
        assert!(event.all_succeeded());
    }

    #[test]
    fn protocol_error_type_is_independent() {
        let _ = super::super::protocol::ProtocolError::InvalidLength;
    }
}
