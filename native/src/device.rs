//! Native RPU queue, command, event, and interrupt controller.

use super::bus::Bus;
use super::memory::{Processor, Rpu, RpuError};
use super::protocol::{
    HOST_MESSAGE_HEADER_LEN, HPQM_INFO_LEN, HostMessageRef, HpqmInfo, ProtocolError, ScanReason,
    ScanRequest, SystemInitConfig, encode_deauthenticate, encode_get_scan_results,
    encode_new_interface, encode_scan, encode_system_init, parse_host_message,
};
use super::protocol::{InterfaceType, MAX_CONTROL_MESSAGE_LEN, SYSTEM_INIT_LEN};

/// Firmware-published host-port queue map.
pub const RPU_MEM_HPQ_INFO: u32 = 0xb000_0024;
/// LMAC RX command-slot base pointer.
pub const RPU_MEM_RX_CMD_BASE: u32 = 0xb700_0d58;
/// UMAC TX command-slot base pointer.
pub const RPU_MEM_TX_CMD_BASE: u32 = 0xb000_00b8;
/// Root interrupt mask register.
pub const RPU_REG_INT_FROM_RPU_CTRL: u32 = 0xa400_0400;
/// Host-to-RPU command trigger register.
pub const RPU_REG_INT_TO_MCU_CTRL: u32 = 0xa400_0480;
/// Host acknowledgement register.
pub const RPU_REG_INT_FROM_MCU_ACK: u32 = 0xa400_0488;
/// UMAC interrupt enable register.
pub const RPU_REG_INT_FROM_MCU_CTRL: u32 = 0xa400_0494;
/// Root interrupt bit used by the RPU.
pub const RPU_INTERRUPT_ROOT_BIT: u32 = 1 << 17;
/// MCU interrupt and acknowledgement bit.
pub const RPU_INTERRUPT_MCU_BIT: u32 = 1 << 31;
/// Command counter synchronization value used by Nordic's HAL.
pub const RPU_COMMAND_COUNTER_START: u32 = 0xdead;
/// Nordic's default command/event fragment limit.
pub const DEFAULT_CONTROL_FRAGMENT_LEN: usize = 400;
/// Nordic's default event-pool fragment limit.
pub const DEFAULT_EVENT_FRAGMENT_LEN: usize = 1000;

/// Native queue-controller failure.
#[derive(Debug)]
pub enum DeviceError<E> {
    /// The bus or RPU memory operation failed.
    Rpu(RpuError<E>),
    /// A packed command or event is invalid.
    Protocol(ProtocolError),
    /// Queue metadata has not been read from firmware.
    NotInitialized,
    /// Firmware returned a malformed queue map or command base.
    InvalidQueueMap,
    /// No command buffer is currently available.
    CommandQueueEmpty,
    /// An event started but not all fragments were present.
    IncompleteEvent,
    /// The event is larger than caller storage.
    EventTooLarge { declared: usize, capacity: usize },
}

impl<E> From<RpuError<E>> for DeviceError<E> {
    fn from(value: RpuError<E>) -> Self {
        Self::Rpu(value)
    }
}

impl<E> From<ProtocolError> for DeviceError<E> {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Invalid command or event fragmentation setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentLimitError;

/// Owns the direct RPU access path and firmware-published hardware queues.
pub struct Device<B> {
    rpu: Rpu<B>,
    queues: Option<HpqmInfo>,
    rx_command_base: u32,
    tx_command_base: u32,
    command_counter: u32,
    command_fragment_len: usize,
    event_fragment_len: usize,
}

impl<B> Device<B> {
    /// Creates a closed native device around one bus.
    pub const fn new(bus: B) -> Self {
        Self {
            rpu: Rpu::new(bus),
            queues: None,
            rx_command_base: 0,
            tx_command_base: 0,
            command_counter: RPU_COMMAND_COUNTER_START,
            command_fragment_len: DEFAULT_CONTROL_FRAGMENT_LEN,
            event_fragment_len: DEFAULT_EVENT_FRAGMENT_LEN,
        }
    }

    /// Borrows the RPU memory controller.
    pub fn rpu_mut(&mut self) -> &mut Rpu<B> {
        &mut self.rpu
    }

    /// Releases the low-level bus.
    pub fn into_inner(self) -> B {
        self.rpu.into_inner()
    }

    /// Returns the firmware-published queue map after initialization.
    pub const fn queues(&self) -> Option<HpqmInfo> {
        self.queues
    }

    /// Returns the LMAC RX command-slot base.
    pub const fn rx_command_base(&self) -> Option<u32> {
        if self.rx_command_base == 0 {
            None
        } else {
            Some(self.rx_command_base)
        }
    }

    /// Returns the UMAC TX command-slot base.
    pub const fn tx_command_base(&self) -> Option<u32> {
        if self.tx_command_base == 0 {
            None
        } else {
            Some(self.tx_command_base)
        }
    }

    /// Sets command and event fragment limits.
    pub fn set_fragment_limits(
        &mut self,
        command_len: usize,
        event_len: usize,
    ) -> Result<(), FragmentLimitError> {
        if command_len < HOST_MESSAGE_HEADER_LEN
            || command_len > MAX_CONTROL_MESSAGE_LEN
            || event_len < HOST_MESSAGE_HEADER_LEN
        {
            return Err(FragmentLimitError);
        }
        self.command_fragment_len = command_len;
        self.event_fragment_len = event_len;
        Ok(())
    }
}

impl<B> Device<B>
where
    B: Bus,
{
    /// Reads the queue map and data-command bases published after firmware boot.
    pub async fn initialize_queues(&mut self) -> Result<HpqmInfo, DeviceError<B::Error>> {
        let mut bytes = [0u8; HPQM_INFO_LEN];
        self.rpu
            .read(Processor::Umac, RPU_MEM_HPQ_INFO, &mut bytes)
            .await?;
        let queues = HpqmInfo::parse(&bytes)?;
        if !queue_map_is_valid(&queues) {
            return Err(DeviceError::InvalidQueueMap);
        }

        let rx_command_base = self
            .rpu
            .read_u32(Processor::Lmac, RPU_MEM_RX_CMD_BASE)
            .await?;
        let tx_command_base = self
            .rpu
            .read_u32(Processor::Umac, RPU_MEM_TX_CMD_BASE)
            .await?;
        if rx_command_base == 0 || tx_command_base == 0 {
            return Err(DeviceError::InvalidQueueMap);
        }

        self.queues = Some(queues);
        self.rx_command_base = rx_command_base;
        self.tx_command_base = tx_command_base;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        Ok(queues)
    }

    /// Enables the root and UMAC interrupt lines.
    pub async fn enable_interrupts(&mut self) -> Result<(), DeviceError<B::Error>> {
        let root = self.rpu.read_register(RPU_REG_INT_FROM_RPU_CTRL).await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_RPU_CTRL, root | RPU_INTERRUPT_ROOT_BIT)
            .await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_CTRL, RPU_INTERRUPT_MCU_BIT)
            .await?;
        Ok(())
    }

    /// Disables the root and UMAC interrupt lines.
    pub async fn disable_interrupts(&mut self) -> Result<(), DeviceError<B::Error>> {
        let root = self.rpu.read_register(RPU_REG_INT_FROM_RPU_CTRL).await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_RPU_CTRL, root & !RPU_INTERRUPT_ROOT_BIT)
            .await?;
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_CTRL, 0)
            .await?;
        Ok(())
    }

    /// Acknowledges one RPU-to-host interrupt.
    pub async fn acknowledge_interrupt(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(RPU_REG_INT_FROM_MCU_ACK, RPU_INTERRUPT_MCU_BIT)
            .await?;
        Ok(())
    }

    /// Sends one complete host/RPU command, with Nordic-compatible fragmentation.
    pub async fn send_control(&mut self, message: &[u8]) -> Result<(), DeviceError<B::Error>> {
        validate_complete_message(message)?;
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;

        for fragment in message.chunks(self.command_fragment_len) {
            let address = self
                .dequeue(queues.command_available)
                .await?
                .ok_or(DeviceError::CommandQueueEmpty)?;
            self.rpu.write(Processor::Umac, address, fragment).await?;
            self.enqueue(queues.command_busy, address).await?;
            self.trigger_command().await?;
        }
        Ok(())
    }

    /// Sends the packed system initialization command.
    pub async fn send_system_init(
        &mut self,
        config: &SystemInitConfig,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; SYSTEM_INIT_LEN + HOST_MESSAGE_HEADER_LEN];
        let len = encode_system_init(&mut message, config)?;
        self.send_control(&message[..len]).await
    }

    /// Creates a station interface in firmware.
    pub async fn add_station_interface(
        &mut self,
        ifaceindex: i32,
        mac_address: [u8; 6],
        interface_name: &[u8],
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 128];
        let len = encode_new_interface(
            &mut message,
            ifaceindex,
            InterfaceType::Station,
            mac_address,
            interface_name,
        )?;
        self.send_control(&message[..len]).await
    }

    /// Starts one firmware scan.
    pub async fn start_scan(
        &mut self,
        ifaceindex: i32,
        request: &ScanRequest<'_>,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut message, ifaceindex, request)?;
        self.send_control(&message[..len]).await
    }

    /// Requests results after a scan-done event.
    pub async fn get_scan_results(
        &mut self,
        ifaceindex: i32,
        reason: ScanReason,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 96];
        let len = encode_get_scan_results(&mut message, ifaceindex, reason)?;
        self.send_control(&message[..len]).await
    }

    /// Sends a station deauthentication request.
    pub async fn deauthenticate(
        &mut self,
        ifaceindex: i32,
        bssid: [u8; 6],
        reason_code: u16,
        local_state_change: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; 96];
        let len = encode_deauthenticate(
            &mut message,
            ifaceindex,
            bssid,
            reason_code,
            local_state_change,
        )?;
        self.send_control(&message[..len]).await
    }

    /// Reads and reassembles one queued event into caller storage.
    ///
    /// `Ok(None)` means that the event queue was empty. After the first
    /// fragment is removed, every remaining fragment must already be queued.
    pub async fn try_read_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        let Some(mut event_address) = self.dequeue(queues.event_busy).await? else {
            return Ok(None);
        };

        let mut header = [0u8; HOST_MESSAGE_HEADER_LEN];
        self.rpu
            .read(Processor::Umac, event_address, &mut header)
            .await?;
        let declared = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let resubmit = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) != 0;

        if declared < HOST_MESSAGE_HEADER_LEN {
            self.release_event_fragment(queues, event_address, resubmit)
                .await?;
            self.acknowledge_interrupt().await?;
            return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
        }
        if declared > scratch.len() {
            self.release_event_fragment(queues, event_address, resubmit)
                .await?;
            self.acknowledge_interrupt().await?;
            return Err(DeviceError::EventTooLarge {
                declared,
                capacity: scratch.len(),
            });
        }

        let mut copied = 0usize;
        while copied < declared {
            let count = core::cmp::min(self.event_fragment_len, declared - copied);
            self.rpu
                .read(
                    Processor::Umac,
                    event_address,
                    &mut scratch[copied..copied + count],
                )
                .await?;
            self.release_event_fragment(queues, event_address, resubmit)
                .await?;
            copied += count;
            if copied < declared {
                let Some(next) = self.dequeue(queues.event_busy).await? else {
                    self.acknowledge_interrupt().await?;
                    return Err(DeviceError::IncompleteEvent);
                };
                event_address = next;
            }
        }

        self.acknowledge_interrupt().await?;
        Ok(Some(parse_host_message(&scratch[..declared])?))
    }

    async fn release_event_fragment(
        &mut self,
        queues: HpqmInfo,
        event_address: u32,
        resubmit: bool,
    ) -> Result<(), DeviceError<B::Error>> {
        if resubmit {
            self.enqueue(queues.event_available, event_address).await?;
        }
        Ok(())
    }

    pub(crate) async fn enqueue(
        &mut self,
        queue: super::protocol::Hpq,
        value: u32,
    ) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(queue.enqueue_address, value)
            .await?;
        Ok(())
    }

    pub(crate) async fn dequeue(
        &mut self,
        queue: super::protocol::Hpq,
    ) -> Result<Option<u32>, DeviceError<B::Error>> {
        let value = self.rpu.read_register(queue.dequeue_address).await?;
        if value == 0 {
            return Ok(None);
        }
        self.rpu
            .write_register(queue.dequeue_address, value)
            .await?;
        Ok(Some(value))
    }

    pub(crate) async fn trigger_command(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.rpu
            .write_register(RPU_REG_INT_TO_MCU_CTRL, self.command_counter | 0x7fff_0000)
            .await?;
        self.command_counter = self.command_counter.wrapping_add(1);
        Ok(())
    }
}

fn queue_map_is_valid(queues: &HpqmInfo) -> bool {
    let all = [
        queues.event_busy,
        queues.event_available,
        queues.command_busy,
        queues.command_available,
        queues.rx_buffer_busy[0],
        queues.rx_buffer_busy[1],
        queues.rx_buffer_busy[2],
    ];
    all.into_iter().all(|queue| {
        queue.enqueue_address != 0
            && queue.dequeue_address != 0
            && queue.enqueue_address & 3 == 0
            && queue.dequeue_address & 3 == 0
    })
}

fn validate_complete_message<E>(message: &[u8]) -> Result<(), DeviceError<E>> {
    if message.len() < HOST_MESSAGE_HEADER_LEN || message.len() > u32::MAX as usize {
        return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
    }
    let declared = u32::from_le_bytes([message[0], message[1], message[2], message[3]]) as usize;
    if declared != message.len() {
        return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{HostMessageType, Hpq, encode_host_message};
    use super::*;

    #[test]
    fn queue_validation_rejects_zero_or_unaligned_addresses() {
        let valid = HpqmInfo {
            event_busy: Hpq {
                enqueue_address: 4,
                dequeue_address: 8,
            },
            event_available: Hpq {
                enqueue_address: 12,
                dequeue_address: 16,
            },
            command_busy: Hpq {
                enqueue_address: 20,
                dequeue_address: 24,
            },
            command_available: Hpq {
                enqueue_address: 28,
                dequeue_address: 32,
            },
            rx_buffer_busy: [
                Hpq {
                    enqueue_address: 36,
                    dequeue_address: 40,
                },
                Hpq {
                    enqueue_address: 44,
                    dequeue_address: 48,
                },
                Hpq {
                    enqueue_address: 52,
                    dequeue_address: 56,
                },
            ],
        };
        assert!(queue_map_is_valid(&valid));
        let mut invalid = valid;
        invalid.event_busy.enqueue_address = 0;
        assert!(!queue_map_is_valid(&invalid));
        invalid.event_busy.enqueue_address = 5;
        assert!(!queue_map_is_valid(&invalid));
    }

    #[test]
    fn complete_message_length_is_checked() {
        let mut bytes = [0u8; 32];
        let len = encode_host_message(&mut bytes, HostMessageType::System, false, &[1, 2]).unwrap();
        assert!(validate_complete_message::<()>(&bytes[..len]).is_ok());
        assert!(validate_complete_message::<()>(&bytes[..len - 1]).is_err());
    }
}
