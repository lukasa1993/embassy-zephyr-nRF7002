//! Native RPU queue, command, event, and interrupt controller.

use embedded_hal_async::delay::DelayNs;

use super::bus::Bus;
use super::control::MAX_STATION_MESSAGE_LEN;
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
/// Fixed UMAC TX command-slot base.
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
/// Nordic's command-buffer fragment limit.
pub const DEFAULT_CONTROL_FRAGMENT_LEN: usize = 400;
/// Largest event fragment in Nordic's pinned host interface.
pub const MAX_EVENT_FRAGMENT_LEN: usize = 1000;
/// Nordic's default event-pool fragment limit.
pub const DEFAULT_EVENT_FRAGMENT_LEN: usize = MAX_EVENT_FRAGMENT_LEN;
/// Default command-buffer polls before a timeout.
pub const DEFAULT_COMMAND_WAIT_ATTEMPTS: u16 = 1000;
/// Delay between command-buffer polls.
pub const DEFAULT_COMMAND_WAIT_DELAY_MS: u32 = 1;

/// Native queue-controller failure.
#[derive(Debug)]
pub enum DeviceError<E> {
    /// The bus or RPU memory operation failed before ownership changed.
    Rpu(RpuError<E>),
    /// A packed command or event is invalid.
    Protocol(ProtocolError),
    /// Queue metadata has not been read from firmware.
    NotInitialized,
    /// Firmware returned a malformed queue map or command base.
    InvalidQueueMap,
    /// No command buffer is currently available.
    CommandQueueEmpty,
    /// A multi-fragment command needs the bounded-wait API.
    CommandNeedsWait,
    /// No command buffer became available before the bounded wait ended.
    CommandQueueTimeout,
    /// Command ownership changed and delivery can no longer be proved.
    CommandDeliveryUncertain,
    /// The RPU must be reset and queues must be initialized again.
    RecoveryRequired,
    /// A caller changed the scratch buffer during fragmented-event assembly.
    EventBufferChanged,
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

#[derive(Clone, Copy, Debug)]
struct PendingEvent {
    declared: usize,
    copied: usize,
    resubmit: bool,
    scratch_address: usize,
    discard: bool,
}

/// Owns the direct RPU access path and firmware-published hardware queues.
pub struct Device<B> {
    rpu: Rpu<B>,
    queues: Option<HpqmInfo>,
    rx_command_base: u32,
    tx_command_base: u32,
    command_counter: u32,
    command_fragment_len: usize,
    event_fragment_len: usize,
    pending_event: Option<PendingEvent>,
    recovery_required: bool,
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
            pending_event: None,
            recovery_required: false,
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

    /// Returns the fixed UMAC TX command-slot base after initialization.
    pub const fn tx_command_base(&self) -> Option<u32> {
        if self.tx_command_base == 0 {
            None
        } else {
            Some(self.tx_command_base)
        }
    }

    /// Reports whether the RPU must be reset before more queue operations.
    pub const fn recovery_required(&self) -> bool {
        self.recovery_required
    }

    /// Invalidates all queue metadata after a confirmed RPU reset.
    ///
    /// Call this after hardware reset and before firmware load. A later
    /// [`Device::initialize_queues`] call makes the device usable again.
    pub fn reset_queue_state(&mut self) {
        self.queues = None;
        self.rx_command_base = 0;
        self.tx_command_base = 0;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        self.pending_event = None;
        self.recovery_required = false;
    }

    /// Sets command and event fragment limits.
    pub fn set_fragment_limits(
        &mut self,
        command_len: usize,
        event_len: usize,
    ) -> Result<(), FragmentLimitError> {
        if !(HOST_MESSAGE_HEADER_LEN..=DEFAULT_CONTROL_FRAGMENT_LEN).contains(&command_len)
            || !(HOST_MESSAGE_HEADER_LEN..=MAX_EVENT_FRAGMENT_LEN).contains(&event_len)
        {
            return Err(FragmentLimitError);
        }
        self.command_fragment_len = command_len;
        self.event_fragment_len = event_len;
        Ok(())
    }

    /// Marks a partly assembled event for discard.
    ///
    /// The next calls to [`Device::try_read_event`] remove its remaining
    /// fragments before they read a new event.
    pub fn discard_pending_event(&mut self) -> bool {
        let Some(mut pending) = self.pending_event else {
            return false;
        };
        pending.discard = true;
        pending.scratch_address = 0;
        self.pending_event = Some(pending);
        true
    }

    fn ensure_operational<E>(&self) -> Result<(), DeviceError<E>> {
        if self.recovery_required {
            Err(DeviceError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn mark_delivery_uncertain<E>(&mut self) -> DeviceError<E> {
        self.recovery_required = true;
        DeviceError::CommandDeliveryUncertain
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
        if rx_command_base == 0 || rx_command_base == 0xaaaa_aaaa {
            return Err(DeviceError::InvalidQueueMap);
        }

        // Nordic's pinned HAL uses RPU_MEM_TX_CMD_BASE as the command area
        // itself. It does not read a pointer from that address.
        self.queues = Some(queues);
        self.rx_command_base = rx_command_base;
        self.tx_command_base = RPU_MEM_TX_CMD_BASE;
        self.command_counter = RPU_COMMAND_COUNTER_START;
        self.pending_event = None;
        self.recovery_required = false;
        Ok(queues)
    }

    /// Enables the root and UMAC interrupt lines.
    pub async fn enable_interrupts(&mut self) -> Result<(), DeviceError<B::Error>> {
        self.ensure_operational()?;
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

    /// Sends one command that fits one firmware command buffer.
    ///
    /// Use [`Device::send_control_with_wait`] for a command that needs more
    /// than one fragment. This rule prevents a normal queue-empty result after
    /// firmware already received the first part of a command.
    pub async fn send_control(&mut self, message: &[u8]) -> Result<(), DeviceError<B::Error>> {
        validate_complete_message(message)?;
        self.ensure_operational()?;
        if message.len() > self.command_fragment_len {
            return Err(DeviceError::CommandNeedsWait);
        }
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        let address = match self.dequeue(queues.command_available).await {
            Ok(Some(value)) => value,
            Ok(None) => return Err(DeviceError::CommandQueueEmpty),
            Err(_) => return Err(self.mark_delivery_uncertain()),
        };
        self.post_control_fragment(queues, address, message).await
    }

    /// Sends a complete command with a bounded wait for each command buffer.
    ///
    /// If a timeout or bus error occurs after ownership changes, the method
    /// marks the device for recovery. Reset the RPU and initialize the queues
    /// before more commands are sent.
    pub async fn send_control_with_wait<D>(
        &mut self,
        message: &[u8],
        delay: &mut D,
        attempts: u16,
        delay_ms: u32,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        validate_complete_message(message)?;
        self.ensure_operational()?;
        if attempts == 0 {
            return Err(DeviceError::CommandQueueTimeout);
        }
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        let mut posted_any = false;

        for fragment in message.chunks(self.command_fragment_len) {
            let mut address = None;
            for _ in 0..attempts {
                match self.dequeue(queues.command_available).await {
                    Ok(Some(value)) => {
                        address = Some(value);
                        break;
                    }
                    Ok(None) => delay.delay_ms(delay_ms).await,
                    Err(_) => return Err(self.mark_delivery_uncertain()),
                }
            }

            let Some(address) = address else {
                if posted_any {
                    return Err(self.mark_delivery_uncertain());
                }
                return Err(DeviceError::CommandQueueTimeout);
            };

            match self.post_control_fragment(queues, address, fragment).await {
                Ok(()) => posted_any = true,
                Err(DeviceError::CommandDeliveryUncertain) => {
                    self.recovery_required = true;
                    return Err(DeviceError::CommandDeliveryUncertain);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Sends a complete command with the default one-second queue wait.
    pub async fn send_control_reliable<D>(
        &mut self,
        message: &[u8],
        delay: &mut D,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        self.send_control_with_wait(
            message,
            delay,
            DEFAULT_COMMAND_WAIT_ATTEMPTS,
            DEFAULT_COMMAND_WAIT_DELAY_MS,
        )
        .await
    }

    async fn post_control_fragment(
        &mut self,
        queues: HpqmInfo,
        address: u32,
        fragment: &[u8],
    ) -> Result<(), DeviceError<B::Error>> {
        if self
            .rpu
            .write(Processor::Umac, address, fragment)
            .await
            .is_err()
        {
            return Err(self.mark_delivery_uncertain());
        }
        if self.enqueue(queues.command_busy, address).await.is_err() {
            return Err(self.mark_delivery_uncertain());
        }
        if self.trigger_command().await.is_err() {
            return Err(self.mark_delivery_uncertain());
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
    ///
    /// The scan command is larger than one Nordic command buffer. Use
    /// [`Device::start_scan_reliable`] for normal operation.
    pub async fn start_scan(
        &mut self,
        ifaceindex: i32,
        request: &ScanRequest<'_>,
    ) -> Result<(), DeviceError<B::Error>> {
        let mut message = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut message, ifaceindex, request)?;
        self.send_control(&message[..len]).await
    }

    /// Starts one firmware scan with bounded command-buffer waits.
    pub async fn start_scan_reliable<D>(
        &mut self,
        ifaceindex: i32,
        request: &ScanRequest<'_>,
        delay: &mut D,
    ) -> Result<(), DeviceError<B::Error>>
    where
        D: DelayNs,
    {
        let mut message = [0u8; MAX_CONTROL_MESSAGE_LEN];
        let len = encode_scan(&mut message, ifaceindex, request)?;
        self.send_control_reliable(&message[..len], delay).await
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
    /// `Ok(None)` means that no complete event is available. It can also mean
    /// that a fragmented event is waiting for its next fragment. Keep the same
    /// scratch buffer unchanged until that event completes. If the buffer must
    /// change, call [`Device::discard_pending_event`] first.
    ///
    /// An oversized event is removed over this call and later calls. The first
    /// call returns [`DeviceError::EventTooLarge`]. Later calls discard the
    /// remaining fragments before they read a new event.
    pub async fn try_read_event<'a>(
        &mut self,
        scratch: &'a mut [u8],
    ) -> Result<Option<HostMessageRef<'a>>, DeviceError<B::Error>> {
        self.ensure_operational()?;
        let queues = self.queues.ok_or(DeviceError::NotInitialized)?;
        loop {
            if let Some(mut pending) = self.pending_event {
                if !pending.discard
                    && (pending.scratch_address != scratch.as_mut_ptr() as usize
                        || scratch.len() < pending.declared)
                {
                    pending.discard = true;
                    pending.scratch_address = 0;
                    self.pending_event = Some(pending);
                    return Err(DeviceError::EventBufferChanged);
                }

                let mut removed_fragment = false;
                while pending.copied < pending.declared {
                    let Some(event_address) = self.dequeue(queues.event_busy).await? else {
                        self.pending_event = Some(pending);
                        if removed_fragment {
                            self.acknowledge_interrupt().await?;
                        }
                        return Ok(None);
                    };
                    let count =
                        core::cmp::min(self.event_fragment_len, pending.declared - pending.copied);
                    if !pending.discard {
                        self.rpu
                            .read(
                                Processor::Umac,
                                event_address,
                                &mut scratch[pending.copied..pending.copied + count],
                            )
                            .await?;
                    }
                    self.release_event_fragment(queues, event_address, pending.resubmit)
                        .await?;
                    pending.copied += count;
                    removed_fragment = true;
                }

                self.pending_event = None;
                if removed_fragment {
                    self.acknowledge_interrupt().await?;
                }
                if pending.discard {
                    continue;
                }
                return Ok(Some(parse_host_message(&scratch[..pending.declared])?));
            }

            let Some(event_address) = self.dequeue(queues.event_busy).await? else {
                return Ok(None);
            };

            let mut header = [0u8; HOST_MESSAGE_HEADER_LEN];
            self.rpu
                .read(Processor::Umac, event_address, &mut header)
                .await?;
            let declared =
                u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let resubmit = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) != 0;

            if declared < HOST_MESSAGE_HEADER_LEN {
                self.release_event_fragment(queues, event_address, resubmit)
                    .await?;
                self.acknowledge_interrupt().await?;
                return Err(DeviceError::Protocol(ProtocolError::InvalidLength));
            }

            let first_count = core::cmp::min(self.event_fragment_len, declared);
            if declared > scratch.len() {
                self.release_event_fragment(queues, event_address, resubmit)
                    .await?;
                if first_count < declared {
                    self.pending_event = Some(PendingEvent {
                        declared,
                        copied: first_count,
                        resubmit,
                        scratch_address: 0,
                        discard: true,
                    });
                }
                self.acknowledge_interrupt().await?;
                return Err(DeviceError::EventTooLarge {
                    declared,
                    capacity: scratch.len(),
                });
            }

            self.rpu
                .read(Processor::Umac, event_address, &mut scratch[..first_count])
                .await?;
            self.release_event_fragment(queues, event_address, resubmit)
                .await?;
            self.acknowledge_interrupt().await?;

            if first_count == declared {
                return Ok(Some(parse_host_message(&scratch[..declared])?));
            }

            self.pending_event = Some(PendingEvent {
                declared,
                copied: first_count,
                resubmit,
                scratch_address: scratch.as_mut_ptr() as usize,
                discard: false,
            });
            return Ok(None);
        }
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
        if value == 0xaaaa_aaaa {
            return Err(DeviceError::InvalidQueueMap);
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
            && queue.enqueue_address != 0xaaaa_aaaa
            && queue.dequeue_address != 0xaaaa_aaaa
            && queue.enqueue_address & 3 == 0
            && queue.dequeue_address & 3 == 0
    })
}

fn validate_complete_message<E>(message: &[u8]) -> Result<(), DeviceError<E>> {
    if message.len() < HOST_MESSAGE_HEADER_LEN || message.len() > MAX_STATION_MESSAGE_LEN {
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
    fn queue_validation_rejects_zero_unaligned_and_sentinel_addresses() {
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
        invalid.event_busy.enqueue_address = 0xaaaa_aaaa;
        assert!(!queue_map_is_valid(&invalid));
    }

    #[test]
    fn complete_message_length_is_checked() {
        let mut bytes = [0u8; 32];
        let len = encode_host_message(&mut bytes, HostMessageType::System, false, &[1, 2]).unwrap();
        assert!(validate_complete_message::<()>(&bytes[..len]).is_ok());
        assert!(validate_complete_message::<()>(&bytes[..len - 1]).is_err());
    }

    #[test]
    fn fragment_limits_match_the_pinned_nordic_interface() {
        let mut device = Device::new(());
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, MAX_EVENT_FRAGMENT_LEN)
                .is_ok()
        );
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN + 1, MAX_EVENT_FRAGMENT_LEN)
                .is_err()
        );
        assert!(
            device
                .set_fragment_limits(DEFAULT_CONTROL_FRAGMENT_LEN, MAX_EVENT_FRAGMENT_LEN + 1)
                .is_err()
        );
    }

    #[test]
    fn pending_event_can_be_changed_to_discard() {
        let mut device = Device::new(());
        device.pending_event = Some(PendingEvent {
            declared: 2000,
            copied: 1000,
            resubmit: true,
            scratch_address: 1,
            discard: false,
        });
        assert!(device.discard_pending_event());
        assert!(device.pending_event.unwrap().discard);
    }

    #[test]
    fn reset_clears_recovery_and_queue_state() {
        let mut device = Device::new(());
        device.recovery_required = true;
        device.tx_command_base = RPU_MEM_TX_CMD_BASE;
        device.reset_queue_state();
        assert!(!device.recovery_required());
        assert_eq!(device.tx_command_base(), None);
    }

    #[test]
    fn tx_command_area_is_a_fixed_address() {
        assert_eq!(RPU_MEM_TX_CMD_BASE, 0xb000_00b8);
    }
}
