//! System-command event parsing for the pinned Nordic ABI.

use super::protocol::{HostMessageRef, HostMessageType, ProtocolError};

/// Fixed system command and event header length.
pub const SYSTEM_HEADER_LEN: usize = 8;

/// System event identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SystemEventId {
    PowerData = 0,
    InitDone = 1,
    Statistics = 2,
    DeinitDone = 3,
    RadioTest = 4,
    CoexistenceConfig = 5,
    InternalUmacStatistics = 6,
    RadioCommandStatus = 7,
    ChannelSetDone = 8,
    ModeSetDone = 9,
    FilterSetDone = 10,
    RawTransmitDone = 11,
    OffloadedRawTransmitStatus = 12,
}

/// Borrowed system event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemEvent<'a> {
    InitDone,
    DeinitDone,
    PowerData(&'a [u8]),
    Statistics(&'a [u8]),
    Other { id: u32, body: &'a [u8] },
}

/// Parses one system event and validates its declared length.
pub fn parse_system_event(message: HostMessageRef<'_>) -> Result<SystemEvent<'_>, ProtocolError> {
    if message.message_type != HostMessageType::System {
        return Err(ProtocolError::WrongMessageType);
    }
    if message.payload.len() < SYSTEM_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let id = read_u32(message.payload, 0);
    let declared = read_u32(message.payload, 4) as usize;
    if declared < SYSTEM_HEADER_LEN || declared > message.payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let body = &message.payload[SYSTEM_HEADER_LEN..declared];
    match id {
        value if value == SystemEventId::InitDone as u32 => {
            if !body.is_empty() {
                return Err(ProtocolError::InvalidLength);
            }
            Ok(SystemEvent::InitDone)
        }
        value if value == SystemEventId::DeinitDone as u32 => {
            if !body.is_empty() {
                return Err(ProtocolError::InvalidLength);
            }
            Ok(SystemEvent::DeinitDone)
        }
        value if value == SystemEventId::PowerData as u32 => Ok(SystemEvent::PowerData(body)),
        value if value == SystemEventId::Statistics as u32 => Ok(SystemEvent::Statistics(body)),
        other => Ok(SystemEvent::Other { id: other, body }),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{encode_host_message, parse_host_message};

    #[test]
    fn parses_init_done() {
        let mut payload = [0u8; SYSTEM_HEADER_LEN];
        payload[0..4].copy_from_slice(&(SystemEventId::InitDone as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&(SYSTEM_HEADER_LEN as u32).to_le_bytes());
        let mut message = [0u8; 32];
        let len = encode_host_message(&mut message, HostMessageType::System, true, &payload).unwrap();
        let parsed = parse_host_message(&message[..len]).unwrap();
        assert_eq!(parse_system_event(parsed), Ok(SystemEvent::InitDone));
    }

    #[test]
    fn rejects_truncated_system_event() {
        let mut payload = [0u8; SYSTEM_HEADER_LEN];
        payload[0..4].copy_from_slice(&(SystemEventId::InitDone as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&16u32.to_le_bytes());
        let message = HostMessageRef {
            resubmit: false,
            message_type: HostMessageType::System,
            payload: &payload,
        };
        assert_eq!(
            parse_system_event(message),
            Err(ProtocolError::InvalidLength)
        );
    }
}
