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
    let (id, body) = validated_event_body(message.payload)?;
    decode_system_event(id, body)
}

fn validated_event_body(payload: &[u8]) -> Result<(u32, &[u8]), ProtocolError> {
    if payload.len() < SYSTEM_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let id = read_u32(payload, 0);
    let declared = read_u32(payload, 4) as usize;
    if declared < SYSTEM_HEADER_LEN || declared > payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((id, &payload[SYSTEM_HEADER_LEN..declared]))
}

fn decode_system_event(id: u32, body: &[u8]) -> Result<SystemEvent<'_>, ProtocolError> {
    const POWER_DATA_ID: u32 = SystemEventId::PowerData as u32;
    const INIT_DONE_ID: u32 = SystemEventId::InitDone as u32;
    const STATISTICS_ID: u32 = SystemEventId::Statistics as u32;
    const DEINIT_DONE_ID: u32 = SystemEventId::DeinitDone as u32;
    match id {
        POWER_DATA_ID => Ok(SystemEvent::PowerData(body)),
        INIT_DONE_ID => empty_body_event(body, SystemEvent::InitDone),
        STATISTICS_ID => Ok(SystemEvent::Statistics(body)),
        DEINIT_DONE_ID => empty_body_event(body, SystemEvent::DeinitDone),
        other => Ok(SystemEvent::Other { id: other, body }),
    }
}

fn empty_body_event<'a>(
    body: &'a [u8],
    event: SystemEvent<'a>,
) -> Result<SystemEvent<'a>, ProtocolError> {
    if !body.is_empty() {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(event)
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

    fn message(message_type: HostMessageType, payload: &[u8]) -> HostMessageRef<'_> {
        HostMessageRef {
            resubmit: false,
            message_type,
            payload,
        }
    }

    fn payload(id: u32, body: &[u8], trailing: &[u8]) -> std::vec::Vec<u8> {
        let declared = SYSTEM_HEADER_LEN + body.len();
        let mut payload = std::vec::Vec::with_capacity(declared + trailing.len());
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(&(declared as u32).to_le_bytes());
        payload.extend_from_slice(body);
        payload.extend_from_slice(trailing);
        payload
    }

    #[test]
    fn parses_every_known_event_shape_and_preserves_unknown_ids() {
        for (id, body, expected) in [
            (0, &[0x10, 0x11][..], SystemEvent::PowerData(&[0x10, 0x11])),
            (1, &[][..], SystemEvent::InitDone),
            (2, &[0x20][..], SystemEvent::Statistics(&[0x20])),
            (3, &[][..], SystemEvent::DeinitDone),
            (
                12,
                &[0x30][..],
                SystemEvent::Other {
                    id: 12,
                    body: &[0x30],
                },
            ),
        ] {
            let bytes = payload(id, body, &[0xaa, 0xbb]);
            assert_eq!(
                parse_system_event(message(HostMessageType::System, &bytes)),
                Ok(expected),
                "event {id}"
            );
        }
    }

    #[test]
    fn rejects_wrong_message_type_and_every_invalid_length_boundary() {
        let valid = payload(1, &[], &[]);
        assert_eq!(
            parse_system_event(message(HostMessageType::Umac, &valid)),
            Err(ProtocolError::WrongMessageType)
        );
        assert_eq!(
            parse_system_event(message(HostMessageType::System, &valid[..7])),
            Err(ProtocolError::InvalidLength)
        );

        let mut below_header = valid.clone();
        below_header[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            parse_system_event(message(HostMessageType::System, &below_header)),
            Err(ProtocolError::InvalidLength)
        );

        let mut beyond_payload = valid;
        beyond_payload[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            parse_system_event(message(HostMessageType::System, &beyond_payload)),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn empty_events_reject_a_body() {
        for id in [1, 3] {
            let bytes = payload(id, &[0xff], &[]);
            assert_eq!(
                parse_system_event(message(HostMessageType::System, &bytes)),
                Err(ProtocolError::InvalidLength)
            );
        }
    }
}
