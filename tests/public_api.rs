use embassy_nrf7002::{DataPath, NRF_WIFI_SOURCE_REVISION, ScanRequest};
use embassy_nrf7002::{
    data::{MAX_TX_TOKENS, RPU_MEM_PACKET_BASE, TX_COMMAND_SLOT_SIZE},
    device::{DEFAULT_CONTROL_FRAGMENT_LEN, MAX_EVENT_FRAGMENT_LEN, RPU_MEM_TX_CMD_BASE},
    protocol::{DataCommand, HostMessageType, UmacCommand, UmacEvent},
};

#[test]
fn pinned_revision_and_public_types_are_available() {
    assert_eq!(NRF_WIFI_SOURCE_REVISION.len(), 40);
    let _ = DataPath::<8, 4>::new(1600, 1514).unwrap();
    let _ = ScanRequest::all_bands();
}

#[test]
fn rust_numeric_abi_matches_the_pinned_nordic_interface() {
    assert_eq!(HostMessageType::System as i32, 0);
    assert_eq!(HostMessageType::Supplicant as i32, 1);
    assert_eq!(HostMessageType::Data as i32, 2);
    assert_eq!(HostMessageType::Umac as i32, 3);

    assert_eq!(UmacCommand::TriggerScan as u32, 0);
    assert_eq!(UmacCommand::GetScanResults as u32, 1);
    assert_eq!(UmacCommand::Deauthenticate as u32, 4);
    assert_eq!(UmacCommand::NewInterface as u32, 15);

    assert_eq!(UmacEvent::ScanStarted as u32, 257);
    assert_eq!(UmacEvent::ScanAborted as u32, 258);
    assert_eq!(UmacEvent::ScanDone as u32, 259);
    assert_eq!(UmacEvent::ScanResult as u32, 260);
    assert_eq!(UmacEvent::Deauthenticate as u32, 264);
    assert_eq!(UmacEvent::Disconnect as u32, 271);
    assert_eq!(UmacEvent::NewInterface as u32, 281);
    assert_eq!(UmacEvent::ScanDisplayResult as u32, 291);
    assert_eq!(UmacEvent::CommandStatus as u32, 292);

    assert_eq!(DataCommand::TransmitBuffer as u32, 1);
    assert_eq!(DataCommand::TransmitDone as u32, 2);
    assert_eq!(DataCommand::ReceiveBuffer as u32, 3);
    assert_eq!(DataCommand::CarrierOn as u32, 4);
    assert_eq!(DataCommand::CarrierOff as u32, 5);

    assert_eq!(DEFAULT_CONTROL_FRAGMENT_LEN, 400);
    assert_eq!(MAX_EVENT_FRAGMENT_LEN, 1000);
    assert_eq!(RPU_MEM_TX_CMD_BASE, 0xb000_00b8);
    assert_eq!(RPU_MEM_PACKET_BASE, 0xb000_5000);
    assert_eq!(TX_COMMAND_SLOT_SIZE, 148);
    assert_eq!(MAX_TX_TOKENS, 137);
}
