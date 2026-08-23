use embassy_nrf7002::{DataPath, NRF_WIFI_SOURCE_REVISION, ScanRequest};

#[test]
fn pinned_revision_and_public_types_are_available() {
    assert_eq!(NRF_WIFI_SOURCE_REVISION.len(), 40);
    let _ = DataPath::<8, 4>::new(1600, 1514).unwrap();
    let _ = ScanRequest::all_bands();
}
