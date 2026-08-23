//! Runtime for the first real-device proof.
//!
//! Zephyr owns the nRF70 mechanism, automatic reconnect/roaming, and the WPA
//! controlled port. Rust owns provisioning and every other runtime decision,
//! DHCP/TCP application logic, and the bounded Embassy tasks below.
//! Credentials are borrowed for one synchronous control call and wiped before
//! the endpoint is handed to the packet reactor.

use embassy_executor::Spawner;
use embassy_net::{Config, Stack, StackResources};
use embassy_time::{Duration, Timer};
use embassy_zephyr_nrf7002::{
    fill_random, split_network, ConnectRequest, DefaultSharedDevice, Error as PlatformError,
    InterfaceRole, NetworkDriver, NetworkReactor, Platform, ProvisioningConsole, Security,
    SharedDevice, Status, WifiController,
};
use static_cell::StaticCell;
use zephyr::{embassy::Executor, printkln};
use zeroize::Zeroize;

const RX_SLOTS: usize = 2;
const TX_SLOTS: usize = 2;
const STACK_SOCKET_SLOTS: usize = 2; // DHCP plus the single HTTP socket.
const CONSOLE_READ_SIZE: usize = 32;
const HTTP_REQUEST_SIZE: usize = 512;
const HTTP_RX_SIZE: usize = 1024;
const HTTP_TX_SIZE: usize = 1024;
const HTTP_PORT: u16 = 80;
const PROVISION_LINE_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 34\r\n\
Connection: close\r\n\
\r\n\
Hello from embassy-zephyr-nRF7002\n";

static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static NETWORK_DEVICE: StaticCell<DefaultSharedDevice> = StaticCell::new();
static NETWORK_RESOURCES: StaticCell<StackResources<STACK_SOCKET_SLOTS>> = StaticCell::new();
static HTTP_RX: StaticCell<[u8; HTTP_RX_SIZE]> = StaticCell::new();
static HTTP_TX: StaticCell<[u8; HTTP_TX_SIZE]> = StaticCell::new();

/// Zephyr calls this symbol from the C application entry shim.
#[no_mangle]
pub extern "C" fn rust_main() {
    printkln!("embassy-zephyr-nrf7002: Rust Wi-Fi provisioning + Embassy HTTP proof");

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(application()).unwrap();
    })
}

/// Runtime-owned bounded Wi-Fi credentials.
///
/// The SSID is wiped as well as the passphrase. This keeps the cleanup rule
/// simple: every return path from provisioning or connection setup drops one
/// value whose `Drop` implementation clears both buffers.
struct Credentials {
    ssid: SecretLine<{ embassy_zephyr_nrf7002::MAX_SSID_LEN }>,
    passphrase: SecretLine<{ embassy_zephyr_nrf7002::MAX_PASSPHRASE_LEN }>,
    security: Security,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.ssid.zeroize();
        self.passphrase.zeroize();
    }
}

/// A fixed-size line buffer with an explicit length and zeroizing cleanup.
struct SecretLine<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> SecretLine<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> Zeroize for SecretLine<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

impl<const N: usize> Drop for SecretLine<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisionError {
    Console(PlatformError),
    LineTooLong,
    EmptySsid,
    InvalidSecurity,
    InvalidPassphrase,
    Timeout,
}

/// Start the application only after Rust has collected dynamic credentials and
/// Zephyr has reported an authorized controlled port.
#[embassy_executor::task]
async fn application() -> ! {
    let mut wifi = loop {
        match WifiController::take() {
            Ok(controller) => break controller,
            Err(error) => {
                printkln!("wifi: control plane unavailable ({:?})", error);
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    };
    let capabilities = wifi.capabilities();
    if !capabilities.station()
        || !capabilities.softap()
        || !capabilities.concurrent_sta_ap()
        || !capabilities.runtime_credentials()
    {
        fatal("required Wi-Fi capabilities", PlatformError::Unsupported);
    }
    printkln!(
        "wifi: {} STA association, {} AP client, {} virtual interfaces",
        capabilities.max_sta_associations,
        capabilities.max_ap_clients,
        capabilities.max_virtual_interfaces
    );

    // Rust, not interface auto-start or a Zephyr application policy, decides
    // which role is powered. The AP role remains disabled until a Rust caller
    // explicitly enables and configures it.
    if let Err(error) = wifi.set_enabled(InterfaceRole::Station, true) {
        fatal("enable station", error);
    }

    let mut console = loop {
        match ProvisioningConsole::open() {
            Ok(console) => break console,
            Err(error) => {
                printkln!("wifi: provisioning console unavailable ({:?})", error);
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    };

    // The world regulatory domain is an explicit Rust-side selection for this
    // proof. Product provisioning may replace it with a validated country
    // without rebuilding the foundation.
    loop {
        match wifi.set_country(
            InterfaceRole::Station,
            embassy_zephyr_nrf7002::CountryCode::WORLD,
            false,
        ) {
            Ok(()) => break,
            Err(error) => {
                printkln!("wifi: regulatory domain rejected ({:?})", error);
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    }

    let platform = provision_and_connect(&mut console, &mut wifi).await;
    let seed = match hardware_seed() {
        Ok(seed) => seed,
        Err(error) => fatal("network random seed", error),
    };

    let device = NETWORK_DEVICE.init(SharedDevice::<RX_SLOTS, TX_SLOTS>::new());
    let split = match split_network(platform, device) {
        Ok(split) => split,
        Err(error) => fatal_driver("network split", error),
    };

    let spawner = Spawner::for_current_executor().await;
    let resources = NETWORK_RESOURCES.init(StackResources::new());
    let (stack, runner) = embassy_net::new(
        split.driver,
        Config::dhcpv4(Default::default()),
        resources,
        seed,
    );

    spawner.spawn(reactor_task(split.reactor)).unwrap();
    spawner.spawn(network_task(runner)).unwrap();
    spawner.spawn(http_task(stack)).unwrap();

    // Keep the Rust control owner alive and drain every management event. The
    // packet reactor independently handles data-plane link state, while this
    // supervisor is where product reactions/reconfiguration belong.
    let mut observed_dropped_events = 0;
    loop {
        match wifi.poll_event() {
            Ok(event) => {
                printkln!("wifi: control event {:?}", event);
                if event.dropped_events != observed_dropped_events {
                    observed_dropped_events = event.dropped_events;
                    printkln!(
                        "wifi: {} control events dropped; resynchronizing",
                        observed_dropped_events
                    );
                    printkln!(
                        "wifi: STA snapshot {:?}",
                        wifi.status(InterfaceRole::Station)
                    );
                    printkln!(
                        "wifi: AP snapshot {:?}",
                        wifi.status(InterfaceRole::AccessPoint)
                    );
                }
            }
            Err(PlatformError::WouldBlock) => {
                Timer::after(Duration::from_millis(25)).await;
            }
            Err(error) => {
                printkln!("wifi: control event error ({:?})", error);
                Timer::after(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Collect credentials from the Rust-owned provisioning console, issue a
/// borrowed connect request, wipe the Rust buffers, and wait for Connected.
async fn provision_and_connect(
    console: &mut ProvisioningConsole,
    wifi: &mut WifiController,
) -> Platform {
    loop {
        printkln!("wifi: opening Zephyr endpoint");
        let mut platform = loop {
            match Platform::open_endpoint() {
                Ok(platform) => break platform,
                Err(error) => {
                    printkln!("wifi: endpoint not ready ({:?})", error);
                    Timer::after(Duration::from_secs(1)).await;
                }
            }
        };

        let credentials = match collect_credentials(console).await {
            Ok(credentials) => credentials,
            Err(error) => {
                printkln!("wifi: invalid provisioning input ({:?})", error);
                Timer::after(Duration::from_millis(250)).await;
                continue;
            }
        };

        let request = ConnectRequest::new(
            credentials.ssid.as_slice(),
            credentials.security,
            credentials.passphrase.as_slice(),
        );
        match wifi.connect(request) {
            Ok(()) => {
                // The Zephyr bridge has synchronously handed the request to
                // the supplicant. No Rust credential bytes live past this
                // point, including while waiting for association.
                drop(credentials);
                printkln!("wifi: connect requested");
            }
            Err(error) => {
                printkln!("wifi: connect request rejected ({:?})", error);
                drop(credentials);
                let _ = platform.close();
                Timer::after(Duration::from_secs(1)).await;
                continue;
            }
        }

        match wait_for_connected(&mut platform, wifi).await {
            Ok(()) => {
                printkln!("wifi: connected");
                return platform;
            }
            Err(error) => {
                printkln!("wifi: association failed ({:?})", error);
                let _ = platform.close();
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn collect_credentials(
    console: &mut ProvisioningConsole,
) -> Result<Credentials, ProvisionError> {
    let mut credentials = Credentials {
        ssid: SecretLine::new(),
        passphrase: SecretLine::new(),
        security: Security::Open,
    };
    let mut skip_leading_delimiter = true;

    printkln!("wifi: enter SSID, then press Enter");
    read_line(console, &mut credentials.ssid, &mut skip_leading_delimiter).await?;
    if credentials.ssid.len == 0 {
        return Err(ProvisionError::EmptySsid);
    }

    let mut security = SecretLine::<8>::new();
    printkln!("wifi: enter security (open, wpa2, or wpa3), then press Enter");
    read_line(console, &mut security, &mut skip_leading_delimiter).await?;
    credentials.security = match security.as_slice() {
        b"open" => Security::Open,
        b"wpa2" => Security::Wpa2Psk,
        b"wpa3" => Security::Wpa3Sae,
        _ => return Err(ProvisionError::InvalidSecurity),
    };

    if !matches!(credentials.security, Security::Open) {
        printkln!("wifi: enter passphrase (input is not echoed), then press Enter");
        read_line(
            console,
            &mut credentials.passphrase,
            &mut skip_leading_delimiter,
        )
        .await?;
        if !(8..=embassy_zephyr_nrf7002::MAX_PASSPHRASE_LEN).contains(&credentials.passphrase.len) {
            return Err(ProvisionError::InvalidPassphrase);
        }
    }

    Ok(credentials)
}

/// Read exactly one bounded line without allocating or echoing its contents.
async fn read_line<const N: usize>(
    console: &mut ProvisioningConsole,
    line: &mut SecretLine<N>,
    skip_leading_delimiter: &mut bool,
) -> Result<(), ProvisionError> {
    let mut chunk = [0u8; CONSOLE_READ_SIZE];
    let mut overflow = false;
    let deadline = embassy_time::Instant::now() + PROVISION_LINE_TIMEOUT;

    loop {
        if embassy_time::Instant::now() >= deadline {
            return Err(ProvisionError::Timeout);
        }

        match console.read(&mut chunk) {
            Ok(0) => Timer::after(Duration::from_millis(10)).await,
            Ok(received) => {
                for (index, byte) in chunk[..received].iter().enumerate() {
                    match *byte {
                        b'\n' => {
                            if *skip_leading_delimiter && line.len == 0 {
                                *skip_leading_delimiter = false;
                                continue;
                            }
                            *skip_leading_delimiter = false;
                            return if overflow {
                                Err(ProvisionError::LineTooLong)
                            } else {
                                Ok(())
                            };
                        }
                        b'\r' => {
                            if *skip_leading_delimiter && line.len == 0 {
                                *skip_leading_delimiter = false;
                                continue;
                            }
                            *skip_leading_delimiter = chunk
                                .get(index + 1)
                                .map(|next| *next != b'\n')
                                .unwrap_or(true);
                            return if overflow {
                                Err(ProvisionError::LineTooLong)
                            } else {
                                Ok(())
                            };
                        }
                        0x20..=0x7e => {
                            *skip_leading_delimiter = false;
                            if line.len < N {
                                line.bytes[line.len] = *byte;
                                line.len += 1;
                            } else {
                                overflow = true;
                            }
                        }
                        _ => {
                            *skip_leading_delimiter = false;
                            overflow = true;
                        }
                    }
                }
            }
            Err(PlatformError::WouldBlock) => {
                Timer::after(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(ProvisionError::Console(error)),
        }
    }
}

async fn wait_for_connected(
    platform: &mut Platform,
    wifi: &mut WifiController,
) -> Result<(), PlatformError> {
    let deadline = embassy_time::Instant::now() + CONNECT_TIMEOUT;
    let mut last_status = None;

    loop {
        if embassy_time::Instant::now() >= deadline {
            return Err(PlatformError::TimedOut);
        }

        loop {
            match wifi.poll_event() {
                Ok(event) => printkln!("wifi: control event {:?}", event),
                Err(PlatformError::WouldBlock) => break,
                Err(error) => return Err(error),
            }
        }

        match platform.poll(0) {
            Ok(result) => {
                if last_status != Some(result.status()) {
                    printkln!("wifi: status {:?}", result.status());
                    last_status = Some(result.status());
                }
                if result.event() == Some(embassy_zephyr_nrf7002::WifiEvent::Disconnected) {
                    return Err(PlatformError::NotConnected);
                }
                if result.status() == Status::Connected {
                    return Ok(());
                }
                if result.status() == Status::Faulted {
                    return Err(PlatformError::Fault);
                }
            }
            Err(PlatformError::WouldBlock | PlatformError::TimedOut) => {}
            Err(error) => return Err(error),
        }

        Timer::after(Duration::from_millis(100)).await;
    }
}

fn hardware_seed() -> Result<u64, PlatformError> {
    let mut bytes = [0u8; 8];
    let result = fill_random(&mut bytes);
    let seed = u64::from_le_bytes(bytes);
    bytes.zeroize();
    result.map(|()| seed)
}

#[embassy_executor::task]
async fn reactor_task(mut reactor: NetworkReactor<'static, Platform, RX_SLOTS, TX_SLOTS>) -> ! {
    loop {
        match reactor.service_once() {
            Ok(report) => {
                if let Some(event) = report.event {
                    printkln!("wifi: link event {:?}", event);
                }
            }
            Err(error) => {
                printkln!("wifi: packet reactor error ({:?})", error);
            }
        }
        Timer::after(Duration::from_millis(10)).await;
    }
}

#[embassy_executor::task]
async fn network_task(
    mut runner: embassy_net::Runner<'static, NetworkDriver<'static, RX_SLOTS, TX_SLOTS>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn http_task(stack: Stack<'static>) -> ! {
    let rx = HTTP_RX.init([0; HTTP_RX_SIZE]);
    let tx = HTTP_TX.init([0; HTTP_TX_SIZE]);
    let mut request = [0u8; HTTP_REQUEST_SIZE];
    let mut socket = embassy_net::tcp::TcpSocket::new(stack, rx, tx);
    let mut announced_ip = false;

    loop {
        stack.wait_config_up().await;
        if !announced_ip {
            if let Some(config) = stack.config_v4() {
                let address = config.address.address().octets();
                printkln!(
                    "network: IPv4 {}.{}.{}.{}",
                    address[0],
                    address[1],
                    address[2],
                    address[3]
                );
                printkln!(
                    "http: http://{}.{}.{}.{}:{}/",
                    address[0],
                    address[1],
                    address[2],
                    address[3],
                    HTTP_PORT
                );
            }
            announced_ip = true;
        }

        match socket.accept(HTTP_PORT).await {
            Ok(()) => {
                request.fill(0);
                let read_result = socket.read(&mut request).await;
                if matches!(read_result, Ok(0)) {
                    socket.abort();
                    continue;
                }

                if read_result.is_ok() {
                    if write_all(&mut socket, HTTP_RESPONSE).await.is_ok() {
                        let _ = socket.flush().await;
                    }
                }
                socket.abort();
            }
            Err(error) => {
                printkln!("http: accept error ({:?})", error);
                socket.abort();
                Timer::after(Duration::from_millis(100)).await;
            }
        }

        if !stack.is_config_up() {
            announced_ip = false;
        }
    }
}

async fn write_all(socket: &mut embassy_net::tcp::TcpSocket<'_>, bytes: &[u8]) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match socket.write(&bytes[offset..]).await {
            Ok(0) => return Err(()),
            Ok(written) => offset += written,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

fn fatal(message: &'static str, error: PlatformError) -> ! {
    printkln!("fatal: {} ({:?})", message, error);
    panic!("embassy-zephyr-nrf7002 runtime initialization failed")
}

fn fatal_driver(message: &'static str, error: embassy_zephyr_nrf7002::NetworkDriverError) -> ! {
    printkln!("fatal: {} ({:?})", message, error);
    panic!("embassy-zephyr-nrf7002 network initialization failed")
}
