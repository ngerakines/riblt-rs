use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use riblt::{ChecksumHash, CodedSymbol, Decoder, Encoder, HashKey, Symbol};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tokio::time::Instant;

const DEFAULT_PORT: u16 = 32000;
const BATCH_SIZE: usize = 10;
const TICK_INTERVAL: Duration = Duration::from_secs(2);
const ALPN: &[u8] = b"riblt-recon/1";

// --- Wire-serializable checksum trait ---

trait WireChecksum: ChecksumHash {
    fn write_to(val: &Self, w: &mut impl Write) -> io::Result<()>;
    fn read_from(r: &mut impl Read) -> io::Result<Self>;
}

impl WireChecksum for u64 {
    fn write_to(val: &Self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&val.to_le_bytes())
    }
    fn read_from(r: &mut impl Read) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

#[cfg(feature = "ecmh")]
impl WireChecksum for riblt::ecmh::EcmhChecksum {
    fn write_to(val: &Self, w: &mut impl Write) -> io::Result<()> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let compressed: CompressedRistretto = val.0.compress();
        w.write_all(compressed.as_bytes())
    }
    fn read_from(r: &mut impl Read) -> io::Result<Self> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        let compressed = CompressedRistretto(buf);
        let point = compressed
            .decompress()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid ristretto point"))?;
        Ok(riblt::ecmh::EcmhChecksum(point))
    }
}

// --- Wire-serializable symbol trait ---

trait WireSymbol: Symbol + Default
where
    Self::Checksum: WireChecksum,
{
    fn data(&self) -> &[u8];
    fn from_data(data: Vec<u8>) -> Self;
}

impl WireSymbol for riblt::byte_symbol::ByteSymbol {
    fn data(&self) -> &[u8] {
        &self.0
    }
    fn from_data(data: Vec<u8>) -> Self {
        Self(data)
    }
}

#[cfg(feature = "ecmh")]
impl WireSymbol for riblt::ecmh::EcmhByteSymbol {
    fn data(&self) -> &[u8] {
        &self.0
    }
    fn from_data(data: Vec<u8>) -> Self {
        Self(data)
    }
}

// --- Wire protocol ---

const TAG_CODED: u8 = 0x01;
const TAG_RESET: u8 = 0x02;

enum Message<T: Symbol> {
    CodedSymbol { epoch: u64, coded: CodedSymbol<T> },
    Reset { epoch: u64 },
}

/// Serialize a coded symbol message into a buffer (sync, writes to impl Write).
fn write_coded_symbol<T: WireSymbol>(
    w: &mut impl Write,
    epoch: u64,
    coded: &CodedSymbol<T>,
) -> io::Result<()>
where
    T::Checksum: WireChecksum,
{
    w.write_all(&[TAG_CODED])?;
    w.write_all(&epoch.to_le_bytes())?;
    w.write_all(&coded.count.to_le_bytes())?;
    <T::Checksum as WireChecksum>::write_to(&coded.hash, w)?;
    let data = coded.symbol.data();
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    Ok(())
}

/// Serialize a reset message into a buffer (sync, writes to impl Write).
fn write_reset(w: &mut impl Write, epoch: u64) -> io::Result<()> {
    w.write_all(&[TAG_RESET])?;
    w.write_all(&epoch.to_le_bytes())?;
    Ok(())
}

/// Read a message from a QUIC recv stream (async).
async fn read_message_async<T: WireSymbol>(r: &mut quinn::RecvStream) -> io::Result<Message<T>>
where
    T::Checksum: WireChecksum,
{
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;

    let mut epoch_buf = [0u8; 8];
    r.read_exact(&mut epoch_buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
    let epoch = u64::from_le_bytes(epoch_buf);

    match tag[0] {
        TAG_CODED => {
            let mut count_buf = [0u8; 8];
            r.read_exact(&mut count_buf)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            let count = i64::from_le_bytes(count_buf);

            // Read checksum: serialize to temp buffer, then parse sync
            let hash = {
                let mut checksum_buf = Vec::new();
                // Determine checksum size by reading into a sufficiently large buffer
                // For u64: 8 bytes, for EcmhChecksum: 32 bytes
                // We use the same trick as the sync version: read via a wrapper
                let size = std::mem::size_of::<T::Checksum>();
                // Fallback: checksums are either 8 bytes (u64) or 32 bytes (EcmhChecksum)
                // Since we can't easily determine size generically, read raw bytes
                // and parse with the sync reader
                checksum_buf.resize(size, 0);
                r.read_exact(&mut checksum_buf)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
                let mut cursor = io::Cursor::new(&checksum_buf);
                <T::Checksum as WireChecksum>::read_from(&mut cursor)?
            };

            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut data = vec![0u8; len];
            r.read_exact(&mut data)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;

            Ok(Message::CodedSymbol {
                epoch,
                coded: CodedSymbol {
                    symbol: T::from_data(data),
                    hash,
                    count,
                },
            })
        }
        TAG_RESET => Ok(Message::Reset { epoch }),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown message tag: {other:#x}"),
        )),
    }
}

// --- Events ---

enum Event<T: Symbol> {
    LocalSymbol(T),
    RemoteMessage(Message<T>),
    StdinClosed,
    NetworkClosed,
}

// --- Peer state ---

struct PeerState<T: Symbol> {
    local_symbols: Vec<T>,
    encoder: Encoder<T>,
    decoder: Decoder<T>,
    #[allow(dead_code)]
    key: Option<HashKey>,
    epoch: u64,
    symbols_sent: usize,
    symbols_received: usize,
    is_decoded: bool,
}

impl<T: WireSymbol> PeerState<T>
where
    T::Checksum: WireChecksum,
{
    fn new(initial_symbols: Vec<T>, key: Option<HashKey>) -> Self {
        let mut encoder: Encoder<T> = match key {
            Some(k) => Encoder::with_key(k),
            None => Encoder::new(),
        };
        let mut decoder: Decoder<T> = match key {
            Some(k) => Decoder::with_key(k),
            None => Decoder::new(),
        };
        for s in &initial_symbols {
            encoder.add_symbol(s.clone());
            decoder.add_symbol(s.clone());
        }
        Self {
            local_symbols: initial_symbols,
            encoder,
            decoder,
            key,
            epoch: 0,
            symbols_sent: 0,
            symbols_received: 0,
            is_decoded: false,
        }
    }

    fn reset(&mut self, new_epoch: u64) {
        self.epoch = new_epoch;
        self.encoder.reset();
        self.decoder.reset();
        for s in &self.local_symbols {
            self.encoder.add_symbol(s.clone());
            self.decoder.add_symbol(s.clone());
        }
        self.symbols_sent = 0;
        self.symbols_received = 0;
        self.is_decoded = false;
    }

    fn add_local_symbol(&mut self, sym: T) {
        self.local_symbols.push(sym);
        self.epoch += 1;
        self.reset(self.epoch);
    }

    fn produce_batch(&mut self) -> Vec<CodedSymbol<T>> {
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        for _ in 0..BATCH_SIZE {
            batch.push(self.encoder.produce_next_coded_symbol());
        }
        self.symbols_sent += BATCH_SIZE;
        batch
    }

    fn receive_coded_symbol(&mut self, coded: CodedSymbol<T>) {
        self.decoder.add_coded_symbol(coded);
        self.symbols_received += 1;
        self.decoder.try_decode();

        if self.decoder.decoded() && !self.is_decoded {
            self.is_decoded = true;
            self.print_results();
        }
    }

    fn print_results(&self) {
        let remote = self.decoder.remote();
        let local = self.decoder.local();

        // Clear the countdown line
        eprint!("\r\x1b[2K");

        eprintln!(
            "  Decoded after {} sent / {} received coded symbols",
            self.symbols_sent, self.symbols_received
        );

        if remote.is_empty() && local.is_empty() {
            eprintln!("  Sets are identical.");
        } else {
            if !remote.is_empty() {
                eprintln!("  Remote-only ({}):", remote.len());
                for s in remote {
                    let data = s.symbol.data();
                    if let Ok(val) = std::str::from_utf8(data) {
                        eprintln!("    + {val}");
                    } else {
                        eprintln!("    + {data:?}");
                    }
                }
            }
            if !local.is_empty() {
                eprintln!("  Local-only ({}):", local.len());
                for s in local {
                    let data = s.symbol.data();
                    if let Ok(val) = std::str::from_utf8(data) {
                        eprintln!("    - {val}");
                    } else {
                        eprintln!("    - {data:?}");
                    }
                }
            }
        }
        eprintln!();
        eprintln!("  Type a value to add to your local set, or Ctrl-C to quit.");
    }
}

// --- TLS configuration ---

fn generate_self_signed() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("cert generation failed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (cert_der, key_der)
}

fn make_server_endpoint(bind_addr: SocketAddr) -> quinn::Endpoint {
    let (cert_der, key_der) = generate_self_signed();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .expect("bad server cert/key");
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).expect("bad quic server config"),
    ));

    quinn::Endpoint::server(server_config, bind_addr).expect("failed to bind endpoint")
}

fn make_client_endpoint() -> quinn::Endpoint {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).expect("bad quic client config"),
    ));

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("failed to create endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Certificate verifier that accepts any server certificate (PoC only).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// --- Async send helpers ---

async fn send_batch_async<T: WireSymbol>(state: &mut PeerState<T>, stream: &mut quinn::SendStream)
where
    T::Checksum: WireChecksum,
{
    let batch = state.produce_batch();
    let mut buf = Vec::new();
    for coded in &batch {
        if write_coded_symbol(&mut buf, state.epoch, coded).is_err() {
            return;
        }
    }
    let _ = stream.write_all(&buf).await;
}

async fn send_reset_async<T: WireSymbol>(
    state: &PeerState<T>,
    stream: &mut quinn::SendStream,
) -> bool
where
    T::Checksum: WireChecksum,
{
    let mut buf = Vec::new();
    if write_reset(&mut buf, state.epoch).is_err() {
        return false;
    }
    stream.write_all(&buf).await.is_ok()
}

// --- Task spawners ---

fn spawn_stdin_reader<T: WireSymbol + Send + 'static>(tx: mpsc::Sender<Event<T>>)
where
    T::Checksum: WireChecksum + Send,
{
    tokio::task::spawn_blocking(move || {
        // Read from stdin (works with piped input)
        {
            let stdin = io::stdin();
            let reader = BufReader::new(stdin.lock());
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() {
                            let sym = T::from_data(trimmed.into_bytes());
                            if tx.blocking_send(Event::LocalSymbol(sym)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // Try to open /dev/tty for interactive input after pipe EOF
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            let reader = BufReader::new(tty);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() {
                            let sym = T::from_data(trimmed.into_bytes());
                            if tx.blocking_send(Event::LocalSymbol(sym)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let _ = tx.blocking_send(Event::StdinClosed);
    });
}

fn spawn_network_reader<T: WireSymbol + Send + 'static>(
    mut recv_stream: quinn::RecvStream,
    tx: mpsc::Sender<Event<T>>,
) where
    T::Checksum: WireChecksum + Send,
{
    tokio::spawn(async move {
        loop {
            match read_message_async::<T>(&mut recv_stream).await {
                Ok(msg) => {
                    if tx.send(Event::RemoteMessage(msg)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        eprintln!("  Network read error: {e}");
                    }
                    let _ = tx.send(Event::NetworkClosed).await;
                    return;
                }
            }
        }
    });
}

// --- Countdown display ---

fn print_countdown<T: WireSymbol>(remaining: Duration, state: &PeerState<T>)
where
    T::Checksum: WireChecksum,
{
    let secs = remaining.as_secs_f32();
    eprint!(
        "\r\x1b[2K  [epoch {}] sent {}, recv {} | next batch in {:.0}s (QUIC)",
        state.epoch, state.symbols_sent, state.symbols_received, secs
    );
    let _ = io::stderr().flush();
}

// --- Main event loop ---

async fn run_peer<T: WireSymbol + Send + 'static>(
    mut send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
    initial_symbols: Vec<T>,
    key: Option<HashKey>,
) where
    T::Checksum: WireChecksum + Send,
{
    let mut state = PeerState::new(initial_symbols, key);

    if key.is_some() {
        eprintln!("  Keyed hashing enabled.");
    }
    eprintln!(
        "  Connected (QUIC). Local set: {} elements. Streaming...",
        state.local_symbols.len()
    );

    let (tx, mut rx) = mpsc::channel::<Event<T>>(256);

    spawn_stdin_reader(tx.clone());
    spawn_network_reader(recv_stream, tx);

    // Send initial batch
    send_batch_async(&mut state, &mut send_stream).await;
    let mut last_send = Instant::now();

    let mut countdown = tokio::time::interval(Duration::from_millis(200));

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(Event::LocalSymbol(sym)) => {
                        eprint!("\r\x1b[2K");
                        let data = sym.data();
                        if let Ok(val) = std::str::from_utf8(data) {
                            eprintln!(
                                "  Added \"{val}\". Re-reconciling (epoch {})...",
                                state.epoch + 1
                            );
                        }
                        state.add_local_symbol(sym);

                        if !send_reset_async(&state, &mut send_stream).await {
                            eprintln!("  Connection lost.");
                            break;
                        }

                        send_batch_async(&mut state, &mut send_stream).await;
                        last_send = Instant::now();
                    }
                    Some(Event::RemoteMessage(Message::Reset { epoch })) => {
                        if epoch > state.epoch {
                            eprint!("\r\x1b[2K");
                            eprintln!("  Peer reset to epoch {epoch}. Re-reconciling...");
                            state.reset(epoch);
                            send_batch_async(&mut state, &mut send_stream).await;
                            last_send = Instant::now();
                        }
                    }
                    Some(Event::RemoteMessage(Message::CodedSymbol { epoch, coded })) => {
                        if epoch == state.epoch {
                            state.receive_coded_symbol(coded);
                        }
                    }
                    Some(Event::NetworkClosed) => {
                        eprint!("\r\x1b[2K");
                        eprintln!("  Peer disconnected.");
                        break;
                    }
                    Some(Event::StdinClosed) => {}
                    None => break,
                }
            }
            _ = countdown.tick() => {
                let elapsed = last_send.elapsed();
                if !state.is_decoded {
                    if elapsed >= TICK_INTERVAL {
                        eprint!("\r\x1b[2K");
                        send_batch_async(&mut state, &mut send_stream).await;
                        last_send = Instant::now();
                    } else {
                        let remaining = TICK_INTERVAL - elapsed;
                        print_countdown(remaining, &state);
                    }
                }
            }
        }
    }

    let _ = send_stream.finish();
}

// --- Argument parsing ---

struct PeerConfig {
    address: Option<String>,
    key: Option<HashKey>,
    #[cfg(feature = "ecmh")]
    ecmh: bool,
}

fn parse_args() -> PeerConfig {
    let args: Vec<String> = env::args().collect();

    if args.len() > 2 {
        print_usage();
        std::process::exit(1);
    }

    if args.len() == 1 {
        return PeerConfig {
            address: None,
            key: None,
            #[cfg(feature = "ecmh")]
            ecmh: false,
        };
    }

    let arg = &args[1];

    let (addr_part, query_part) = match arg.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (arg.as_str(), None),
    };

    let address = if addr_part.is_empty() {
        None
    } else {
        Some(addr_part.to_string())
    };

    let mut key: Option<HashKey> = None;
    #[cfg(feature = "ecmh")]
    let mut ecmh = false;

    if let Some(query) = query_part {
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                match k {
                    "key" => key = Some(derive_key(v)),
                    #[cfg(feature = "ecmh")]
                    "ecmh" => ecmh = v == "true" || v == "1",
                    _ => {}
                }
            }
        }
    }

    PeerConfig {
        address,
        key,
        #[cfg(feature = "ecmh")]
        ecmh,
    }
}

fn print_usage() {
    eprintln!("Usage: quinn-peer [address[:port][?key=VALUE&ecmh=true]]");
    eprintln!();
    eprintln!("  Listen mode:  seq 100 200 | quinn-peer");
    eprintln!("  With key:     seq 100 200 | quinn-peer '?key=mysecret'");
    eprintln!("  Connect mode: seq 98 198 | quinn-peer 127.0.0.1:32000");
    eprintln!("  With key:     seq 98 198 | quinn-peer '127.0.0.1:32000?key=mysecret'");
    #[cfg(feature = "ecmh")]
    eprintln!("  With ECMH:    seq 98 198 | quinn-peer '127.0.0.1:32000?ecmh=true&key=mysecret'");
}

/// Derive a 16-byte HashKey from an arbitrary string by hashing it.
fn derive_key(passphrase: &str) -> HashKey {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    passphrase.hash(&mut h1);
    let a = h1.finish();
    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    let b = h2.finish();
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&a.to_le_bytes());
    key[8..].copy_from_slice(&b.to_le_bytes());
    key
}

// --- Entry point ---

fn read_initial_symbols<T: WireSymbol>() -> Vec<T>
where
    T::Checksum: WireChecksum,
{
    let mut symbols = Vec::new();
    let stdin = io::stdin();

    if atty_check() {
        return symbols;
    }

    let reader = BufReader::new(stdin.lock());
    for line in reader.lines() {
        match line {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    symbols.push(T::from_data(trimmed.into_bytes()));
                }
            }
            Err(_) => break,
        }
    }
    symbols
}

/// Simple check: try to determine if stdin is a terminal.
fn atty_check() -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { isatty(io::stdin().as_raw_fd()) != 0 }
}

unsafe extern "C" {
    fn isatty(fd: i32) -> i32;
}

async fn start_peer<T: WireSymbol + Send + 'static>(config: &PeerConfig)
where
    T::Checksum: WireChecksum + Send,
{
    let symbols: Vec<T> = read_initial_symbols();

    match &config.address {
        None => {
            let bind_addr: SocketAddr = format!("0.0.0.0:{DEFAULT_PORT}").parse().unwrap();
            eprintln!(
                "  Listening on {bind_addr} ({} elements loaded) [QUIC]",
                symbols.len()
            );

            let endpoint = make_server_endpoint(bind_addr);
            let incoming = endpoint.accept().await.expect("no incoming connection");
            let connection = incoming.await.expect("connection failed");
            eprintln!(
                "  Peer connected from {} [QUIC]",
                connection.remote_address()
            );

            let (send_stream, recv_stream) = connection
                .accept_bi()
                .await
                .expect("failed to accept bi stream");
            run_peer(send_stream, recv_stream, symbols, config.key).await;

            endpoint.close(0u32.into(), b"done");
        }
        Some(target) => {
            let target_str = if target.contains(':') {
                target.clone()
            } else {
                format!("{target}:{DEFAULT_PORT}")
            };

            eprintln!(
                "  Connecting to {target_str} ({} elements loaded) [QUIC]...",
                symbols.len()
            );

            let target_addr: SocketAddr = target_str.parse().expect("invalid address");
            let endpoint = make_client_endpoint();
            let connection = endpoint
                .connect(target_addr, "localhost")
                .expect("connect config failed")
                .await
                .expect("connection failed");

            let (send_stream, recv_stream) = connection
                .open_bi()
                .await
                .expect("failed to open bi stream");
            run_peer(send_stream, recv_stream, symbols, config.key).await;

            endpoint.close(0u32.into(), b"done");
        }
    }
}

#[tokio::main]
async fn main() {
    let config = parse_args();

    #[cfg(feature = "ecmh")]
    if config.ecmh {
        eprintln!("  ECMH mode (ristretto255 checksums)");
        start_peer::<riblt::ecmh::EcmhByteSymbol>(&config).await;
        return;
    }

    start_peer::<riblt::byte_symbol::ByteSymbol>(&config).await;
}
