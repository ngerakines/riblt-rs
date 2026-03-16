use std::env;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use riblt::{ChecksumHash, CodedSymbol, Decoder, Encoder, HashKey, Symbol};

const DEFAULT_PORT: u16 = 32000;
const BATCH_SIZE: usize = 10;
const TICK_INTERVAL: Duration = Duration::from_secs(2);

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

fn write_reset(w: &mut impl Write, epoch: u64) -> io::Result<()> {
    w.write_all(&[TAG_RESET])?;
    w.write_all(&epoch.to_le_bytes())?;
    Ok(())
}

fn read_message<T: WireSymbol>(r: &mut impl Read) -> io::Result<Message<T>>
where
    T::Checksum: WireChecksum,
{
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;

    let mut epoch_buf = [0u8; 8];
    r.read_exact(&mut epoch_buf)?;
    let epoch = u64::from_le_bytes(epoch_buf);

    match tag[0] {
        TAG_CODED => {
            let mut count_buf = [0u8; 8];
            r.read_exact(&mut count_buf)?;
            let count = i64::from_le_bytes(count_buf);

            let hash = <T::Checksum as WireChecksum>::read_from(r)?;

            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut data = vec![0u8; len];
            r.read_exact(&mut data)?;

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

// --- Thread spawners ---

fn spawn_stdin_reader<T: WireSymbol + Send + 'static>(
    tx: Sender<Event<T>>,
) -> thread::JoinHandle<()>
where
    T::Checksum: WireChecksum + Send,
{
    thread::spawn(move || {
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
                            if tx.send(Event::LocalSymbol(sym)).is_err() {
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
                            if tx.send(Event::LocalSymbol(sym)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let _ = tx.send(Event::StdinClosed);
    })
}

fn spawn_network_reader<T: WireSymbol + Send + 'static>(
    stream: TcpStream,
    tx: Sender<Event<T>>,
) -> thread::JoinHandle<()>
where
    T::Checksum: WireChecksum + Send,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        loop {
            match read_message::<T>(&mut reader) {
                Ok(msg) => {
                    if tx.send(Event::RemoteMessage(msg)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        eprintln!("  Network read error: {e}");
                    }
                    let _ = tx.send(Event::NetworkClosed);
                    return;
                }
            }
        }
    })
}

// --- Countdown display ---

fn print_countdown<T: WireSymbol>(remaining: Duration, state: &PeerState<T>)
where
    T::Checksum: WireChecksum,
{
    let secs = remaining.as_secs_f32();
    eprint!(
        "\r\x1b[2K  [epoch {}] sent {}, recv {} | next batch in {:.0}s",
        state.epoch, state.symbols_sent, state.symbols_received, secs
    );
    let _ = io::stderr().flush();
}

// --- Main event loop ---

fn run_peer<T: WireSymbol + Send + 'static>(
    stream: TcpStream,
    initial_symbols: Vec<T>,
    key: Option<HashKey>,
) where
    T::Checksum: WireChecksum + Send,
{
    let write_stream = stream.try_clone().expect("failed to clone TcpStream");
    let read_stream = stream;

    let mut writer = BufWriter::new(write_stream);
    let mut state = PeerState::new(initial_symbols, key);

    if key.is_some() {
        eprintln!("  Keyed hashing enabled.");
    }
    eprintln!(
        "  Connected. Local set: {} elements. Streaming...",
        state.local_symbols.len()
    );

    let (tx, rx): (Sender<Event<T>>, Receiver<Event<T>>) = mpsc::channel();

    let stdin_tx = tx.clone();
    let _stdin_handle = spawn_stdin_reader(stdin_tx);

    let net_tx = tx;
    let _net_handle = spawn_network_reader(read_stream, net_tx);

    // Send initial batch
    send_batch(&mut state, &mut writer);
    let mut last_send = Instant::now();

    // Use a short poll interval so countdown updates smoothly
    let poll_interval = Duration::from_millis(200);

    loop {
        match rx.recv_timeout(poll_interval) {
            Ok(Event::LocalSymbol(sym)) => {
                // Clear countdown line
                eprint!("\r\x1b[2K");
                let data = sym.data();
                if let Ok(val) = std::str::from_utf8(data) {
                    eprintln!(
                        "  Added \"{val}\". Re-reconciling (epoch {})...",
                        state.epoch + 1
                    );
                }
                state.add_local_symbol(sym);

                // Notify peer of epoch reset
                if write_reset(&mut writer, state.epoch).is_err() {
                    eprintln!("  Connection lost.");
                    break;
                }
                let _ = writer.flush();

                // Send initial batch for new epoch
                send_batch(&mut state, &mut writer);
                last_send = Instant::now();
            }
            Ok(Event::RemoteMessage(Message::Reset { epoch })) => {
                if epoch > state.epoch {
                    eprint!("\r\x1b[2K");
                    eprintln!("  Peer reset to epoch {epoch}. Re-reconciling...");
                    state.reset(epoch);
                    // Send initial batch for new epoch
                    send_batch(&mut state, &mut writer);
                    last_send = Instant::now();
                }
            }
            Ok(Event::RemoteMessage(Message::CodedSymbol { epoch, coded })) => {
                if epoch == state.epoch {
                    state.receive_coded_symbol(coded);
                }
            }
            Ok(Event::NetworkClosed) => {
                eprint!("\r\x1b[2K");
                eprintln!("  Peer disconnected.");
                break;
            }
            Ok(Event::StdinClosed) => {
                // Stdin done, keep running for network
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Check if it's time to send the next batch
                let elapsed = last_send.elapsed();
                if !state.is_decoded {
                    if elapsed >= TICK_INTERVAL {
                        eprint!("\r\x1b[2K");
                        send_batch(&mut state, &mut writer);
                        last_send = Instant::now();
                    } else {
                        let remaining = TICK_INTERVAL - elapsed;
                        print_countdown(remaining, &state);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
}

fn send_batch<T: WireSymbol>(state: &mut PeerState<T>, writer: &mut BufWriter<TcpStream>)
where
    T::Checksum: WireChecksum,
{
    let batch = state.produce_batch();
    for coded in &batch {
        if write_coded_symbol(writer, state.epoch, coded).is_err() {
            return;
        }
    }
    let _ = writer.flush();
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

    // Split on '?' to separate address from query params
    let (addr_part, query_part) = match arg.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (arg.as_str(), None),
    };

    // Parse address (empty string means listen mode with just query params)
    let address = if addr_part.is_empty() {
        None
    } else {
        Some(addr_part.to_string())
    };

    // Parse query parameters
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
    eprintln!("Usage: rateless-peer [address[:port][?key=VALUE&ecmh=true]]");
    eprintln!();
    eprintln!("  Listen mode:  seq 100 200 | rateless-peer");
    eprintln!("  With key:     seq 100 200 | rateless-peer '?key=mysecret'");
    eprintln!("  Connect mode: seq 98 198 | rateless-peer 127.0.0.1:32000");
    eprintln!("  With key:     seq 98 198 | rateless-peer '127.0.0.1:32000?key=mysecret'");
    #[cfg(feature = "ecmh")]
    eprintln!(
        "  With ECMH:    seq 98 198 | rateless-peer '127.0.0.1:32000?ecmh=true&key=mysecret'"
    );
}

/// Derive a 16-byte HashKey from an arbitrary string by hashing it.
fn derive_key(passphrase: &str) -> HashKey {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    passphrase.hash(&mut h1);
    let a = h1.finish();
    // Hash again with a different seed for the second 8 bytes
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

    // Check if stdin is a tty — if so, no piped input
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

fn start_peer<T: WireSymbol + Send + 'static>(config: &PeerConfig)
where
    T::Checksum: WireChecksum + Send,
{
    let symbols: Vec<T> = read_initial_symbols();

    match &config.address {
        None => {
            let addr = format!("0.0.0.0:{DEFAULT_PORT}");
            eprintln!("  Listening on {addr} ({} elements loaded)", symbols.len());

            let listener = TcpListener::bind(&addr).expect("failed to bind");
            let (stream, peer_addr) = listener.accept().expect("failed to accept");
            eprintln!("  Peer connected from {peer_addr}");
            run_peer(stream, symbols, config.key);
        }
        Some(target) => {
            let target = if target.contains(':') {
                target.clone()
            } else {
                format!("{target}:{DEFAULT_PORT}")
            };

            eprintln!(
                "  Connecting to {target} ({} elements loaded)...",
                symbols.len()
            );

            let stream = TcpStream::connect(&target).expect("failed to connect");
            run_peer(stream, symbols, config.key);
        }
    }
}

fn main() {
    let config = parse_args();

    #[cfg(feature = "ecmh")]
    if config.ecmh {
        eprintln!("  ECMH mode (ristretto255 checksums)");
        start_peer::<riblt::ecmh::EcmhByteSymbol>(&config);
        return;
    }

    start_peer::<riblt::byte_symbol::ByteSymbol>(&config);
}
