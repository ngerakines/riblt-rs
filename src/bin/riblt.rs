use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process;

use riblt::byte_symbol::ByteSymbol;
use riblt::file_format::RibltFile;
use riblt::{CodedSymbol, Encoder, Symbol};

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  <data> | riblt --out <file.riblt> [--num <count>]");
    eprintln!("  riblt compare <file_a.riblt> <file_b.riblt>");
    eprintln!("  riblt difference <file_a.riblt> <file_b.riblt>");
    process::exit(1);
}

fn build_from_stdin(output: PathBuf, num_symbols: Option<usize>) -> io::Result<()> {
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());

    let mut encoder = Encoder::<ByteSymbol>::new();
    let mut num_records: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        encoder.add_symbol(ByteSymbol(line.into_bytes()));
        num_records += 1;
    }

    // Default: 2x records, minimum 100
    let count = num_symbols.unwrap_or_else(|| (num_records as usize * 2).max(100));

    let coded_symbols: Vec<CodedSymbol<ByteSymbol>> = (0..count)
        .map(|_| encoder.produce_next_coded_symbol())
        .collect();

    let file = RibltFile {
        num_records,
        coded_symbols,
    };

    let out = File::create(&output)?;
    let mut writer = BufWriter::new(out);
    file.write_to(&mut writer)?;
    writer.flush()?;

    eprintln!(
        "Encoded {num_records} records into {count} coded symbols -> {}",
        output.display()
    );

    Ok(())
}

fn cmd_compare(file_a: PathBuf, file_b: PathBuf) -> io::Result<()> {
    let a = RibltFile::read_from(&mut BufReader::new(File::open(&file_a)?))?;
    let b = RibltFile::read_from(&mut BufReader::new(File::open(&file_b)?))?;

    let use_len = a.coded_symbols.len().min(b.coded_symbols.len());
    if use_len == 0 {
        eprintln!("Error: one or both files have no coded symbols");
        process::exit(1);
    }

    let mut diff_symbols: Vec<CodedSymbol<ByteSymbol>> = a
        .coded_symbols
        .iter()
        .zip(b.coded_symbols.iter())
        .take(use_len)
        .map(|(ca, cb)| CodedSymbol {
            symbol: ca.symbol.xor(&cb.symbol),
            hash: ca.hash ^ cb.hash,
            count: ca.count - cb.count,
        })
        .collect();

    let all_zero = diff_symbols.iter().all(|cs| cs.is_zero());

    if all_zero {
        println!("MATCH: sets are identical");
        println!(
            "  File A: {} ({} records, {} symbols)",
            file_a.display(),
            a.num_records,
            a.coded_symbols.len()
        );
        println!(
            "  File B: {} ({} records, {} symbols)",
            file_b.display(),
            b.num_records,
            b.coded_symbols.len()
        );
    } else {
        let (fwd, rev, success) = peel_difference(&mut diff_symbols);

        if success {
            let total_diff = fwd.len() + rev.len();
            println!("DIFFER: {total_diff} element(s) differ");
            println!("  {} only in {}", fwd.len(), file_a.display());
            println!("  {} only in {}", rev.len(), file_b.display());
        } else {
            println!("DIFFER: sets are not identical (could not fully decode difference)");
            println!("  Hint: files may need more coded symbols for full comparison");
        }
    }

    Ok(())
}

fn cmd_difference(file_a: PathBuf, file_b: PathBuf) -> io::Result<()> {
    let a = RibltFile::read_from(&mut BufReader::new(File::open(&file_a)?))?;
    let b = RibltFile::read_from(&mut BufReader::new(File::open(&file_b)?))?;

    let use_len = a.coded_symbols.len().min(b.coded_symbols.len());
    if use_len == 0 {
        eprintln!("Error: one or both files have no coded symbols");
        process::exit(1);
    }

    let mut diff_symbols: Vec<CodedSymbol<ByteSymbol>> = a
        .coded_symbols
        .iter()
        .zip(b.coded_symbols.iter())
        .take(use_len)
        .map(|(ca, cb)| CodedSymbol {
            symbol: ca.symbol.xor(&cb.symbol),
            hash: ca.hash ^ cb.hash,
            count: ca.count - cb.count,
        })
        .collect();

    let (fwd, rev, success) = peel_difference(&mut diff_symbols);

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for s in &fwd {
        writeln!(out, "- {}", String::from_utf8_lossy(&s.0))?;
    }
    for s in &rev {
        writeln!(out, "+ {}", String::from_utf8_lossy(&s.0))?;
    }

    if !success {
        eprintln!(
            "Warning: could not fully decode difference. \
             Try encoding with more coded symbols (--num)."
        );
        process::exit(2);
    }

    Ok(())
}

/// Peel a difference sketch to extract forward (A-only) and reverse (B-only) elements.
fn peel_difference(
    symbols: &mut [CodedSymbol<ByteSymbol>],
) -> (Vec<ByteSymbol>, Vec<ByteSymbol>, bool) {
    let mut forward = Vec::new();
    let mut reverse = Vec::new();
    let len = symbols.len();

    loop {
        let mut progress = false;

        for i in 0..len {
            if symbols[i].is_zero() {
                continue;
            }
            if !symbols[i].is_pure() {
                continue;
            }

            let recovered = ByteSymbol::default().xor(&symbols[i].symbol);
            let hash = symbols[i].hash;
            let direction = if symbols[i].count == 1 {
                forward.push(recovered.clone());
                -1i64
            } else {
                reverse.push(recovered.clone());
                1i64
            };

            // Peel from all mapped coded symbols
            let mut mapping = riblt::RandomMapping::new(hash);
            loop {
                let idx = mapping.last_index();
                if idx >= len {
                    break;
                }
                symbols[idx].symbol = symbols[idx].symbol.xor(&recovered);
                symbols[idx].hash ^= hash;
                symbols[idx].count += direction;
                mapping.next_index();
            }

            progress = true;
        }

        if !progress {
            break;
        }
    }

    let success = symbols.iter().all(|cs| cs.is_zero());
    (forward, reverse, success)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Parse --out and --num flags, collect remaining positional args
    let mut output: Option<PathBuf> = None;
    let mut num_symbols: Option<usize> = None;
    let mut positional = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                output = Some(PathBuf::from(args.get(i).unwrap_or_else(|| {
                    eprintln!("Error: --out requires a path");
                    process::exit(1);
                })));
            }
            "--num" => {
                i += 1;
                let val = args.get(i).unwrap_or_else(|| {
                    eprintln!("Error: --num requires a number");
                    process::exit(1);
                });
                num_symbols = Some(val.parse().unwrap_or_else(|_| {
                    eprintln!("Error: --num must be a positive integer");
                    process::exit(1);
                }));
            }
            "--help" | "-h" => usage(),
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    let result = match positional.len() {
        0 => {
            // Build mode: read from stdin
            let out = output.unwrap_or_else(|| {
                eprintln!("Error: --out <path> is required when building from stdin");
                usage();
            });
            build_from_stdin(out, num_symbols)
        }
        3 => {
            let cmd = positional[0].as_str();
            let file_a = PathBuf::from(&positional[1]);
            let file_b = PathBuf::from(&positional[2]);
            match cmd {
                "compare" => cmd_compare(file_a, file_b),
                "difference" => cmd_difference(file_a, file_b),
                _ => {
                    eprintln!("Error: unknown command '{cmd}'");
                    usage();
                }
            }
        }
        _ => usage(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
