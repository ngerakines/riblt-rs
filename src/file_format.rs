use std::io::{self, Read, Write};

use crate::byte_symbol::ByteSymbol;
use crate::coded_symbol::CodedSymbol;

/// Magic bytes identifying an RIBLT file.
const MAGIC: &[u8; 6] = b"RIBLT1";

/// File format version.
const VERSION: u8 = 1;

/// An RIBLT file containing metadata and coded symbols.
pub struct RibltFile {
    /// Number of source records encoded.
    pub num_records: u64,
    /// The coded symbols.
    pub coded_symbols: Vec<CodedSymbol<ByteSymbol>>,
}

impl RibltFile {
    /// Write this file to a writer in binary format.
    ///
    /// Format:
    /// - Magic: "RIBLT1" (6 bytes)
    /// - Version: u8
    /// - num_records: u64 LE
    /// - num_symbols: u64 LE
    /// - For each coded symbol:
    ///   - count: i64 LE
    ///   - hash: u64 LE
    ///   - value_len: u32 LE
    ///   - value_bytes: [u8; value_len]
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&[VERSION])?;
        w.write_all(&self.num_records.to_le_bytes())?;
        w.write_all(&(self.coded_symbols.len() as u64).to_le_bytes())?;

        for cs in &self.coded_symbols {
            w.write_all(&cs.count.to_le_bytes())?;
            w.write_all(&cs.hash.to_le_bytes())?;
            let val = &cs.symbol.0;
            w.write_all(&(val.len() as u32).to_le_bytes())?;
            w.write_all(val)?;
        }

        Ok(())
    }

    /// Read an RIBLT file from a reader.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 6];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a valid RIBLT file (bad magic)",
            ));
        }

        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported RIBLT file version: {}", version[0]),
            ));
        }

        let mut buf8 = [0u8; 8];

        r.read_exact(&mut buf8)?;
        let num_records = u64::from_le_bytes(buf8);

        r.read_exact(&mut buf8)?;
        let num_symbols = u64::from_le_bytes(buf8);

        let mut coded_symbols = Vec::with_capacity(num_symbols as usize);
        for _ in 0..num_symbols {
            r.read_exact(&mut buf8)?;
            let count = i64::from_le_bytes(buf8);

            r.read_exact(&mut buf8)?;
            let hash = u64::from_le_bytes(buf8);

            let mut buf4 = [0u8; 4];
            r.read_exact(&mut buf4)?;
            let val_len = u32::from_le_bytes(buf4) as usize;

            let mut val = vec![0u8; val_len];
            r.read_exact(&mut val)?;

            coded_symbols.push(CodedSymbol {
                symbol: ByteSymbol(val),
                hash,
                count,
            });
        }

        Ok(Self {
            num_records,
            coded_symbols,
        })
    }
}
