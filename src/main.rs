use clap::Parser;
use deku::prelude::*;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

#[derive(Parser, Debug)]
struct Opt {
    /// Input pcap file to extract TCP streams from
    #[arg(short, long, required = true)]
    input: String,

    /// Output name template
    #[arg(short, long, default_value = "output.pcap")]
    output: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

const PCAP_HEADER_LEN: usize = 24;
const PCAP_MAGIC: u32 = 0xa1b2c3d4;

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct PcapHeader {
    magic: u32,
    major: u16,
    minor: u16,
    resv1: u32,
    resv2: u32,
    snaplen: u32,
    #[deku(bits = "3")]
    fcs: u8,
    #[deku(bits = "1")]
    f: u8,
    #[deku(bits = "28")]
    linktype: u32,
}

impl PcapHeader {
    fn read(reader: &[u8]) -> Option<Self> {
        let (_, header) = PcapHeader::from_bytes((reader, 0)).ok()?;
        if header.magic == PCAP_MAGIC {
            Some(header)
        } else {
            None
        }
    }

    fn out(&self) -> Vec<u8> {
        self.to_bytes().unwrap()
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct PcapRecord {
    ts: u32,
    tn: u32,
    caplen: u32,
    origlen: u32,
    #[deku(count = "caplen")]
    data: Vec<u8>,
}

impl PcapRecord {
    fn read_all(mut cursor: &[u8]) -> Vec<Self> {
        let mut records = Vec::<Self>::new();
        while let Some(record) = Self::read(cursor) {
            cursor = &cursor[record.len()..];
            records.push(record);
        }
        records
    }

    fn read(reader: &[u8]) -> Option<Self> {
        let (_, record) = PcapRecord::from_bytes((reader, 0)).ok()?;
        Some(record)
    }

    fn write_all(records: &[Self], opt: &Opt) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        for (n, r) in records.iter().enumerate() {
            if opt.verbose {
                print!("\rAppending {:04} of {:04}", n + 1, records.len());
                let _ = io::stdout().flush();
            }
            out.append(&mut r.out());
        }
        out
    }

    fn out(&self) -> Vec<u8> {
        self.to_bytes().unwrap()
    }

    fn len(&self) -> usize {
        self.data.len() + 16
    }

    fn detruncate(records: Vec<PcapRecord>, opt: &Opt) -> Vec<PcapRecord> {
        let mut out = Vec::<PcapRecord>::new();
        let total_count = records.len();
        let mut count = 0;
        let mut orig_size = PCAP_HEADER_LEN;
        let mut out_size = PCAP_HEADER_LEN;

        for (n, mut rec) in records.into_iter().enumerate() {
            if rec.caplen == rec.origlen {
                if opt.verbose {
                    orig_size += rec.len();
                    out_size += rec.len();
                }
                out.push(rec);
                continue;
            }

            if rec.caplen > rec.origlen {
                panic!("Error: Captured length is greater than original length!");
            }

            if opt.verbose {
                println!(
                    "Packet {}: Resizing from {} to {}",
                    n + 1,
                    rec.caplen,
                    rec.origlen
                );
                orig_size += rec.len();
                out_size += rec.origlen as usize + 16;
            }
            rec.data.resize(
                rec.origlen
                    .try_into()
                    .expect("Error: Unable to convert origlen to usize"),
                0x00,
            );
            rec.caplen = rec.origlen;
            count += 1;
            out.push(rec);
        }

        if opt.verbose {
            println!("Packets detruncated: {count} of {total_count}");
            println!("Original filesize: {orig_size} New filesize: {out_size}");
        }

        out
    }
}

fn main() {
    let opt = Opt::parse();

    let mut file = File::open(&opt.input).expect("Error: Cannot open file");
    let mut reader = Vec::<u8>::new();
    let _ = file.read_to_end(&mut reader).expect("Cannot read file");

    if let Some(header) = PcapHeader::read(&reader) {
        println!("Loading {}...", opt.input);

        let records = PcapRecord::read_all(&reader[PCAP_HEADER_LEN..]);

        println!("Detruncating pcap records...");
        let detruncated = PcapRecord::detruncate(records, &opt);

        println!("Preparing data to write...");
        let mut data = header.out();
        data.append(&mut PcapRecord::write_all(&detruncated, &opt));

        println!("Writing output to: {}", opt.output);
        let mut output = File::create(&opt.output).expect("Error: Cannot create output file");
        output
            .write_all(&data)
            .expect("Error writing to output file");
    } else {
        println!("Error: {} cannot be loaded as a pcap file", opt.input);
    }
}
