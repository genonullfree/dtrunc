# dtrunc: PCAP Detruncater

This tool processes a PCAP file and will output a file with any truncated packets fully expanded out with `0x00` bytes.

## Usage
```
Usage: dtrunc [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    Input pcap file to extract TCP streams from
  -o, --output <OUTPUT>  Output name template [default: output.pcap]
  -v, --verbose          Verbose output
  -h, --help             Print help
```
