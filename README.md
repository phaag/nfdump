# nfdump - Development branch

[![Build Status](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml)

**nfdump** is a powerful suite of tools for collecting, processing, and analyzing NetFlow, IPFIX, and sFlow data from network devices. It supports advanced [filtering](https://gist.github.com/phaag/06369bed7f39f97e1de51b1b0f5bc29a#file-cheatsheet-md), aggregation, and enrichment (geolocation, AS, Tor) of flow data with a focus on efficiency, flexibility, and extensibility.

---

## Table of Contents

- [Features](#features)
- [What changed in nfdump-1.8.0](#what-changed-in-nfdump-180)
- [Compatibility](#compatibility)
- [Installation](#installation)
- [Configuration Options](#configuration-options)
- [Basic Usage](#basic-usage)
- [Included Tools](#included-tools)
- [Compression](#compression)
- [How nfdump Works](#how-nfdump-works)
- [Sampling](#sampling)
- [NetFlow/NSEL/NAT Support](#netflownselnat-support)
- [Related Projects](#related-projects)
- [Sponsorship](#sponsorship)
- [License](#license)

---

## Features

- Collects NetFlow (v1, v5/v7, v9, IPFIX) and sFlow data.
- Converts live or file pcap traffic to flow data. 
- Multi-threaded for high-performance processing and sorting.
- Advanced flow filtering and aggregation (filter syntax similar to tcpdump, but optimized for flow data).
- Supports user-defined flow aggregation.
- Enriches flow records with geolocation, AS, and Tor exit node information.
- Flexible output formats (text, CSV, JSON, and user-defined).
- Optionally integrates GeoDB (geolookup/Maxmind) and TorDB (torlookup) databases.
- Companion tools for extending functionality and integration with monitoring stacks.
- Actively maintained and compatible with [NfSen](https://github.com/phaag/nfsen).

---
## What changed in nfdump-1.8.0

nfdump-1.8.0 replaces the nffile v2 container format with **nffile v3**, a redesigned
on-disk layout that adds a block directory and a redundant footer.  The directory records
the type, compressed size, and offset for every data block.  This makes random-access
and integrity verification possible without a full sequential scan, and lays the groundwork
for optional columnar indexing.  Furthermore, new data block types may be introduced as needed.
The footer carries an optional xxHash-64 checksum field covering the directory region. This enables the fast detection of truncated or corrupted files.  
Files are memory-mapped for reading (`mmap(2)`), eliminating intermediate copy buffers and letting
the OS page cache manage I/O scheduling.

Flow records move from the v3 extension format to **record format v4**.  The key structural
change is the replacement of a linear element list with a compact **offset table** indexed
by a 64-bit extension bitmap.  Locating a specific extension—say `EXipv4Flow` or
`EXasInfo`—no longer requires walking the preceding elements; instead a single
`__builtin_popcountll` on the bitmap gives the slot index directly, which is a branchless
O(1) operation that keeps the CPU pipeline and branch predictor in a clean state.  The
extension set is reorganized between V3 and V4. V3's combined `EXasRouting`
and `EXmacAddr` are split into separate IPv4/IPv6 and in/out variants respectively; the
BGP next-hop and IP next-hop types are removed (their data is covered by the routing
extensions). Newly added types are `EXinterface`, `EXasInfo`, `EXflowId`, `EXnokiaNat`,
`EXnokiaNatString`, and `EXipInfo`. The on-disk file size of nffile v3 is comparable to nffile v2 — sometimes marginally larger, sometimes marginally smaller. 

Both the v3 file format and the v4 record format are now strictly **8-byte aligned**, which avoids unaligned loads and matches the natural granularity of modern 64-bit load/store units.  Block-level compression
(LZO, LZ4, BZ2, ZSTD) is per-block. The file-level default can be overridden on a per-block basis.

The earliest nfdump version dates back to 2004, the era of **Intel Pentium 4** type CPUs, 1 core, 1–2 threads, DDR2 memory. Nowadays a Core i9 for example has 24 cores and 32 threads and uses DDR5 memory — roughly 50–100× faster than 2004 hardware. Although software designed in 2004 still runs on modern CPUs, the design and architecture can be significantly improved to exploit modern CPU features: adapt data layout to cache lines, optimize code for branch prediction, and avoid pointer chasing. nfdump 1.8.x still focuses on efficiency and speed and has removed a lot of legacy code. However, nfdump-1.7.x is not slow - it was constantly improved over time. The new 1.8.x simply improves and modernizes the code where possible.

The good news: nfdump-1.8.0 retains full **backward read compatibility**. All programs transparently read and process nfdump-1.7.x v2 files, but only write the new nffile v3 format. Some improvements are already implemented, such as a new IPFIX/NetFlow v9 pipeline decoder that improves decode throughput for these protocols. The collector hot path has been redesigned to reduce per-packet overhead.

The other news: nfdump-1.8.0 does not yet implement a full set of new features. The user experience should still feel familiar. Once the code stabilizes and is declared production-ready, new features will be added.

This is development code and should **not yet be used in production**. The branch is not yet fully tested. Feedback from real-world testing is very welcome — particularly from users testing their own nfdump workflows.

---
## Compatibility

- nfdump-1.8.x (codename "Colibri") is the current development release.

- Fully compatible with files created by nfdump-1.7.x or newer.

- Flow files from nfdump-1.7.x ("Unicorn") are processed transparently from all binaries.

- Legacy flow files from nfdump 1.6.x can no longer be processed. Use nfdump-1.7.8 to update these flow files to nfdump-1.7.x format and then process the resulting files with nfdump-1.8.x.

- To convert old files to the new format:

  ```sh
  ./nfdump -r old-flowfile -w new-flowfile -z=lz4
  ```

- **NfSen Users:** nfdump-1.8.x is not fully tested with NfSen and may or may not work. It is planned to keep nfdump-1.8.x compatible with legacy NfSen, although this compatibility may be removed in a future release.

---

## Installation

### Building for general use or to create a package

nfdump uses the GNU autotools 2.71 build system.

```sh
./autogen.sh
./configure
make
sudo make install
```

### Building for the local system

If you plan to run the tools on the same system where they are built, you can enable additional optimizations:
```sh
./autogen.sh
./configure --enable-native --enable-lto
make
sudo make install
```

This enables CPU-specific optimizations (`-march=native`) and link-time optimization (`-flto`) for improved performance.

#### Building on CentOS 7.x

Make sure, you have autotools 2.71 installed.

```sh
yum install centos-release-scl
yum install devtoolset-8-gcc devtoolset-8-gcc-c++
scl enable devtoolset-8 -- bash
```

#### Building on Ubuntu 18.04 LTS

Make sure, you have autotools 2.71 installed.

```sh
sudo apt-get install clang-10
CC=clang-10 ./configure ...
```

---

## Configuration Options

By default ./configure builds:

- the collectors `nfcapd`, `sfcapd`
- `nfdump` for processing flows
- additional tools `geolookup`, and `torlookup`

For a full list, run `./configure --help`. Options include:

- `--enable-nfpcapd`
  Build `nfpcapd` to create NetFlow from interface or pcap traffic (default: NO)
- `--enable-ja4`
  Enable all JA4 fingerprinting modules (default: NO)
- `--enable-jnat`
  Support JunOS special NAT event logging (default: NO)
- `--enable-readpcap`
  Enable reading flow data from pcap files in nfcapd (default: NO)
- `--enable-ftconv`
  Build the flow-tools to nfdump converter (default: NO)
- `--enable-nfprofile`
  Build nfprofile and nftrack, required by NfSen (default: NO)
- `--enable-devel`
  Enable debugging and developer options. For developers only (default: NO)
- `--with-lz4=PATH`, `--with-zstd=PATH`, `--with-bz2=PATH`
  Specify non-default library install locations for compression libraries.
- `--enable-lto`
  Enable link-time optimization (LTO) if supported. This allows the compiler to optimize across all source files during the final link step, improving performance and reducing binary size.
- `--enable-native`
  Use `-march=native` to enable CPU-specific optimizations for the build host. This enables vectorization and instruction set tuning based on the local processor. Recommended for local builds, not for portable binaries.

Compared to previous versions, the configure script has changed: many tools that previously required explicit enabling are now built automatically. The old options `--enable-xxxpath=path` have been replaced by the standard `--with-xxx=path`

Compression libraries are searched for and integrated, if found. If you want to explicitly disable a library and therefore a compression method, use the format `--enable-xxx=no` This disables that library.

The following options no longer exist:

`--enable-nsel`
NSEL support is built-in by default; you only need to adjust the output format if you prefer the legacy *line* or *long* format for NSEL/NAT. Change the `fmt` formats accordingly in the config file `nfdump.conf`

Notes:

- Make sure your system does provide autoconf 2.71.
- Older Linux distributions may require libbsd and libbsd-dev installed. 

- `nfprofile` is a legacy binary, used by NfSen and may be moved into a separate archive in future.

---

## Basic Usage

Exporter → nfcapd → nfdump → analysis/export (CSV, JSON, InfluxDB, Prometheus)

nfdump provides a set of collection and processing tools. Common tools and example commands:

### Start NetFlow Collector

```sh
nfcapd -D -S 2 -w /flow_base_dir/router1 -p 23456
```

### View Collected Data

```sh
nfdump -r /flow_base_dir/router1/nfcapd.202501011200
```

### Filter and Aggregate Flows

```sh
nfdump -r flowfile 'src ip 192.0.2.1 and dst port 443' -A srcip,dstip
```

### Enrich with Geolocation or Tor Information

Enable and configure geolookup/torlookup databases as needed. For details, see the relevant man pages (`man geolookup`, `man torlookup`).

### Export Metrics

Send metrics to InfluxDB or Prometheus-compatible tools using [nfinflux](https://github.com/phaag/nfinflux) or [nfexporter](https://github.com/phaag/nfexporter).

---

## Included Tools

nfdump includes several related tools for extended workflows:

- **nfcapd**
  NetFlow collector daemon. Collects NetFlow version v1/v5/v7/v9 and IPFIX streams from one or many exporters and stores the flow record data in nfdump binary files.

- **sfcapd**
  sFlow collector daemon. Collects sflow v4/v6 (sflowtool compatible) streams from one or many exporters and stores the flow record data in nfdump binary files.

- **nfpcapd**
  Converts live traffic from a host interface or pcap-captured network traffic to NetFlow records. Stores the flow record data in nfdump binary files or forwards a data stream to a running `nfcapd` collector on another host.

- **nfdump**
  Reads nfdump binary files, filters flow records and post-processes flow records. The extensive filter language (See the available [cheatsheet](https://gist.github.com/phaag/06369bed7f39f97e1de51b1b0f5bc29a#file-cheatsheet-md) ) selects flows for processing. The post-processing includes:

  - Flexible flow aggregation
  - Flow statistics, based on any flow element
  - Flow listings
  - Flow enrichment with optional geo and/or tor exit node information.
  
- **geolookup**
  Look up IP addresses for country, region, city, and optionally AS information. Requires a geo database to work. See the provided `updateGeoDB.sh` script in order to build the database.

- **torlookup**
  Look up IP addresses for Tor exit node information. Requires a TorDB database to work. See the provided `updateTorDB.sh` script in order to build the database.

- **nfanon**
  Anonymizes IP addresses in flow records using CryptoPAn.

- **nfexpire**
  Manages expiration of old flow data.

- **nfreplay**
  Replays collected NetFlow data to another collector.

- **ft2nfdump**
  Converts flow-tools format to nfdump format. (optionally built)

- **nfprofile** and **nftrack**


  Programs required by NfSen. `nfprofile` filters and organizes flows by profile, and `nftrack` provides port tracking for the PortTracker plugin.

- **nfreader**
  Framework for custom C code to process nfdump files. Not installed by default.

---

## Compression

Collected data files can be compressed using LZO, LZ4, ZSTD, or bzip2.  
- LZO and LZ4 are embedded and require no external dependencies by default.
- ZSTD and bzip2 require system libraries, auto-detected at build time.
- To compress on the fly, use the `-z` option, e.g. `-z=lz4`.

**Example:**

```sh
nfcapd -z=lz4 ...
```

- Use bzip2 for maximum compression when archiving; use LZ4 (recommended) for fast, efficient real-time compression.

---

## How nfdump Works

nfdump is designed to analyze both historical and live NetFlow data, enabling continuous or retrospective monitoring of network traffic. The system is optimized for speed and efficiency, allowing complex filtering and aggregation of flow records with a syntax similar to tcpdump.

### Data Storage and Organization

- All collected data is stored to disk before analysis, separating collection from processing.
- Data is organized in a time-based directory structure, typically rotating files every 5 minutes.

**Example directory structure:**
```
/flow_base_dir/router1
/flow_base_dir/router2
```
Each subdirectory corresponds to a different flow source.

**Example file rotation:**
```
nfcapd.YYYYMMDDhhmm (e.g., nfcapd.200907110845 contains data from July 11th 2009 08:45 onward)
```
With a 5-minute interval, there are 288 files per day.

### Collecting from Multiple Sources

While multiple flow sources can be sent to a single collector, it is recommended to run multiple collectors on busy networks.

**Start two collectors on different ports:**
```sh
nfcapd -D -S 2 -B 1024000 -w /flow_base_dir/router1 -p 23456
nfcapd -D -S 2 -B 1024000 -w /flow_base_dir/router2 -p 23457
```

**Collect all sources into the same file:**
```sh
nfcapd -D -S 2 -w /flow_base_dir/routers -p 23456
```

**Split collected data per source:**
```sh
nfcapd -D -S 2 -n router1,172.16.17.18,/flow_base_dir/router1 \
       -n router2,172.16.17.20,/flow_base_dir/router2 -p 23456
```

See `nfcapd(1)` for a detailed explanation of all options.

### Security

- No root privileges are required unless binding to ports < 1024.
- nfcapd has no built-in access control; rely on host-level security to filter IP addresses.

### Analyzing and Filtering Data

Data can be analyzed from a single file or by concatenating multiple files. Output can be in ASCII text or binary format for further processing.

**Example:**
```sh
nfdump -r /flow_base_dir/router1/nfcapd.202501011200
```

The filter syntax is powerful and inspired by tcpdump but tailored for flow data. For example:

```sh
nfdump -r flowfile 'src ip 192.0.2.1 and dst port 443'
```

Filter rules can be combined, and flows can be aggregated and output in various formats, including CSV for post-processing.

### Example: Cisco Router NetFlow Configuration

**Enable NetFlow on an interface:**
```
interface fastethernet 0/0
 ip address 192.168.92.162 255.255.255.224
 ip route-cache flow
```

**Export NetFlow data:**
```
ip flow-export 192.168.92.218 9995
ip flow-export version 5 
ip flow-cache timeout active 5
```
This breaks up long-lived flows into 5-minute segments. You can set any number of minutes between 1 and 60.

**NetFlow v9 full export example with sampling:**
```
interface Ethernet1/0
 ip address 192.168.92.162 255.255.255.224
 duplex half
 flow-sampler my-map
!
!
flow-sampler-map my-map
 mode random one-out-of 5
!
ip flow-cache timeout inactive 60
ip flow-cache timeout active 1
ip flow-capture fragment-offset
ip flow-capture packet-length
ip flow-capture ttl
ip flow-capture vlan-id
ip flow-capture icmp
ip flow-capture ip-id
ip flow-capture mac-addresses
ip flow-export version 9
ip flow-export template options export-stats
ip flow-export template options sampler
ip flow-export template options timeout-rate 1
ip flow-export template timeout-rate 1
ip flow-export destination 192.168.92.218 9995
```

See your device documentation for full details on NetFlow configuration.

**Note:** NetFlow v5 and v7 use 32-bit counters, which may overflow on busy routers. To prevent overflow, reduce the flow-cache timeout. All nfdump tools use 64-bit counters internally.

### Architecture Notes

- The binary file format is NetFlow version independent but architecture-dependent  (little vs. big endian).
- Internally, all processing is IP protocol independent (supports IPv4 and IPv6).

---

## Sampling

By default, the sampling rate is 1 (unsampled) or the value specified via `-s`. If the NetFlow stream contains sampling information, that value takes precedence. Nfcapd automatically recognizes sampling when announced in v9/IPFIX option templates with tags set (`#302, #304, #305, #306`, `#48, #49, #50`, `#34, #35`), or in the unofficial v5 header hack. The sampling data is stored in the sampling information fields in the flow record.

**Note:** Not all platforms (or vendor software versions) support exporting sampling information in NetFlow data, even if sampling is configured. The number of bytes and packets in each NetFlow record is automatically multiplied by the sampling rate. The total number of flows is not changed as this is not accurate enough (small flows versus large flows).

---

## NetFlow/NSEL/NAT Support

- Supports Cisco NSEL (Network Event Security Logging) and NEL (NAT Event Logging) via NetFlow v9.
- Partially compatible with JunOS NAT Event Logging (enable with `--enable-jnat`).

---

## Related Projects

- [go-nfdump](https://github.com/phaag/go-nfdump): Read nfdump files in Go.
- [nfinflux](https://github.com/phaag/nfinflux): Export metrics to InfluxDB.
- [nfexporter](https://github.com/phaag/nfexporter): Export metrics for Prometheus.
- [NfSen](https://github.com/phaag/nfsen): Old legacy graphical frontend.
- [nfsen-ng](https://github.com/mbolli/nfsen-ng): Project from Michael Bolli

---

## Sponsorship

If you find nfdump useful, please consider supporting development:  
[GitHub Sponsors: phaag](https://github.com/sponsors/phaag)

---

## License

nfdump is released under the BSD license. See the [LICENSE](LICENSE) file for details.

---

## Support & Documentation

- For detailed usage instructions, consult the man pages (`man nfdump`, `man nfcapd`, etc.) or run any tool with the `-h` switch.
- Feel free to open issues or pull requests.
- For other questions please see my email address in the AUTHORS.
- For the latest updates, visit the [nfdump repository on GitHub](https://github.com/phaag/nfdump).
