# nfdump

[![Build Status](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml)

**nfdump** is a powerful suite of tools for collecting, processing, and analyzing NetFlow, IPFIX, and sFlow data from network devices. It supports advanced filtering, aggregation, and enrichment (geolocation, AS, Tor) of flow data with a focus on efficiency, flexibility, and extensibility.

---

## Table of Contents

- [Features](#features)
- [Compatibility](#compatibility)
- [Installation](#installation)
- [Configuration Options](#configuration-options)
- [Usage Overview](#usage-overview)
- [Additional Tools](#additional-tools)
- [Compression](#compression)
- [General Operation](#general-operation-of-nfdump)
- [Sampling](#sampling)
- [NetFlow/NSEL/NAT Support](#netflownselnat-support)
- [Related Projects](#related-projects)
- [Sponsorship](#sponsorship)
- [License](#license)

---

## Features

- Collects NetFlow (v1, v5/v7, v9, IPFIX) and sFlow data.
- Multi-threaded for high-performance processing and sorting.
- Advanced flow filtering and aggregation (filter syntax similar to tcpdump, but optimized for flow data).
- Supports user-defined flow aggregation.
- Enriches flow records with geolocation, AS, and Tor exit node information.
- Flexible output formats (text, CSV, JSON, and user-defined).
- Optionally integrates GeoDB (geolookup/Maxmind) and TorDB (torlookup) databases.
- Companion tools for extending functionality and integration with monitoring stacks.
- Actively maintained and compatible with [NfSen](https://github.com/phaag/nfsen).

---

## Compatibility

- nfdump-1.7.x (codename “unicorn”) is the current release series.
- Fully compatible with files created by nfdump-1.6.18 or newer.
- Legacy flow files from earlier versions may lack certain fields. Use nfdump-1.6.17 to update such records where necessary.
- To convert old files to the new format:

  ```sh
  ./nfdump -r old-flowfile -y -w new-flowfile
  ```

- **Note:** Only `nfdump` can read legacy nfdump-1.6.x files; all other programs require the new format.
- **NfSen Users:** Upgrade NfSen to the latest [GitHub version](https://github.com/phaag/nfsen) for full compatibility. Some legacy binaries (e.g., nfprofile, nftrack) are still available but may be deprecated in future releases.

---

## Installation

### Building

nfdump uses the GNU autotools build system.

```sh
./autogen.sh
./configure
make
sudo make install
```

#### Building on CentOS 7.x

```sh
yum install centos-release-scl
yum install devtoolset-8-gcc devtoolset-8-gcc-c++
scl enable devtoolset-8 -- bash
```

#### Building on Ubuntu 18.04 LTS

```sh
sudo apt-get install clang-10
CC=clang-10 ./configure ...
```

---

## Configuration Options

For a full list, run `./configure --help`. Key options include:

- `--enable-sflow`  
  Build sFlow collector `sfcapd` (default: NO)
- `--enable-nfpcapd`  
  Build `nfpcapd` to create NetFlow from interface or pcap traffic (default: NO)
- `--enable-maxmind`  
  Build geolookup program for geolocation enrichment (default: NO)
- `--enable-tor`  
  Build torlookup program for Tor exit node enrichment (default: NO)
- `--enable-nsel`  
  NSEL support is built-in by default in 1.7.x. This switch only affects the default output format (line/nsel).
- `--enable-jnat`  
  Support JunOS NAT event logging (default: NO)
- `--enable-ftconv`  
  Build the flow-tools to nfdump converter (default: NO)
- `--enable-nfprofile`  
  Build nfprofile, required by NfSen (default: NO)
- `--enable-nftrack`  
  Build nftrack, used by PortTracker (default: NO)
- `--enable-ja4`  
  Enable all JA4 fingerprinting modules (default: NO)
- `--enable-devel`  
  Enable debugging and developer options (default: NO)
- `--enable-readpcap`  
  Enable reading flow data from pcap files in nfcapd (default: NO)
- `--with-lz4path=PATH`, `--with-zstdpath=PATH`, `--with-bz2path=PATH`  
  Specify non-default library install locations for compression libraries.

---

## Usage Overview

nfdump provides a set of collection and processing tools. Common tools and example commands:

### Collect NetFlow Data

```sh
nfcapd -D -S 2 -w /flow_base_dir/router1 -p 23456
```

### Process Collected Data

```sh
nfdump -r /flow_base_dir/router1/nfcapd.202501011200
```

### Filter and Aggregate Flows

```sh
nfdump -r flowfile 'src ip 192.0.2.1 and dst port 443' -A srcip,dstip
```

### Enrich with Geolocation or Tor Information

Enable and configure geolookup/torlookup databases as needed. See respective man pages for details.

### Export Metrics

Send metrics to InfluxDB or Prometheus-compatible tools using [nfinflux](https://github.com/phaag/nfinflux) or [nfexporter](https://github.com/phaag/nfexporter).

---

## Additional Tools

nfdump includes several related tools for extended workflows:

- **geolookup**  
  Enriches IP addresses with country, region, city, and optionally AS information. Requires Maxmind database and must be enabled with `--enable-maxmind`.

- **torlookup**  
  Tags flows with Tor exit node information. Requires the TorDB database and must be enabled with `--enable-tor`.

- **nfprofile**  
  NetFlow profiler for NfSen integration. Filters and organizes flows by profile.

- **nfpcapd**  
  Converts live or pcap-captured network traffic to NetFlow records. Supports storing locally or forwarding to a remote collector.

- **sfcapd**  
  sFlow collector daemon, stores data in nfcapd-compatible files.

- **nfanon**  
  Anonymizes IP addresses in flow records using CryptoPAn.

- **nfexpire**  
  Manages expiration of old flow data.

- **nfreplay**  
  Replays collected NetFlow data to another collector.

- **ft2nfdump**  
  Converts flow-tools format to nfdump format.

- **nftrack**  
  Port tracking decoder for NfSen’s PortTracker plugin.

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

## General Operation of nfdump

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

- The binary data format is NetFlow version independent, but is architecture-dependent (little vs. big endian).
- Internally, all processing is IP protocol independent (supports IPv4 and IPv6).

---

## Sampling

By default, the sampling rate is set to 1 (unsampled) or to any value specified by the `-s` command line option. If sampling information is found in the NetFlow stream, it overrides the default value. Sampling is automatically recognized when announced in v9/IPFIX option templates with tags set (`#302, #304, #305, #306`, `#48, #49, #50`, `#34, #35`), or in the unofficial v5 header hack. The sampling data is stored in the sampling information fields in the flow record.

**Note:** Not all platforms (or vendor software versions) support exporting sampling information in NetFlow data, even if sampling is configured. The number of bytes/packets in each NetFlow record is automatically multiplied by the sampling rate. The total number of flows is not changed as this is not accurate enough (small flows versus large flows).

---

## NetFlow/NSEL/NAT Support

- Supports Cisco NSEL (Network Event Security Logging) and NEL (NAT Event Logging) via NetFlow v9.
- Partially compatible with JunOS NAT Event Logging (enable with `--enable-jnat`).
- Binary file format is NetFlow version-independent but architecture-dependent.

---

## Related Projects

- [go-nfdump](https://github.com/phaag/go-nfdump): Read nfdump files in Go.
- [nfinflux](https://github.com/phaag/nfinflux): Export metrics to InfluxDB.
- [nfexporter](https://github.com/phaag/nfexporter): Export metrics for Prometheus.

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
- Feel free to open issues or pull requests
- For other questions please see my email address in the AUTHORS.
- For the latest updates, visit the [nfdump repository on GitHub](https://github.com/phaag/nfdump).
