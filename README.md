# nfdump 1.8.x

[![Build Status](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml)

nfdump is a collection of tools for collecting, storing, processing, and
analysing NetFlow, IPFIX, sFlow, and packet-capture data. Nfdump supports advanced [filtering](https://gist.github.com/phaag/06369bed7f39f97e1de51b1b0f5bc29a#file-cheatsheet-md), aggregation, and enrichment (geolocation, AS, Tor) of flow data with a focus on efficiency, flexibility, and extensibility.

The 1.8.x branch is the next major generation of nfdump.

> [!WARNING]
> **Public beta.** 1.8.x has substantial internal and on-disk format changes.
> Test it with representative traffic and retain backups before using it for
> production retention data. The command-line interfaces and configuration
> format described here are those of the development branch and may still
> receive compatibility fixes before the final release.

## Highlights of 1.8.x

### Core, file format, and runtime

Much of the old code has been removed or rewritten. The new core is designed
for contemporary CPU and memory hierarchies: hot data structures are arranged
to be friendlier to L1/L2 caches and the processing pipeline avoids work that
was needed by older implementations.

- A new threading core shares the available CPU budget between readers,
  writers, and worker roles. Set the budget with `-W` or `limitCores`; zero
  means all available cores. Thread-role settings are available in
  `nfdump.conf`.
- Frontend flow processing and backend storage are now logically separated,
  making additional storage backends easier to add later.
- The new **nffile V3** backend format uses an indexed block layout, redundant
  footer information, and strict eight-byte data alignment. It is designed to
  provide efficient sequential processing while keeping CPU alignment
  predictable.
- V3 files can optionally use xxHash64 integrity checks. With libsodium,
  backend files can also be protected with XChaCha20-Poly1305 authenticated
  encryption.
- Flow records have a compact V4 representation with an extension bitmap and
  offset table; the fields available to filters and output formats remain the
  same logical flow data.
- Configuration is TOML-based. More settings are available in `nfdump.conf`,
  including shared and per-program thread settings. `nfdump` and all
  collectors support runtime configuration overrides with `-x <key>=<value>`.

### Collectors

`nfcapd`, `sfcapd`, and `nfpcapd` share the new backend and threading model.
Their receive and storage paths have been simplified, and asynchronous
backends reduce the time a collector spends blocked on file I/O and rotation.

#### nfcapd

- The NetFlow/IPFIX collector has been substantially refactored.
- Native nfdump flow forwarding is available with `-H`. Plain forwarding uses
  protocol version 250; version 251 adds XChaCha20-Poly1305 transport
  protection when built with libsodium.
- `-K`, `-k`, `-N`, and `-Q` configure file and forwarding-transport crypto
  functions. See `nfcapd(1)` for the exact direction and key-management
  semantics of each option.
- NetFlow v9 and IPFIX template decoding now uses a compile-once decoding VM
  rather than interpreting a per-field loop for every record.
- IPFIX information element 315, `dataLinkFrameSection`, can reconstruct and
  decode embedded L2--L4 frames, including VLAN/QinQ, MPLS, PPPoE, GRE/ERSPAN,
  and IP-in-IP encapsulations where present.
- The receive path has less frontend contention under load.
- The listener supports a true dual-socket path for platforms that do not
  provide IPv4-mapped IPv6 sockets.

#### sfcapd

- The sFlow decoder has been newly written for the new runtime.
- It has the same backend, forwarding, encryption, threading, and relevant
  command-line interface changes as `nfcapd`.

#### nfpcapd

- Packet-capture ingestion has been refactored around a self-contained,
  state-machine packet decoder.
- It can forward UDP flow data using the native forwarding transport, including
  optional XChaCha20-Poly1305 protection when built with libsodium.
- Offline pcap input is batched and mmap-based; compressed gzip input uses a
  batch-copy path. This is expected to improve large offline ingests, though
  the gain depends on the capture and host.
- Native pcap reading and writing avoids unnecessary format conversion in the
  pcap-output path.
- All collectors support `-x <key>=<value>` for runtime configuration overrides.

### Analysis and metadata tools

- Filter expressions are compiled into a compact filter VM program.
- Payload regular expressions use system **PCRE2-8** instead of the unmaintained
  sgregex matcher. Matching is binary-safe: the payload length is supplied
  explicitly, so embedded NUL bytes do not truncate input. PCRE2 JIT is used
  when the installed library supports it. If PCRE2 is not available at build
  time, payload-regex filters fail to compile rather than silently using a
  different matcher.
- `nfmeta` maintains per-flow-block IPv4/IPv6 source and destination Bloom
  filters. `nfdump` can use these metadata filters to skip blocks that cannot
  satisfy an address query.
- GeoIP timezone data is available for output and filtering when the relevant
  MaxMind data is installed.

## Compatibility and migration

1.8.x reads nffile V2 files written by 1.7.x and writes the new V3 format.
Files from the 1.6.x format are no longer read directly; convert them first
with nfdump 1.7.8.

Do not mix a beta deployment into an archive without first validating your
readers, exporters, rotation scripts, and backup procedure. Keep the original
files until the converted or newly collected data has been verified.

## Build from the development tree

The build requires a C17 compiler, GNU autotools 2.71 or newer, flex, and
bison. Optional libraries enable additional codecs and features.

```sh
./autogen.sh
./configure
make
make check
sudo make install
```

Run `./configure --help` for the complete option list. Common feature toggles
include `--enable-nfpcapd`, `--enable-readpcap`, `--enable-nfprofile`,
`--enable-ja4`, `--enable-native`, and `--enable-lto`.

| Dependency or data | Enables |
| --- | --- |
| liblz4, libzstd, bzip2 | nffile compression codecs |
| zlib | gzip-compressed pcap input |
| libsodium | XChaCha20-Poly1305 backend-file and forwarding encryption |
| PCRE2-8 | Payload regular-expression filters |
| libpcap | Packet-capture reading and `nfpcapd` support |
| MaxMind database | GeoIP enrichment, including timezones when provided by the database |

The configure summary reports which optional libraries were found. PCRE2 and
libsodium are optional build dependencies, but the features that require them
are unavailable without them. MaxMind data is installed and maintained
separately from the build.

## Configuration options

### Configure-time options

The default build includes the core collectors, `nfdump`, and the supporting
tools that do not have an optional external dependency. Use `./configure
--help` as the definitive list. The project-specific options are:

| Option | Purpose |
| --- | --- |
| `--enable-nfpcapd` | Build the pcap-to-flow collector. Requires libpcap. |
| `--enable-readpcap` | Enable pcap input in `nfcapd` and `sfcapd`. |
| `--enable-nfprofile` | Build the legacy NfSen support programs `nfprofile` and `nftrack`. |
| `--enable-ftconv` | Build `ft2nfdump`, the flow-tools converter. |
| `--enable-jnat` | Enable Junos NAT event logging support. |
| `--enable-ja4` | Build the optional JA4+ fingerprinting code. Review the JA4 licensing terms before enabling it. |
| `--enable-devel` | Enable developer/debug mode; this also disables shared libraries. |
| `--enable-native` | Use CPU-specific compiler tuning for a build that will run only on the build host. |
| `--enable-lto[=auto\|yes\|no]` | Control link-time optimization; the default is `auto`. |
| `--with-lz4=PATH`, `--with-zstd=PATH`, `--with-bz2=PATH` | Search a non-standard prefix for compression libraries. |
| `--with-pcre2=PATH`, `--with-libsodium=PATH`, `--with-zlib=PATH` | Search a non-standard prefix for PCRE2, libsodium, or zlib. |
| `--with-pcap=PATH`, `--with-ft=PATH`, `--with-rrd=PATH` | Search a non-standard prefix for libpcap, flow-tools, or RRD libraries. |

`--enable-native` is appropriate for a local installation, but do not use it
for portable packages or binaries intended for other CPU models. Library
checks use `pkg-config` first and a header/library fallback second; the
corresponding `*_CFLAGS` and `*_LIBS` environment variables can override the
detected values.

### Runtime configuration and command-line changes

The distributed [`nfdump.conf.dist`](src/libnffile/conf/nfdump.conf.dist) is the
authoritative starting point for runtime settings. It includes common settings
and program-specific sections. Thread allocation can be controlled with
`limitCores` and the `[common.threads]` or per-program `threads` sections.

Several option meanings have changed from the 1.7.x release:

| Program | Change |
| --- | --- |
| `nfcapd`, `sfcapd`, `nfpcapd` | `-W` is the total CPU-core limit; `0` uses all available cores. It is no longer the number of compression workers. |
| `nfcapd`, `sfcapd`, `nfpcapd` | Use `-z=lzo|lz4|bz2|zstd[:level]` for compression. The old per-codec `-j` and `-y` options are gone. |
| `nfcapd`, `sfcapd` | `-R` accepts one repeater, not the former advertised set of up to eight. |
| `nfcapd`, `sfcapd`, `nfpcapd` | `-H` enables native UDP forwarding; encryption-related options require a libsodium build. |
| `nfdump`, `nfcapd`, `sfcapd`, `nfpcapd` | `-x <key>=<value>` overrides a configuration value for that invocation. |

In 1.8.x, nfcapd and sfcapd move their post-rotation launcher command from
`-x command` to `-l command`; `-x` is now the common configuration-override
switch. nfpcapd's long-deprecated `-l` alias for `-w` is removed.

## Quick examples

Collect NetFlow/IPFIX into a rotating directory:

```sh
nfcapd -w /var/nfdump/flows -p 2055
```

Read a collection and apply a filter:

```sh
nfdump -r /var/nfdump/flows 'proto tcp and port 443'
```

Apply a temporary configuration override in nfdump or any collector:

```sh
nfdump -x threads.workers=4 -r /var/nfdump/flows
```

The exact forwarding and cryptographic setup depends on which program sends or
receives the data. Consult [`nfcapd(1)`](man/nfcapd.1),
[`sfcapd(1)`](man/sfcapd.1), and [`nfpcapd(1)`](man/nfpcapd.1) before deploying
encrypted forwarding.

## How nfdump works

nfdump separates collection from analysis. A collector decodes exporter data
and writes time-rotated nffile files. `nfdump` and the other processing tools
then read those files independently, allowing historical analysis without
holding up collection.

### Storage and collection

Collectors normally write one time-rotated file series per flow source. A
typical layout is:

```text
/var/nfdump/edge-router/nfcapd.YYYYMMDDhhmm
/var/nfdump/core-router/nfcapd.YYYYMMDDhhmm
```

The rotation interval and naming are collector settings; five-minute files are
a common operational choice. `nfcapd` can collect multiple exporters on one
listener and can assign sources to separate storage directories with `-n`.
For high-volume sites, separate collector processes, listening ports, and
storage paths can isolate busy exporters.

The V3 backend stores data in blocks. Its directory and footer allow the
reader to locate blocks without treating the file as one monolithic record
stream. Block-level metadata, optional checksums, optional encryption, and
metadata indexes are handled by the backend; the filter and output tools work
with logical flow fields.

### Reading, filtering, and output

`nfdump` reads a single file with `-r`, a file collection with `-R`, or an
explicit file list. It compiles the filter once, applies it to the selected
flows, and can print records, aggregate fields with `-A`, calculate statistics,
or write another nffile. Text, CSV, JSON, and user-defined formats support
integration with other tools.

For example, aggregate TLS traffic by source and destination address:

```sh
nfdump -r /var/nfdump/edge-router 'proto tcp and port 443' -A srcip,dstip
```

`nfexpire` maintains a bounded archive by removing expired files according to
its configured retention policy. Use it rather than an unconstrained cleanup
job when the flow directory is shared with active collectors.

### Operational security

Collectors do not need root privileges unless they bind a UDP port below 1024
or open a protected capture interface. **Restrict** which exporters may reach the
collector using **host or network firewall rules.** Treat forwarding keys and
encrypted-file passphrases as secrets; do not put them in command histories or
issue reports.

## Compression

nffile V3 compresses data blocks independently. This permits streaming writes,
parallel backend work where appropriate, and reading only the blocks needed
for a query. Use `-z` on collectors and programs that write nffile output:

```sh
nfcapd -w /var/nfdump/edge-router -p 2055 -z=lz4
```

| Setting | Availability and typical use |
| --- | --- |
| `-z=lzo` | Built-in LZO codec; a fast compatibility-oriented choice. |
| `-z=lz4[:level]` | LZ4; a good general choice for low-latency collection. A bundled implementation is used if no system LZ4 is found. |
| `-z=zstd[:level]` | Zstandard; generally a good balance of compression ratio and speed when libzstd is available. |
| `-z=bz2` | bzip2; prioritize archive size over CPU time when libbz2 is available. |

Choose the codec based on measured CPU, disk, and retention requirements. A
reader automatically recognizes the codec recorded in a file. Compression and
backend encryption can be used together; encrypted files cannot be recompressed
in place.

## Programs

- `nfcapd` — Collect NetFlow v1/v5/v7/v9 and IPFIX, then store or forward the
  decoded flows.
- `sfcapd` — Collect sFlow, then store or forward the decoded flows.
- `nfpcapd` — Read live interfaces or pcap files, decode packets into flows,
  and store, write pcap, or forward them. Optional at configure time.
- `nfdump` — Read, filter, aggregate, convert, and report flow files.
- `nfexpire` — Maintain flow-file retention and expire old data safely.
- `nfmeta` — Create or update flow-file metadata, including address Bloom
  filters for block-level query skipping.
- `nfreplay` — Send stored flows to another collector using NetFlow v5, NetFlow
  v9, or IPFIX.
- `nfanon` — Anonymize flow records using Crypto-PAn.
- `geolookup` — Look up IP geolocation, AS, and timezone information in an
  nfdump MaxMind database.
- `torlookup` — Look up Tor exit-node information in an nfdump Tor database.
- `ft2nfdump` — Convert flow-tools files to nfdump; optional at configure time.
- `nfprofile` — Process NfSen profiles and channels; optional at configure time.
- `nftrack` — Support NfSen port tracking; optional at configure time.
- `nfreader` — A C framework/example for custom nffile readers; it is not
  installed by default.

## Sampling and event logging

Sampling is normally determined from exporter-provided NetFlow v9/IPFIX option
templates. A configured sampling rate can be supplied when an exporter does
not provide one. Packet and byte counters are scaled by the sampling rate;
the number of flow records is not, because it cannot be reliably inferred.

Cisco NSEL and NEL records are supported through NetFlow v9. Junos NAT event
logging support is optional and requires `--enable-jnat` at build time.

## Data enrichment

nfdump can enrich flow output, statistics, and filters with local MaxMind and
Tor databases. The MaxMind database provides country, location, IANA time-zone,
and AS-organisation information for IP addresses. Generate nfdump's compact
database from the MaxMind **GeoLite2** or commercial City and ASN CSV downloads
with `geolookup`: set your MaxMind license key in `updateGeoDB.sh`, then run:

```sh
cd src/maxmind
./updateGeoDB.sh
nfdump -r /path/to/flows -G ./mmdb.nf -o gline
```

The Tor database records the time-bounded Tor exit-node intervals used to
identify source and destination Tor traffic. Generate it from the Tor Project
archive with `torlookup`; refresh it regularly because the exit-node list
changes over time:

```sh
cd src/tor
NFTORDB="$PWD/tordb.nf" ./updateTorDB.sh 6
nfdump -r /path/to/flows -H "$PWD/tordb.nf" -o 'fmt:%ts %sa %stor %da %dtor'
```

For persistent use, install the generated files at a suitable local location
and configure `geodb.path` and `tordb.path` in `nfdump.conf`; `-G` and `-H`
select them for an individual invocation.

## Documentation

Useful project documentation includes:

- [Configuration reference](src/libnffile/conf/nfdump.conf.dist)
- [nffile V3 format definitions](src/libnffile/nffileV3/nffileV3.h)
- [Manual pages](man)

## Reporting beta issues

Please report reproducible issues with the command used, the relevant
configuration (with secrets removed), exporter type and version, platform,
and a small capture or flow-file sample where possible. For performance
reports, include CPU model, storage type, input rate, enabled compression or
encryption, and the core limit in use.

## Ecosystem and support

- [go-nfdump](https://github.com/phaag/go-nfdump) reads nfdump files from Go.
- [nfinflux](https://github.com/phaag/nfinflux) exports metrics to InfluxDB.
- [nfexporter](https://github.com/phaag/nfexporter) exports metrics for
  Prometheus-compatible systems.
- [NfSen](https://github.com/phaag/nfsen) is the legacy graphical frontend;
  build `nfprofile` and `nftrack` if it is part of your deployment.
  Note: nfdump-1.8.x may run with NfSen, but is **untested** so far.

For usage details, read the installed manual page or run a program with `-h`.
Please report bugs with the information requested above. Development can be
supported through [GitHub Sponsors](https://github.com/sponsors/phaag).

## License

nfdump is distributed under the BSD 3-Clause License. See
[BSD-license.txt](BSD-license.txt).
