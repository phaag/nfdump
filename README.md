# nfdump 1.8.x

[![Build Status](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/phaag/nfdump/actions/workflows/c-cpp.yml)

nfdump is a collection of tools for collecting, storing, processing, and
analyzing NetFlow, IPFIX, sFlow, and packet-capture data. Nfdump supports advanced [filtering](https://gist.github.com/phaag/06369bed7f39f97e1de51b1b0f5bc29a#file-cheatsheet-md), aggregation, and enrichment (geolocation, AS, Tor) of flow data with a focus on efficiency, flexibility, and extensibility.

The 1.8.x branch (codename "Colibri") is the next major generation of nfdump: a modern file format
and runtime, secure collector-to-collector forwarding, and richer
packet-derived flow decoding. It keeps the familiar collection and query
workflow while giving operators a practical path to higher-volume and more
security-conscious deployments.

> [!WARNING]
> **Public beta.** 1.8.x has substantial internal and on-disk format changes.
> Test it with representative traffic and retain backups before using it for
> production retention data. The command-line interfaces and configuration
> format described here are those of the development branch and may still
> receive compatibility fixes before the final release.

1.8.x is ready to explore, with many new features and improvements. Start
with a test deployment, then use the collector manuals and migration notes to
plan a production rollout.

## Highlights of 1.8.x

### Core, file format, and runtime

nfdump has received continuous updates over the years, but some design choices needed to be rethought to meet the demands of modern CPU architectures. A large part of the old code has therefore been removed or rewritten. The new core is designed for contemporary CPU and memory hierarchies: hot data structures are arranged
to be friendlier to L1/L2 caches, and the processing pipeline avoids work that was needed by older implementations.

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
  encryption, a fast and reliable method to protect your data.
- `nfdump -r file.nf -v hash` verifies stored V3 checksums only. `check`,
  `check-verbose`, and `repair` provide increasingly deep validation and can
  rewrite recoverable on-disk inconsistencies.
- Flow records have a new compact representation (record type v4) with an extension bitmap and
  offset table. The fields available to filters and output formats follow the
  same logical data flow already proven useful by pre-1.8.x nfdump versions.
- The TOML-style configuration file `nfdump.conf` has become much more important, since many more settings are now available to tune or preset. The new command-line switch `-x <key>=<value>`, supported by every program, additionally allows any setting to be overridden for a single run.

### Collectors

`nfcapd`, `sfcapd`, and `nfpcapd` share the new backend and threading model.
Their receive and storage paths have been simplified, and asynchronous
backends reduce the time a collector spends blocked on file I/O and rotation.

#### nfcapd

- The NetFlow/IPFIX collector has been substantially refactored.
- In addition to storing flows locally, `nfcapd` can forward decoded flows to another collector over UDP with the new `-H` switch. Plain forwarding uses the nfdump native protocol version 250; version 251 adds XChaCha20-Poly1305 transport protection when built with libsodium.
- `-K[=passphrase|@keyfile]` instructs `nfcapd` to encrypt locally stored V3 files with XChaCha20-Poly1305.
- `-k[=passphrase|@keyfile]` authenticates and decrypts/encrypts version-251 forwarding traffic. Rekeying and anti-replay controls are also available. See `nfcapd(1)` for the exact key-management semantics.
- The post filter `-F <filter>` filters collected flow records before they are stored on disk or forwarded to a remote collector.
- NetFlow v9 and IPFIX template decoding now uses a compile-once decoding VM rather than interpreting a per-field loop for every record.
- IPFIX information element 315, `dataLinkFrameSection`, can reconstruct and decode embedded L2--L4 frames, including VLAN/QinQ, MPLS, PPPoE, GRE/ERSPAN, and IP-in-IP encapsulations where present.
- The receive path has less frontend contention under load.
- The listener supports a true dual-socket path for platforms that do not
  provide IPv4-mapped IPv6 sockets.

#### sfcapd

- The sFlow decoder has been newly written for the new runtime and no longer depends on sflowtool code.
  Its code is now an integral part of nfdump.
- It has the same backend, forwarding, encryption, threading, and relevant
  command-line interface changes as `nfcapd`.

#### nfpcapd

- Packet-capture ingestion has been refactored around a self-contained,
  state-machine packet decoder.
- It can forward flow data using the native UDP forwarding transport, including
  optional XChaCha20-Poly1305 protection when built with libsodium.
- Offline pcap input is batched and mmap-based; compressed gzip input uses a
  batch-copy path. This is expected to improve large offline ingests, though
  the gain depends on the capture and host.
- Native and independent libpcap pcap reading and writing avoids unnecessary
  format conversion in the pcap-output path.
- Configurable limits bound the active-flow cache, queued output, and retained
  payload state, so capture capacity can be matched to the host.
- All collectors support `-x <key>=<value>` for runtime configuration overrides.

### Analysis and metadata tools

- Filter expressions are compiled into a compact filter VM program.
- Payload regular expressions now use system **PCRE2-8** when built with libpcre2, 
  which is well maintained and faster. Matching is binary-safe: the payload 
  length is supplied explicitly, so embedded NUL bytes do not truncate input. 
  PCRE2 JIT is used when the installed library supports it. **Note:** If PCRE2 is not available
  at build time, payload-regex filters fail to compile.
- `nfmeta` is a new tool that builds per-flow-block IPv4/IPv6 source and
  destination Bloom filters for existing flow files. `nfdump` uses these
  metadata filters to skip whole blocks that cannot satisfy an address query,
  speeding up host-focused searches over large archives.
- `nfanon` gains a new `-K` option to read and write backend-encrypted flow
  files; the CryptoPAn anonymization key, previously `-K`, has moved to `-A`
  so the two features cannot be confused. See the example below.
- GeoIP timezone data is available for output and filtering when the relevant
  MaxMind data is installed.
- Output formats can render an exporter/router address with country information
  through `%gra`; source and destination AS aggregation is handled consistently.
- `nfreplay` can now also replay flows as IPFIX, in addition to NetFlow v5, v9,
  and the native nfdump protocol; forwarded traffic can be authenticated and
  encrypted with `-k`, the same UDP transport protection used by the collectors.

### Authenticated collector forwarding

For a sensor that runs `nfpcapd`, forward decoded flows to a central `nfcapd`
without exposing a plaintext collector-to-collector hop. With a libsodium build
and the same protected key file on both hosts:

```sh
# Sensor: decode packets and send authenticated, encrypted native flows.
nfpcapd -i eth1 -H collector.example.net/9995 -k@/etc/nfdump/forward.key

# Collector: authenticate/decrypt v251 packets and write its normal flow files.
nfcapd -w /var/nfdump/flows -p 9995 -k@/etc/nfdump/forward.key
```

`-k` selects native protocol v251, which uses XChaCha20-Poly1305; without it,
`-H` uses plaintext v250. Encryption complements rather than replaces network
policy: firewall the receiving UDP port to the known sensor addresses.
The `-z` file-compression options do not apply to UDP forwarding; the receiver
chooses its own file compression. Encrypted v251 transport may use internal,
opportunistic LZ4 packet compression, independently of `-z`.

### nfanon with separated anonymization and encryption

In 1.7.x, `nfanon`'s only crypto-related option was `-K`, the CryptoPAn
anonymization key. In 1.8.x that key has moved to `-A`, and `-K` now means
what it means everywhere else in the suite: the backend file-encryption
passphrase. This frees `nfanon` to read and re-write encrypted archives
directly, without ever writing the anonymized data to a plaintext
intermediate file:

```sh
# Anonymize an encrypted archive, keeping it encrypted end to end.
nfanon -A 0x<64-char-hex-key> -K@/etc/nfdump/archive.key \
       -r /var/nfdump/edge-router -w /var/nfdump/edge-router-anon.nf
```

`-A` and `-K` are independent of each other; use `-A` for the anonymization key
and `-K` to re-encrypt in case of anonymizing encrypted files.
See [`nfanon(1)`](man/nfanon.1) for the key-file and interactive-prompt
forms of `-K`, and the migration table below for the exact 1.7.x-to-1.8.x
option mapping.

## Compatibility and migration

### File formats

1.8.x reads nffile V2 files written by 1.7.x transparently but always writes the new V3 format.
Reading nffile V1 files written by 1.6.x  is no longer supported; convert them first with nfdump 1.7.8.

Do not mix a beta deployment into an archive without first validating your
readers, exporters, rotation scripts, and backup procedure. Keep the original
files until the converted or newly collected data has been verified.

### Migrating from 1.7.x: incompatible options

1.8.x reused a number of option letters for different, unrelated purposes,
and dropped a handful of long-deprecated compatibility flags outright.
Existing 1.7.x invocations, wrapper scripts, and systemd units should be
checked against the tables below before switching a production deployment.
An option that is silently accepted but now does something else is more
dangerous than one that is rejected outright, so review the "repurposed"
rows first.

**Changed for most programs** (`nfdump`, `nfcapd`, `sfcapd`, `nfpcapd`,
`nfanon`, `nfprofile`):

| Option | 1.7.x meaning | 1.8.x meaning |
| --- | --- | --- |
| `-W <num>` | Number of compression worker threads. | Total CPU-core budget for the whole process; `0` uses all online cores. Thread roles (reader/writer/worker) are now derived automatically from this budget, or tuned individually in `nfdump.conf`. |
| `-x` | Not a shared option; program-specific or unused. | New everywhere: `-x <key>=<value>` overrides one `nfdump.conf` setting for this run (repeatable). For example: `-x threads.writers=4` replaces old `-W 4` behaviour. |
| `-j`, `-y` | Legacy shorthands for `-z=bz2` and `-z=lz4`. | Still work in `nfdump`. Removed from `nfcapd`, `sfcapd`, and `nfpcapd`; use `-z=bz2` / `-z=lz4[:level]` there. |

**`nfdump`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-v <file>` | Verified a file, given directly as the argument. | `-v <mode>` with `hash`, `check`, `check-verbose`, or `repair`, applied to the file given separately with `-r`. |
| `-x <file>` | Verified the extension records in a file. | Repurposed; see the shared `-x` row above. nffile v1 1.6.x extension based flow records are no longer supported. |
| `-J <0-4>` | Selected a compression codec by number. | `-J=<codec>` takes the same codec name as `-z` (`lzo`, `lz4`, `bz2`, `zstd`). |
| `-t <time>` | Selected a time window. | Removed. Use `'first seen' >= ... and 'last seen' <= ...'` filter expressions instead. |
| new | — | `-l <num>` sets the log level (1-4); `-K[=passphrase\|@keyfile]` reads and writes backend-encrypted files. |

**`nfcapd`, `sfcapd`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-l <dir>` | Legacy alias for `-w <dir>`. | Launches a program after each file rotation (`-l process`) — the collectors' old `-x process` launcher, moved here now that `-x` is the shared config-override switch. |
| `-R <ip[/port]>` | Up to eight packet repeaters. | Exactly one repeater. |
| `-E`, `-T` | Deprecated, silently accepted no-ops. | Removed; now rejected as unknown options. |
| new | — | `-H` forwards decoded flows to another collector over UDP; `-K`/`-k`/`-N`/`-Q` configure backend and transport encryption. See the forwarding example above. |

**`nfpcapd`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-l <dir>`, `-T` | Legacy alias for `-w`, and a deprecated no-op flag. | Both removed outright (unlike `nfcapd`, the letter `-l` is not reused). |
| new | — | `-K`/`-k` backend and UDP transport encryption. |

**`nfanon`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-K <key>` | CryptoPAn anonymization key. | Backend file-encryption passphrase (`-K[=passphrase\|@keyfile]`). |
| `-A <key>` | — | The CryptoPAn anonymization key, moved here from `-K`. Still required. |
| `-q`, `-t <num>` | Deprecated flags (`-q` for quiet, `-t` as an alias for `-W`). | Both removed. |

This is the change worked through in the [nfanon example](#try-nfanon-with-separated-anonymization-and-encryption) above — it is the option remapping most likely to bite an automated 1.7.x invocation, because old and new `-K` both parse successfully but do something completely different.

**`nfreplay`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-r <file>` | Optional; read from stdin if omitted. | Required. |
| `-i <host/ip>` | Compatibility alias for `-H`. | Removed; use `-H`. |
| `-t <time>` | Selected a time window. | Removed. |
| `-v <version>` | Sent NetFlow v5, v9, or native (250). | Also accepts `10` to send IPFIX. |
| new | — | `-k[=passphrase\|@keyfile]` authenticates and encrypts forwarded flows (use with `-v 250`). |

**`nfexpire`:**

| Option | 1.7.x | 1.8.x |
| --- | --- | --- |
| `-L <datadir>` | Listed stat and bookkeeping records from a directory. | Removed. |
| new | — | `-n` runs a dry run: reports what would expire without deleting anything. |

### Other behavioral changes

- **Exit codes are now consistent** across `nfdump` and the collectors: `0`
  for success, `1` for any user-facing error (bad arguments, a missing or
  invalid input file, a filter syntax error, or a failed `-v check`/`repair`),
  and `255` reserved for genuine internal faults (out of memory, unable to
  start a worker thread). Earlier releases mixed `250`, `254`, and `255` for
  ordinary, expected failures; scripts that specifically branched on one of
  those numbers should be checked against the new, single `1`.
- Running `nfdump` with no arguments at all now exits `1` instead of `0`; `-h`
  is unaffected and still exits `0`.

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

As of 1.8.x `./configure` automatically enables building `geolookup` and `torlookup` .

| Dependency or data | Enables |
| --- | --- |
| liblz4, libzstd, bzip2 | nffile compression codecs |
| zlib | gzip-compressed pcap input |
| libsodium | XChaCha20-Poly1305 backend-file and forwarding encryption |
| PCRE2-8 | Payload regular-expression filters |
| libpcap | Packet-capture reading and `nfpcapd` support |
| MaxMind database | GeoIP enrichment, including timezones when provided by the database |
| Tor database | Tor exit node enrichment, when provided by the database. |

The configure summary reports which optional libraries were found. PCRE2 and
libsodium are optional build dependencies, but the features that require them
are unavailable without them. MaxMind and tor data DBs are installed and maintained
separately from the build. Use the provided scripts to update and build the relevant DB files. Rebuild these databases, if you migrate to 1.8.x.

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

`--enable-native` is appropriate for a local installation, but *do not use* it
for portable packages or binaries intended for other CPU models. Library
checks use `pkg-config` first and a header/library fallback second; the
corresponding `*_CFLAGS` and `*_LIBS` environment variables can override the
detected values. If you deliberately want to disable an automatically discovered library, use `--with-xxxx=no`

### Runtime configuration

The distributed [`nfdump.conf.dist`](src/libnffile/conf/nfdump.conf.dist) is the
authoritative starting point for runtime settings. It includes common settings
and program-specific sections. Thread allocation can be controlled with
`limitCores` and the `[common.threads]` or per-program `threads` sections.

For the option letters that changed meaning from the 1.7.x release, see
[Migrating from 1.7.x: incompatible options](#migrating-from-17x-incompatible-options)
above.

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
nfdump -x limitCores=4 -r /var/nfdump/flows
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
or open a protected capture interface. **Restrict which exporters may reach
the collector using host or network firewall rules.** Treat forwarding keys
and encrypted-file passphrases as secrets; do not put them in command
histories or issue reports.

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
  v9, IPFIX, or native nfdump protocol (including encrypted v251 forwarding
  when built with libsodium).
- `nfanon` — Anonymize flow records using CryptoPAn (`-A`); can also read and
  write backend-encrypted files (`-K`, when built with libsodium).
- `geolookup` — Look up IP geolocation, AS, and timezone information in an
  nfdump MaxMind database.
- `torlookup` — Look up Tor exit-node information in an nfdump Tor database.
- `ft2nfdump` — Convert flow-tools files to nfdump; optional at configure time.
- `nfprofile` — Process NfSen profiles and channels; optional at configure time.
- `nftrack` — Support NfSen port tracking; optional at configure time.

## Reading flow files from other programs (C ABI)

Besides the tools above, nfdump exposes a small, new, read-only C ABI
for external programs to open an nffile V3 file and iterate its flow
records directly. The full interface is documented in
[`nfdump.h`](src/libnfdump/nfdump.h). nffile V2 files from nfdump 1.7.x
are read transparently, matching the CLI's own behavior.
The ABI is plain C, no C++ — so any language with a C FFI can call
it, and `make install` installs the header and a `pkg-config nfdump`
entry alongside the usual binaries. The directory `extra/examples/` contains
small examples in C (replaces old nfreader) , Python, Rust, Go, and Lua and a corresponding README file
to build and run them.

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
and AS-organization information for IP addresses. Generate nfdump's compact
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
select them for an individual invocation. You can temporarily disable a configured DB, with `-G none` or `-H none`.  Both update scripts now create a flat cache file along the DB file to speed up loading. 

## Documentation

Useful project documentation includes:

- [Configuration reference](src/libnffile/conf/nfdump.conf.dist)
- [nffile V3 format definitions](src/libnffile/nffileV3/nffileV3.h)
- [Manual pages](man)

## Reporting beta issues

Please report reproducible issues with the commands used, the relevant
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
Please report bugs with the information requested above. 

## Sponsorship

Development can be supported through [GitHub Sponsors](https://github.com/sponsors/phaag). Any sponsoring is appreciated.

## License

nfdump is distributed under the BSD 3-Clause License. See
[BSD-license.txt](BSD-license.txt).
