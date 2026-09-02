# Extra dist directory

This directory contains extra material as well as 3rd party code from various users. 
The 3rd party code is not guaranteed to work, nor will it get updated by the author of nfdump.

Feel free to send updates/patches if something does not work.

## Contents

- `examples/` - usage examples for the nfdump read ABI
  (`src/libnfdump/nfdump.h`) in C, Python, Rust, Go, and Lua. These files
  are part of the nfdump distribution — see `examples/README.md`.
- `CreateSubHierarchy.pl` - reorganizes flat `nfcapd.*` files into a `-S`
  subdirectory layout. Its format table still matches nfcapd/sfcapd's `-S`
  numbering in 1.8.x. Legacy code.
- `PortTracker.pm` - NfSen plugin demonstrating `nftrack` port statistics.
  Its `nftrack` CLI usage is still valid in 1.8.x. Legacy code.
- `flowgraph.gnuplot` - example gnuplot script for `nfdump -g` output.
  Still matches the current CSV column layout. 
- `nfdump.spec` - example RPM spec file.
- `docker/` - example Dockerfiles. Build from a git ref (branch or tag)
  rather than a numbered release tarball, since a "v1.8.0" tag does not
  exist yet during the beta period.
