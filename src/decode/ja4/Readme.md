# JA4

This directory contains the source files for ja4 fingerprint processing. 

See https://github.com/FoxIO-LLC/ja4 for details. 

The usage of ja4 fingerprinting may require a license to use, please see
https://github.com/FoxIO-LLC/ja4#licensing and
https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md

By default only the free **JA4: TLS Client Fingerprinting** module is build into nfdump. If you fulfill the license requirements, you can build all ja4 modules with `./configure --enable-ja4 ..`. 

In general, the fingerprinting applies only on flows with collected payload data. These can be collected with nfpcapd: `nfpcapd <your options> -o fat,payload` or any other exporter, which is capable to export payload data, such as **yaf**.





