# JA4

This directory contains the source files for ja4 fingerprint processing. 

See https://github.com/FoxIO-LLC/ja4 for details. 

The usage of ja4 fingerprinting may require a license to use, please see
https://github.com/FoxIO-LLC/ja4#licensing and
https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md

In order to use ja4 in nfdump, make sure to run `./configure --enable-ja4 ..` otherwise only the free ja4 client fingerprinting module will be enabled. The fingerprinting applies only on flows with collected payload data. These can be collected with nfpcapd: `nfpcapd <your options> -o fat,payload` or any other exporter capable to export payload data, such as **yaf**.





