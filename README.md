# nfdump

nfdump-1.7.x or nfdump **unicorn** is the new release of nfdump.

nfdump-1.6.x receives bug fixes, but will no longer get new features. The latest release for nfdump-1.6.x is [nfdump-1.6.25](https://github.com/phaag/nfdump/releases/tag/v1.6.25). 

## Introduction

nfdump is a toolset in order to collect and process netflow/ipfix and sflow data, sent from netflow/sflow compatible devices.

The toolset contains several collectors to collect flow data:

- nfcapd supports netflow __v1__, __v5/v7__, __v9__ and __IPFIX__
- sfcapd supports **sflow**. 
- nfpcapd converts pcap data read from a host interface or from pcap files.

The collected flow data is stored into files and can be process afterwards.
nfdump processes and lists the flows in many different output formats and
can create a wide range of statistics.

**nfdump** has a very powerful flow filter to process flows. The filter syn‐
tax is very similar to tcpdump, but adapted and extended for flow filter‐
ing. A flow filter may also contain arrays of *many thousand IP addresses*
etc. to search for specific records.

**nfdump** can aggreagte flows according to a user defined number of ele‐
ments. This masks certain elements and allows to sum up flow records
matching the same values.

The combination of flow *filtering* and *aggregation* as input for any flow
statistics allows **complex flow processing**. Pre‐filtered and aggregated
flow data may also be written back into a binary flow file, which again
may be processed with nfdump

**nfdump** can enrich the listing of flows with **geo location** information and
**AS** information, unless AS information is already available in the flow
records. IP addresses can be tagged with a two letter **country code**, or
with a longer location label containing the geographic region, country
and city.  The geo location and AS information is retrieved from the
optional **geoDB** database, created by the geolookup program from the nfdump
tools.  geolookup uses the **Maxmind** database GeoDB or GeoLite2 to create a
binary lookup database for nfdump Please check the geolooup(1) man page
for more details.

### Compatibility
You may use nfdump-1.6.24 oder nfdump-1.7.x, depending on your needs. 
nfdump-1.7.x is compatible to nfdump-1.6.18, which means it can read files 
created with nfdump-1.6.18 or newer. Flow files created with earlier nfdump
versions may not contain all flow elements. If you have older files, it is
recommended to use nfdump-1.6.17 to update the records.

Nfdump 1.7.x provides the same set of programs as 1.6.x and can be used almost
as a drop-in replacement. This may change in future and older legacy programs
may be removed. You can convert any old files from nfdump-1.6 to nfdump-1.7
format by reading/writing files: __./nfdump -r old-flowfile -y -w new-flowfile__

Please note, that only __nfdump__ may read older flow files. All other programs
relay on the new file format.

Although nfdump-1.7.x ist mostly compatible with old Nfsen, it not recommended
to replace nfdump iin your NfSen installation. However, all specific binaries such 
as nfprofile and nftrack are still available with nfdump-1.7 but may be removed
in future.

### Improvements 
- nfdump is now a multi-threaded program and uses parallel threads mainly for
reading, writing and processing flows as well as for sorting. This may result
in faster flow processing, depending on the tasks. The speedimprovement 
also heavily depends on the hardware (SSD/HD) and flow compression
option. 

- For netflow v9 and IPFIX, nfdump now supports flexible length fields. This
improves compatibility with some exporters such as yaf and others.

- Support for Cisco Network Based Application Recognition (NBAR).

- Supports Maxmind geo location information to tag/geolocate IP addresses
  and AS numbers.

- nfpcapd automatically uses TPACKET_V3 for Linux or direct BPF sockets for
  *BSD. This improves packet processing. It adds new options to collect MAC and
  VLAN information if requested as well as the payload of the first packet. This
  creates a lot of new possibilities in oder to process and filter flows, such
  as __nfdump -r flowfile 'payload content "POST"'__
  nfpcapd can now store flow files locally or can sent them to a remote nfcapd
  collector.

- Metric exports: By default, every 60s a flow summary statistics  can be sent
  to a UNIX socket. The corresponding program may be [nfinflux](https://github.com/phaag/nfinflux) to insert 
  these metrics into an influxDB or [nfexporter](https://github.com/phaag/nfexporter) for Prometheus monitoring.

### New programs
The nfdump program suite has been extended by __geolookup__. It allows either
to enrich IP addresses by country codes/locations and may add potential
missing AS information. Flows may be filtered according to country codes.
geolookup may also be used as standalone program to lookup IPs for AS/Geo
information, similar to the famous Team Cymru whois service. geolookup uses a
local database, which allows to process as many requests as you have.
In order to use geolookup, you need either a free or payed Maxmind account
in order to convert the Maxmind .csv files into an nfdump vector data file. 
__geolookup__ needs to be enabled when running configure: __--enable-maxmind__

---



## NSEL/ASA, NEL/NAT support

__NSEL__ (Network Event Security Logging) as well as NEL (NAT Event Logging) are technologies invented by __CISCO__ and also use the netflow v9 protocol. However, NSEL and NEL are not flows as commonly known but rather *__Events__!* exported from specific devices such as CISCO ASA. nfdump supports Event looging as part of netflow v9.

__Jun OS NAT Event Logging__ is mostly compatible with CISCO's NAT Event Logging - mostly - it needs another data interpretation.
See __--enable-jnat__ below



## Installation

### Building and config options

The toolset is build upon the autotools framework. Run `./autogen.sh` first.
Afterwards `./configure` `make` and `make install` should do the trick. 

If you run CentOS 7.x you need to install a more recent compiler:

```c
yum install centos-release-scl
```

Then you can install GCC 8 and its C++ compiler:

```c
yum install devtoolset-8-gcc devtoolset-8-gcc-c++
```

To switch to a shell which defaults `gcc` and `g++` to this GCC version, use:

```c
scl enable devtoolset-8 -- bash
```

The following config options are available:

* __--enable-sflow__  
Build sflow collector sfcapd; default is __NO__
* __--enable-nfpcapd__  
Build nfpcapd collector to create netflow data from interface traffic or precollected pcap traffic; default is __NO__
* __--enable-maxmind__  
Build geolookup program; default is __NO__
*  __--enable-nsel__   
Compile nfdump, to read and process NSEL/NEL event data; default is __NO__
*  __--enable-jnat__   
compile nfdump, to read and process JunOS NAT event logging __NO__
* __--enable-ftconv__  
Build the flow-tools to nfdump converter; default is __NO__
* __--enable-nfprofile__  
Build nfprofile used by NfSen; default is __NO__
* __--enable-nftrack__  
Build nftrack used by PortTracker; default is __NO__

Development and beta options

* __--enable-devel__  
Insert lots of debug and development code into nfdump for testing and debugging; default is __NO__
* __--enable-readpcap__  
Add code to nfcapd to read flow data also from pcap files; default is __NO__  

### The tools
__nfcapd__ - netflow collector daemon.  
Collects the netflow data, sent from exporters and stores the flow records 
into files.  Automatically rotates files every n minutes. ( typically 
every 5 min ) The netflow versions mentioned above are read transparently
Multiple netflow streams can be collected by a single or collector.  
nfcapd can listen on IPv6 or IPv4. Furthermore multicast is supported.

__nfdump__ - process collected netflow records.  
Nfdump reads the netflow data from one or many files stored by nfcapd. 
It's filter syntax is similar to tcpdump ( pcap like ) but adapted for netflow.
If you like tcpdump you will like nfdump. nfdump displays netflow 
data and/or creates top N statistics of flows, bytes, packets. nfdump 
has a powerful and flexible flow aggregation including bi-directional 
flows. The output format is user selectable and also includes a simple 
csv format for post processing.

__nfanon__ - anonymize netflow records  
IP addresses in flow records are anonimized using the CryptoPAn method.

__nfexpire__ - expire old netflow data  
Manages data expiration. Sets appropriate limits. Used by NfSen.

__nfreplay__ - netflow replay  
Reads the netflow data from the files stored by nfcapd and sends it
over the network to another host.

#### Optional binaries:

__sfcapd__ - sflow collector daemon  
scfapd collects sflow data and stores it into nfcapd comaptible files.
"sfcapd includes sFlow(TM) code, freely available from https://github.com/sflow/sflowtool.

__nfpcapd__ - pcap to netflow collector daemon  
nfpcapd listens on a network interface, or reads precollected pcap traffic.
It either stores locally flow records into nfcapd comaptible files or sends
the flows to a remote nfcapd collector. It is nfcapd's companion to convert
traffic directly into nfdump records.

__geolookup__ - Geo location lookup program.
geolookup converts Maxmind's .csv files into the nfdump vector DB. The 
converted DB may be used as a standalone lookup tool, or be be used by
nfdump in order to automatically lookup country and location. 
Please not: You need a legitimate Maxmind account (free or payed) in 
order to download the files.

__ft2nfdump__ - flow-tools flow converter  
ft2nfdump converts flow-tools data into nfdump format. 

__nfprofile__ - netflow profiler. Required by NfSen  
Reads the netflow data from the files stored by nfcapd. Filters the 
netflow data according to the specified filter sets ( profiles ) and
stores the filtered data into files for later use. 

__nftrack__ - Port tracking decoder for NfSen plugin PortTracker.

__nfreader__ - Framework for programmers  
nfreader is a framework to read nfdump files for any other purpose.
Own C code can be added to process flows. nfreader is not installed

#### Notes for sflow users:
sfcapd and nfcapd can be used concurrently to collect netflow and sflow
data at the same time. Generic command line options apply to both 
collectors likewise. sfcapd's sflow decoding module is based on InMon's 
sflowtool code and supports similar fields as nfcapd does for netflow v9, 
which is a subset of all available sflow fields in an sflow record. 
More fields may be integrated in future versions of sfcapd.

---

### Compression
Binary data files can optionally be compressed using either the fast LZO1X-1 compression, 
LZ4 or the efficient but slow bzip2 method. 
If you compress automatically flows while they are collected, LZO1X-1 or LZ4 methods are
recommended. bzip2 uses about 30 times more CPU than LZO1X-1. Use bzip2 to archive netflow
data, which may reduce the disk usage again by a factor of 2. The compression of flow files 
can be changed any time with nfdump -J <num>
For more details on each methde, see:

LZO1X-1: http://www.oberhumer.com/opensource/lzo

LZ4: https://github.com/lz4/lz4

bzip2: http://www.bzip.org

You can check the compression speed for your system by running ./nftest <path/to/an/existing/netflow/file>. 

---

## General Operation of nfdump
The goal of the design is to able to analyze netflow data from
the past as well as to track interesting traffic patterns 
continuously. The amount of time back in the past is limited only
by the disk storage available for all the netflow data. The tools
are optimized for speed for efficient filtering. The filter rules
should look familiar to the syntax of tcpdump ( pcap compatible ).

All data is stored to disk, before it gets analyzed. This separates
the process of storing and analyzing the data. 

The data is organized in a time-based fashion. Every n minutes
- typically 5 min - nfcapd rotates and renames the output file
with the timestamp nfcapd.YYYYMMddhhmm of the interval e.g. 
nfcapd.200907110845 contains data from July 11th 2009 08:45 onward.
Based on a 5min time interval, this results in 288 files per day.

Analyzing the data can be done for a single file, or by concatenating
several files for a single output. The output is either ASCII text
or binary data, when saved into a file, ready to be processed again
with the same tools.

You may have several netflow sources - let's say 'router1' 'router2'
and so on. The data is organized as follows:

	/flow_base_dir/router1
	/flow_base_dir/router2

which means router1 and router2 are subdirs of the flow_base_dir.

Although several flow sources can be sent to a single collector,
It's recommended to have multiple collector on busy networks for 
each source.
Example: Start two collectors on different ports:

	nfcapd -D -S 2 -B 1024000 -w /flow_base_dir/router1 -p 23456
	nfcapd -D -S 2 -B 1024000 -w /flow_base_dir/router2 -p 23457

nfcapd can handle multiple flow sources.
All sources can go into a single file or can be split:

All into the same file:

	nfcapd -D -S 2 -w /flow_base_dir/routers -p 23456

Collected on one port and split per source:

	nfcapd -D -S 2 -n router1,172.16.17.18,/flow_base_dir/router1 \
		-n router2,172.16.17.20,/flow_base_dir/router2 -p 23456

See nfcapd(1) for a detailed explanation of all options.

Security: none of the tools requires root privileges, unless you have
a port < 1024. However, there is no access control mechanism in nfcapd.
It is assumed, that host level security is in place to filter the 
proper IP addresses.

See the manual pages or use the -h switch for details on using each of 
the programs. For any questions send email to peter@people.ops-trust.net

Configure your router to export netflow. See the relevant documentation
for your model. 

A generic Cisco sample configuration enabling NetFlow on an interface:

    ip address 192.168.92.162 255.255.255.224
     interface fastethernet 0/0
     ip route-cache flow

To tell the router where to send the NetFlow data, enter the following 
global configuration command:

	ip flow-export 192.168.92.218 9995
	ip flow-export version 5 
	
	ip flow-cache timeout active 5

This breaks up long-lived flows into 5-minute segments. You can choose 
any number of minutes between 1 and 60;


Netflow v9 full export example of a cisco 7200 with sampling enabled:

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


See the relevant documentation for a full description of netflow commands

Note: Netflow version v5 and v7 have 32 bit counter values. The number of
packets or bytes may overflow this value, within the flow-cache timeout
on very busy routers. To prevent overflow, you may consider to reduce the 
flow-cache timeout to lower values. All nfdump tools use 64 bit counters 
internally, which means, all aggregated values are correctly reported.

The binary format of the data files is netflow version independent.
For speed reasons the binary format is machine architecture dependent, and 
as such can not be exchanged between little and big endian systems.
Internally nfdump does all processing IP protocol independent, which means
everything works for IPv4 as well as IPv6 addresses.
See the nfdump(1) man page for details. 

netflow version 9:
nfcapd supports a large range of netflow v9 tags. Version 1.6 nfdump 
supports the following fields. This list can be found in netflow_v9.h

---

### Flowset record types

Links

Extensions: nfcapd supports a large number of v9 tags. It automatically add
extensions to store data for v9/IPFIX elements which are supported.

### Sampling
By default, the sampling rate is set to 1 (unsampled) or to any given value specified 
by the -s cmd line option. If sampling information is found in the netflow stream, 
it overwrites the default value. Sampling is automatically recognised when announced 
in v9 option templates (tags #48, #49, #50 ), (tag #34, #35) or in the unofficial v5 
header hack. 
Note: Not all platforms (or CISCO IOS versions) support exporting sampling information
in netflow data, even if sampling is configured. The number of bytes/packets in each 
netflow record is automatically multiplied by the sampling rate. The total number of 
flows is not changed as this is not accurate enough. (Small flows versus large flows)

For more information, see the GitHub Wiki.
