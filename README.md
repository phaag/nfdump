# nfdump

UNICORN is the development branch of nfdump.
It implements all new changes for nfdump 1.7

__This is beta code. Use it at your own risk. The file format may be changed
if required until the final release of nfdump-1.7__

For production environments use stabe releases 1.6.23 or newer.
nfdump-1.7.x is compatible to nfdump-1.6.18, which means it can read files
created with nfdump-1.6.18 or newer. Flow files created with earlier nfdump
versions are not guaranteed to be fully processed. 

If you are new to nfdump, see the Introduction and Overview chapters below.
If you are already an experienced nfdump use, see the What's New chapter.
This Readme is still incomplete and will get improved. 

---

## What's New
Nfdump exists since 2004 and has got a lot of updates and new features over
time. Usually this resulted in substantial changes in code and file format.
All major version changes introduced a bunch of new things. Nfdump 1.7 is no 
exception to this. 

### Compatibility
Nfdump 1.7 reads and processes transparently files from nfdump-1.6.18 and newer
and nfdump-1.6.x with minor restrictions. New files are always written in the
new format for nfdump-1.7.x. Reading and processing 1.6.x files may introduce
a small format conversion penalty, depending on the task requested. Conversion
is requested for any flow statistics, sorting and flow writing tasks. No
format conversion is requesting for flow filtering and printing. 
Nfdump 1.7.0 provides the same set of programs as 1.6.x and can be used almost
as a drop-in replacement. This may change in future and older legacy programs
may be removed. You can convert any old files from nfdump-1.6 to nfdump-1.7
format by reading/writing files: __./nfdump -r old-flowfile -y -w new-flowfile__

### Improvements
A lot of old code has been removed and rewritten for Nfdump-1.7. Additionally
nfdump is now a multi-threaded program and uses parallel threads mainly for
reading, writing and processing flows as well as for sorting. This may result
in a 2 to 3 times faster flow processing, depending on the tasks. The speed
improvement also heavily depends on the hardware (SSD/HD) and flow compression
option. 

For netflow v9 and IPFIX, nfdump now supports flexible length fields. This
improves compatibility with some exporters such as yaf and others.

Support for Cisco Network Based Application Recognition (NBAR).

nfpcapd automatically uses TPACKET_V3 for Linux or direct BPF sockets for
*BSD. This improves packet processing. It adds new options to collect MAC and
VLAN information if requested as well as the payload of the first packet. This
creates a lot of new possibilities in oder to process and filter flows, such
as __nfdump -r flowfile 'payload content POST'__

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

## Introduction

nfdump is a toolset in order to collect and process netflow and sflow data, sent from netflow/sflow compatible devices. 
The toolset supports netflow __v1__, __v5/v7__,__v9__,__IPFIX__ and __SFLOW__.  nfdump supports IPv4 as well as IPv6.

---

## NSEL/ASA, NEL/NAT support

__NSEL__ (Network Event Security Logging) as well as NEL (NAT Event Logging) are technologies invented by __CISCO__ and also use the netflow v9 protocol. However, NSEL and NEL are not flows as commonly known but rather *__Events__!* exported from specific devices such as CISCO ASA. nfdump supports Event looging as part of netflow v9.

__Jun OS NAT Event Logging__ is mostly compatible with CISCO's NAT Event Logging - mostly - it needs another data interpretation.
See __--enable-jnat__ below

---

## IPFIX

nfdump contains an IPFIX module for decoding IPFIX flow data. It
does not support the full IPFIX definition.

* Supports basically same feature set of elements as netflow_v9 module
* Only UDP traffic is accepted no TCP/SCTP
* If you would like to see more IPFIX support, please contact me. 

---


## Overview

### Building and config options

The toolset is build upon the autotools framework. Run `./autogen.sh` first.
Afterwards `./configure` `make` and `make install` should do the trick.

The following config options are available:

*  __--enable-nsel__   
Compile nfdump, to read and process NSEL/NEL event data; default is __NO__
*  __--enable-jnat__   
compile nfdump, to read and process JunOS NAT event logging __NO__
* __--enable-ftconv__  
Build the flow-tools to nfdump converter; default is __NO__
* __--enable-sflow__  
Build sflow collector sfcpad; default is __NO__
* __--enable-nfprofile__  
Build nfprofile used by NfSen; default is __NO__
* __--enable-nftrack__  
Build nftrack used by PortTracker; default is __NO__

Development and beta options

* __--enable-devel__  
Insert lots of debug and development code into nfdump for testing and debugging; default is __NO__
* __--enable-readpcap__  
Add code to nfcapd to read flow data also from pcap files; default is __NO__  
* __--enable-nfpcapd__  
Build nfpcapd collector to create netflow data from interface traffic or precollected pcap traffic, similar to softflowd; default is __NO__


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

__nfpcapd__ - pcap to netflow collector daemon  
nfpcapd listens on a network interface, or reads precollected pcap traffic 
and stores flow records into nfcapd comaptible files. It is nfcapd's
companion to convert traffic directly into nfdump records.

__sfcapd__ - sflow collector daemon  
scfapd collects sflow data and stores it into nfcapd comaptible files.
"sfcapd includes sFlow(TM) code, freely available from https://github.com/sflow/sflowtool.

__nfprofile__ - netflow profiler. Required by NfSen  
Reads the netflow data from the files stored by nfcapd. Filters the 
netflow data according to the specified filter sets ( profiles ) and
stores the filtered data into files for later use. 

__nftrack__ - Port tracking decoder for NfSen plugin PortTracker.

__ft2nfdump__ - flow-tools flow converter  
ft2nfdump converts flow-tools data into nfdump format. 

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

	nfcapd -w -D -S 2 -B 1024000 -l /flow_base_dir/router1 -p 23456
	nfcapd -w -D -S 2 -B 1024000 -l /flow_base_dir/router2 -p 23457

nfcapd can handle multiple flow sources.
All sources can go into a single file or can be split:

All into the same file:

	nfcapd -w -D -S 2 -l /flow_base_dir/routers -p 23456

Collected on one port and split per source:

	nfcapd -w -D -S 2 -n router1,172.16.17.18,/flow_base_dir/router1 \-n router2,172.16.17.20,/flow_base_dir/router2 -p 23456

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

Tag | ID
----|---
NF9_IN_BYTES | 1
IN_PACKETS | 2
NF9_FLOWS_AGGR | 3
NF9_IN_PROTOCOL | 4
NF9_SRC_TOS | 5
NF9_TCP_FLAGS | 6
NF9_L4_SRC_PORT | 7
NF9_IPV4_SRC_ADDR | 8
NF9_SRC_MASK | 9
NF9_INPUT_SNMP | 10
NF9_L4_DST_PORT | 11
NF9_IPV4_DST_ADDR | 12
NF9_DST_MASK | 13
NF9_OUTPUT_SNMP | 14
NF9_V4_NEXT_HOP | 15
NF9_SRC_AS  | 16
NF9_DST_AS  | 17
NF9_BGP_V4_NEXT_HOP | 	18
NF9_LAST_SWITCHED | 21
NF9_FIRST_SWITCHED | 22
NF9_OUT_BYTES | 23
NF9_OUT_PKTS | 24
NF9_IPV6_SRC_ADDR | 27
NF9_IPV6_DST_ADDR | 28
NF9_IPV6_SRC_MASK | 29
NF9_IPV6_DST_MASK | 30
NF9_IPV6_FLOW_LABEL | 31
NF9_ICMP_TYPE | 32
NF9_SAMPLING_INTERVAL | 34
NF9_SAMPLING_ALGORITHM | 35
NF9_ENGINE_TYPE | 38
NF9_ENGINE_ID | 39
NF9_FLOW_SAMPLER_ID | 48 
FLOW_SAMPLER_MODE  | 49 
NF9_FLOW_SAMPLER_RANDOM_INTERVAL | 50
NF9_MIN_TTL | 52
NF9_MAX_TTL | 53
NF9_IPV4_IDENT | 54
NF9_DST_TOS | 55
NF9_IN_SRC_MAC | 56
NF9_OUT_DST_MAC | 57
NF9_SRC_VLAN | 58
NF9_DST_VLAN | 59
NF9_DIRECTION | 61
NF9_V6_NEXT_HOP | 62 
NF9_BPG_V6_NEXT_HOP | 63 
// NF9_V6_OPTION_HEADERS | 64
NF9_MPLS_LABEL_1 | 70
NF9_MPLS_LABEL_2 | 71
NF9_MPLS_LABEL_3 | 72
NF9_MPLS_LABEL_4 | 73
NF9_MPLS_LABEL_5 | 74
NF9_MPLS_LABEL_6 | 75
NF9_MPLS_LABEL_7 | 76
NF9_MPLS_LABEL_8 | 77
NF9_MPLS_LABEL_9 | 78
NF9_MPLS_LABEL_10 | 79
NF9_IN_DST_MAC | 80
NF9_OUT_SRC_MAC | 81
NF9_FORWARDING_STATUS | 89
NF9_BGP_ADJ_NEXT_AS  | 128
NF9_BGP_ADJ_PREV_AS  | 129

### CISCO ASA NSEL extension - Network Security Event Logging__
Tag | ID
----|---
NF_F_FLOW_BYTES | 85
NF_F_CONN_ID | 148
NF_F_FLOW_CREATE_TIME_MSEC | 152
NF_F_ICMP_TYPE | 176
NF_F_ICMP_CODE | 177
NF_F_ICMP_TYPE_IPV6 | 178
NF_F_ICMP_CODE_IPV6 | 179
NF_F_FWD_FLOW_DELTA_BYTES | 231
NF_F_REV_FLOW_DELTA_BYTES | 232
NF_F_FW_EVENT84 | 		233
NF_F_EVENT_TIME_MSEC | 323
NF_F_INGRESS_ACL_ID | 33000
NF_F_EGRESS_ACL_ID | 33001
NF_F_FW_EXT_EVENT | 33002
NF_F_USERNAME | 40000
NF_F_XLATE_SRC_ADDR_IPV4 | 40001
NF_F_XLATE_DST_ADDR_IPV4 | 40002
NF_F_XLATE_SRC_PORT | 40003
NF_F_XLATE_DST_PORT | 40004
NF_F_FW_EVENT | 40005

### Cisco ASR 1000 series NEL extension - Nat Event Logging__
Tag | ID
----|---
NF_N_NAT_EVENT | 230
NF_N_INGRESS_VRFID | 234
NF_N_EGRESS_VRFID | 235
NF_N_NAT_INSIDE_GLOBAL_IPV4 | 225
NF_N_NAT_OUTSIDE_GLOBAL_IPV4 | 226
NF_N_POST_NAPT_SRC_PORT | 	227
NF_N_POST_NAPT_DST_PORT | 	228

### latency extensions for nfpcapd and nprobe__
Tag | ID
----|---
NF9_NPROBE_CLIENT_NW_DELAY_SEC | 57554
NF9_NPROBE_CLIENT_NW_DELAY_USEC | 57555
NF9_NPROBE_SERVER_NW_DELAY_SEC | 57556
NF9_NPROBE_SERVER_NW_DELAY_USEC | 57557
NF9_NPROBE_APPL_LATENCY_SEC | 	57558
NF9_NPROBE_APPL_LATENCY_USEC | 57559

32 and 64 bit counters are supported for any counters. However, internally
nfdump stores packets and bytes counters always as 64bit counters. 
16 and 32 bit AS numbers are supported.

Extensions: nfcapd supports a large number of v9 tags. It automatically add
extensions to store data for v9/IPFIX elements which are supported.

### Sampling
By default, the sampling rate is set to 1 (unsampled) or to 
any given value specified by the -s cmd line option. If sampling information is found 
in the netflow stream, it overwrites the default value. Sampling is automatically 
recognised when announced in v9 option templates (tags #48, #49, #50 ), (tag #34, #35)
or in the unofficial v5 header hack. 
Note: Not all platforms (or IOS versions) support exporting sampling information in 
netflow data, even if sampling is configured. The number of bytes/packets in each 
netflow record is automatically multiplied by the sampling rate. The total number of 
flows is not changed as this is not accurate enough. (Small flows versus large flows)

### InfluxDB
You can send nfprofile stats data to an influxdb database. The data are the same of rrd files.
For enable this option you need libcurl dev package installed, use --enable-influxdb for configure the project and the nfprofile command should be invoked with option: -i <influxurl> . 
Example: -i http://localhost:8086/write?db=mydb&u=user&p=pass 
The parameters for auth (&u=user&p=pass) are optional.
Then you get the stats data on influxdb mydb in the measurement nfsen_stats.

For put the stats of live profile you need to apply a patch to nfsen (in extra/nfsen) and add in nfsen.conf the option:
	$influxdb_url="http://mydbhost.local:8086/write?db=nfsen";
as example I added a preconfigured grafana dashboard in extra/grafana/Nfsen_Stats.json .

---

For more information, see the GitHub Wiki
