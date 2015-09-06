/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nffile.h 40 2009-12-16 10:41:44Z haag $
 *
 *  $LastChangedRevision: 40 $
 *	
 */

#ifndef _NFFILE_H
#define _NFFILE_H 1

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#define IDENTLEN	128
#define IDENTNONE	"none"

#define NF_EOF		 	 0
#define NF_ERROR		-1
#define NF_CORRUPT		-2

#define NF_DUMPFILE         "nfcapd.current"

/* 
 * output buffer max size, before writing data to the file 
 * used to cache flows before writing to disk. size: tradeoff between
 * size and time to flush to disk. Do not delay collector with long I/O
 */
#define WRITE_BUFFSIZE 1048576

/*
 * use this buffer size to allocate memory for the output buffer
 * data other than flow records, such as histograms, may be larger than
 * WRITE_BUFFSIZE and have potentially more time to flush to disk
 */
#define BUFFSIZE (5*WRITE_BUFFSIZE)

/* if the output buffer reaches this limit, it gets flushed. This means,
 * that 0.5MB input data may produce max 1MB data in output buffer, otherwise
 * a buffer overflow may occur, and data does not get processed correctly.
 * However, every Process_vx function checks buffer boundaries.
 */

/*
 * nfdump binary file layout
 * =========================
 * Each data file starts with a file header, which identifies the file as an nfdump data file.
 * The magic 16bit integer at the beginning of each file must read 0xA50C. This also guarantees 
 * that endian dependant files are read correct.
 *
 * Principal layout, recognized as LAYOUT_VERSION_1:
 *
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 *   |Fileheader | stat record | datablock 1 | datablock 2 | ... | datablock n |
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 */

typedef struct file_header_s {
	uint16_t	magic;				// magic to recognize nfdump file type and endian type
#define MAGIC 0xA50C

	uint16_t	version;			// version of binary file layout, incl. magic
#define LAYOUT_VERSION_1	1

	uint32_t	flags;				
#define NUM_FLAGS		3
#define FLAG_COMPRESSED 	0x1		// flow records are compressed
#define FLAG_ANONYMIZED 	0x2		// flow data are anonimized 
#define FLAG_CATALOG		0x4		// has a file catalog record after stat record

									/*
										0x1 File is compressed with LZO1X-1 compression
									 */
	uint32_t	NumBlocks;			// number of data blocks in file
	char		ident[IDENTLEN];	// string identifier for this file
} file_header_t;

/* 
 * Compatible with nfdump x.x.x file format: After the file header an 
 * inplicit stat record follows, which contains the statistics 
 * information about all netflow records in this file.
 */

typedef struct stat_record_s {
	// overall stat
	uint64_t	numflows;
	uint64_t	numbytes;
	uint64_t	numpackets;
	// flow stat
	uint64_t	numflows_tcp;
	uint64_t	numflows_udp;
	uint64_t	numflows_icmp;
	uint64_t	numflows_other;
	// bytes stat
	uint64_t	numbytes_tcp;
	uint64_t	numbytes_udp;
	uint64_t	numbytes_icmp;
	uint64_t	numbytes_other;
	// packet stat
	uint64_t	numpackets_tcp;
	uint64_t	numpackets_udp;
	uint64_t	numpackets_icmp;
	uint64_t	numpackets_other;
	// time window
	uint32_t	first_seen;
	uint32_t	last_seen;
	uint16_t	msec_first;
	uint16_t	msec_last;
	// other
	uint32_t	sequence_failure;
} stat_record_t;

typedef struct stat_header_s {
	uint16_t	type;		// stat record type
// compatible stat type nfdump 1.5.x in new extended stat record type
#define STD_STAT_TYPE	0
	uint16_t	size;		// size of the stat record in bytes without this header
} stat_header_t;


// Netflow v9 field type/values


/*
 *
 * Block type 2:
 * =============
 * Each data block start with a common data block header, which specifies the size, type and the number of records
 * in this data block
 */

typedef struct data_block_header_s {
	uint32_t	NumRecords;		// number of data records in data block
	uint32_t	size;			// size of this block in bytes without this header
	uint16_t	id;				// Block ID == DATA_BLOCK_TYPE_2
	uint16_t	flags;			// 0 - kompatibility
								// 1 - block uncompressed
								// 2 - block compressed
} data_block_header_t;

// compat nfdump 1.5.x data block type
#define DATA_BLOCK_TYPE_1		1

// nfdump 1.6.x data block type
#define DATA_BLOCK_TYPE_2		2

/*
 *
 * Block type 3
 * ============
 * same block header as type 2. Used for data other than flow data - e.g. histograms. Important difference:
 * included data records have type L_record_header_t headers in order to allow larger data records.
 *
 */ 

#define Large_BLOCK_Type	3

typedef struct L_record_header_s {
 	// record header
 	uint32_t	type;
 	uint32_t	size;
} L_record_header_t;

/*
 *
 * Catalog Block
 * =============
 * introduces a file catalog for nfdump files. Not yet really used in nfdump-1.6.x
 * The catalog will get implemented later - most likely 1.7
 * The flag FLAG_CATALOG is used to flag the file for having a catalog
 * 
 */

#define CATALOG_BLOCK	4

typedef struct catalog_s {
	uint32_t	NumRecords;		// set to the number of catalog entries
	uint32_t	size;			// sizeof(nffile_catalog_t) without this header (-12)
	uint16_t	id;				// Block ID == CATALOG_BLOCK
	uint16_t	pad;			// unused align 32 bit

	off_t		reserved;		// reserved, set to 0;

	// catalog data
	struct catalog_entry_s {
		uint32_t	type;		// what catalog type does the entry point to
// type = 0 reserved
#define EXPORTER_table	1
#define MAX_CATALOG_ENTRIES 16
		off_t		offset;			// point to a data block with standard header data_block_header_t
	} entries[MAX_CATALOG_ENTRIES];	// the number of types we currently have defined - may grow in future

} catalog_t;

/*
 * Generic file handle for reading/writing files
 * if a file is read only writeto and block_header are NULL
 */
typedef struct nffile_s {
	file_header_t		*file_header;	// file header
	data_block_header_t	*block_header;	// buffer
	void				*buff_ptr;		// pointer into buffer for read/write blocks/records
	stat_record_t 		*stat_record;	// flow stat record
	catalog_t			*catalog;		// file catalog
	int					_compress;		// data compressed flag
	int					fd;				// file descriptor
} nffile_t;

/* 
 * The new block type 2 introduces a changed common record and multiple extension records. This allows a more flexible data
 * storage of netflow v9 records and 3rd party extension to nfdump.
 * 
 * A block type 2 may contain different record types, as described below.
 * 
 * Record description:
 * -------------------
 * A record always starts with a 16bit record id followed by a 16bit record size. This record size is the full size of this
 * record incl. record type and size fields and all record extensions. 
 * 
 * Know record types:
 * Type 0: reserved
 * Type 1: Common netflow record incl. all record extensions
 * Type 2: Extension map
 * Type 3: xstat - port histogram record
 * Type 4: xstat - bpp histogram record
 */

#define CommonRecordV0Type	1
#define ExtensionMapType	2
#define PortHistogramType	3
#define BppHistogramType	4

// TC code - phased out
#define ExporterRecordType	5
#define SamplerRecordype	6

// replaces TC Types
#define ExporterInfoRecordType	7
#define ExporterStatRecordType	8
#define SamplerInfoRecordype	9

// new extended Common Record as intermediate solution to overcome 255 exporters
// requires moderate changes till 1.7
#define CommonRecordType	10

 /* 
 * All records are 32bit aligned and layouted in a 64bit array. The numbers placed in () refer to the netflow v9 type id.
 *
 * Record type 1
 * =============
 * The record type 1 describes a netflow data record incl. all optional extensions for this record.
 * A netflow data record requires at least the first 3 extensions 1..3. All other extensions are optional 
 * and described in the extensiion map. The common record contains a reference to the extension map which 
 * applies for this record.
 *
 * flags:
 * bit  0:	0: IPv4				 1: IPv6
 * bit  1:	0: 32bit dPkts		 1: 64bit dPkts
 * bit  2:	0: 32bit dOctets	 1: 64bit dOctets 
 * bit  3:  0: IPv4 next hop     1: IPv6 next hop
 * bit  4:  0: IPv4 BGP next hop 1: BGP IPv6 next hop
 * bit  5:  0: IPv4 exporter IP  1: IPv6 exporter IP
 * bit  6:  0: flow              1: event
 * bit  7:  0: unsampled         1: sampled flow - sampling applied
 * 
 * Required extensions: 1,2,3
 * ------------------------------
 * A netflow record consists at least of a common record ( extension 0 ) and 3  required extension:
 * 
 * Extension 1: IPv4 or IPv4 src and dst addresses	Flags bit 0: 0: IPv4,  1: IPv6
 * Extension 2: 32 or 64 bit packet counter         Flags bit 1: 0: 32bit, 1: 64bit
 * Extension 3: 32 or 64 bit byte counter           Flags bit 2: 0: 32bit, 1: 64bit
 * 
 * Commmon record - extension 0
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |       0      |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |         record type == 1    |             size            |    flags     |    tag       |           ext. map          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |          msec_first         |           msec_last         |                          first (22)                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                          last (21)                        |fwd_status(89)| tcpflags (6) |  proto (4)   |  src tos (5) |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |           srcport (7)       |   dstport(11)/ICMP (32)     |
 * +----+--------------+--------------+--------------+--------------+
 *
 * Commmon record - extension 0 - Type 10
 * required for larger exporter ID reference 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |       0      |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |         record type == 10   |             size            |            flags            |           ext. map          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |          msec_first         |           msec_last         |                          first (22)                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                          last (21)                        |fwd_status(89)| tcpflags (6) |  proto (4)   |  src tos (5) |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |           srcport (7)       |   dstport(11)/ICMP (32)     |          exporter ID        |           <free>            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+

 * 
 */

#define COMMON_BLOCK_ID 0

typedef struct record_header_s {
 	// record header
 	uint16_t	type;
 	uint16_t	size;
} record_header_t;

typedef struct common_record_s {
 	// record head
 	uint16_t	type;
 	uint16_t	size;

	// record meta data
	uint16_t	flags;
#define FLAG_IPV6_ADDR	1
#define FLAG_PKG_64		2
#define FLAG_BYTES_64	4
#define FLAG_IPV6_NH	8
#define FLAG_IPV6_NHB	16
#define FLAG_IPV6_EXP	32
#define FLAG_EVENT		64
#define FLAG_SAMPLED	128

#define SetFlag(var, flag) 		(var |= flag)
#define ClearFlag(var, flag) 	(var &= ~flag)
#define TestFlag(var, flag)		(var & flag)

 	uint16_t	ext_map;

	// netflow common record
 	uint16_t	msec_first;
 	uint16_t	msec_last;
 	uint32_t	first;
 	uint32_t	last;
 
 	uint8_t		fwd_status;
 	uint8_t		tcp_flags;
 	uint8_t		prot;
 	uint8_t		tos;
 	uint16_t	srcport;
 	uint16_t	dstport;

	uint16_t	exporter_sysid;
	uint16_t	reserved;

	// link to extensions
 	uint32_t	data[1];
} common_record_t;

typedef struct common_record_v0_s {
 	// record head
 	uint16_t	type;
 	uint16_t	size;

	// record meta data
	uint8_t		flags;
	uint8_t		exporter_sysid;
 	uint16_t	ext_map;

	// netflow common record
 	uint16_t	msec_first;
 	uint16_t	msec_last;
 	uint32_t	first;
 	uint32_t	last;
 
 	uint8_t		fwd_status;
 	uint8_t		tcp_flags;
 	uint8_t		prot;
 	uint8_t		tos;
 	uint16_t	srcport;
 	uint16_t	dstport;

	// link to extensions
 	uint32_t	data[1];
} common_record_v0_t;

#define COMMON_RECORD_DATA_SIZE   (sizeof(common_record_t) - sizeof(uint32_t) )
#define COMMON_RECORDV0_DATA_SIZE (sizeof(common_record_v0_t) - sizeof(uint32_t) )

#define COMMON_BLOCK	0

 /* 
 * Required extensions:
 * --------------------
 * Extension 1: 
 * IPv4/v6 address type
 *                IP version: IPv4
 *                |
 * Flags: xxxx xxx0	
 * IPv4:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                           srcip (8)                       |                           dstip (12)                      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * 
 * IPv6:
 *                IP version: IPv6
 *                |
 * Flags: xxxx xxx1	
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                         srcip (27)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                         srcip (27)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                         dstip (28)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         dstip (28)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * 
 */

#define EX_IPv4v6	1

typedef struct ipv4_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint8_t		data[4];	// .. more data below
} ipv4_block_t;

typedef struct ipv6_block_s {
	uint64_t	srcaddr[2];
	uint64_t	dstaddr[2];
	uint8_t		data[4];	// .. more data below
} ipv6_block_t;

// single IP addr for next hop and bgp next hop
typedef struct ip_addr_s {
	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint32_t	fill[3];
			uint32_t	_v4;
#else
			uint32_t	fill1[2];
			uint32_t	_v4;
			uint32_t	fill2;
#endif
		};
		uint64_t		_v6[2];
	} ip_union;
} ip_addr_t;

#define v4 ip_union._v4
#define v6 ip_union._v6

 /*
 * Extension 2: 
 * In packet counter size
 * 
 *               In packet counter size 4byte
 *               |
 * Flags: xxxx xx0x	
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |                         in pkts (2)                       |
 * +---++--------------+--------------+--------------+--------------+
 * 
 *               In packet counter size 8byte
 *               |
 * Flags: xxxx xx1x	
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                       in pkts (2)                                                     |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * 
 */

#define EX_PACKET_4_8	2

typedef struct value32_s {
	uint32_t	val;
	uint8_t		data[4];	// .. more data below
} value32_t;

typedef struct value64_s {
	union val_s {
		uint64_t	val64;
		uint32_t	val32[2];
	} val;
	uint8_t		data[4];	// .. more data below
} value64_t;


 /* Extension 3: 
 * in byte counter size
 *              In byte counter size 4byte
 *              |
 * Flags: xxxx x0xx	
 * 
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |                        in bytes (1)                       |
 * +---++--------------+--------------+--------------+--------------+
 * 
 *              In byte counter size 8byte
 *              |
 * Flags: xxxx x1xx	
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                        in bytes (1)                                                   |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */

#define EX_BYTE_4_8	3

/* 
 * 
 * Optional extension:
 * ===================
 * 
 * Interface record
 * ----------------
 * Interface records are optional and accepted as either 2 or 4 bytes numbers
 * Extension 4: 
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |            input (10)       |            output (14)      |
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_IO_SNMP_2	4
typedef struct tpl_ext_4_s {
	uint16_t	input;
	uint16_t	output;
	uint8_t	data[4];	// points to further data
} tpl_ext_4_t;

/*
 * Extension 5: 
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                           input (10)                      |                           output (14)                     |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 4 and 5 are mutually exclusive in the extension map
 */
#define EX_IO_SNMP_4	5
typedef struct tpl_ext_5_s {
	uint32_t	input;
	uint32_t	output;
	uint8_t	data[4];	// points to further data
} tpl_ext_5_t;


/* 
 * AS record
 * ---------
 * AS records are optional and accepted as either 2 or 4 bytes numbers
 * Extension 6: 
 * +---++--------------+--------------+--------------+--------------+
 * |  0 |            src as (16)      |            dst as (17)      |
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_AS_2	6
typedef struct tpl_ext_6_s {
	uint16_t	src_as;
	uint16_t	dst_as;
	uint8_t	data[4];	// points to further data
} tpl_ext_6_t;

/*
 * Extension 7: 
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                         src as (16)                       |                          dst as (17)                      |
 * +---++--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 6 and 7 are mutually exclusive in the extension map
 */
#define EX_AS_4	7
typedef struct tpl_ext_7_s {
	uint32_t	src_as;
	uint32_t	dst_as;
	uint8_t	data[4];	// points to further data
} tpl_ext_7_t;


/*
 * Multiple fields record
 * ----------------------
 * These 4 different fields are grouped together in a 32bit value.
 * Extension 8:
 * +---++--------------+--------------+--------------+--------------+
 * |  3 |  dst tos(55) |   dir(61)    | srcmask(9,29)|dstmask(13,30)|  
 * +---++--------------+--------------+--------------+--------------+
 */
#define EX_MULIPLE	8
typedef struct tpl_ext_8_s {
	union {
		struct {
			uint8_t	dst_tos;
			uint8_t	dir;
			uint8_t	src_mask;
			uint8_t	dst_mask;
		};
		uint32_t	any;
	};
	uint8_t	data[4];	// points to further data
} tpl_ext_8_t;

/* 
 * IP next hop
 * -------------
 * IPv4:
 * Extension 9:
 *             IP version: IPv6
 *             |
 * Flags: xxxx 0xxx	
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       next hop ip (15)                    |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_v4	9
typedef struct tpl_ext_9_s {
	uint32_t	nexthop;
	uint8_t		data[4];	// points to further data
} tpl_ext_9_t;

/*
 * IPv6:
 * Extension 10:
 *             IP version: IPv6
 *             |
 * Flags: xxxx 1xxx	
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     next hop ip (62)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     next hop ip (62)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 9 and 10 are mutually exclusive in the extension map
 */
#define EX_NEXT_HOP_v6	10
typedef struct tpl_ext_10_s {
	uint64_t	nexthop[2];
	uint8_t		data[4];	// points to further data
} tpl_ext_10_t;


/*
 * BGP next hop IP
 * ------------------
 * IPv4:
 * Extension 11:
 *           IP version: IPv6
 *           |
 * Flags: xxx0 xxxx	
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       bgp next ip (18)                    |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_BGP_v4	11
typedef struct tpl_ext_11_s {
	uint32_t	bgp_nexthop;
	uint8_t		data[4];	// points to further data
} tpl_ext_11_t;

/*
 * IPv6:
 * Extension 12:
 *           IP version: IPv6
 *           |
 * Flags: xxx1 xxxx	
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     bgp next ip (63)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     bgp next ip (63)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NEXT_HOP_BGP_v6	12
typedef struct tpl_ext_12_s {
	uint64_t	bgp_nexthop[2];
	uint8_t		data[4];	// points to further data
} tpl_ext_12_t;


/*
 * VLAN record
 * -----------
 * Extension 13: 
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |           src vlan(58)      |          dst vlan (59)      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_VLAN	13
typedef struct tpl_ext_13_s {
	uint16_t	src_vlan;
	uint16_t	dst_vlan;
	uint8_t		data[4];	// points to further data
} tpl_ext_13_t;


/* 
 * Out packet counter size
 * ------------------------
 * 4 byte
 * Extension 14: 
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        out pkts (24)                      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_OUT_PKG_4	14
typedef struct tpl_ext_14_s {
	uint32_t	out_pkts;
	uint8_t		data[4];	// points to further data
} tpl_ext_14_t;

/*
 * 4 byte
 * Extension 15: 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      out pkts (24)                                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 14 and 15 are mutually exclusive in the extension map
 */
#define EX_OUT_PKG_8	15
typedef struct tpl_ext_15_s {
	union {
		uint64_t	out_pkts;
		uint32_t	v[2];	// for strict alignment use 2x32bits
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_15_t;


/* 
 * Out byte counter size
 * ---------------------
 * 4 byte
 * Extension 16: 
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        out bytes (23)                     |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_OUT_BYTES_4	16
typedef struct tpl_ext_16_s {
	uint32_t	out_bytes;
	uint8_t		data[4];	// points to further data
} tpl_ext_16_t;


/* 8 byte
 * Extension 17:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      out bytes (23)                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 16 and 17 are mutually exclusive in the extension map
 */
#define EX_OUT_BYTES_8	17
typedef struct tpl_ext_17_s {
	union {
		uint64_t	out_bytes;
		uint32_t 	v[2];	// potential 32bit alignment
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_17_t;

/* 
 * Aggr flows
 * ----------
 * 4 byte
 * Extension 18: 
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                        aggr flows (3)                     |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_AGGR_FLOWS_4	18
typedef struct tpl_ext_18_s {
	uint32_t	aggr_flows;
	uint8_t		data[4];	// points to further data
} tpl_ext_18_t;


/* 8 byte
 * Extension 19:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                      aggr flows (3)                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 18 and 19 are mutually exclusive in the extension map
 */
#define EX_AGGR_FLOWS_8	19
typedef struct tpl_ext_19_s {
	union {
		uint64_t	aggr_flows;
		uint32_t	v[2];	// 32bit alignment
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_19_t;

/* 16 byte
 * Extension 20:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |              0              |                                     in src mac (56)                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |              0              |                                     out dst mac (57)                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MAC_1 20	
typedef struct tpl_ext_20_s {
	union {
		uint64_t	in_src_mac;
		uint32_t	v1[2];
	};
	union {
		uint64_t	out_dst_mac;
		uint32_t	v2[2];
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_20_t;

/* 16 byte
 * Extension 21:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |              0              |                                     in dst mac (80)                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |              0              |                                     out src mac (81)                                    |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MAC_2 21	
typedef struct tpl_ext_21_s {
	union {
		uint64_t	in_dst_mac;
		uint32_t	v1[2];
	};
	union {
		uint64_t	out_src_mac;
		uint32_t	v2[2];
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_21_t;

/* 40 byte
 * Extension 22:
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |      0       |             MPLS_LABEL_2 (71)              |       0      |              MPLS_LABEL_1 (70)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |      0       |             MPLS_LABEL_4 (73)              |       0      |              MPLS_LABEL_3 (72)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |      0       |             MPLS_LABEL_6 (75)              |       0      |              MPLS_LABEL_5 (74)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |      0       |             MPLS_LABEL_8 (77)              |       0      |              MPLS_LABEL_7 (76)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |      0       |             MPLS_LABEL_10 (79)             |       0      |              MPLS_LABEL_9 (78)             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_MPLS 22	
typedef struct tpl_ext_22_s {
	uint32_t	mpls_label[10];
	uint8_t		data[4];	// points to further data
} tpl_ext_22_t;

/* 
 * Sending router IP
 * -----------------
 * IPv4:
 * Extension 23:
 *          IP version: IPv6
 *          |
 * Flags: xx0x xxxx	
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |                       router ipv4 ()                      |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_ROUTER_IP_v4	23
typedef struct tpl_ext_23_s {
	uint32_t	router_ip;
	uint8_t		data[4];	// points to further data
} tpl_ext_23_t;

/*
 * IPv6:
 * Extension 24:
 *          IP version: IPv6
 *          |
 * Flags: xx1x xxxx	
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                     router ip v6 ()                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                     router ip v6 ()                                                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * Extension 23 and 24 are mutually exclusive in the extension map
 */
#define EX_ROUTER_IP_v6	24
typedef struct tpl_ext_24_s {
	uint64_t	router_ip[2];
	uint8_t		data[4];	// points to further data
} tpl_ext_24_t;

/* 
 * router source ID
 * ----------------
 * For v5 netflow, it's engine type/engine ID 
 * for v9 it's the source_id
 * Extension 25:
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |            fill             |engine tpe(38)|engine ID(39) |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_ROUTER_ID 25
typedef struct tpl_ext_25_s {
	uint16_t	fill;
	uint8_t		engine_type;
	uint8_t		engine_id;
	uint8_t		data[4];	// points to further data
} tpl_ext_25_t;

/*
 * BGP prev/next adjacent AS
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                  bgpNextAdjacentAsNumber(128)             |                bgpPrevAdjacentAsNumber(129)               |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_BGPADJ 26
typedef struct tpl_ext_26_s {
	uint32_t	bgpNextAdjacentAS;
	uint32_t	bgpPrevAdjacentAS;
	uint8_t		data[4];	// points to further data
} tpl_ext_26_t;

/*
 * time flow received in ms
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                    T received()                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_RECEIVED		27
typedef struct tpl_ext_27_s {
	union {
		uint64_t	received;
		uint32_t	v[2];
	};
	uint8_t		data[4];	// points to further data
} tpl_ext_27_t;



#define EX_RESERVED_1	28
#define EX_RESERVED_2	29
#define EX_RESERVED_3	30
#define EX_RESERVED_4	31
#define EX_RESERVED_5	32
#define EX_RESERVED_6	33
#define EX_RESERVED_7	34
#define EX_RESERVED_8	35
#define EX_RESERVED_9	36

/*
 * NSEL Common block
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                           NF_F_FLOW_CREATE_TIME_MSEC(152)                                             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                      NF_F_CONN_ID(148)                    |i type(176/8) |i code(177/9) |EVT(40005/233)|    fill      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |   NF_F_FW_EXT_EVENT(33002)  |            fill2            |
 * +----+--------------+--------------+--------------+--------------+
 * * EVT: NF_F_FW_EVENT
 * * XEVT: NF_F_FW_EXT_EVENT
 */
#define EX_NSEL_COMMON	37
typedef struct tpl_ext_37_s {
	union {
		uint64_t	event_time;
		uint32_t	v[2];
	};
	uint32_t	conn_id;
	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint8_t		icmp_type;
			uint8_t		icmp_code;
#else
			uint8_t		icmp_code;
			uint8_t		icmp_type;
#endif
		};
		uint16_t nsel_icmp;
	};
	uint8_t		fw_event;
	uint8_t		fill;
	uint16_t	fw_xevent;
	uint16_t	fill2;
	uint8_t		data[4];	// points to further data
} tpl_ext_37_t;

/*
 * NSEL/NEL xlate ports
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |  NF_F_XLATE_SRC_PORT(227)   |  NF_F_XLATE_DST_PORT(228)   |
 * +----+--------------+--------------+--------------+--------------+
 * ASA 8.4 compatibility mapping 40003 -> 227
 * ASA 8.4 compatibility mapping 40004 -> 228
 */
#define EX_NSEL_XLATE_PORTS	38
typedef struct tpl_ext_38_s {
	uint16_t	xlate_src_port;
	uint16_t	xlate_dst_port;
	uint8_t		data[4];	// points to further data
} tpl_ext_38_t;

/*
 * NSEL xlate v4 IP address
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                NF_F_XLATE_SRC_ADDR_IPV4(225)              |                NF_F_XLATE_DST_ADDR_IPV4(226)              |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ASA 8.4 compatibility mapping 40001 -> 225
 * ASA 8.4 compatibility mapping 40002 -> 226
 */
#define EX_NSEL_XLATE_IP_v4	39
typedef struct tpl_ext_39_s {
	uint32_t	xlate_src_ip;
	uint32_t	xlate_dst_ip;
	uint8_t		data[4];	// points to further data
} tpl_ext_39_t;

/*
 * NSEL xlate v6 IP address - not yet implemented by CISCO
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                         xlate src ip (281)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                         xlate src ip (281)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                         xlate dst ip (282)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         xlate dst ip (282)                                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_XLATE_IP_v6	40
typedef struct tpl_ext_40_s {
	uint64_t	xlate_src_ip[2];
	uint64_t	xlate_dst_ip[2];
	uint8_t		data[4];	// points to further data
} tpl_ext_40_t;


/*
 * NSEL ACL ingress/egress acl ID
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                            NF_F_INGRESS_ACL_ID(33000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                 NF_F_INGRESS_ACL_ID(33000)                |               NF_F_EGRESS_ACL_ID(33001)                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                            NF_F_EGRESS_ACL_ID(33001)                                                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_ACL		41
typedef struct tpl_ext_41_s {
	uint32_t	ingress_acl_id[3];
	uint32_t	egress_acl_id[3];
	uint8_t		data[4];	// points to further data
} tpl_ext_41_t;

/*
 * NSEL ACL username
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                  NF_F_USERNAME(40000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_USER	42
typedef struct tpl_ext_42_s {
	char		username[24];
	uint8_t		data[4];	// points to further data
} tpl_ext_42_t;

/*
 * NSEL ACL username max
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                                  NF_F_USERNAME(40000)                                                 |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * | .. |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  8 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_NSEL_USER_MAX 43
typedef struct tpl_ext_43_s {
	char		username[72];
	uint8_t		data[4];	// points to further data
} tpl_ext_43_t;


#define EX_NSEL_RESERVED 44

/*
 * nprobe extensions
 */

/*
 * latency extension 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |                                           client_nw_delay_usec (57554/57554)                                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                           server_nw_delay_usec (57556/57557)                                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                           appl_latency_usec (57558/57559)                                             |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_LATENCY 45
typedef struct tpl_ext_latency_s {
	uint64_t	client_nw_delay_usec;
	uint64_t	server_nw_delay_usec;
	uint64_t	appl_latency_usec;
	uint8_t		data[4];	// points to further data
} tpl_ext_latency_t;

/*
 * NEL xlate ports
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |NAT_EVENT(230)|     flags    |            fill             |                  NF_N_EGRESS_VRFID(235)                   |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                 NF_N_INGRESS_VRFID(234)                   |
 * +----+--------------+--------------+--------------+--------------+
 */
#define EX_NEL_COMMON 46
typedef struct tpl_ext_46_s {
	uint8_t		nat_event;
	uint8_t		flags;
	uint16_t	fill;
	uint32_t	egress_vrfid;
	uint32_t	ingress_vrfid;
	uint8_t		data[4];	// points to further data
} tpl_ext_46_t;

#define EX_NEL_GLOBAL_IP_v4	47
/* 
 * no longer used. Mapped to NSEL extension EX_NSEL_XLATE_IP_v4
 */
typedef struct tpl_ext_47_s {
	uint32_t    nat_inside;
	uint32_t    nat_outside;
	uint8_t     data[4];    // points to further data
} tpl_ext_47_t;

/*
 * NEL Port Block Allocation
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 | NF_F_XLATE_PORT_BLOCK_START |  NF_F_XLATE_PORT_BLOCK_END  |  NF_F_XLATE_PORT_BLOCK_STEP |  NF_F_XLATE_PORT_BLOCK_SIZE |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
#define EX_PORT_BLOCK_ALLOC	48
typedef struct tpl_ext_48_s {
	uint16_t	block_start;
	uint16_t	block_end;
	uint16_t	block_step;
	uint16_t	block_size;
	uint8_t     data[4];    // points to further data
} tpl_ext_48_t;

#define EX_NEL_RESERVED_1	49


/* 
 * 
 * 
 * V1 Extension map:
 * =================
 * The extension map replaces the individual flags in v1 layout. With many possible extensions and combination of extensions
 * an extension map is more efficient and flexible while reading and decoding the record.
 * In current version of nfdump, up to 65535 individual extension maps are supported, which is considered to be enough.
 * 
 * For each available extension record, the ids are recorded in the extension map in the order they appear.
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 2      |             size            |            map id           |      extension size         |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       extension id 1        |      extension id 2         |      extension id 3         |       extension id 4        |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ...
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       extension id n        |      extension id n+1       |      extension id n+2       |       extension id n+3      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ...
 * +----+--------------+--------------+--------------+--------------+
 * |  0 |              0              | opt. 32bit alignment: 0     |
 * +----+--------------+--------------+--------------+--------------+
 */

/* extension IDs above are 16 bit integers. So themax number of available extensions is */
#define MAX_EXTENSIONS 65536

typedef struct extension_map_s {
 	// record head
 	uint16_t	type;	// is ExtensionMapType
 	uint16_t	size;	// size of full map incl. header

	// map data
#define INIT_ID 0xFFFF
	uint16_t	map_id;			// identifies this map
 	uint16_t	extension_size; // size of all extensions
	uint16_t	ex_id[1];		// extension id array
} extension_map_t;


/* 
 * 
 * 
 * V2 Extension map:
 * =================
 * The V2 extension map replaces the V1 extension map. The basic extension architecture remains the same. V2 extensions
 * adds extra information about the extension such as size and offset within the packed record. This allows more 
 * flexibility by using flexible length extensions up to the extension defined maximum. With the introduction of V2
 * extension maps, the old master_record will become obsolete in near future.
 * Implementation wise: if extension size is set to 0 - the first 2 bytes of the extension data contains the size of
 * the extension. Extensions with flexible size must only appended at the end of the record block.
 * 
 * For each available extension record, the ids are recorded in the extension map in the order they appear.
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 10     |             size            |            map id           |      max extension size     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |       extension id 1        |   offset extension id 1     |        extension id 2       |    offset extension id 2    | 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |       extension id 3        |   offset extension id 3     |        extension id 4       |    offset extension id 4    | 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ...
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  n |       extension id n        |      size extension id n    |              0              |              0              |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */

/* extension IDs above are 16 bit integers. So themax number of available extensions is */
#define MAX_EXTENSIONS 65536
/* XXX extension 1.7
typedef struct extension_map17_s {
 	// record head
 	uint16_t	type;	// is ExtensionMapType2
 	uint16_t	size;	// size of full map incl. header

	// map data
	uint16_t	map_id;			// identifies this map
 	uint16_t	extension_size; // max size of all extensions
	struct ex_def_s {
		uint16_t	id;		// extension id
		uint16_t	offset;	// max extension size
	} ex[1];				// array of all extensions
} extension_map17_t;
*/

// see nfx.c - extension_descriptor
#ifdef NSEL
// Defaults for NSEL
#define DefaultExtensions  "1,8,26,27,28,29,30,31"
#else
// Collector netflow defaults
#define DefaultExtensions  "1,2"
#endif

/*
 * nfcapd writes an info stat record for each new exporter
 * 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 7      |             size            |                          version                          |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                                                                                                                       |
 * +----+--------------+--------------+--------------+----------  ip   ------------+--------------+--------------+--------------+
 * |  2 |                                                                                                                       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |          sa_family          |            sysid            |                             id                            |      
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
typedef struct exporter_info_record_s {
	record_header_t	header;

	// exporter version
	uint32_t 	version;
#define SFLOW_VERSION  9999

	// IP address
	ip_addr_t	ip;
	uint16_t	sa_family;

	// internal assigned ID
	uint16_t	sysid;

	// exporter ID/Domain ID/Observation Domain ID assigned by the device
	uint32_t	id;

} exporter_info_record_t;

/*
 * nfcapd writes a stat record at the end of the file which contains the exporter statistics.
 * 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 8      |             size            |                         stat_count                        |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                           sysid[0]                        |                      sequence_failure[0]                  |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  2 |                                                        packets[0]                                                     |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  3 |                                                         flows[0]                                                      |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * ... more stat records [x], one for each exporter
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 */
typedef struct exporter_stats_record_s {
	record_header_t	header;

	uint32_t	stat_count;		// number of stat records 
	
	struct exporter_stat_s {
		uint32_t	sysid;				// identifies the exporter
		uint32_t	sequence_failure;	// number of sequence failues
		uint64_t	packets;			// number of packets sent by this exporter
		uint64_t	flows;				// number of flow records sent by this exporter
	} stat[1];

} exporter_stats_record_t;


/*
 * nfcapd writes a sampler record for each new sampler announced
 * 
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  - |	     0     |      1       |      2       |      3       |      4       |      5       |      6       |      7       |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  0 |       record type == 9      |             size            |                             id                            |
 * +----+--------------+--------------+--------------+--------------+--------------+--------------+--------------+--------------+
 * |  1 |                          interval                         |             mode            |       exporter_sysid        |
 * +----+--------------+--------------+--------------+-----------------------------+--------------+--------------+--------------+
 */
typedef struct sampler_info_record_s {
	record_header_t	header;

	// sampler data
	int32_t		id;				// id assigned by the exporting device
	uint32_t	interval;		// sampling interval
	uint16_t	mode;			// sampling mode
	uint16_t	exporter_sysid; // internal reference to exporter

} sampler_info_record_t;



/*
 * TC test code - records will disappear ..
 */
typedef struct exporter_record_s {
	record_header_t	header;

	// exporter data
	uint32_t 	version;		// make sure it's a version 9 exporter 

	// IP address
	uint32_t	sa_family;
	ip_addr_t	ip;

	// internal assigned ID
	uint32_t	sysid;

	// exporter info
	uint32_t	exporter_id;
	uint32_t	sequence_failure;

} exporter_record_t;

typedef struct sampler_record_s {
	record_header_t	header;

	// reference to exporter
	uint32_t	exporter_sysid;

	// sampler data
	int32_t		id;
	uint32_t	interval;
	uint8_t		mode;
} sampler_record_t;


/* the master record contains all possible records unpacked */
typedef struct master_record_s {
	// common information from all netflow versions
	// 							// interpreted as uint64_t[]
	// 							#ifdef WORDS_BIGENDIAN

	uint16_t	type;			// index 0  0xffff 0000 0000 0000
	uint16_t	size;			// index 0	0x0000'ffff'0000 0000
	uint16_t	flags;			// index 0	0x0000'0000'ffff'0000
	uint16_t	ext_map;		// index 0	0x0000'0000'0000'ffff
#	define OffsetRecordFlags 	0
#ifdef WORDS_BIGENDIAN
#	define MaskRecordFlags  	0x00000000ff000000LL
#	define ShiftRecordFlags 	24
#else
#	define MaskRecordFlags  	0x000000ff00000000LL
#	define ShiftRecordFlags 	32
#endif

	//
	uint16_t	msec_first;		// index 1	0xffff'0000'0000'0000
	uint16_t	msec_last;		// index 1	0x0000'ffff'0000'0000

	// 12 bytes offset in master record to first
#define BYTE_OFFSET_first	12

	uint32_t	first;			// index 1	0x0000'0000'ffff'ffff

	//
	uint32_t	last;			// index 2	0xffff'ffff'0000'0000
	uint8_t		fwd_status;		// index 2	0x0000'0000'ff00'0000
	uint8_t		tcp_flags;		// index 2  0x0000'0000'00ff'0000
	uint8_t		prot;			// index 2  0x0000'0000'0000'ff00
	uint8_t		tos;			// index 2  0x0000'0000'0000'00ff
#ifdef WORDS_BIGENDIAN
#	define OffsetStatus 		2
#	define MaskStatus  			0x00000000ff000000LL
#	define ShiftStatus  		24

#	define OffsetFlags 			2
#	define MaskFlags   			0x0000000000ff0000LL
	#define ShiftFlags  		16

#	define OffsetProto 			2
#	define MaskProto   			0x000000000000ff00LL
#	define ShiftProto  			8

#	define OffsetTos			2
#	define MaskTos	   			0x00000000000000ffLL
#	define ShiftTos  			0

#else
#	define OffsetStatus 		2
#	define MaskStatus  			0x000000ff00000000LL
#	define ShiftStatus  		32

#	define OffsetFlags 			2
#	define MaskFlags   			0x0000ff0000000000LL
#	define ShiftFlags  			40

#	define OffsetProto 			2
#	define MaskProto   			0x00ff000000000000LL
#	define ShiftProto  			48

#	define OffsetTos			2
#	define MaskTos	   			0xff00000000000000LL
#	define ShiftTos  			56
#endif

	uint16_t	srcport;		// index 3	0xffff'0000'0000'0000
	uint16_t	dstport;		// index 3  0x0000'ffff'0000'0000
	uint16_t	exporter_sysid; // index 3	0x0000'0000'ffff'0000

	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint8_t		icmp_type;	// index 3  0x0000'0000'0000'ff00
			uint8_t		icmp_code;	// index 3  0x0000'0000'0000'00ff
#else
			// little endian confusion ...
			uint8_t		icmp_code;	
			uint8_t		icmp_type;
#endif
		};
		uint16_t icmp;
	};


#ifdef WORDS_BIGENDIAN
#	define OffsetPort 			3
#	define OffsetExporterSysID	3
#	define MaskSrcPort			0xffff000000000000LL
#	define ShiftSrcPort			48

#	define MaskDstPort			0x0000ffff00000000LL
#	define ShiftDstPort 		32	

#	define MaskExporterSysID  	0x00000000ffff0000LL
#	define ShiftExporterSysID 	16

#	define MaskICMPtype			0x000000000000ff00LL
#	define ShiftICMPtype 		8
#	define MaskICMPcode			0x00000000000000ffLL
#	define ShiftICMPcode 		0

#else
#	define OffsetPort 			3
#	define OffsetExporterSysID	3
#	define MaskSrcPort			0x000000000000ffffLL
#	define ShiftSrcPort			0

#	define MaskDstPort			0x00000000ffff0000LL
#	define ShiftDstPort 		16

#	define MaskExporterSysID  	0x0000ffff00000000LL
#	define ShiftExporterSysID 	32

#	define MaskICMPtype			0xff00000000000000LL
#	define ShiftICMPtype 		56
#	define MaskICMPcode			0x00ff000000000000LL
#	define ShiftICMPcode 		48
#endif

	// extension 4 / 5
	uint32_t	input;			// index 4	0xffff'ffff'0000'0000
	uint32_t	output;			// index 4	0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#	define OffsetInOut     		4
#	define MaskInput       		0xffffffff00000000LL
#	define ShiftInput      		32
#	define MaskOutput      		0x00000000ffffffffLL
#	define ShiftOutput     		0

#else
#	define OffsetInOut     		4
#	define MaskInput      		0x00000000ffffffffLL
#	define ShiftInput      		0
#	define MaskOutput       	0xffffffff00000000LL
#	define ShiftOutput     		32
#endif

	// extension 6 / 7
	uint32_t	srcas;			// index 5	0xffff'ffff'0000'0000
	uint32_t	dstas;			// index 5	0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#	define OffsetAS 			5
#	define MaskSrcAS 			0xffffffff00000000LL
#	define ShiftSrcAS 			32
#	define MaskDstAS 			0x00000000ffffffffLL
#	define ShiftDstAS 			0

#else
#	define OffsetAS 			5
#	define MaskSrcAS 			0x00000000ffffffffLL
#	define ShiftSrcAS 			0
#	define MaskDstAS 			0xffffffff00000000LL
#	define ShiftDstAS 			32
#endif


	// IP address block 
	union {						
		struct _ipv4_s {
#ifdef WORDS_BIGENDIAN
			uint32_t	fill1[3];	// <empty>		index 6	0xffff'ffff'ffff'ffff
									// <empty>		index 7 0xffff'ffff'0000'0000
			uint32_t	srcaddr;	// srcaddr      index 7 0x0000'0000'ffff'ffff
			uint32_t	fill2[3];	// <empty>		index 8	0xffff'ffff'ffff'ffff
									// <empty>		index 9	0xffff'ffff'0000'0000
			uint32_t	dstaddr;	// dstaddr      index 9 0x0000'0000'ffff'ffff
#else
			uint32_t	fill1[2];	// <empty>		index 6	0xffff'ffff'ffff'ffff
			uint32_t	srcaddr;	// srcaddr      index 7 0xffff'ffff'0000'0000
			uint32_t	fill2;		// <empty>		index 7 0x0000'0000'ffff'ffff
			uint32_t	fill3[2];	// <empty>		index 8 0xffff'ffff'ffff'ffff
			uint32_t	dstaddr;	// dstaddr      index 9 0xffff'ffff'0000'0000
			uint32_t	fill4;		// <empty>		index 9 0xffff'ffff'0000'0000
#endif
		} _v4;	
		struct _ipv6_s {
			uint64_t	srcaddr[2];	// srcaddr[0-1] index 6 0xffff'ffff'ffff'ffff
									// srcaddr[2-3] index 7 0xffff'ffff'ffff'ffff
			uint64_t	dstaddr[2];	// dstaddr[0-1] index 8 0xffff'ffff'ffff'ffff
									// dstaddr[2-3] index 9 0xffff'ffff'ffff'ffff
		} _v6;
		struct _ip64_s {
			uint64_t	addr[4];
		} _ip_64;
	} ip_union;

#ifdef WORDS_BIGENDIAN
#	define OffsetSrcIPv4 		7
#	define MaskSrcIPv4  		0x00000000ffffffffLL
#	define ShiftSrcIPv4 		0

#	define OffsetDstIPv4 		9
#	define MaskDstIPv4  		0x00000000ffffffffLL
#	define ShiftDstIPv4  		0	

#	define OffsetSrcIPv6a 		6
#	define OffsetSrcIPv6b 		7
#	define OffsetDstIPv6a 		8
#	define OffsetDstIPv6b 		9
#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0

#else
#	define OffsetSrcIPv4 		6
#	define MaskSrcIPv4  		0xffffffff00000000LL
#	define ShiftSrcIPv4 		32

#	define OffsetDstIPv4 		8
#	define MaskDstIPv4  		0xffffffff00000000LL
#	define ShiftDstIPv4  		32

#	define OffsetSrcIPv6a 		6
#	define OffsetSrcIPv6b 		7
#	define OffsetDstIPv6a 		8
#	define OffsetDstIPv6b 		9
#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0
#endif


	// counter block - expanded to 8 bytes
	uint64_t	dPkts;			// index 10	0xffff'ffff'ffff'ffff
#	define OffsetPackets 		10
#	define MaskPackets  		0xffffffffffffffffLL
#	define ShiftPackets 		0

	uint64_t	dOctets;		// index 11 0xffff'ffff'ffff'ffff
#	define OffsetBytes 			11
#	define MaskBytes  			0xffffffffffffffffLL
#	define ShiftBytes 			0

	// extension 9 / 10
	ip_addr_t	ip_nexthop;		// ipv4   index 13 0x0000'0000'ffff'ffff
								// ipv6	  index 12 0xffff'ffff'ffff'ffff
								// ipv6	  index 13 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetNexthopv4 		13	
#	define MaskNexthopv4  		0x00000000ffffffffLL
#	define ShiftNexthopv4 		0

#	define OffsetNexthopv6a		12
#	define OffsetNexthopv6b		13
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetNexthopv4 		13	
#	define MaskNexthopv4  		0xffffffff00000000LL
#	define ShiftNexthopv4 		0

#	define OffsetNexthopv6a		12
#	define OffsetNexthopv6b		13
#endif

	// extension 11 / 12
	ip_addr_t	bgp_nexthop;	// ipv4   index 15 0x0000'0000'ffff'ffff
								// ipv6	  index 14 0xffff'ffff'ffff'ffff
								// ipv6	  index 15 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetBGPNexthopv4 	15	
#	define MaskBGPNexthopv4  	0x00000000ffffffffLL
#	define ShiftBGPNexthopv4 	0

#	define OffsetBGPNexthopv6a	14
#	define OffsetBGPNexthopv6b	15
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetBGPNexthopv4 	15	
#	define MaskBGPNexthopv4  	0xffffffff00000000LL
#	define ShiftBGPNexthopv4 	0

#	define OffsetBGPNexthopv6a	14
#	define OffsetBGPNexthopv6b	15
#endif

	// extension 8
	union {
		struct {
			uint8_t	dst_tos;	// index 16 0xff00'0000'0000'0000
			uint8_t	dir;		// index 16 0x00ff'0000'0000'0000
			uint8_t	src_mask;	// index 16 0x0000'ff00'0000'0000
			uint8_t	dst_mask;	// index 16 0x0000'00ff'0000'0000
		};
		uint32_t	any;
	};

	// extension 13
	uint16_t	src_vlan;		// index 16 0x0000'0000'ffff'0000
	uint16_t	dst_vlan;		// index 16 0x0000'0000'0000'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetDstTos			16
#	define MaskDstTos			0xff00000000000000LL
#	define ShiftDstTos  		56

#	define OffsetDir			16
#	define MaskDir				0x00ff000000000000LL
#	define ShiftDir  			48

#	define OffsetMask			16
#	define MaskSrcMask			0x0000ff0000000000LL
#	define ShiftSrcMask  		40

#	define MaskDstMask			0x000000ff00000000LL
#	define ShiftDstMask 		32

#	define OffsetVlan 			16	
#	define MaskSrcVlan  		0x00000000ffff0000LL
#	define ShiftSrcVlan 		16

#	define MaskDstVlan  		0x000000000000ffffLL
#	define ShiftDstVlan 		0

#else
#	define OffsetDstTos			16
#	define MaskDstTos			0x00000000000000ffLL
#	define ShiftDstTos  		0

#	define OffsetDir			16
#	define MaskDir				0x000000000000ff00LL
#	define ShiftDir  			8

#	define OffsetMask			16
#	define MaskSrcMask			0x0000000000ff0000LL
#	define ShiftSrcMask  		16

#	define MaskDstMask			0x00000000ff000000LL
#	define ShiftDstMask 		24

#	define OffsetVlan 			16	
#	define MaskSrcVlan  		0x0000ffff00000000LL
#	define ShiftSrcVlan 		32

#	define MaskDstVlan  		0xffff000000000000LL
#	define ShiftDstVlan 		48

#endif

	// extension 14 / 15
	uint64_t	out_pkts;		// index 17	0xffff'ffff'ffff'ffff
#	define OffsetOutPackets 	17
// MaskPackets and ShiftPackets already defined

	// extension 16 / 17
	uint64_t	out_bytes;		// index 18 0xffff'ffff'ffff'ffff
#	define OffsetOutBytes 		18

	// extension 18 / 19
	uint64_t	aggr_flows;		// index 19 0xffff'ffff'ffff'ffff
#	define OffsetAggrFlows 		19
#	define MaskFlows 	 		0xffffffffffffffffLL

	// extension 20
	uint64_t	in_src_mac;		// index 20 0xffff'ffff'ffff'ffff
#	define OffsetInSrcMAC 		20
#	define MaskMac 	 			0xffffffffffffffffLL

	// extension 20
	uint64_t	out_dst_mac;	// index 21 0xffff'ffff'ffff'ffff
#	define OffsetOutDstMAC 		21

	// extension 21
	uint64_t	in_dst_mac;		// index 22 0xffff'ffff'ffff'ffff
#	define OffsetInDstMAC 		22

	// extension 21
	uint64_t	out_src_mac;	// index 23 0xffff'ffff'ffff'ffff
#	define OffsetOutSrcMAC 		23

	// extension 22
	uint32_t	mpls_label[10];
#	define OffsetMPLS12 		24
#	define OffsetMPLS34 		25
#	define OffsetMPLS56 		26
#	define OffsetMPLS78 		27
#	define OffsetMPLS910 		28

#ifdef WORDS_BIGENDIAN
#	define MaskMPLSlabelOdd  	0x00fffff000000000LL
#	define ShiftMPLSlabelOdd 	36
#	define MaskMPLSexpOdd  		0x0000000e00000000LL
#	define ShiftMPLSexpOdd 		33

#	define MaskMPLSlabelEven  	0x0000000000fffff0LL
#	define ShiftMPLSlabelEven 	4
#	define MaskMPLSexpEven  	0x000000000000000eLL
#	define ShiftMPLSexpEven 	1
#else
#	define MaskMPLSlabelOdd 	0x000000000000fff0LL
#	define ShiftMPLSlabelOdd 	4
#	define MaskMPLSexpOdd  		0x000000000000000eLL
#	define ShiftMPLSexpOdd 		1

#	define MaskMPLSlabelEven 	0x00fffff000000000LL
#	define ShiftMPLSlabelEven 	36
#	define MaskMPLSexpEven 		0x0000000e00000000LL
#	define ShiftMPLSexpEven		33

#endif

	// extension 23 / 24
	ip_addr_t	ip_router;		// ipv4   index 30 0x0000'0000'ffff'ffff
								// ipv6	  index 29 0xffff'ffff'ffff'ffff
								// ipv6	  index 30 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetRouterv4 		30
#	define MaskRouterv4  		0x00000000ffffffffLL
#	define ShiftRouterv4 		0

#	define OffsetRouterv6a		29
#	define OffsetRouterv6b		30
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetRouterv4 		30
#	define MaskRouterv4  		0xffffffff00000000LL
#	define ShiftRouterv4 		0

#	define OffsetRouterv6a		29
#	define OffsetRouterv6b		30
#endif

	// extension 25
	uint16_t	fill;			// fill	index 31 0xffff'0000'0000'0000
	uint8_t		engine_type;	// type index 31 0x0000'ff00'0000'0000
	uint8_t		engine_id;		// ID	index 31 0x0000'00ff'0000'0000
	uint32_t	fill2;

#	define OffsetRouterID	31
#ifdef WORDS_BIGENDIAN
#	define MaskEngineType		0x0000FF0000000000LL
#	define ShiftEngineType		40
#	define MaskEngineID			0x000000FF00000000LL
#	define ShiftEngineID		32

#else
#	define MaskEngineType		0x0000000000FF0000LL
#	define ShiftEngineType		16
#	define MaskEngineID			0x00000000FF000000LL
#	define ShiftEngineID		24
#endif

	// IPFIX extensions in v9
	// BGP next/prev AS
	uint32_t	bgpNextAdjacentAS;	// index 32 0xffff'ffff'0000'0000
	uint32_t	bgpPrevAdjacentAS;	// index 32 0x0000'0000'ffff'ffff

// extension 18
#	define OffsetBGPadj	32
#ifdef WORDS_BIGENDIAN
#	define MaskBGPadjNext		0xFFFFFFFF00000000LL
#	define ShiftBGPadjNext		32
#	define MaskBGPadjPrev		0x00000000FFFFFFFFLL
#	define ShiftBGPadjPrev		0

#else
#	define MaskBGPadjNext		0x00000000FFFFFFFFLL
#	define ShiftBGPadjNext		0
#	define MaskBGPadjPrev		0xFFFFFFFF00000000LL
#	define ShiftBGPadjPrev		32
#endif

	// NSEL extensions
#ifdef NSEL 
#define NSEL_BASE_OFFSET     (offsetof(master_record_t, conn_id) >> 3)

	// common block
#   define OffsetConnID  NSEL_BASE_OFFSET
#   define OffsetNATevent  NSEL_BASE_OFFSET
	uint32_t	conn_id;			// index OffsetConnID    0xffff'ffff'0000'0000
	uint8_t		event;				// index OffsetConnID    0x0000'0000'ff00'0000
#define FW_EVENT 1
#define NAT_EVENT 2
	uint8_t		event_flag;			// index OffsetConnID    0x0000'0000'00ff'0000
	uint16_t	fw_xevent;			// index OffsetConnID    0x0000'0000'0000'ffff
	uint64_t	event_time;			// index OffsetConnID +1 0x1111'1111'1111'1111
#ifdef WORDS_BIGENDIAN
#	define MaskConnID		0xFFFFFFFF00000000LL
#	define ShiftConnID		32
#	define MaskFWevent		0x00000000FF000000LL
#	define ShiftFWevent		24
#	define MasNATevent		0x00000000FF000000LL
#	define ShiftNATevent	24
#	define MaskFWXevent		0x000000000000FFFFLL
#	define ShiftFWXevent	0
#else
#	define MaskConnID		0x00000000FFFFFFFFLL
#	define ShiftConnID		0
#	define MaskFWevent		0x000000FF00000000LL
#	define ShiftFWevent		32
#	define MasNATevent		0x000000FF00000000LL
#	define ShiftNATevent	32
#	define MaskFWXevent		0xFFFF000000000000LL
#	define ShiftFWXevent	48

#endif

	// xlate ip/port
#   define OffsetXLATEPort NSEL_BASE_OFFSET+2
	uint16_t	xlate_src_port;		// index OffsetXLATEPort 0xffff'0000'0000'0000
	uint16_t	xlate_dst_port;		// index OffsetXLATEPort 0x0000'ffff'0000'0000
	uint32_t	xlate_flags;
#   define OffsetXLATESRCIP NSEL_BASE_OFFSET+3
	ip_addr_t	xlate_src_ip;		// ipv4  OffsetXLATESRCIP +1 0x0000'0000'ffff'ffff
									// ipv6	 OffsetXLATESRCIP 	 0xffff'ffff'ffff'ffff
									// ipv6	 OffsetXLATESRCIP	 0xffff'ffff'ffff'ffff

	ip_addr_t	xlate_dst_ip;		// ipv4  OffsetXLATEDSTIP +1 0x0000'0000'ffff'ffff
									// ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff
									// ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff
#ifdef WORDS_BIGENDIAN
#	define MaskXLATESRCPORT	 0xFFFF000000000000LL
#	define ShiftXLATESRCPORT 48
#	define MaskXLATEDSTPORT	 0x0000FFFF00000000LL
#	define ShiftXLATEDSTPORT 32

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0x00000000fFFFFFFFLL
#	define ShiftXLATEIPv4 	 0

#	define OffsetXLATESRCv6a OffsetXLATESRCIP
#	define OffsetXLATESRCv6b OffsetXLATESRCIP+1

#	define OffsetXLATEDSTv6a OffsetXLATESRCIP+2
#	define OffsetXLATEDSTv6b OffsetXLATESRCIP+3

#else
#	define MaskXLATESRCPORT	 0x000000000000FFFFLL
#	define ShiftXLATESRCPORT 0
#	define MaskXLATEDSTPORT	 0x00000000FFFF0000LL
#	define ShiftXLATEDSTPORT 16

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0xFFFFFFFF00000000LL
#	define ShiftXLATEIPv4 	 32

#	define OffsetXLATESRCv6a OffsetXLATESRCIP
#	define OffsetXLATESRCv6b OffsetXLATESRCIP+1

#	define OffsetXLATEDSTv6a OffsetXLATESRCIP+2
#	define OffsetXLATEDSTv6b OffsetXLATESRCIP+3

#endif


	// ingress/egress ACL id
#   define OffsetIngressAclId NSEL_BASE_OFFSET+7
#	define OffsetIngressAceId NSEL_BASE_OFFSET+7
#	define OffsetIngressGrpId NSEL_BASE_OFFSET+8
#	define OffsetEgressAclId  NSEL_BASE_OFFSET+8
#	define OffsetEgressAceId  NSEL_BASE_OFFSET+9
#	define OffsetEgressGrpId  NSEL_BASE_OFFSET+9
	uint32_t ingress_acl_id[3];	// index OffsetIngressAclId   0xffff'ffff'0000'0000
								// index OffsetIngressAceId   0x0000'0000'ffff'ffff
								// index OffsetIngressGrpId   0xffff'ffff'0000'0000
	uint32_t egress_acl_id[3];	// index OffsetEgressAclId	  0x0000'0000'ffff'ffff
								// index OffsetEgressAceId	  0xffff'ffff'0000'0000
								// index OffsetEgressGrpId	  0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#define MaskIngressAclId	0xffffffff00000000LL
#define ShiftIngressAclId	32
#define MaskIngressAceId	0x00000000ffffffffLL
#define ShiftIngressAceId	0
#define MaskIngressGrpId	0xffffffff00000000LL
#define ShiftIngressGrpId	32
#define MaskEgressAclId		0x00000000ffffffffLL
#define ShiftEgressAclId	0
#define MaskEgressAceId		0xffffffff00000000LL
#define ShiftEgressAceId	32
#define MaskEgressGrpId		0x00000000ffffffffLL
#define ShiftEgressGrpId	0
#else
#define MaskIngressAclId	0x00000000ffffffffLL
#define ShiftIngressAclId	0
#define MaskIngressAceId	0xffffffff00000000LL
#define ShiftIngressAceId	32
#define MaskIngressGrpId	0x00000000ffffffffLL
#define ShiftIngressGrpId	0
#define MaskEgressAclId		0xffffffff00000000LL
#define ShiftEgressAclId	32
#define MaskEgressAceId		0x00000000ffffffffLL
#define ShiftEgressAceId	0
#define MaskEgressGrpId		0xffffffff00000000LL
#define ShiftEgressGrpId	32
#endif

	// username
#	define OffsetUsername  NSEL_BASE_OFFSET+10
	char username[72];

	// NAT extensions
	// NAT event is mapped into ASA event
#define NAT_BASE_OFFSET     (offsetof(master_record_t, ingress_vrfid) >> 3)
	// common block
#   define OffsetNELcommon  NEL_BASE_OFFSET
#   define OffsetIVRFID  	NAT_BASE_OFFSET
#   define OffsetEVRFID  	NAT_BASE_OFFSET
#   define OffsetPortBlock	NAT_BASE_OFFSET+1
	uint32_t	ingress_vrfid;	// OffsetIVRFID	   0xffff'ffff'0000'0000
	uint32_t	egress_vrfid;	// OffsetEVRFID	   0x0000'0000'ffff'ffff

	// Port block allocation
	uint16_t	block_start;	// OffsetPortBlock 0xffff'0000'0000'0000
	uint16_t	block_end;		// OffsetPortBlock 0x0000'ffff'0000'0000
	uint16_t	block_step;		// OffsetPortBlock 0x0000'0000'ffff'0000
	uint16_t	block_size;		// OffsetPortBlock 0x0000'0000'0000'ffff

#ifdef WORDS_BIGENDIAN
#	define MaskIVRFID			0xFFFFFFFF00000000LL
#	define ShiftIVRFID			32
#	define MaskEVRFID			0x00000000FFFFFFFFLL
#	define ShiftEVRFID			0
#	define MaskPortBlockStart	0xFFFF000000000000LL
#	define ShiftPortBlockStart	48
#	define MaskPortBlockEnd		0x0000FFFF00000000LL
#	define ShiftPortBlockEnd	32
#	define MaskPortBlockStep	0x00000000FFFF0000LL
#	define ShiftPortBlockStep	16
#	define MaskPortBlockSize	0x000000000000FFFFLL
#	define ShiftPortBlockSize	0
#else
#	define MaskIVRFID			0x00000000FFFFFFFFLL
#	define ShiftIVRFID			0
#	define MaskEVRFID			0xFFFFFFFF00000000LL
#	define ShiftEVRFID			32
#	define MaskPortBlockStart	0x000000000000FFFFLL
#	define ShiftPortBlockStart	0
#	define MaskPortBlockEnd		0x00000000FFFF0000LL
#	define ShiftPortBlockEnd	16
#	define MaskPortBlockStep	0x0000FFFF00000000LL
#	define ShiftPortBlockStep	32
#	define MaskPortBlockSize	0xFFFF000000000000LL
#	define ShiftPortBlockSize	48
#endif

#endif

	// nprobe extensions
	// latency extension
	uint64_t	client_nw_delay_usec;	// index LATENCY_BASE_OFFSET 0xffff'ffff'ffff'ffff
	uint64_t	server_nw_delay_usec;	// index LATENCY_BASE_OFFSET + 1 0xffff'ffff'ffff'ffff
	uint64_t	appl_latency_usec;		// index LATENCY_BASE_OFFSET + 2 0xffff'ffff'ffff'ffff

#define LATENCY_BASE_OFFSET     (offsetof(master_record_t, client_nw_delay_usec) >> 3)
#   define OffsetClientLatency  LATENCY_BASE_OFFSET
#   define OffsetServerLatency  LATENCY_BASE_OFFSET + 1
#   define OffsetAppLatency     LATENCY_BASE_OFFSET + 2
#   define MaskLatency          0xFFFFFFFFFFFFFFFFLL
#   define ShiftLatency         0

	// flow received time in ms
	uint64_t	received;

/* possible user extensions may fit here
 * - Put each extension into its own #ifdef
 * - Define the base offset for the user extension as reference to the first object
 * - Refer to this base offset for each of the values in the master record for the extension
 * - make sure the extension is 64bit aligned
 * - The user extension must be independant of the number of user extensions already defined
 * - the extension map must be updated accordingly
 */

#ifdef USER_EXTENSION_1
	uint64_t	u64_1;
#	define Offset_BASE_U1	offsetof(master_record_t, u64_1)
#	define OffsetUser1_u64	Offset_BASE_U1
	
	uint32_t	u32_1;
	uint32_t	u32_2;
#	define OffsetUser1_u32_1	Offset_BASE_U1 + 8
#	define MaskUser1_u32_1 		0xffffffff00000000LL
#	define MaskUser1_u32_2 		0x00000000ffffffffLL

#endif

	// reference to exporter
	exporter_info_record_t	*exp_ref;

	// last entry in master record 
#	define Offset_MR_LAST	offsetof(master_record_t, map_ref)
	extension_map_t	*map_ref;
} master_record_t;

#define AnyMask  	0xffffffffffffffffLL


// convenience type conversion record 
typedef struct type_mask_s {
	union {
		uint8_t		val8[8];
		uint16_t	val16[4];
		uint32_t	val32[2];
		uint64_t	val64;
	} val;
} type_mask_t;

/*
 * offset translation table
 * In netflow v9 values may have a different length, and may or may not be present.
 * The commmon information ( see data_block_record_t ) is expected to be present
 * unconditionally, and has a fixed size. IP addrs as well as counters for packets and
 * bytes are expexted to exist as well, but may be variable in size. Further information
 * may or may not be present, according the flags. See flags
 * To cope with this situation, the offset translation table gives the offset into an
 * uint32_t array at which offset the requested value start.
 *
 * index:
 *	 0:	dstip
 *				for IPv4 netflow v5/v7	10
 *	 1: dPkts
 * 				for IPv4 netflow v5/v7	11
 *	 2: dOctets
 * 				for IPv4 netflow v5/v7	12
 */

/*
 * exporter records
 */

#ifdef COMPAT15
/*
 * Data block type 1 compatibility
 */
 
typedef struct common_record_v1_s {
    // the head of each data record
    uint32_t    flags;
    uint16_t    size;
    uint16_t    exporter_ref;
    uint16_t    msec_first;
    uint16_t    msec_last;
    uint32_t    first;
    uint32_t    last;

    uint8_t     dir;
    uint8_t     tcp_flags;
    uint8_t     prot;
    uint8_t     tos;
    uint16_t    input;
    uint16_t    output;
    uint16_t    srcport;
    uint16_t    dstport;
    uint16_t    srcas;
    uint16_t    dstas;
    uint8_t     data[4];    // .. more data below
} common_record_v1_t;

#endif


// a few handy shortcuts
#define FILE_IS_COMPRESSED(n) ((n)->file_header->flags & FLAG_COMPRESSED)
#define BLOCK_IS_COMPRESSED(n) ((n)->flags == 2 )
#define HAS_CATALOG(n) ((n)->file_header->flags & FLAG_CATALOG)
#define IP_ANONYMIZED(n) ((n)->file_header->flags & FLAG_ANONYMIZED)

void SumStatRecords(stat_record_t *s1, stat_record_t *s2);

nffile_t *OpenFile(char *filename, nffile_t *nffile);

nffile_t *OpenNewFile(char *filename, nffile_t *nffile, int compressed, int anonymized, char *ident);

nffile_t *AppendFile(char *filename);

int ChangeIdent(char *filename, char *Ident);

void PrintStat(stat_record_t *s);

void QueryFile(char *filename);

stat_record_t *GetStatRecord(char *filename, stat_record_t *stat_record);

nffile_t *DisposeFile(nffile_t *nffile);

void CloseFile(nffile_t *nffile);

int CloseUpdateFile(nffile_t *nffile, char *ident);

int ReadBlock(nffile_t *nffile);

int WriteBlock(nffile_t *nffile);

int WriteExtraBlock(nffile_t *nffile, data_block_header_t *block_header);

int RenameAppend(char *from, char *to);

void UnCompressFile(char * filename);

void ExpandRecord_v1(common_record_t *input_record,master_record_t *output_record );

#ifdef COMPAT15
void Convert_v1_to_v2(void *mem);
#endif

#endif //_NFFILE_H

