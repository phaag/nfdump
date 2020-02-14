/*
 *  Copyright (c) 2020, Peter Haag
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
 */

#ifndef _NFFILEV2_H
#define _NFFILEV2_H 1

#include "config.h"

#include <stddef.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/*
 * nfdump binary file layout 2
 * ===========================
 * Each data file starts with a file header, which identifies the file as an nfdump data file.
 * The magic 16bit integer at the beginning of each file must read 0xA50C. This also guarantees 
 * that endian dependant files are read correct.
 *
 * Principal layout, recognized as LAYOUT_VERSION_2:
 *
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 *   |Fileheader | datablock 0 | datablock 1 | datablock 2 | ... | datablock n |
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 */


typedef struct fileHeaderV2_s {
	uint16_t	magic;				// magic to recognize nfdump file type and endian type
#define MAGIC 0xA50C

	uint16_t	version;			// version of binary file layout
#define LAYOUT_VERSION_2	2

	uint32_t	nfversion;			// version of nfdump created this file
									// 4bytes 1.6.19-1 0x01061301 
	time_t		created;			// file create time

	uint8_t		compression;
#define NOT_COMPRESSED 0
#define LZO_COMPRESSED 1
#define BZ2_COMPRESSED 2
#define LZ4_COMPRESSED 3
	uint8_t		encryption;
	uint16_t	flags;
	uint32_t	unused;				// unused 0	- reserved for futur use
	uint64_t	unused2;			// unused 0 - reserved for futur use

	uint32_t	BlockSize;			// max block size of data blocks
	uint32_t	NumBlocks;			// number of data blocks in file
} fileHeaderV2_t;


/*
 *
 * Generic data block
 * ==================
 * Data blocks are generic containers for the any type of data records.
 * Each data block starts with a block header, which specifies the size, the number of records
 * and data block properties. The struct is compatible with type 2 data records
 */

typedef struct dataBlock_s {
	uint32_t	NumRecords;		// number of data records in data block
	uint32_t	size;			// size of this block in bytes without this header
	uint16_t	id;				// Block ID == DATA_BLOCK_TYPE_3
#define DATA_BLOCK_TYPE_3 3
	uint16_t	flags;
#define FLAG_BLOCK_COMPRESSED 1
// Bit 0 - 0: uncompressed data, 1: compressed data
} dataBlock_t;

/*
 * Generic data record
 * Contains any type of data, specified by type
 */
typedef struct recordHeader_s {
 	// record header
 	uint16_t	type;
 	uint16_t	size;
} recordHeader_t;


#endif //_NFFILEV2_H

