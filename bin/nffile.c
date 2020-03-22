/*
 *  Copyright (c) 2009-2020, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <bzlib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "minilzo.h"
#include "lz4.h"
#include "flist.h"
#include "nffile.h"
#include "nffileV2.h"

/* global vars */

// LZO params
#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);
static int lzo_initialized = 0;
static int lz4_initialized = 0;
static int bz2_initialized = 0;

static int LZO_initialize(void);

static int LZ4_initialize(void);

static int BZ2_initialize(void);

static void BZ2_prep_stream (bz_stream*);

static int Compress_Block_LZO(nffile_t *nffile);

static int Uncompress_Block_LZO(nffile_t *nffile);

static int Compress_Block_LZ4(nffile_t *nffile);

static int Uncompress_Block_LZ4(nffile_t *nffile);

static int Compress_Block_BZ2(nffile_t *nffile);

static int Uncompress_Block_BZ2(nffile_t *nffile);

static int ReadAppendix(nffile_t *nffile);

static int WriteAppendix(nffile_t *nffile);

static nffile_t *NewFile(nffile_t *nffile);

static int QueryFileV1(int fd, fileHeaderV2_t *fileHeaderV2);

extern char *nf_error;

/* function prototypes */
static nffile_t *NewFile(nffile_t *nffile);

/* function definitions */

static int LZO_initialize(void) {

	if (lzo_init() != LZO_E_OK) {
		// this usually indicates a compiler bug - try recompiling 
		// without optimizations, and enable `-DLZO_DEBUG' for diagnostics
		LogError("Compression lzo_init() failed.");
		return 0;
	} 
	lzo_initialized = 1;

	return 1;

} // End of LZO_initialize

static int LZ4_initialize (void) {

	int lz4_buff_size = LZ4_compressBound(BUFFSIZE + sizeof (dataBlock_t));
	if ( lz4_buff_size > (2 * BUFFSIZE) ) {
		LogError ("LZ4_compressBound() error in %s line %d: Buffer too small", __FILE__, __LINE__);
		return 0;
	}
	lz4_initialized = 1;

	return 1;

} // End of LZ4_initialize

static int BZ2_initialize (void) {

	bz2_initialized = 1;

	return 1;

} // End of BZ2_initialize

static void BZ2_prep_stream (bz_stream* bs)
{
   bs->bzalloc = NULL;
   bs->bzfree = NULL;
   bs->opaque = NULL;
} // End of BZ2_prep_stream

static int Compress_Block_LZO(nffile_t *nffile) {
unsigned char __LZO_MMODEL *in;
unsigned char __LZO_MMODEL *out;
lzo_uint in_len;
lzo_uint out_len;
int r;

	in  = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[0] + sizeof(dataBlock_t));	
	out = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[1] + sizeof(dataBlock_t));	
	in_len = nffile->block_header->size;
	r = lzo1x_1_compress(in,in_len,out,&out_len,wrkmem);

	if (r != LZO_E_OK) {
		LogError("Compress_Block_LZO() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, r);
		return -1;
	}
	
	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];

	return 1;

} // End of Compress_Block_LZO

static int Uncompress_Block_LZO(nffile_t *nffile) {
unsigned char __LZO_MMODEL *in;
unsigned char __LZO_MMODEL *out;
lzo_uint in_len;
lzo_uint out_len;
int r;

	in  = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[0] + sizeof(dataBlock_t));	
	out = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[1] + sizeof(dataBlock_t));	
	in_len  = nffile->block_header->size;
	out_len = nffile->buff_size;

	if ( in_len == 0 ) {
		LogError("Uncompress_Block_LZO() header length error in %s line %d", __FILE__, __LINE__);
   		return -1;
	}
	r = lzo1x_decompress_safe(in,in_len,out,&out_len,NULL);
	if (r != LZO_E_OK ) {
		LogError("Uncompress_Block_LZO() error decompression failed in %s line %d: LZO error: %d", __FILE__, __LINE__, r);
   		return -1;
	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(dataBlock_t);

	return 1;

} // End of Uncompress_Block_LZO

static int Compress_Block_LZ4(nffile_t *nffile) {

	const char *in  = (const char *)(nffile->buff_pool[0] + sizeof(dataBlock_t));
	char *out 		= (char *)(nffile->buff_pool[1] + sizeof(dataBlock_t));
	int in_len 		= nffile->block_header->size;

	int out_len = LZ4_compress_default(in, out, in_len, nffile->buff_size);
	if (out_len == 0 ) {
		LogError("Compress_Block_LZ4() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
   		return -1;
   	}
   	if (out_len < 0 ) {
		LogError("Compress_Block_LZ4() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, out_len);
   		return -1;
   	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];

	return 1;

} // End of Compress_Block_LZ4

static int Uncompress_Block_LZ4(nffile_t *nffile) {

	const char *in  = (const char *)(nffile->buff_pool[0] + sizeof(dataBlock_t));
	char *out 		= (char *)(nffile->buff_pool[1] + sizeof(dataBlock_t));
	int in_len 		= nffile->block_header->size;

	int out_len = LZ4_decompress_safe(in, out, in_len, nffile->buff_size);
	if (out_len == 0 ) {
		LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
   		return -1;
   	}
   	if (out_len < 0 ) {
		LogError("LZ4_decompress_safe() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, out_len);
   		return -1;
   	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(dataBlock_t);

	return 1;

} // End of Uncompress_Block_LZ4

static int Compress_Block_BZ2(nffile_t *nffile) {
bz_stream bs;

	BZ2_prep_stream (&bs);
	BZ2_bzCompressInit (&bs, 9, 0, 0);

	bs.next_in   = (char*)(nffile->buff_pool[0] + sizeof(dataBlock_t));
	bs.next_out  = (char*)(nffile->buff_pool[1] + sizeof(dataBlock_t));
	bs.avail_in  = nffile->block_header->size;
	bs.avail_out = nffile->buff_size;
 
	for (;;) {
		int r = BZ2_bzCompress (&bs, BZ_FINISH);
		if (r == BZ_FINISH_OK) continue;
		if (r != BZ_STREAM_END) {
			LogError("Compress_Block_BZ2() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, r);
			return -1;
		}
		break;
	}

 	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = bs.total_out_lo32;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];

	BZ2_bzCompressEnd (&bs);
	
	return 1;

} // End of Compress_Block_BZ2

static int Uncompress_Block_BZ2(nffile_t *nffile) {
bz_stream bs;

	BZ2_prep_stream (&bs);
	BZ2_bzDecompressInit (&bs, 0, 0);

	bs.next_in   = (char*)(nffile->buff_pool[0] + sizeof(dataBlock_t));
	bs.next_out  = (char*)(nffile->buff_pool[1] + sizeof(dataBlock_t));
	bs.avail_in  = nffile->block_header->size;
	bs.avail_out = nffile->buff_size;
 
	for (;;) {
		int r = BZ2_bzDecompress (&bs);
		if (r == BZ_OK) {
			continue;
		} else if (r != BZ_STREAM_END) {
			BZ2_bzDecompressEnd (&bs);
			return NF_CORRUPT;
		} else {
			break;
		}
	}

 	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(dataBlock_t));
	((dataBlock_t *)nffile->buff_pool[1])->size = bs.total_out_lo32;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(dataBlock_t);

	BZ2_bzDecompressEnd (&bs);
	
	return 1;

} // End of Uncompress_Block_BZ2

static int ReadAppendix(nffile_t *nffile) {

	dbg_printf("Process appendix ..\n");
	off_t currentPos = lseek(nffile->fd, 0, SEEK_CUR);
	if ( currentPos < 0 ) {
		LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}

	// seek to Appendix
	if ( lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0 ) {
		LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}

	dbg_printf("Num of appendix records: %u\n", nffile->file_header->appendixBlocks);
	for (int i=0; i<nffile->file_header->appendixBlocks; i++ ) {
		size_t processed = 0;
		int ret = ReadBlock(nffile);
		if ( ret <= 0 ) {
			LogError("Unable to read appendix block");
			lseek(nffile->fd, currentPos, SEEK_SET);
			return 0;
		}

		for (int j=0; j<nffile->block_header->NumRecords; j++ ) {
			record_header_t *record_header = (record_header_t *)nffile->buff_ptr;
			void *data = (void *)record_header + sizeof(record_header_t);
			uint16_t dataSize = record_header->size - sizeof(record_header_t);
			dbg_printf("appendix record: %u - type: %u, size: %u\n", j, record_header->type, record_header->size);
			switch (record_header->type) {
				case TYPE_IDENT:
					dbg_printf("Read ident from appendix block\n");
					if ( nffile->ident) 
						free(nffile->ident);
					if ( record_header->size < IDENTLEN ) {
						nffile->ident = strdup(data);
					} else {
						LogError("Error processing appendix ident record");
					}
					break;
				case TYPE_STAT:
					dbg_printf("Read stat record from appendix block\n");
					if ( dataSize == sizeof(stat_record_t) ) {
						memcpy(nffile->stat_record, data, sizeof(stat_record_t));
					} else {
						LogError("Error processing appendix stat record");
					}
					break;
				default:
					LogError("Error process appendix record type: %u", record_header->type);
			}
			processed += record_header->size;
			nffile->buff_ptr += record_header->size;
			if ( processed > nffile->block_header->size ) {
				LogError("Error processing appendix records: processed %u > block size %u", 
					processed, nffile->block_header->size);
				return 0;
			}
		}
	}

	// seek back to currentPos
	off_t backPosition = lseek(nffile->fd, currentPos, SEEK_SET);
	dbg_printf("Reset position to %llu -> %llu\n", currentPos, backPosition);
	if ( backPosition < 0 ) {
		LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}
	return 1;

} // End of ReadAppendix

// Write appendix - assume current file pos is end of data blocks
static int WriteAppendix(nffile_t *nffile) {

	// add appendix to end of data
	off_t currentPos = lseek(nffile->fd, 0, SEEK_CUR);
	if ( currentPos < 0 ) {
		LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return 0;
	}

	// set appendx info
	nffile->file_header->offAppendix = currentPos;
	nffile->file_header->appendixBlocks = 1;

	// make sure ident is set
	if ( nffile->ident == NULL ) 
		nffile->ident = strdup("none");

	// write ident
	recordHeader_t *recordHeader = (recordHeader_t *)nffile->buff_ptr;
	void *data = (void *)recordHeader + sizeof(recordHeader_t);

	recordHeader->type = TYPE_IDENT;
	recordHeader->size = sizeof(recordHeader_t) + strlen(nffile->ident) + 1;
	strcpy(data, nffile->ident);

	nffile->block_header->NumRecords++;
	nffile->block_header->size += recordHeader->size;
	nffile->buff_ptr += recordHeader->size;

	// write stat record
	recordHeader = (recordHeader_t *)nffile->buff_ptr;
	data = (void *)recordHeader + sizeof(recordHeader_t);

	recordHeader->type = TYPE_STAT;
	recordHeader->size = sizeof(recordHeader_t) + sizeof(stat_record_t);
	memcpy(data, nffile->stat_record, sizeof(stat_record_t));

	nffile->block_header->NumRecords++;
	nffile->block_header->size += recordHeader->size;
	nffile->buff_ptr += recordHeader->size;

	// flush appendix
	if ( !FlushFile(nffile) ) 
		return 0;

	return 1;

} // End of WriteAppendix

static nffile_t *NewFile(nffile_t *nffile) {
int i;

	// Create struct
	if ( !nffile ) {
		nffile = calloc(1, sizeof(nffile_t));
		if ( !nffile ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}

		// Init file header
		nffile->file_header = calloc(1, sizeof(fileHeaderV2_t));
		if ( !nffile->file_header ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}

		nffile->stat_record = calloc(1, sizeof(stat_record_t));
		if ( !nffile->stat_record ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}

		// init data buffer
		nffile->buff_size = 2 * BUFFSIZE;
		for (i=0; i<NUM_BUFFS; i++ ) {
			// allocate twice of BUFFSIZE initially - should be ok, otherwise expand
			nffile->buff_pool[i] = malloc(nffile->buff_size);
			if ( !nffile->buff_pool[i] ) {
				LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				return NULL;
			}
		}
	}

	memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
	nffile->file_header->magic 	   = MAGIC;
	nffile->file_header->version   = LAYOUT_VERSION_2;

	nffile->buff_ptr = NULL;
	nffile->fd	 	 = 0;
	if ( nffile->fileName ) {
		free(nffile->fileName);
		nffile->fileName = NULL;
	}
	if ( nffile->ident ) {
		free(nffile->ident);
		nffile->ident = NULL;
	}
	memset((void *)nffile->stat_record, 0, sizeof(stat_record_t));
	nffile->stat_record->first_seen = 0x7fffffff;
	nffile->stat_record->msec_first = 999;

	nffile->block_header 			 = nffile->buff_pool[0];
	nffile->block_header->NumRecords = 0;
	nffile->block_header->size 		 = 0;
	nffile->block_header->flags 	 = 0;
	nffile->block_header->type		 = DATA_BLOCK_TYPE_3;

	// reset read/write pointer
	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
	
	return nffile;

} // End of NewFile

nffile_t *OpenFile(char *filename, nffile_t *nffile){
struct stat stat_buf;
int ret, fd;

	if ( filename == NULL ) {
		return NULL;
	} else {
		// regular file
		if ( stat(filename, &stat_buf) ) {
			LogError("stat() '%s': %s", filename, strerror(errno));
			return NULL;
		}

		if (!S_ISREG(stat_buf.st_mode) ) {
			LogError("'%s' is not a file", filename);
			return NULL;
		}

		fd = open(filename, O_RDONLY);
		if ( fd < 0 ) {
			LogError("Error open file: %s", strerror(errno));
			return NULL;
		}

	}

	// initialise and/or allocate new nffile handle
	nffile = NewFile(nffile);
	if ( nffile == NULL ) {
		return NULL;
	}
	nffile->fd = fd;
	nffile->blockCount = 0;
	if ( filename )
		nffile->fileName = strdup(filename);

	// assume file layout V2
	ret = read(nffile->fd, (void *)nffile->file_header, sizeof(fileHeaderV2_t));
	if ( ret < 1 ) {
		LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		CloseFile(nffile);
		return NULL;
	}

	if ( ret != sizeof(fileHeaderV2_t) ) {
		LogError("Short read from file: %s", filename);
		CloseFile(nffile);
		return NULL;
	}

	if ( nffile->file_header->magic != MAGIC ) {
		LogError("Open file '%s': bad magic: 0x%X", filename ? filename : "<stdin>", nffile->file_header->magic );
		CloseFile(nffile);
		return NULL;
	}

	if ( nffile->file_header->version != LAYOUT_VERSION_2 ) {
		if ( nffile->file_header->version == LAYOUT_VERSION_1 ) {
			dbg_printf("Found layout type 1 => convert\n");
			// transparent read old v1 layout
			// convert old layout
			fileHeaderV1_t fileHeaderV1;

			// re-read file header - assume layout V1
			if ( lseek(nffile->fd, 0, SEEK_SET) < 0 ) {
				LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				CloseFile(nffile);
				return NULL;
			}

			ret = read(nffile->fd, (void *)&fileHeaderV1, sizeof(fileHeaderV1_t));
			if ( ret < 1 ) {
				LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				CloseFile(nffile);
				return NULL;
			}
		
			if ( ret != sizeof(fileHeaderV1_t) ) {
				LogError("Short read from file: %s", filename);
				CloseFile(nffile);
				return NULL;
			}

			if ( fileHeaderV1.version != LAYOUT_VERSION_1 ) {
				LogError("Open file %s: bad version: %u", filename, fileHeaderV1.version);
				CloseFile(nffile);
				return NULL;
			}

			// initialize V2 header
			memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
			nffile->file_header->magic		 = MAGIC;
			nffile->file_header->version	 = LAYOUT_VERSION_2;
			nffile->file_header->nfversion	 = NFVERSION;
			nffile->file_header->created	 = stat_buf.st_mtimespec.tv_sec; // best we can guess
			nffile->file_header->compression = FILEV1_COMPRESSION(&fileHeaderV1);
			nffile->file_header->encryption  = NOT_ENCRYPTED;
			nffile->file_header->NumBlocks	 = fileHeaderV1.NumBlocks;
			if ( strlen(fileHeaderV1.ident) > 0 )
				nffile->ident = strdup(fileHeaderV1.ident);

			// read v1 stat record
			ret = read(nffile->fd, (void *)nffile->stat_record, sizeof(stat_record_t));
			if ( ret < 0 ) {
				LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				CloseFile(nffile);
				return NULL;
			}

		} else {
			LogError("Open file %s: bad version: %u", filename, nffile->file_header->version );
			CloseFile(nffile);
			return NULL;
		}
	}

	if ( nffile->file_header->NumBlocks == 0 ) {
		LogError("Open file: Unclean closed file. Repair first");
		CloseFile(nffile);
		return NULL;
	}

	if ( FILE_ENCRYPTION(nffile) ) {
		LogError("Open file %s: Can not handle encrypted files", filename);
		CloseFile(nffile);
		return NULL;
	}

	switch (FILE_COMPRESSION(nffile)) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED: 
			if ( !lzo_initialized && !LZO_initialize() ) {
				return NULL;
			}
			break;
		case LZ4_COMPRESSED: 
			if ( !lz4_initialized && !LZ4_initialize() ) {
				return NULL;
			}
			break;
		case BZ2_COMPRESSED: 
			if ( !bz2_initialized && !BZ2_initialize() ) {
				return NULL;
			}
			break;
	}

	if (nffile->file_header->appendixBlocks) {
		if ( nffile->file_header->offAppendix < stat_buf.st_size ) {
			ReadAppendix(nffile);
		} else {
			LogError("Open file %s: appendix offset error", filename);
			CloseFile(nffile);
			return NULL;
		}
	}
	return nffile;

} // End of OpenFile

nffile_t *OpenNewFile(char *filename, nffile_t *nffile, int compress, int encryption) {
size_t			len;
int 			fd;

	switch (compress) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED:
			if ( !lzo_initialized && !LZO_initialize() ) {
				LogError("Failed to initialize LZO compression");
				return NULL;
			}
			break;
		case LZ4_COMPRESSED:
			if ( !lz4_initialized && !LZ4_initialize() ) {
				LogError("Failed to initialize LZ4 compression");
				return NULL;
			}
			break;
		case BZ2_COMPRESSED:
			if ( !bz2_initialized && !BZ2_initialize() ) {
				LogError("Failed to initialize BZ2 compression");
				return NULL;
			}
			break;
		default:
			LogError("Unknown compression ID: %i", compress);
			return NULL;
	}

	if ( encryption != NOT_ENCRYPTED ) {
		LogError("Unknown encryption ID: %i", encryption);
		return NULL;
	}

	fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( fd < 0 ) {
		LogError("Failed to open file %s: '%s'" , filename, strerror(errno));
		return NULL;
	}

	// Allocate/Init nffile struct
	nffile = NewFile(nffile);
	if ( nffile == NULL ) {
		return NULL;
	}
	nffile->fd = fd;
	nffile->fileName = strdup(filename);

	memset((void *)nffile->file_header, 0, sizeof(fileHeaderV2_t));
	nffile->file_header->magic		 = MAGIC;
	nffile->file_header->version	 = LAYOUT_VERSION_2;
	nffile->file_header->nfversion	 = NFVERSION;
	nffile->file_header->created	 = time(NULL);
	nffile->file_header->compression = compress;
	nffile->file_header->encryption  = encryption;

	len = sizeof(fileHeaderV2_t);
	if ( write(nffile->fd, (void *)nffile->file_header, len) < len ) {
		LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		close(nffile->fd);
		nffile->fd = 0;
		return NULL;
	}

	return nffile;

} /* End of OpenNewFile */

nffile_t *AppendFile(char *filename) {
nffile_t		*nffile;

	// try to open the existing file
	nffile = OpenFile(filename, NULL);
	if ( !nffile )
		return NULL;

	switch (nffile->file_header->compression) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED: 
			if ( !lzo_initialized && !LZO_initialize() ) {
				LogError("Failed to initialize LZO compression");
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case LZ4_COMPRESSED: 
			if ( !lz4_initialized && !LZ4_initialize() ) {
				LogError("Failed to initialize LZ4 compression");
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case BZ2_COMPRESSED: 
			if ( !bz2_initialized && !BZ2_initialize() ) {
				LogError("Failed to initialize BZ2 compression");
				DisposeFile(nffile);
				return NULL;
			}
			break;
	}

	// file is valid - re-open the file mode RDWR
	close(nffile->fd);
	nffile->fd = open(filename, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if ( nffile->fd < 0 ) {
		LogError("Failed to open file (rw) %s: '%s'" , filename, strerror(errno));
		DisposeFile(nffile);
		return NULL;
	}

	if ( nffile->file_header->offAppendix ) {
		// seek to  end of data blocks
		if ( lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0 ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			DisposeFile(nffile);
			return NULL;
		}
	} else {
		// if no appendix
		if ( lseek(nffile->fd, 0, SEEK_END) < 0 ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			DisposeFile(nffile);
			return NULL;
		}
	}
	return nffile;

} /* End of AppendFile */

int FlushFile(nffile_t *nffile) {

	if ( nffile->block_header->size ) {
		int ret = WriteBlock(nffile);
		if ( ret < 0 ) {
			LogError("Failed to flush output buffer");
			return 0;
		}
	}
	return 1;

} // End of FlushFile

void CloseFile(nffile_t *nffile){

	if ( !nffile ) 
		return;

	// do not close stdout
	if ( nffile->fd ) {
		close(nffile->fd);
		nffile->fd = 0;
	}

	if ( nffile->fileName ) {
		free(nffile->fileName);
		nffile->fileName = NULL;
	}

	if ( nffile->ident ) {
		free(nffile->ident);
		nffile->ident = NULL;
	}

	nffile->file_header->NumBlocks = 0;

} // End of CloseFile

int CloseUpdateFile(nffile_t *nffile) {

	if ( !FlushFile(nffile) ) 
		return 0;

	if ( !WriteAppendix(nffile) ) {
		LogError("Failed to write appendix");
	}

	if ( lseek(nffile->fd, 0, SEEK_SET) < 0 ) {
		// lseek on stdout works if output redirected:
		// e.g. -w - > outfile
		// but fails on pipe e.g. -w - | ./nfdump .... 
		if ( nffile->fd != STDOUT_FILENO ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			close(nffile->fd);
			return 0;
		}
	}

	// NumBlock are plain data block - subtract appendix blocks
	nffile->file_header->NumBlocks -= nffile->file_header->appendixBlocks;

	if ( write(nffile->fd, (void *)nffile->file_header, sizeof(fileHeaderV2_t)) <= 0 ) {
		LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
	}

	CloseFile(nffile);

	return 1;

} /* End of CloseUpdateFile */

void DisposeFile(nffile_t *nffile) {
int i;

	if ( nffile->fd > 0 )
		CloseFile(nffile);
	if ( nffile->file_header ) free(nffile->file_header);
	if ( nffile->stat_record ) free(nffile->stat_record);
	if ( nffile->ident ) 	   free(nffile->ident);
	if ( nffile->fileName )    free(nffile->fileName);

	for (i=0; i<NUM_BUFFS; i++ ) {
		free(nffile->buff_pool[i]);
	}

	free(nffile);

} // End of DisposeFile

int ReadBlock(nffile_t *nffile) {
ssize_t ret, read_bytes;
uint32_t compression;

	if ( nffile->blockCount == (nffile->file_header->NumBlocks + nffile->file_header->appendixBlocks ))
		return NF_EOF;

	ret = read(nffile->fd, nffile->block_header, sizeof(dataBlock_t));
	if ( ret == 0 )		// EOF
		return NF_EOF;
		
	if ( ret == -1 )	// ERROR
		return NF_ERROR;
		
	// Check for sane buffer size
	if ( ret != sizeof(dataBlock_t) ) {
		// this is most likely a corrupt file
		LogError("Corrupt data file: Read %i bytes, requested %u", ret, sizeof(dataBlock_t));
		return NF_CORRUPT;
	}

	// block header read successfully
	read_bytes = ret;

	dbg_printf("ReadBlock - type: %u, size: %u, numRecords: %u, flags: %u\n", 
		nffile->block_header->type, nffile->block_header->size, 
		nffile->block_header->NumRecords, nffile->block_header->flags);
	// Check for sane buffer size
	if ( nffile->block_header->size > BUFFSIZE ||
	     nffile->block_header->size == 0 || nffile->block_header->NumRecords == 0) {
		// this is most likely a corrupt file
		LogError("Corrupt data file: Requested buffer size %u exceeds max. buffer size", nffile->block_header->size);
		return NF_CORRUPT;
	}

	// check block compression - defaults to file compression setting

	compression = nffile->file_header->compression;
	dbg_printf("ReadBlock - compression: %u\n", nffile->file_header->compression);
	// v1.6.x DATA_BLOCK_TYPE_2 do not honor flags
	// process only data block types 2 and 3
	if ( nffile->block_header->type == DATA_BLOCK_TYPE_3 ) {
		if ( TestFlag(nffile->block_header->flags, FLAG_BLOCK_UNCOMPRESSED) ) {
			compression = NOT_COMPRESSED;
			dbg_printf("ReadBlock - overwrite file compression. Block is uncompressed\n");
		}
	} else if ( nffile->block_header->type != DATA_BLOCK_TYPE_2 ) {
		LogError("ReadBlock() Unexpected block type %u", nffile->block_header->type);
		return NF_CORRUPT;
	}

	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
	dbg_printf("ReadBlock - read: %u\n", nffile->block_header->size);
	ret = read(nffile->fd, nffile->buff_ptr, nffile->block_header->size);
	if ( ret == nffile->block_header->size ) {
		nffile->blockCount++;
		// we have the whole record and are done for now
		switch (compression) {
			case NOT_COMPRESSED:
				break;
			case LZO_COMPRESSED: 
				if ( Uncompress_Block_LZO(nffile) < 0 ) 
					return NF_CORRUPT;
				break;
			case LZ4_COMPRESSED: 
				if ( Uncompress_Block_LZ4(nffile) < 0 ) 
					return NF_CORRUPT;
				break;
			case BZ2_COMPRESSED: 
				if ( Uncompress_Block_BZ2(nffile) < 0 )
					return NF_CORRUPT;
			break;
		}
		dbg_printf("ReadBlock - expanded: %u\n", nffile->block_header->size);
		nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
		return read_bytes + nffile->block_header->size;
	} 
			
	if ( ret == 0 ) {
		// EOF not expected here - this should never happen, file may be corrupt
		LogError("ReadBlock() Corrupt data file: Unexpected EOF while reading data block");
		return NF_CORRUPT;
	}

	if ( ret == -1 ) {	// ERROR
		LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
		return NF_ERROR;
	}

	LogError("read() error: Short read: Expected: %u, received: %u\n", nffile->block_header->size, ret);
	return NF_ERROR;
	

} // End of ReadBlock

int WriteBlock(nffile_t *nffile) {
int ret;

	// empty blocks need not to be stored 
	if ( nffile->block_header->size == 0 )
		return 1;

	dbg_printf("WriteBlock - write: %u\n", nffile->block_header->size);

	if ( TestFlag(nffile->block_header->flags, FLAG_BLOCK_UNCOMPRESSED)) {
		dbg_printf("WriteBlock - overwrite file compression. Block is uncompressed\n");
	} else {
		// compress according file compression
		dbg_printf("WriteBlock - compression: %u\n", nffile->file_header->compression);
		switch (nffile->file_header->compression) {
			case NOT_COMPRESSED:
				break;
			case LZO_COMPRESSED: 
				if ( Compress_Block_LZO(nffile) < 0 ) return -1;
				break;
			case LZ4_COMPRESSED:
				if ( Compress_Block_LZ4(nffile) < 0 ) return -1;
				break;
			case BZ2_COMPRESSED:
				if ( Compress_Block_BZ2(nffile) < 0 ) return -1;
			break;
		}
	} 

	dbg_printf("WriteBlock - compressed: %u\n", nffile->block_header->size);

	ret = write(nffile->fd, (void *)nffile->block_header, sizeof(dataBlock_t) + nffile->block_header->size);
	if (ret < 0) {
		LogError("write() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
	} else {
		nffile->block_header->size = 0;
		nffile->block_header->NumRecords = 0;
		nffile->buff_ptr = (void *)((pointer_addr_t) nffile->block_header + sizeof (dataBlock_t));
		nffile->file_header->NumBlocks++;
	}
 	
	return ret;

} // End of WriteBlock

void SetIdent(nffile_t *nffile, char *Ident) {

	if (Ident && strlen(Ident) > 0) {
		if ( nffile->ident ) 
			free(nffile->ident);
		nffile->ident = strdup(Ident);
	}

} // End of SetIdent

int ChangeIdent(char *filename, char *Ident) {

	nffile_t *nffile = OpenFile(filename, NULL);
	if ( !nffile ) {
		return 0;
	}

	// file is valid - re-open the file mode RDWR
	close(nffile->fd);
	nffile->fd = open(filename, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffile->fd < 0 ) {
		LogError("Failed to open file %s: '%s'" , filename, strerror(errno));
		DisposeFile(nffile);
		return 0;
	}

	SetIdent(nffile, Ident);

	// seek to end of data
	if ( nffile->file_header->offAppendix ) {
		// seek to  end of data blocks
		if ( lseek(nffile->fd, nffile->file_header->offAppendix, SEEK_SET) < 0 ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			DisposeFile(nffile);
			return 0;
		}
	} else {
		// if no appendix
		if ( lseek(nffile->fd, 0, SEEK_END) < 0 ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
			DisposeFile(nffile);
			return 0;
		}
	}

	if ( !WriteAppendix(nffile) ) {
		LogError("Failed to write appendix");
	}

	if ( !CloseUpdateFile(nffile) ) {
		return 0;
	}

	DisposeFile(nffile);

	return 1;

} // End of ChangeIdent

void ModifyCompressFile(char * rfile, char *Rfile, int compress) {
int 			i, compression;
ssize_t			ret;
nffile_t		*nffile_r, *nffile_w;
stat_record_t	*_s;
char 			outfile[MAXPATHLEN];

	SetupInputFileSequence(NULL, rfile, Rfile, NULL);

	nffile_r = NULL;
	while (1) {
		nffile_r = GetNextFile(nffile_r);

		// last file
		if ( !nffile_r || (nffile_r == EMPTY_LIST))
			break;

		compression = nffile_r->file_header->compression;
		if ( compression == compress ) {
			printf("File %s is already same compression methode\n", nffile_r->fileName);
			continue;
		}

		// tmp filename for new output file
		snprintf(outfile, MAXPATHLEN, "%s-tmp", nffile_r->fileName);
		outfile[MAXPATHLEN-1] = '\0';

		// allocate output file
		nffile_w = OpenNewFile(outfile, NULL, compress, NOT_ENCRYPTED);
		if ( !nffile_w ) {
			DisposeFile(nffile_r);
			break;;
		}

		SetIdent(nffile_w, nffile_r->ident);

		// swap stat records :)
		_s = nffile_r->stat_record;
		nffile_r->stat_record = nffile_w->stat_record;
		nffile_w->stat_record = _s;
	
		for ( i=0; i < nffile_r->file_header->NumBlocks; i++ ) {
			ret = ReadBlock(nffile_r);
			if ( ret < 0 ) {
				LogError("Error reading data block");
				DisposeFile(nffile_r);
				DisposeFile(nffile_w);
				unlink(outfile);
				return;
			}

			// swap buffers
			void *_tmp = nffile_r->buff_pool[0];
			nffile_r->buff_pool[0] = nffile_w->buff_pool[0];
			nffile_w->buff_pool[0] = _tmp;
			nffile_w->block_header = nffile_w->buff_pool[0];
			nffile_r->block_header = nffile_r->buff_pool[0];
			nffile_r->buff_ptr = (void *)((pointer_addr_t)nffile_r->block_header + sizeof(dataBlock_t));

			if ( WriteBlock(nffile_w) <= 0 ) {
				LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
				DisposeFile(nffile_r);
				DisposeFile(nffile_w);
				unlink(outfile);
				return;
			}
		}

		printf("File %s compression changed\n", nffile_r->fileName);
		if ( !CloseUpdateFile(nffile_w) ) {
			unlink(outfile);
			LogError("Failed to close file: '%s'" , strerror(errno));
		} else {
			unlink(nffile_r->fileName);
			rename(outfile, nffile_r->fileName);
		}

		DisposeFile(nffile_w);
	}

} // End of ModifyCompressFile

void QueryFile(char *filename) {
int i, fd;
uint32_t totalRecords, numBlocks, type1, type2, type3;
struct stat stat_buf;
ssize_t	ret;
off_t	fsize;

	type1 = type2 = type3 = 0;
	totalRecords = numBlocks = 0;

	if ( stat(filename, &stat_buf) ) {
		LogError("Can't stat '%s': %s", filename, strerror(errno));
		return;
	}

	fd = open(filename, O_RDONLY);
	if ( fd < 0 ) {
		LogError("Error open file: %s", strerror(errno));
		return;
	}

	// assume fileHeaderV2_t
	fileHeaderV2_t fileHeader;
	ret = read(fd, (void *)&fileHeader, sizeof(fileHeaderV2_t));
	if ( ret < 1 ) {
		LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return;
	}

	if ( fileHeader.magic != MAGIC ) {
        LogError("Open file '%s': bad magic: 0x%X", filename, fileHeader.magic );
        close(fd);
		return;
    }

	printf("File       : %s\n", filename);
	if ( fileHeader.version == LAYOUT_VERSION_1 ) {
		if ( lseek(fd, 0, SEEK_SET) < 0 ) {
			LogError("lseek() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			close(fd);
			return;
		}
		if ( !QueryFileV1(fd, &fileHeader) ) {
			close(fd);
			return;
		}
	} else {

		if ( fileHeader.version != LAYOUT_VERSION_2 ) {
        	LogError("Unknown layout version: %u", fileHeader.version );
        	close(fd);
			return;
		}

		if ( fileHeader.compression > LZ4_COMPRESSED) {
        	LogError("Unknown compression: %u", fileHeader.compression );
        	close(fd);
			return;
		}

		printf("Version    : %u - %s\n", fileHeader.version,
			fileHeader.compression == LZO_COMPRESSED ? "lzo compressed" :
			fileHeader.compression == LZ4_COMPRESSED ? "lz4 compressed" :
			fileHeader.compression == BZ2_COMPRESSED ? "bz2 compressed" :
            	"not compressed");

		if ( fileHeader.encryption != NOT_ENCRYPTED) {
        	LogError("Unknown encryption: %u", fileHeader.encryption );
        	close(fd);
			return;
		}

		struct tm   *tbuff = localtime(&fileHeader.created);
		char t1[64];
		strftime(t1, 63, "%Y-%m-%d %H:%M:%S", tbuff);
		printf("Created    : %s\n", t1);
		printf("nfdump     : %x\n", fileHeader.nfversion);
		printf("encryption : %s\n", fileHeader.encryption ? "yes" : "no");
		printf("Appendix   : %u blocks\n", fileHeader.appendixBlocks);
		printf("Blocks     : %u\n", fileHeader.NumBlocks);
		numBlocks = fileHeader.NumBlocks;

		if ( fileHeader.offAppendix >= stat_buf.st_size ) {
        	LogError("Invalid appendix offset: %u", fileHeader.offAppendix );
        	close(fd);
			return;
		}
	} 

	// first check ok - abstract nffile level
	nffile_t *nffile = NewFile(NULL);
	if ( !nffile ) {
		close(fd);
		return;
	}
	nffile->fd = fd;
	nffile->fileName = strdup(filename);
	memcpy(nffile->file_header, &fileHeader, sizeof(fileHeader));

	switch (FILE_COMPRESSION(nffile)) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED: 
			if ( !lzo_initialized && !LZO_initialize() ) {
				return;
			}
			break;
		case LZ4_COMPRESSED: 
			if ( !lz4_initialized && !LZ4_initialize() ) {
				return;
			}
			break;
		case BZ2_COMPRESSED: 
			if ( !bz2_initialized && !BZ2_initialize() ) {
				return;
			}
			break;
	}

	fsize = lseek(fd, 0, SEEK_CUR);

	printf("Checking data blocks\n");
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	char spinner[] = { '|', '/', '-', '\\' }; 
	for ( i=0; i < fileHeader.NumBlocks + fileHeader.appendixBlocks; i++ ) {
		printf(" %c\r", spinner[i & 0x2]);
		if ( (fsize + sizeof(dataBlock_t)) > stat_buf.st_size ) {
			LogError("Unexpected read beyond EOF! File corrupted");
			LogError("Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
			break;
		}
		ret = read(fd, nffile->block_header, sizeof(dataBlock_t));
		if ( ret < 0 ) {
			LogError("Error reading block %i: %s", i, strerror(errno));
			close(fd);
			return;
		}

		// Should never happen, as catched already in first check, but test it anyway ..
		if ( ret == 0 ) {
			LogError("Unexpected eof. Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
			close(fd);
			return;
		}
		if ( ret < sizeof(dataBlock_t) ) {
			LogError("Short read: Expected %u bytes, read: %i", sizeof(dataBlock_t), ret);
			close(fd);
			return;
		}
		fsize += ret;

		switch ( nffile->block_header->type) {
			case DATA_BLOCK_TYPE_1:
				type1++;
				break;
			case DATA_BLOCK_TYPE_2:
				type2++;
				break;
			case DATA_BLOCK_TYPE_3:
				type3++;
				break;
			default:
				printf("block %i has unknown type %u\n", i, nffile->block_header->type);
				close(fd);
				return;
		}

		if ( (fsize + nffile->block_header->size ) > stat_buf.st_size ) {
			LogError("Expected to seek beyond EOF! File corrupted");
			close(fd);
			return;
		}
		
		dbg_printf("Checking block %i, type: %u, size: %u\n", i, nffile->block_header->type, nffile->block_header->size);
		int compression = nffile->file_header->compression;
		if ( TestFlag(nffile->block_header->flags, FLAG_BLOCK_UNCOMPRESSED) ) {
			compression = NOT_COMPRESSED;
		}

		nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(dataBlock_t));
		ret = read(nffile->fd, nffile->buff_ptr, nffile->block_header->size);
		if ( ret < 0 ) {
			LogError("Error reading block %i: %s", i, strerror(errno));
			close(fd);
			return;
		}

		if ( ret == 0 ) {
			LogError("Unexpected eof. Expected %u blocks, counted %i", fileHeader.NumBlocks, i);
			close(fd);
			return;
		}
		if ( ret != nffile->block_header->size ) {
			LogError("Short read: Expected %u bytes, read: %i", nffile->block_header->size, ret);
			close(fd);
			return;
		}
		fsize += ret;

		switch (compression) {
			case NOT_COMPRESSED:
				break;
			case LZO_COMPRESSED: 
				if ( Uncompress_Block_LZO(nffile) < 0 ) {
					LogError("LZO decommpress failed");
					return;
				}
				break;
			case LZ4_COMPRESSED: 
				if ( Uncompress_Block_LZ4(nffile) < 0 ) {
					LogError("LZ4 decommpress failed");
					return;
				}
				break;
			case BZ2_COMPRESSED: 
				if ( Uncompress_Block_BZ2(nffile) < 0 ) {
					LogError("Bzip2 decommpress failed");
					return;
				}
			break;
		}

		// record counting
		int blockSize = 0;
		int numRecords = 0;
		while (blockSize < nffile->block_header->size) {
			recordHeader_t *recordHeader = (recordHeader_t *)nffile->buff_ptr;
			numRecords++;
			dbg_printf("Record %i, type: %u, size: %u - block size: %u\n", 
				numRecords, recordHeader->type, recordHeader->size, blockSize);
			if ( (blockSize + recordHeader->size) > nffile->block_header->size ) {
				LogError("Record size %u extends beyond block size: %u", blockSize + recordHeader->size, nffile->block_header->size );
				close(fd);
				return;
			}

			nffile->buff_ptr += recordHeader->size;
			blockSize += recordHeader->size;
		}
		if (numRecords != nffile->block_header->NumRecords) {
			LogError("Block %u num records %u != counted records: %u", i, nffile->block_header->NumRecords, numRecords);
			close(fd);
			return;
		}
		totalRecords += numRecords;

		if (blockSize != nffile->block_header->size) {
			LogError("block size %u != sum record size: %u", blockSize, nffile->block_header->size);
			close(fd);
			return;
		}

		if ( i+1 == fileHeader.NumBlocks ) {
			fsize = lseek(fd, 0, SEEK_CUR);
			if ( fileHeader.appendixBlocks && fsize != fileHeader.offAppendix ) {
				LogError("Invalid appendix offset - Expected: %u, found: %u", fileHeader.offAppendix, fsize);
				close(fd);
				return;
			}
			if ( fileHeader.appendixBlocks ) 
				printf("Checking appendix blocks\n");
		}
	}

	fsize = lseek(fd, 0, SEEK_CUR);
	if ( fsize < stat_buf.st_size ) {
		LogError("Extra data detected after regular blocks: %i bytes", stat_buf.st_size-fsize);
	}
	printf("  \nFound:\n");
	printf(" Type 1    : %u\n", type1);
	printf(" Type 2    : %u\n", type2);
	printf(" Type 3    : %u\n", type3);
	printf("Records    : %u\n", totalRecords);

	DisposeFile(nffile);

} // End of QueryFile

static int QueryFileV1(int fd, fileHeaderV2_t *fileHeaderV2) {
struct stat stat_buf;
int ret;

	if ( fstat(fd, &stat_buf) ) {
		LogError("Can't fstat: %s", strerror(errno));
		return 0;
	}

	fileHeaderV1_t fileHeader;
	// set file size to current position ( file header )
	ret = read(fd, (void *)&fileHeader, sizeof(fileHeaderV1_t));
	if ( ret < 1 ) {
		LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	// magic and version already checked
	fileHeaderV2->version = fileHeader.version;
	fileHeaderV2->magic   = fileHeader.magic;
	fileHeaderV2->encryption = NOT_ENCRYPTED;
	fileHeaderV2->appendixBlocks = 0;
	fileHeaderV2->offAppendix = 0;
	fileHeaderV2->NumBlocks = fileHeader.NumBlocks;

	int anon = TestFlag(fileHeader.flags, FLAG_ANONYMIZED);
	ClearFlag(fileHeader.flags, FLAG_ANONYMIZED);
	
	if ((TestFlag(fileHeader.flags, FLAG_LZO_COMPRESSED) + 
		 TestFlag(fileHeader.flags, FLAG_LZ4_COMPRESSED) + 
		 TestFlag(fileHeader.flags, FLAG_BZ2_COMPRESSED)) > FLAG_LZ4_COMPRESSED ) {
		LogError("Multiple v1 compression flags: 0x%x", fileHeader.flags & COMPRESSION_MASK );
		return 0;
	}
	int compression = NOT_COMPRESSED;
	char *s = "not compressed";
	if ( TestFlag(fileHeader.flags, FLAG_LZO_COMPRESSED) ) {
		compression = LZO_COMPRESSED;
		s = "lzo compressed";
	}
	if ( TestFlag(fileHeader.flags, FLAG_LZ4_COMPRESSED) ) {
		compression = LZ4_COMPRESSED;
		s = "lz4 compressed";
	}
	if ( TestFlag(fileHeader.flags, FLAG_BZ2_COMPRESSED) ) {
		compression = BZ2_COMPRESSED;
		s = "bz2 compressed";
	}
	fileHeaderV2->compression = compression;

	printf("Version    : %u - %s %s\n", fileHeader.version, s, anon ? "anonymized" : "");
	printf("Blocks     : %u\n", fileHeader.NumBlocks);

	stat_record_t stat_record;
	ret = read(fd, (void *)&stat_record, sizeof(stat_record_t));
	if ( ret < 0 ) {
		LogError("read() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	if ( ret != sizeof(stat_record_t)) {
		LogError("Error reading v1 stat record - short read. Expected: %u, get %u", sizeof(stat_record_t), ret);
		return 0;
	}
 
	return 1;
} // End of QueryFileV1

// simple interface to get a stat record
int GetStatRecord(char *filename, stat_record_t *stat_record) {
	
	nffile_t *nffile = OpenFile(filename, NULL);
	if ( !nffile ) {
		return 0;
	}

	memcpy((void *)stat_record, nffile->stat_record, sizeof(stat_record_t));
	DisposeFile(nffile);

	return 1;

} // End of GetStatRecord

void PrintStat(stat_record_t *s, char *ident) {

	if ( s == NULL )
		return;

	// format info: make compiler happy with conversion to (unsigned long long), 
	// which does not change the size of the parameter
	printf("Ident: %s\n", ident);
	printf("Flows: %llu\n", (unsigned long long)s->numflows);
	printf("Flows_tcp: %llu\n", (unsigned long long)s->numflows_tcp);
	printf("Flows_udp: %llu\n", (unsigned long long)s->numflows_udp);
	printf("Flows_icmp: %llu\n", (unsigned long long)s->numflows_icmp);
	printf("Flows_other: %llu\n", (unsigned long long)s->numflows_other);
	printf("Packets: %llu\n", (unsigned long long)s->numpackets);
	printf("Packets_tcp: %llu\n", (unsigned long long)s->numpackets_tcp);
	printf("Packets_udp: %llu\n", (unsigned long long)s->numpackets_udp);
	printf("Packets_icmp: %llu\n", (unsigned long long)s->numpackets_icmp);
	printf("Packets_other: %llu\n", (unsigned long long)s->numpackets_other);
	printf("Bytes: %llu\n", (unsigned long long)s->numbytes);
	printf("Bytes_tcp: %llu\n", (unsigned long long)s->numbytes_tcp);
	printf("Bytes_udp: %llu\n", (unsigned long long)s->numbytes_udp);
	printf("Bytes_icmp: %llu\n", (unsigned long long)s->numbytes_icmp);
	printf("Bytes_other: %llu\n", (unsigned long long)s->numbytes_other);
	printf("First: %u\n", s->first_seen);
	printf("Last: %u\n", s->last_seen);
	printf("msec_first: %u\n", s->msec_first);
	printf("msec_last: %u\n", s->msec_last);
	printf("Sequence failures: %u\n", s->sequence_failure);
} // End of PrintStat

void SumStatRecords(stat_record_t *s1, stat_record_t *s2) {

	s1->numflows			+= s2->numflows;
	s1->numbytes			+= s2->numbytes;
	s1->numpackets			+= s2->numpackets;
	s1->numflows_tcp		+= s2->numflows_tcp;
	s1->numflows_udp		+= s2->numflows_udp;
	s1->numflows_icmp		+= s2->numflows_icmp;
	s1->numflows_other		+= s2->numflows_other;
	s1->numbytes_tcp		+= s2->numbytes_tcp;
	s1->numbytes_udp		+= s2->numbytes_udp;
	s1->numbytes_icmp		+= s2->numbytes_icmp;
	s1->numbytes_other		+= s2->numbytes_other;
	s1->numpackets_tcp		+= s2->numpackets_tcp;
	s1->numpackets_udp		+= s2->numpackets_udp;
	s1->numpackets_icmp		+= s2->numpackets_icmp;
	s1->numpackets_other	+= s2->numpackets_other;
	s1->sequence_failure	+= s2->sequence_failure;

	if ( s2->first_seen < s1->first_seen ) {
		s1->first_seen = s2->first_seen;
		s1->msec_first = s2->msec_first;
	}
	if ( s2->first_seen == s1->first_seen && 
		 s2->msec_first < s1->msec_first ) 
			s1->msec_first = s2->msec_first;

	if ( s2->last_seen > s1->last_seen ) {
		s1->last_seen = s2->last_seen;
		s1->msec_last = s2->msec_last;
	}
	if ( s2->last_seen == s1->last_seen && 
		 s2->msec_last > s1->msec_last ) 
			s1->msec_last = s2->msec_last;

} // End of SumStatRecords
