/*
 *  Copyright (c) 2017, Peter Haag
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2011, Peter Haag
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

#include "minilzo.h"
#include "lz4.h"
#include "nf_common.h"
#include "nffile.h"
#include "flist.h"
#include "util.h"

/* global vars */

// required for idet filter in nftree.c
char 	*CurrentIdent;


#define READ_FILE	1
#define WRITE_FILE	1

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

static int OpenRaw(char *filename, stat_record_t *stat_record, int *compressed);

extern char *nf_error;

/* function prototypes */
static nffile_t *NewFile(void);

/* function definitions */

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


static int LZO_initialize(void) {

	if (lzo_init() != LZO_E_OK) {
		// this usually indicates a compiler bug - try recompiling 
		// without optimizations, and enable `-DLZO_DEBUG' for diagnostics
		LogError("Compression lzo_init() failed.\n");
		return 0;
	} 
	lzo_initialized = 1;

	return 1;

} // End of LZO_initialize

static int LZ4_initialize (void) {

	int lz4_buff_size = LZ4_compressBound(BUFFSIZE + sizeof (data_block_header_t));
	if ( lz4_buff_size > (2 * BUFFSIZE) ) {
		LogError ("LZ4_compressBound() error in %s line %d: Buffer too small\n", __FILE__, __LINE__);
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

	in  = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[0] + sizeof(data_block_header_t));	
	out = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[1] + sizeof(data_block_header_t));	
	in_len = nffile->block_header->size;
	r = lzo1x_1_compress(in,in_len,out,&out_len,wrkmem);

	if (r != LZO_E_OK) {
		LogError("Compress_Block_LZO() error compression failed in %s line %d: LZ4 : %d\n", __FILE__, __LINE__, r);
		return -1;
	}
	
	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = out_len;

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

	in  = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[0] + sizeof(data_block_header_t));	
	out = (unsigned char __LZO_MMODEL *)(nffile->buff_pool[1] + sizeof(data_block_header_t));	
	in_len  = nffile->block_header->size;
	out_len = nffile->buff_size;

	if ( in_len == 0 ) {
		LogError("Uncompress_Block_LZO() header length error in %s line %d\n", __FILE__, __LINE__);
   		return -1;
	}
	r = lzo1x_decompress_safe(in,in_len,out,&out_len,NULL);
	if (r != LZO_E_OK ) {
  		/* this should NEVER happen */
		LogError("Uncompress_Block_LZO() error decompression failed in %s line %d: LZO error: %d\n", __FILE__, __LINE__, r);
   		return -1;
	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(data_block_header_t);

	return 1;

} // End of Uncompress_Block_LZO

static int Compress_Block_LZ4(nffile_t *nffile) {

	const char *in  = (const char *)(nffile->buff_pool[0] + sizeof(data_block_header_t));
	char *out 		= (char *)(nffile->buff_pool[1] + sizeof(data_block_header_t));
	int in_len 		= nffile->block_header->size;

	int out_len = LZ4_compress_default(in, out, in_len, nffile->buff_size);
	if (out_len == 0 ) {
		LogError("Compress_Block_LZ4() error compression aborted in %s line %d: LZ4 : buffer too small\n", __FILE__, __LINE__);
   		return -1;
   	}
   	if (out_len < 0 ) {
		LogError("Compress_Block_LZ4() error compression failed in %s line %d: LZ4 : %d\n", __FILE__, __LINE__, out_len);
   		return -1;
   	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];

	return 1;

} // End of Compress_Block_LZ4

static int Uncompress_Block_LZ4(nffile_t *nffile) {

	const char *in  = (const char *)(nffile->buff_pool[0] + sizeof(data_block_header_t));
	char *out 		= (char *)(nffile->buff_pool[1] + sizeof(data_block_header_t));
	int in_len 		= nffile->block_header->size;

	int out_len = LZ4_decompress_safe(in, out, in_len, nffile->buff_size);
	if (out_len == 0 ) {
		LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small\n", __FILE__, __LINE__);
   		return -1;
   	}
   	if (out_len < 0 ) {
		LogError("LZ4_decompress_safe() error compression failed in %s line %d: LZ4 : %d\n", __FILE__, __LINE__, out_len);
   		return -1;
   	}

	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = out_len;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(data_block_header_t);

	return 1;

} // End of Uncompress_Block_LZ4

static int Compress_Block_BZ2(nffile_t *nffile) {
bz_stream bs;

	BZ2_prep_stream (&bs);
	BZ2_bzCompressInit (&bs, 9, 0, 0);

	bs.next_in   = (char*)(nffile->buff_pool[0] + sizeof(data_block_header_t));
	bs.next_out  = (char*)(nffile->buff_pool[1] + sizeof(data_block_header_t));
	bs.avail_in  = nffile->block_header->size;
	bs.avail_out = nffile->buff_size;
 
	for (;;) {
		int r = BZ2_bzCompress (&bs, BZ_FINISH);
		if (r == BZ_FINISH_OK) continue;
		if (r != BZ_STREAM_END) {
			LogError("Compress_Block_BZ2() error compression failed in %s line %d: LZ4 : %d\n", __FILE__, __LINE__, r);
			return -1;
		}
		break;
	}

 	// copy header
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = bs.total_out_lo32;

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

	bs.next_in   = (char*)(nffile->buff_pool[0] + sizeof(data_block_header_t));
	bs.next_out  = (char*)(nffile->buff_pool[1] + sizeof(data_block_header_t));
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
	memcpy(nffile->buff_pool[1], nffile->buff_pool[0], sizeof(data_block_header_t));
	((data_block_header_t *)nffile->buff_pool[1])->size = bs.total_out_lo32;

	// swap buffers
	void *_tmp = nffile->buff_pool[1];
	nffile->buff_pool[1] = nffile->buff_pool[0];
	nffile->buff_pool[0] = _tmp;

	nffile->block_header = nffile->buff_pool[0];
	nffile->buff_ptr 	 = nffile->buff_pool[0] + sizeof(data_block_header_t);

	BZ2_bzDecompressEnd (&bs);
	
	return 1;

} // End of Uncompress_Block_BZ2

nffile_t *OpenFile(char *filename, nffile_t *nffile){
struct stat stat_buf;
int ret, allocated;

	if ( !nffile ) {
		nffile = NewFile();
		if ( nffile == NULL ) {
			return NULL;
		}
		allocated = 1;
	} else 
		allocated = 0;


	if ( filename == NULL ) {
		// stdin
		// Zero Stat
		nffile->fd = STDIN_FILENO;
	} else {
		// regular file
		if ( stat(filename, &stat_buf) ) {
			LogError("Can't stat '%s': %s\n", filename, strerror(errno));
			if ( allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
		}

		if (!S_ISREG(stat_buf.st_mode) ) {
			LogError("'%s' is not a file\n", filename);
			if ( allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
		}

		// printf("Statfile %s\n",filename);
		nffile->fd = open(filename, O_RDONLY);
		if ( nffile->fd < 0 ) {
			LogError("Error open file: %s\n", strerror(errno));
			if ( allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
		}

	}

	ret = read(nffile->fd, (void *)nffile->file_header, sizeof(file_header_t));
	if ( nffile->file_header->magic != MAGIC ) {
		LogError("Open file '%s': bad magic: 0x%X\n", filename ? filename : "<stdin>", nffile->file_header->magic );
		CloseFile(nffile);
		if ( allocated ) {
			DisposeFile(nffile);
			return NULL;
		}
	}

	if ( nffile->file_header->version != LAYOUT_VERSION_1 ) {
		LogError("Open file %s: bad version: %u\n", filename, nffile->file_header->version );
		CloseFile(nffile);
		if ( allocated ) {
			DisposeFile(nffile);
			return NULL;
		}
	}

	ret = read(nffile->fd, (void *)nffile->stat_record, sizeof(stat_record_t));
	if ( ret < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		CloseFile(nffile);
		if ( allocated ) {
			DisposeFile(nffile);
			return NULL;
		}
	}

	CurrentIdent		= nffile->file_header->ident;

	int compression = FILE_COMPRESSION(nffile);
	switch (compression) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED: 
			if ( !lzo_initialized && !LZO_initialize() && allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case LZ4_COMPRESSED: 
			if ( !lz4_initialized && !LZ4_initialize() && allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case BZ2_COMPRESSED: 
			if ( !bz2_initialized && !BZ2_initialize() && allocated ) {
				DisposeFile(nffile);
				return NULL;
			}
			break;
	}

	return nffile;

} // End of OpenFile

void CloseFile(nffile_t *nffile){

	if ( !nffile ) 
		return;

	// do not close stdout
	if ( nffile->fd )
		close(nffile->fd);

} // End of CloseFile

int ChangeIdent(char *filename, char *Ident) {
file_header_t	FileHeader;
struct stat stat_buf;
int fd;

	if ( filename == NULL ) 
		return 0;

	if ( stat(filename, &stat_buf) ) {
		LogError("Can't stat '%s': %s\n", filename, strerror(errno));
		return -1;
	}

	if (!S_ISREG(stat_buf.st_mode) ) {
		LogError("'%s' is not a file\n", filename);
		return -1;
	}

	fd =  open(filename, O_RDWR);
	if ( fd < 0 ) {
		LogError("Error open file: %s\n", strerror(errno));
		return fd;
	}

	if ( read(fd, (void *)&FileHeader, sizeof(FileHeader)) < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return -1;
	}
	if ( FileHeader.magic != MAGIC ) {
		LogError("Open file '%s': bad magic: 0x%X\n", filename, FileHeader.magic );
		close(fd);
		return -1;
	}
	if ( FileHeader.version != LAYOUT_VERSION_1 ) {
		LogError("Open file %s: bad version: %u\n", filename, FileHeader.version );
		close(fd);
		return -1;
	}

	strncpy(FileHeader.ident, Ident, IDENTLEN);
	FileHeader.ident[IDENTLEN - 1] = 0;

	if ( lseek(fd, 0, SEEK_SET) < 0 ) {
		LogError("lseek() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return -1;
	}

	if ( write(fd, (void *)&FileHeader, sizeof(file_header_t)) <= 0 ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
	}

	if ( close(fd) < 0 ) {
		LogError("close() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return -1;
	}
	
	return 0;

} // End of ChangeIdent


void PrintStat(stat_record_t *s) {

	if ( s == NULL )
		return;

	// format info: make compiler happy with conversion to (unsigned long long), 
	// which does not change the size of the parameter
	printf("Ident: %s\n", CurrentIdent);
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

static nffile_t *NewFile(void) {
nffile_t *nffile;
int i;

	// Create struct
	nffile = calloc(1, sizeof(nffile_t));
	if ( !nffile ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	nffile->buff_ptr = NULL;
	nffile->fd	 	= 0;

	// Init file header
	nffile->file_header = calloc(1, sizeof(file_header_t));
	if ( !nffile->file_header ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	nffile->file_header->magic 	   = MAGIC;
	nffile->file_header->version   = LAYOUT_VERSION_1;
	nffile->file_header->flags 	   = 0;
	nffile->file_header->NumBlocks = 0;

	nffile->stat_record = calloc(1, sizeof(stat_record_t));
	if ( !nffile->stat_record ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}

/*
	XXX catalogs not yet implemented
	nffile->catalog = calloc(1, sizeof(catalog_t));
	if ( !nffile->catalog ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	nffile->catalog->NumRecords = 0;
	nffile->catalog->size 		= sizeof(catalog_t) - sizeof(data_block_header_t);
	nffile->catalog->id 		= CATALOG_BLOCK;
	nffile->catalog->pad 		= 0;
	nffile->catalog->reserved 	= 0;
*/
	// init data buffer
	nffile->buff_size = 2 * BUFFSIZE;
	for (i=0; i<NUM_BUFFS; i++ ) {
		// allocate twice of BUFFSIZE initially - should be ok, otherwise expand
		nffile->buff_pool[i] = malloc(nffile->buff_size);
		if ( !nffile->buff_pool[i] ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
	}

	nffile->block_header 			 = nffile->buff_pool[0];
	nffile->block_header->size 		 = 0;
	nffile->block_header->NumRecords = 0;
	nffile->block_header->id		 = DATA_BLOCK_TYPE_2;
	nffile->block_header->flags		 = 0;

	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));
	
	return nffile;

} // End of NewFile

nffile_t *DisposeFile(nffile_t *nffile) {
int i;

	free(nffile->file_header);
	free(nffile->stat_record);

	for (i=0; i<NUM_BUFFS; i++ ) {
		free(nffile->buff_pool[i]);
	}

	return NULL;
} // End of DisposeFile

nffile_t *OpenNewFile(char *filename, nffile_t *nffile, int compress, int anonymized, char *ident) {
size_t			len;
int 			fd, flags;

	switch (compress) {
		case NOT_COMPRESSED:
			flags = FLAG_NOT_COMPRESSED;
			break;
		case LZO_COMPRESSED:
			flags = FLAG_LZO_COMPRESSED;
			if ( !lzo_initialized && !LZO_initialize() ) {
				LogError("Failed to initialize LZO compression");
				return NULL;
			}
			break;
		case LZ4_COMPRESSED:
			flags = FLAG_LZ4_COMPRESSED;
			if ( !lz4_initialized && !LZ4_initialize() ) {
				LogError("Failed to initialize LZ4 compression");
				return NULL;
			}
			break;
		case BZ2_COMPRESSED:
			flags = FLAG_BZ2_COMPRESSED;
			if ( !bz2_initialized && !BZ2_initialize() ) {
				LogError("Failed to initialize BZ2 compression");
				return NULL;
			}
			break;
		default:
			LogError("Unknown compression ID: %i\n", compress);
			return NULL;
	}

	fd = 0;
	if ( strcmp(filename, "-") == 0 ) { // output to stdout
		fd = STDOUT_FILENO;
	} else {
		fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( fd < 0 ) {
			LogError("Failed to open file %s: '%s'" , filename, strerror(errno));
			return NULL;
		}
	}

	// Allocate new struct if not given
	if ( nffile == NULL ) {
		nffile = NewFile();
		if ( nffile == NULL ) {
			return NULL;
		}
	}

	nffile->fd = fd;

	if ( anonymized ) 
		SetFlag(flags, FLAG_ANONYMIZED);

	nffile->file_header->flags 	   = flags;

/*
	XXX catalogs not yet implemented
	if ( nffile->catalog && nffile->catalog->NumRecords ) {
		memset((void *)nffile->catalog->entries, 0, nffile->catalog->NumRecords * sizeof(struct catalog_entry_s));
		nffile->catalog->NumRecords = 0;
		nffile->catalog->size		= 0;
	} 
*/
	if ( nffile->stat_record ) {
		memset((void *)nffile->stat_record, 0, sizeof(stat_record_t));
		nffile->stat_record->first_seen = 0x7fffffff;
		nffile->stat_record->msec_first = 999;
	}

	if ( ident ) {
		strncpy(nffile->file_header->ident, ident, IDENTLEN);
		nffile->file_header->ident[IDENTLEN - 1] = 0;
	} 

	nffile->file_header->NumBlocks = 0;
	len = sizeof(file_header_t);
	if ( write(nffile->fd, (void *)nffile->file_header, len) < len ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(nffile->fd);
		nffile->fd = 0;
		return NULL;
	}

	// write empty stat record - ist updated when file gets closed
	len = sizeof(stat_record_t);
	if ( write(nffile->fd, (void *)nffile->stat_record, len) < len ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(nffile->fd);
		nffile->fd = 0;
		return NULL;
	}

/* skip writing catalog in this test version
	XXX catalogs not yet implemented
	if ( WriteExtraBlock(nffile, (data_block_header_t *)nffile->catalog) < 0 ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(nffile->fd);
		return NULL;
	}
*/

	return nffile;

} /* End of OpenNewFile */

nffile_t *AppendFile(char *filename) {
nffile_t		*nffile;

	// try to open the existing file
	nffile = OpenFile(filename, NULL);
	if ( !nffile )
		return NULL;

	// file is valid - re-open the file mode RDWR
	close(nffile->fd);
	nffile->fd = open(filename, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffile->fd < 0 ) {
		LogError("Failed to open file %s: '%s'" , filename, strerror(errno));
		DisposeFile(nffile);
		return NULL;
	}

	// init output data buffer
	nffile->block_header = malloc(BUFFSIZE + sizeof(data_block_header_t));
	if ( !nffile->block_header ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(nffile->fd);
		DisposeFile(nffile);
		return NULL;
	}
	nffile->block_header->size 		 = 0;
	nffile->block_header->NumRecords = 0;
	nffile->block_header->id		 = DATA_BLOCK_TYPE_2;
	nffile->block_header->flags		 = 0;
	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));

	int compression = FILE_COMPRESSION(nffile);
	switch (compression) {
		case NOT_COMPRESSED:
			break;
		case LZO_COMPRESSED: 
			if ( !lzo_initialized && !LZO_initialize() ) {
				LogError("Failed to initialize LZO compression");
				close(nffile->fd);
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case LZ4_COMPRESSED: 
			if ( !lz4_initialized && !LZ4_initialize() ) {
				LogError("Failed to initialize LZ4 compression");
				close(nffile->fd);
				DisposeFile(nffile);
				return NULL;
			}
			break;
		case BZ2_COMPRESSED: 
			if ( !bz2_initialized && !BZ2_initialize() ) {
				LogError("Failed to initialize BZ2 compression");
				close(nffile->fd);
				DisposeFile(nffile);
				return NULL;
			}
			break;
	}

	return nffile;

} /* End of AppendFile */

int RenameAppend(char *from, char *to) {
int fd_to, fd_from, ret;
int compressed_to, compressed_from;
stat_record_t stat_record_to, stat_record_from;
data_block_header_t *block_header;
void *p;

	fd_to = OpenRaw(to, &stat_record_to, &compressed_to);
	if ( fd_to == 0 ) {
		// file does not exists, use rename
		return rename(from, to) == 0 ? 1 : 0;
	}

	fd_from = OpenRaw(from, &stat_record_from, &compressed_from);
	if ( fd_from <= 0 ) {
		// file does not exists - strange
		close(fd_to);
		return 0;
	}

	// both files open - append data
	ret = lseek(fd_to, 0, SEEK_END);
	if ( ret < 0 ) {
		LogError("lseek() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd_from);
		close(fd_to);
		return 0;
	}

	block_header = malloc(sizeof(data_block_header_t) + BUFFSIZE);
	if ( !block_header ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
		close(fd_from);
		close(fd_to);
		return 0;
	}
	p = (void *)((void *)block_header + sizeof(data_block_header_t));

	while (1) {
		ret = read(fd_from, (void *)block_header, sizeof(data_block_header_t));
		if ( ret == 0 ) 
			// EOF
			break;

		if ( ret < 0 ) {
			// that's bad! difficult to recover. stat will be inconsistent
			LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			break;
		}

		// read data block
		ret = read(fd_from, p, block_header->size);
		if ( ret != block_header->size ) {
			// that's bad! difficult to recover. stat will be inconsistent
			LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			break;
		}
		// append data block
		ret = write(fd_to, block_header, sizeof(data_block_header_t) + block_header->size);
		if ( ret < 0 ) {
			// that's bad! difficult to recover. stat will be inconsistent
			LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			break;
		}
	}

	SumStatRecords(&stat_record_to, &stat_record_from);
	// both files open - append data
	ret = lseek(fd_to, sizeof(file_header_t), SEEK_SET);
	if ( ret < 0 ) {
		LogError("lseek() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd_from);
		close(fd_to);
		return 0;
	}

	if ( write(fd_to, (void *)&stat_record_to, sizeof(stat_record_t)) <= 0 ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd_from);
		close(fd_to);
		return 0;
	}

	close(fd_from);
	close(fd_to);
	unlink(from);
	return 1;

} // End of RenameAppend

static int OpenRaw(char *filename, stat_record_t *stat_record, int *compressed) {
struct stat stat_buf;
file_header_t file_header;
int fd, ret;

	if ( stat(filename, &stat_buf) ) {
		// file does not exists
		return 0;
	}

	// file exists - should be a regular file 
	if (!S_ISREG(stat_buf.st_mode) ) {
		// should nor really happen - catch it anyway
		LogError("'%s' is not a regular file\n", filename);
		return -1;
	}

	// file exists - append to existing
	fd = open(filename, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( fd < 0 ) {
		LogError("open() failed for file %s: '%s'" , filename, strerror(errno));
		return -1;
	}

	ret = read(fd, (void *)&file_header, sizeof(file_header_t));
	if ( ret < 0 ) {
		LogError("read() failed for file %s: '%s'" , filename, strerror(errno));
		close(fd);
		return -1;
	}

	if ( file_header.magic != MAGIC ) {
		LogError("Open file '%s': bad magic: 0x%X\n", filename, file_header.magic );
		close(fd);
		return -1;
	}

	if ( file_header.version != LAYOUT_VERSION_1 ) {
		LogError("Open file %s: bad version: %u\n", filename, file_header.version );
		close(fd);
		return -1;
	}

	ret = read(fd, (void *)stat_record, sizeof(stat_record_t));
	if ( ret < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return -1;
	}

	if ( file_header.flags & FLAG_LZO_COMPRESSED ) 
		*compressed = FLAG_LZO_COMPRESSED;
	else if ( file_header.flags & FLAG_LZ4_COMPRESSED )
		*compressed = FLAG_LZ4_COMPRESSED;
	else if ( file_header.flags & FLAG_BZ2_COMPRESSED )
		*compressed = FLAG_BZ2_COMPRESSED;
	else
		*compressed = 0;

	return fd;

} // End of OpenRaw

int CloseUpdateFile(nffile_t *nffile, char *ident) {

	if ( nffile->block_header->size ) {
		int ret = WriteBlock(nffile);
		if ( ret < 0 ) {
			LogError("Failed to flush output buffer");
			return 0;
		}
	}

	if ( lseek(nffile->fd, 0, SEEK_SET) < 0 ) {
		// lseek on stdout works if output redirected:
		// e.g. -w - > outfile
		// but fails on pipe e.g. -w - | ./nfdump .... 
		if ( nffile->fd == STDOUT_FILENO ) {
			return 1;
		} else {
			LogError("lseek() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			close(nffile->fd);
			return 0;
		}
	}

	if ( ident ) {
		strncpy(nffile->file_header->ident, ident, IDENTLEN);
	} else {
		if ( strlen(nffile->file_header->ident) == 0 ) 
		strncpy(nffile->file_header->ident, IDENTNONE, IDENTLEN);
	}

	if ( write(nffile->fd, (void *)nffile->file_header, sizeof(file_header_t)) <= 0 ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
	}
	if ( write(nffile->fd, (void *)nffile->stat_record, sizeof(stat_record_t)) <= 0 ) {
		LogError("write() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
	}
	if ( close(nffile->fd) < 0 ) {
		LogError("close() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	nffile->file_header->NumBlocks = 0;
	
	return 1;

} /* End of CloseUpdateFile */

int ReadBlock(nffile_t *nffile) {
ssize_t ret, read_bytes, buff_bytes, request_size;
void 	*read_ptr;
uint32_t compression;

	ret = read(nffile->fd, nffile->block_header, sizeof(data_block_header_t));
	if ( ret == 0 )		// EOF
		return NF_EOF;
		
	if ( ret == -1 )	// ERROR
		return NF_ERROR;
		
	// Check for sane buffer size
	if ( ret != sizeof(data_block_header_t) ) {
		// this is most likely a corrupt file
		LogError("Corrupt data file: Read %i bytes, requested %u\n", ret, sizeof(data_block_header_t));
		return NF_CORRUPT;
	}

	// block header read successfully
	read_bytes = ret;

	// Check for sane buffer size
	if ( nffile->block_header->size > BUFFSIZE ) {
		// this is most likely a corrupt file
		LogError("Corrupt data file: Requested buffer size %u exceeds max. buffer size.\n", nffile->block_header->size);
		return NF_CORRUPT;
	}

	compression = FILE_COMPRESSION(nffile);
	ret = read(nffile->fd, nffile->buff_ptr, nffile->block_header->size);
	if ( ret == nffile->block_header->size ) {
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
		nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));
		return read_bytes + nffile->block_header->size;
	} 
			
	if ( ret == 0 ) {
		// EOF not expected here - this should never happen, file may be corrupt
		LogError("ReadBlock() Corrupt data file: Unexpected EOF while reading data block.\n");
		return NF_CORRUPT;
	}

	if ( ret == -1 ) {	// ERROR
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NF_ERROR;
	}

	// Ups! - ret is != block_header->size
	// this was a short read - most likely reading from the stdin pipe
	// loop until we have requested size

	buff_bytes 	 = ret;								// already in buffer
	request_size = nffile->block_header->size - buff_bytes;	// still to go for this amount of data

	read_ptr 	 = (void *)((pointer_addr_t)nffile->buff_ptr + buff_bytes);	
	do {
		ret = read(nffile->fd, read_ptr, request_size);
		if ( ret < 0 ) {
			// -1: Error - not expected
			LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NF_ERROR;
		}

		if ( ret == 0 ) {
			//  0: EOF   - not expected
			LogError("read() corrupt data file: Unexpected EOF in %s line %d: %s\n", __FILE__, __LINE__);
			return NF_CORRUPT;
		} 
		
		buff_bytes 	 += ret;
		request_size = nffile->block_header->size - buff_bytes;

		if ( request_size > 0 ) {
			// still a short read - continue in read loop
			read_ptr = (void *)((pointer_addr_t)nffile->buff_ptr + buff_bytes);
		}
	} while ( request_size > 0 );

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

	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->block_header + sizeof(data_block_header_t));
	return read_bytes + nffile->block_header->size;

} // End of ReadBlock

int WriteBlock(nffile_t *nffile) {
int ret, compression;

	// empty blocks need not to be stored 
	if ( nffile->block_header->size == 0 )
		return 1;

	compression = FILE_COMPRESSION(nffile);
	switch (compression) {
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

	ret = write(nffile->fd, (void *)nffile->block_header, sizeof(data_block_header_t) + nffile->block_header->size);
	if (ret > 0) {
		nffile->block_header->size = 0;
		nffile->block_header->NumRecords = 0;
		nffile->buff_ptr = (void *)((pointer_addr_t) nffile->block_header + sizeof (data_block_header_t));
		nffile->file_header->NumBlocks++;
	}
 	
	return ret;

} // End of WriteBlock

inline void ExpandRecord_v1(common_record_t *input_record, master_record_t *output_record ) {
uint32_t	*u;
size_t		size;
void		*p = (void *)input_record;

	// Copy common data block
	size = sizeof(common_record_t) - sizeof(uint8_t[4]);
	memcpy((void *)output_record, p, size);
	p = (void *)input_record->data;

	if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		// keep compiler happy
		// memcpy((void *)output_record->V6.srcaddr, p, 4 * sizeof(uint64_t));	
		memcpy((void *)output_record->ip_union._ip_64.addr, p, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		u = (uint32_t *)p;
		output_record->V6.srcaddr[0] = 0;
		output_record->V6.srcaddr[1] = 0;
		output_record->V4.srcaddr 	 = u[0];

		output_record->V6.dstaddr[0] = 0;
		output_record->V6.dstaddr[1] = 0;
		output_record->V4.dstaddr 	 = u[1];
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// packet counter
	if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// byte counter
	if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

} // End of ExpandRecord_v1

void ModifyCompressFile(char * rfile, char *Rfile, int compress) {
int 			i, anonymized, compression;
ssize_t			ret;
nffile_t		*nffile_r, *nffile_w;
stat_record_t	*_s;
char 			*filename, outfile[MAXPATHLEN];

	SetupInputFileSequence(NULL, rfile, Rfile);

	nffile_r = NULL;
	while (1) {
		nffile_r = GetNextFile(nffile_r, 0, 0);

		// last file
		if ( nffile_r == EMPTY_LIST )
			break;

		filename = GetCurrentFilename();

		if ( !nffile_r || !filename) {
			break;
		}
	
		compression = FILE_COMPRESSION(nffile_r);
		if ( compression == compress ) {
			printf("File %s is already same compression methode\n", filename);
			continue;
		}

		// tmp filename for new output file
		snprintf(outfile, MAXPATHLEN, "%s-tmp", filename);
		outfile[MAXPATHLEN-1] = '\0';

		anonymized = IP_ANONYMIZED(nffile_r);

		// allocate output file
		nffile_w = OpenNewFile(outfile, NULL, compress, anonymized, NULL);
		if ( !nffile_w ) {
			CloseFile(nffile_r);
			DisposeFile(nffile_r);
			break;;
		}

		// swap stat records :)
		_s = nffile_r->stat_record;
		nffile_r->stat_record = nffile_w->stat_record;
		nffile_w->stat_record = _s;
	
		for ( i=0; i < nffile_r->file_header->NumBlocks; i++ ) {
			ret = ReadBlock(nffile_r);
			if ( ret < 0 ) {
				LogError("Error while reading data block. Abort.\n");
				CloseFile(nffile_r);
				DisposeFile(nffile_r);
				CloseFile(nffile_w);
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
			nffile_r->buff_ptr = (void *)((pointer_addr_t)nffile_r->block_header + sizeof(data_block_header_t));

			if ( WriteBlock(nffile_w) <= 0 ) {
				LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
				CloseFile(nffile_r);
				DisposeFile(nffile_r);
				CloseFile(nffile_w);
				DisposeFile(nffile_w);
				unlink(outfile);
				return;
			}
		}

		printf("File %s compression changed\n", filename);
		if ( !CloseUpdateFile(nffile_w, nffile_r->file_header->ident) ) {
			unlink(outfile);
			LogError("Failed to close file: '%s'" , strerror(errno));
		} else {
			unlink(filename);
			rename(outfile, filename);
		}

		DisposeFile(nffile_w);
	}

} // End of ModifyCompressFile

void QueryFile(char *filename) {
int i;
nffile_t	*nffile;
uint32_t num_records, type1, type2, type3;
struct stat stat_buf;
ssize_t	ret;
off_t	fsize;

	if ( stat(filename, &stat_buf) ) {
		LogError("Can't stat '%s': %s\n", filename, strerror(errno));
		return;
	}

	nffile = OpenFile(filename, NULL);
	if ( !nffile ) {
		return;
	}

	num_records = 0;
	// set file size to current position ( file header )
	fsize = lseek(nffile->fd, 0, SEEK_CUR);
	type1 = 0;
	type2 = 0;
	type3 = 0;
	printf("File    : %s\n", filename);
	printf ("Version : %u - %s\n", nffile->file_header->version,
		FILE_IS_LZO_COMPRESSED (nffile) ? "lzo compressed" :
		FILE_IS_LZ4_COMPRESSED (nffile) ? "lz4 compressed" :
		FILE_IS_BZ2_COMPRESSED (nffile) ? "bz2 compressed" :
            "not compressed");

	printf("Blocks  : %u\n", nffile->file_header->NumBlocks);
	for ( i=0; i < nffile->file_header->NumBlocks; i++ ) {
		if ( (fsize + sizeof(data_block_header_t)) > stat_buf.st_size ) {
			LogError("Unexpected read beyond EOF! File corrupted. Abort.\n");
			LogError("Expected %u blocks, counted %i\n", nffile->file_header->NumBlocks, i);
			break;
		}
		ret = read(nffile->fd, (void *)nffile->block_header, sizeof(data_block_header_t));
		if ( ret < 0 ) {
			LogError("Error reading block %i: %s\n", i, strerror(errno));
			break;
		}

		// Should never happen, as catched already in first check, but test it anyway ..
		if ( ret == 0 ) {
			LogError("Unexpected end of file reached. Expected %u blocks, counted %i\n", nffile->file_header->NumBlocks, i);
			break;
		}
		if ( ret < sizeof(data_block_header_t) ) {
			LogError("Short read: Expected %u bytes, read: %i\n", sizeof(data_block_header_t), ret);
			break;
		}
		fsize += sizeof(data_block_header_t);

		num_records += nffile->block_header->NumRecords;
		switch ( nffile->block_header->id) {
			case DATA_BLOCK_TYPE_1:
				type1++;
				break;
			case DATA_BLOCK_TYPE_2:
				type2++;
				break;
			case Large_BLOCK_Type:
				type3++;
				break;
			default:
				printf("block %i has unknown type %u\n", i, nffile->block_header->id);
		}

		if ( (fsize + nffile->block_header->size ) > stat_buf.st_size ) {
			LogError("Expected to seek beyond EOF! File corrupted. Abort.\n");
			break;
		}
		fsize += nffile->block_header->size;
		
		ret = lseek(nffile->fd, nffile->block_header->size, SEEK_CUR);
		if ( ret < 0 ) {
			LogError("Error seeking block %i: %s\n", i, strerror(errno));
			break;
		}
		if ( fsize != ret ) {
			LogError("Expected seek: Expected: %u, got: %u\n", fsize, ret);
			break;
		}
	}

	if ( fsize < stat_buf.st_size ) {
		LogError("Extra data detected after regular blocks: %i bytes\n", stat_buf.st_size-fsize);
	}

	printf(" Type 1 : %u\n", type1);
	printf(" Type 2 : %u\n", type2);
	printf(" Type 3 : %u\n", type3);
	printf("Records : %u\n", num_records);

	CloseFile(nffile);
	DisposeFile(nffile);

} // End of QueryFile

// simple interface to get a statrecord from a file without nffile overhead
stat_record_t *GetStatRecord(char *filename, stat_record_t *stat_record) {
file_header_t file_header;
int fd, ret;

	fd = open(filename, O_RDONLY);
	if ( fd < 0 ) {
		LogError("open() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}

	ret = read(fd, (void *)&file_header, sizeof(file_header_t));
	if ( ret < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return NULL;
	}

	if ( file_header.magic != MAGIC ) {
		LogError("Open file '%s': bad magic: 0x%X\n", filename ? filename : "<stdin>", file_header.magic );
		close(fd);
		return NULL;
	}

	if ( file_header.version != LAYOUT_VERSION_1 ) {
		LogError("Open file %s: bad version: %u\n", filename, file_header.version );
		close(fd);
		return NULL;
	}

	ret = read(fd, (void *)stat_record, sizeof(stat_record_t));
	if ( ret < 0 ) {
		LogError("read() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(fd);
		return NULL;
	}

	close(fd);
	return stat_record;

} // End of GetStatRecord
