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

#ifndef _NBAR_H
#define _NBAR_H 1

#include "config.h"

#include "fnf.h"
#include "nffile.h"

// record type definition
#define NbarRecordType		12

typedef struct nbarRecordHeader_s {
 	// record header
 	uint16_t	type;
 	uint16_t	size;
 	uint16_t	numElements;
 	uint16_t	fill;
} nbarRecordHeader_t;

#define NBAR_APPLICATION_DESC	94
#define NBAR_APPLICATION_ID		95
#define NBAR_APPLICATION_NAME	96

// var length extension
// size = sizeof nbarAppInfo_t + *_length
typedef struct NbarAppInfo_s {
#define NbarAppInfoID 1
	uint16_t app_id_length;
	uint16_t app_name_length;
	uint16_t app_desc_length;
	uint8_t data[1];
} NbarAppInfo_t;

typedef struct nbarOptionList_s {
	struct nbarOptionList_s *next;

	uint16_t 	tableID;
	uint16_t	scopeSize;
	optionTag_t id;
	optionTag_t name;
	optionTag_t desc;

} nbarOptionList_t;

#define AddNbarHeader(p, h) \
	nbarRecordHeader_t *h = (nbarRecordHeader_t *)p; \
	memset(h, 0, sizeof(nbarRecordHeader_t)); \
	h->type = NbarRecordType; \
	h->size = sizeof(nbarRecordHeader_t);

#define PushNbarVarLengthExtension(h, x, v, s) { \
	elementHeader_t *elementHeader = (elementHeader_t *)((void *)h + h->size); \
	elementHeader->type = x ## ID; \
	elementHeader->length = s; \
	h->size += sizeof(elementHeader_t); } \
	x ## _t *v = (x ## _t *)((void *)h + h->size); \
	memset(v, 0, s); \
	h->numElements++; \
	h->size += s;
	
int AddNbarRecord(nbarRecordHeader_t *nbarRecord);

char *GetNbarInfo(uint8_t *id, size_t size);

void DumpNbarList(void);

void PrintNbarRecord(nbarRecordHeader_t *nbarRecord);

#endif // _NBAR_H

