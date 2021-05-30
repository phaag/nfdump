/*
 *  Copyright (c) 2021, Peter Haag
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "util.h"
#include "nfdump.h"
#include "nfxV3.h"

// sub template IDs
#define subTemplateListType				292
#define subTemplateMultiListType		293

#include "inline.c"


static void DumpHex(const void* data, size_t size);

__attribute__((unused)) static void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

static void CompactSequencer(sequencer_t *sequencer) {

	int i = 0;
	while ( i < sequencer->numSequences ) {
		if ( sequencer->sequenceTable[i].inputType || ( sequencer->sequenceTable[i].inputLength == 0xFFFF )) {
			i++;
			continue;
		}
		int j = i+1;
		while ( j < sequencer->numSequences ) {
			if ( sequencer->sequenceTable[j].inputType == 0 && sequencer->sequenceTable[j].inputLength != 0xFFFF ) {
				 sequencer->sequenceTable[i].inputLength += sequencer->sequenceTable[j].inputLength;
				j++;
			} else {
				break;
			}
		}
		int k = i+1;
		while ( j < sequencer->numSequences ) {
			sequencer->sequenceTable[k] = sequencer->sequenceTable[j];
			k++; j++;
		}
		i++;
		sequencer->numSequences -= (j-k);
	}

} // End of CompactSequencer

uint16_t *SetupSequencer(sequencer_t *sequencer, sequence_t *sequenceTable, uint32_t numSequences) {

	memset((void *)sequencer->ExtSize, 0, sizeof(sequencer->ExtSize));

	sequencer->sequenceTable = sequenceTable;
	sequencer->numSequences  = numSequences;
	sequencer->inLength		 = 0;
	sequencer->outLength	 = 0;

	CompactSequencer(sequencer);

	int hasVarInLength = 0;
	int hasVarOutLength = 0;
	for (int i=0; i<sequencer->numSequences; i++ ) {
		uint32_t ExtID = sequencer->sequenceTable[i].extensionID;
		if ( sequencer->sequenceTable[i].inputLength == VARLENGTH ) {
			hasVarInLength = 1;
		} else {
			sequencer->inLength += sequencer->sequenceTable[i].inputLength;
		}
		// output byte array, but fixed length due to fixed input length
		if ( sequencer->sequenceTable[i].outputLength == VARLENGTH ) {
			if ( sequencer->sequenceTable[i].inputLength != VARLENGTH ) {
				sequencer->sequenceTable[i].outputLength = sequencer->sequenceTable[i].inputLength;
				sequencer->ExtSize[ExtID] = sequencer->sequenceTable[i].outputLength + extensionTable[ExtID].size;
			} else {
				sequencer->ExtSize[ExtID] = extensionTable[ExtID].size;
				hasVarOutLength = 1;
			}
		} else {
			sequencer->ExtSize[ExtID] = extensionTable[ExtID].size;
		}
	}

	sequencer->numElements = 0;
	for (int i=1; i<MAXELEMENTS; i++ ) {
		if ( sequencer->ExtSize[i] ) {
			sequencer->outLength += sequencer->ExtSize[i];
			sequencer->numElements++;
		}
	}

	if ( hasVarInLength ) {
		sequencer->inLength = 0;
		dbg_printf("SetupSequencer() has varLength input fields, found %u elements in %u sequences\n",
			sequencer->numElements, sequencer->numSequences);
	} 
	if ( hasVarOutLength ) {
		sequencer->outLength = 0;
		dbg_printf("SetupSequencer() has varLength output fields, found %u elements in %u sequences\n",
			sequencer->numElements, sequencer->numSequences);
	} 
	if (!hasVarInLength && !hasVarOutLength) {
		dbg_printf("SetupSequencer() Fixed length fields, found %u elements in %u sequences\n",
			sequencer->numElements, sequencer->numSequences);
		dbg_printf("SetupSequencer() Calculated input length: %lu, output length: %lu\n",
			sequencer->inLength, sequencer->outLength);
	}

	// dynamically create extension list
	dbg_printf("Extensionlist:\n");
	uint16_t *extensionList = calloc(sequencer->numElements, sizeof(uint16_t));
	if ( !extensionList ) {
		LogError("SetupSequencer: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	int j = 0;
	for (int i=1; i<MAXELEMENTS; i++ ) {
		if ( sequencer->ExtSize[i] ) {
			dbg_printf("%u -> %d %s size: %u\n", j, i, extensionTable[i].name, sequencer->ExtSize[i]);
			extensionList[j++] = i;
		}
	}

	return extensionList;

} // End of SetupSequencer

void ClearSequencer(sequencer_t *sequencer) {

	if ( sequencer->sequenceTable )
		free(sequencer->sequenceTable);

	memset((void *)sequencer, 0, sizeof(sequencer_t));

} // End of ClearSequencer

int CalcOutRecordSize(sequencer_t *sequencer, void *in, size_t inSize) {

	int length;
	if ( sequencer->outLength == 0 ) {
		length = 1024;
		dbg_printf("Dyn record length: %u\n", length);
	} else {
		length = sequencer->outLength;
		dbg_printf("Fix record length: %u\n", length);
	}

	return length;

} // End of OutRecordSize

static sequencer_t *GetSubTemplateSequencer(sequencer_t *sequencer, uint16_t templateID) {
	sequencer_t *self = sequencer;
	while (sequencer->next != self && sequencer->templateID != templateID) {
		sequencer = sequencer->next;
	}

	if ( sequencer->templateID == templateID ) {
		dbg_printf("Sub template sequencer found for id: %u %u\n", templateID, sequencer->templateID);
		return sequencer;
	} else {
		dbg_printf("No sub template sequencer found for id: %u\n", templateID);
		return NULL;
	}
}

static int ProcessSubTemplate(sequencer_t *sequencer, uint16_t type, 
	void *inBuff, uint16_t inLength, void *outBuff, size_t outSize, uint64_t *stack) {

	if ( inLength < 1 )
		return SEQ_ERROR;

#ifdef DEVEL
	printf("Process sub template\n");
	uint8_t Semantic = *((uint8_t *)inBuff);
#endif
	inBuff++;
	inLength--;
	if ( type == subTemplateMultiListType ) {
		dbg_printf("Semantic multilist template: %u\n", Semantic);
		while ( inLength > 4 ) {
			uint16_t subTemplateID   = ntohs(*((uint16_t *)inBuff));
			uint16_t subTemplateSize = ntohs(*((uint16_t *)(inBuff+2)));
			if ( subTemplateSize > inLength ) 
				return SEQ_ERROR;

			dbg_printf(" Sub template ID: %u, length: %u\n", subTemplateID, subTemplateSize);
			sequencer_t *subSequencer = GetSubTemplateSequencer(sequencer, subTemplateID);
			if ( subSequencer ) {
				int ret = SequencerRun(subSequencer, inBuff+4, subTemplateSize, outBuff, outSize, stack);
				sequencer->outLength += subSequencer->outLength;
				dbg_printf("Sub sequencer returns: %d, processed inLength: %zu, outLength: %zu\n", 
					ret, subSequencer->inLength, subSequencer->outLength);
				if ( ret != SEQ_OK )
					return ret;
			} else {
				dbg_printf("No sub sequencer for id: %d\n", subTemplateID);
			}

			inBuff += subTemplateSize;
			inLength -= subTemplateSize;
		}
		dbg_printf("End of multilist processing\n");
	} else if ( type == subTemplateListType ) {
		dbg_printf("Semantic sub template: %u\n", Semantic);
		if ( inLength < 2 )
			return SEQ_ERROR;

		uint16_t subTemplateID = ntohs(*((uint16_t *)inBuff));
		dbg_printf(" Sub template ID: %u\n", subTemplateID);
		sequencer_t *subSequencer = GetSubTemplateSequencer(sequencer, subTemplateID);
		if ( subSequencer ) {
			int ret = SequencerRun(subSequencer, inBuff+2, inLength-2, outBuff, outSize, stack);
			dbg_printf("Sub sequencer returns: %d\n", ret);
			if ( ret != SEQ_OK )
				return ret;
		} else {
			dbg_printf("No sub sequencer for id: %d\n", subTemplateID);
		}
		dbg_printf("End of single list processing\n");
	} else {
		dbg_printf("Skipped unknown sub template: %u\n", type);
	}

	return SEQ_OK;

} // End of ProcessSubTemplate


// SequencerRun requires calling CalcOutRecordSize first 
int SequencerRun(sequencer_t *sequencer, void *inBuff, size_t inSize, void *outBuff, size_t outSize, uint64_t *stack) {
static int nestLevel = 0;

	nestLevel++;
	dbg_printf("[%u] Run sequencer ID: %u, inSize: %zu, outSize: %zu\n", 
		nestLevel, sequencer->templateID, inSize, outSize);

	if ( inSize == 0 ) {
		dbg_printf("[%u] End sequencer ID: %u, Skip 0 input stream\n", nestLevel, sequencer->templateID);
		nestLevel--;
		return SEQ_OK;
	}

	if ( nestLevel > 16 ) {
		LogError("SequencerRun() sub template run nested too deeply");
		nestLevel--;
		return SEQ_ERROR;
	}

	recordHeaderV3_t *recordHeaderV3 = (recordHeaderV3_t *)outBuff;
	dbg_printf("[%u] v3 header size: %u\n", nestLevel, recordHeaderV3->size);

	// clear cache
	memset((void *)sequencer->offsetCache, 0, MAXELEMENTS * sizeof(void *));

	uint32_t totalInLength  = 0;
	uint32_t totalOutLength = 0;
	// input/output length checks ok - move data
	dbg_printf("[%u] Run sequencer with %u sequences\n", nestLevel, sequencer->numSequences);

	for (int i=0; i<sequencer->numSequences; i++) {
		// check for dyn length element
		uint16_t inLength  = sequencer->sequenceTable[i].inputLength;
		uint16_t outLength = sequencer->sequenceTable[i].outputLength;
		bool varLength = sequencer->sequenceTable[i].inputLength == VARLENGTH;
		if (varLength) { 	// dyn length
			uint16_t len = ((uint8_t *)inBuff)[0];
			if ( len < 255 ) {
				inLength = len;
				inBuff += 1;	// adjust var length field
				totalInLength += 1;
			} else {
				inLength = Get_val16(inBuff+1);
				inBuff += 3;	// adjust var length fields
				totalInLength += 3;
			}
			dbg_printf("Sequencer process var length field %u: true length: %u\n", 
				sequencer->sequenceTable[i].inputType, inLength);
		}

		if ( (totalInLength + inLength) > inSize) {
			LogError("SequencerRun() ERROR - Attempt to read beyond input stream size");
			dbg_printf("Attempt to read beyond input stream size: total: %u, inLength: %u, inSize: %zu\n", 
				totalInLength, inLength, inSize);
			nestLevel--;
			return SEQ_ERROR;
		}

		// check output extension
		// ExtID 0 == skip input
		uint32_t ExtID   = sequencer->sequenceTable[i].extensionID;
		uint32_t stackID = sequencer->sequenceTable[i].stackID;

		// check for skip sequence
		if ( ExtID == EXnull && stackID == 0 ) {
			uint16_t type = sequencer->sequenceTable[i].inputType;
#ifdef DEVEL
			DumpHex(inBuff,inLength);
#endif
			if (type == subTemplateListType || type == subTemplateMultiListType) {
				dbg_printf("[%i:%i] Sub template %u, length %u: \n", nestLevel, i, type, inLength);
				int ret = ProcessSubTemplate(sequencer, type, inBuff, inLength, outBuff, outSize, stack);
				if ( ret != SEQ_OK ) {
					nestLevel--;
					return ret;
				}
			} else {
				dbg_printf("[%i:%i] Skip element %u, length %u: \n",
					nestLevel, i, type, inLength);
				dbg_printf("Dump skip element length: %u\n", inLength);
			}
			inBuff += inLength;
			totalInLength += inLength;
			continue;
		}

		void *outRecord = sequencer->offsetCache[ExtID];
		if ( outRecord == NULL && ExtID != EXnull ) {
			// check for dyn length
			size_t elementSize;
			if (sequencer->sequenceTable[i].outputLength == VARLENGTH ) { 	// dyn length out record
				outLength = inLength;
				elementSize = sequencer->ExtSize[ExtID] + outLength;
			} else {
				elementSize = sequencer->ExtSize[ExtID];
			}

			if ( (recordHeaderV3->size + elementSize) > outSize ) {
				dbg_printf("Size error add output element: header size: %u, element size: %zu, output size: %zu\n", 
					recordHeaderV3->size, elementSize, outSize);
				nestLevel--;
				return SEQ_MEM_ERR;
			} else {
				dbg_printf("Add output element at: header size: %u, element size: %zu, output size: %zu\n", 
					recordHeaderV3->size, elementSize, outSize);
			}

			outRecord = outBuff + recordHeaderV3->size;
			memset(outRecord, 0, elementSize);
			elementHeader_t *elementHeader = (elementHeader_t *)outRecord;
			outRecord += sizeof(elementHeader_t);

			elementHeader->type   = extensionTable[ExtID].id;
			elementHeader->length = elementSize;
			dbg_printf("Add output element ID: %u, size: %u\n", elementHeader->type, elementHeader->length);
			sequencer->offsetCache[ExtID] = outRecord;
			
			recordHeaderV3->size += elementSize;
			recordHeaderV3->numElements++;

			totalOutLength += elementSize;
		}

		// check for placeholder sequence
		if (inLength == 0) {
			dbg_printf("[%i:%i] put placeholder for extension: %u %s\n",
				nestLevel, i, ExtID, extensionTable[ExtID].name );
			continue;
		}

		if ( varLength == true || sequencer->sequenceTable[i].copyMode == ByteCopy || inLength > 16 ) {
			uint8_t *out = (uint8_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
			if ( inLength == outLength ) {
				memcpy(out, inBuff, inLength);
			} else {
				size_t copyLen = inLength < outLength ? inLength : outLength;
				memcpy(out, inBuff, copyLen);
			}
		} else {
			uint64_t v;		// up to 8 bytes
			uint64_t vv[2];	// 16 bytes
			v = 0;
			memset(vv, 0, sizeof(vv));
			switch (inLength) {
				case 1:
					v = ((uint8_t *)inBuff)[0]; break;
				case 2:
					v = Get_val16(inBuff); break;
				case 3:
					v = Get_val24(inBuff); break;
				case 4:
					v = Get_val32(inBuff); break;
				case 5:
					v = Get_val40(inBuff); break;
				case 6:
					v = Get_val48(inBuff); break;
				case 7:
					v = Get_val56(inBuff); break;
				case 8:
					v = Get_val64(inBuff); break;
				case 16:
					vv[0] = Get_val64(inBuff);
					vv[1] = Get_val64(inBuff+8);
					break;
				default:
					// for length 9, 10, 11 and 12
					memcpy(vv, inBuff, inLength); break;
			}
#ifdef DEVEL
			if ( sequencer->sequenceTable[i].inputLength <= 8 )
				printf("[%i] Type: %u, read length: %u, val: %llu, outLength: %u\n", 
					i, sequencer->sequenceTable[i].inputType, sequencer->sequenceTable[i].inputLength, (long long unsigned)v, outLength);

			if ( sequencer->sequenceTable[i].inputLength == 16 )
				printf("[%i] Type: %u, read length: %u, val: %llx %llx, outLength: %u\n",
					i, sequencer->sequenceTable[i].inputType, sequencer->sequenceTable[i].inputLength, (long long unsigned)vv[0], (long long unsigned)vv[1], outLength);
#endif
			if ( stackID && stack ) {
				stack[stackID] = v;
				dbg_printf("Stack value %llu in slot %u\n", (long long unsigned)v, stackID);
			}

			switch (outLength) {
				case 0:
					// do not store this value - use this to stack a value
					dbg_printf("No output for sequence %i\n", i);
					break;
				case 1: {
					uint8_t *d = (uint8_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					*d = v;
					} break;
				case 2: {
					uint16_t *d = (uint16_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					*d = v;
					} break;
				case 4: {
					uint32_t *d = (uint32_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					*d = v;
					} break;
				case 8: {
					uint64_t *d = (uint64_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					*d = v;
					} break;
				case 16: {
					uint64_t *d = (uint64_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					memcpy(d, vv, 16);
					} break;
				default: {
					// for length 9, 10, 11 and 12
					uint8_t *d = (uint8_t *)(outRecord + sequencer->sequenceTable[i].offsetRel);
					uint32_t copyLen = inLength < outLength ? inLength : outLength;
					memcpy(d, vv, copyLen);
				}
			}
		}

		inBuff += inLength;
		totalInLength += inLength;
	}

	nestLevel--;
#ifdef DEVEL
	printf("[%u] End sequencer ID: %u, inputLength: %lu, processed: %u, outputLength: %u header size: %u\n",
		nestLevel, sequencer->templateID, inSize, totalInLength, totalOutLength, recordHeaderV3->size);
#endif

	sequencer->inLength  = totalInLength;
	sequencer->outLength = totalOutLength;

	return SEQ_OK;
} // End of SequencerRun

void PrintSequencer(sequencer_t *sequencer) {

	printf("TemplateID       : %u\n", sequencer->templateID);
	printf("Max elements     : %i\n", MAXELEMENTS);
	printf("Num elements     : %u\n", sequencer->numElements);
	printf("Num sequences    : %u\n", sequencer->numSequences);
	printf("Has VarInLength  : %s\n", sequencer->inLength == 0 ? "true" : "false");
	printf("Has VarOutLength : %s\n", sequencer->outLength == 0 ? "true" : "false");
	printf("Inlength         : %lu\n", sequencer->inLength);
	printf("Outlength        : %lu\n", sequencer->outLength);
	printf("Sequences\n");
	for (int i=0; i<sequencer->numSequences; i++) {
		int extID = sequencer->sequenceTable[i].extensionID;
		printf("[%u] inputType: %u, inputLength: %d, extension: %s(%u), outputLength: %u, offsetRel: %lu, stackID: %u\n",
		i, sequencer->sequenceTable[i].inputType, sequencer->sequenceTable[i].inputLength,
		extensionTable[extID].name, extID, sequencer->sequenceTable[i].outputLength,
		sequencer->sequenceTable[i].offsetRel, sequencer->sequenceTable[i].stackID);
	}
	printf("\n");
}
