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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nfxV3.h"

#include "inline.c"

static int calculateRecordLength(sequencer_t *sequencer, void *in, size_t inSize);

static void DumpHex(const void* data, size_t size);

static int calculateRecordLength(sequencer_t *sequencer, void *in, size_t inSize) {
uint32_t	ExtSize[MAXELEMENTS];

	memset((void *)ExtSize, 0, sizeof(ExtSize));

	uint32_t totalInputLength  = 0;
	uint32_t totalOutputLength = 0;

	dbg_printf("calculateRecordLength(): check %u sequences\n", sequencer->numSequences);
	// input/output length checks ok - move data
	for (int i=0; i<sequencer->numSequences; i++) {
		// check for dyn length element
		uint16_t inLength  = sequencer->sequenceTable[i].inputLength;
		uint32_t ExtID = sequencer->sequenceTable[i].extensionID;

		if (sequencer->sequenceTable[i].inputLength == 0xFFFF) { 	// dyn length
			uint16_t len = ((uint8_t *)in)[0];
			if ( len < 255 ) {
				inLength = len;
				in += 1;	// adjust var lenth field
				totalInputLength += 1;
				inSize -= 1;
			} else {
				inLength = Get_val16(in+1);
				in += 3;	// adjust var length fields
				totalInputLength += 3;
				inSize -= 3;
			}
			dbg_printf(" found var length field %u, type %u: -> %u\n",
				i, sequencer->sequenceTable[i].inputType, inLength);
			dbg_printf("   mapped to ext %u size %lu\n", 
				ExtID, sizeof(elementHeader_t) + inLength);
			// output size equals input size
			ExtSize[ExtID] = sizeof(elementHeader_t) + inLength;
		} else {
			dbg_printf(" fixed length field %u, type %u: -> %u\n",
				i, sequencer->sequenceTable[i].inputType, inLength);
			dbg_printf("   mapped to ext %u size %u\n", 
				ExtID, extensionTable[ExtID].size);
			ExtSize[ExtID] = extensionTable[ExtID].size;
		}
		
		// input data length error
		if ( inSize < inLength ) {
			LogError(" inSize(%u) < inLength(%u) in %s line %d", 
				inSize, inLength, __FILE__, __LINE__);
			return 0;
		}

		inSize -= inLength;
		totalInputLength += inLength;
		in += inLength;
	}

	for (int i=1; i<MAXELEMENTS; i++ ) {
		totalOutputLength += ExtSize[i];
	}

	dbg_printf("calculateRecordLength(): Calculated input length: %u, output length: %u\n",
		totalInputLength, totalOutputLength);

	sequencer->inLength  = totalInputLength;
	sequencer->outLength = totalOutputLength;

	return 1;
} // End of calculateRecordLength

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
	sequencer->hasVarLength  = false;
	sequencer->inLength  = 0;
	sequencer->outLength = 0;

	CompactSequencer(sequencer);

	for (int i=0; i<sequencer->numSequences; i++ ) {
		uint32_t ExtID = sequencer->sequenceTable[i].extensionID;
		if ( sequencer->sequenceTable[i].inputLength == VARLENGTH ) {
			sequencer->hasVarLength = true;
		} else {
			sequencer->inLength += sequencer->sequenceTable[i].inputLength;
		}
		// output byte array, but fixed length due to fixed input length
		if ( sequencer->sequenceTable[i].outputLength == VARLENGTH && sequencer->sequenceTable[i].inputLength != VARLENGTH ) {
			sequencer->sequenceTable[i].outputLength = sequencer->sequenceTable[i].inputLength;
			sequencer->ExtSize[ExtID] = sequencer->sequenceTable[i].outputLength + sizeof(elementHeader_t);
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

	if ( sequencer->hasVarLength ) {
		sequencer->inLength = 0;
		sequencer->outLength = 0;
		dbg_printf("SetupSequencer() has varLength fields, found %u elements in %u sequences\n",
			sequencer->numElements, sequencer->numSequences);
	} else {
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

	if ( sequencer->hasVarLength && !calculateRecordLength(sequencer, in, inSize)) {
		return 0;
	} 

	dbg_printf("CalcOutRecordSize: %lu - %s\n", 
		sequencer->outLength, sequencer->hasVarLength ? "varLength" : "static");
	return sequencer->outLength;

} // End of OutRecordSize

// SequencerRun requires calling CalcOutRecordSize first 
int SequencerRun(sequencer_t *sequencer, void *inBuff, size_t inSize, void *outBuff, size_t outSize, uint64_t *stack) {

	if (sequencer->inLength > inSize) {
		LogError("SequencerRun() Skip processing input stream. Expected %u bytes, available %u bytes",
			sequencer->inLength, inSize);
		return 0;
	}

	if (sequencer->outLength > outSize) {
		LogError("SequencerRun() Skip processing input stream. Required %u out bytes, available %u out bytes",
			sequencer->outLength, outSize);
		return 0;
	}

	// clear cache
	memset((void *)sequencer->offsetCache, 0, MAXELEMENTS * sizeof(void *));

	uint32_t totalInLength  = 0;
	uint32_t totalOutLength = 0;
	// input/output length checks ok - move data
	dbg_printf("Run sequencer with %u sequences\n", sequencer->numSequences);
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
				inSize -= 1;
			} else {
				inLength = Get_val16(inBuff+1);
				inBuff += 3;	// adjust var length fields
				totalInLength += 3;
				inSize -= 3;
			}
			outLength = inLength;
			dbg_printf("Sequencer process var length field %u: true length: %u\n", 
				sequencer->sequenceTable[i].inputType, inLength);
		}

		// check output extension
		// ExtID 0 == skip input
		uint32_t ExtID   = sequencer->sequenceTable[i].extensionID;
		uint32_t stackID = sequencer->sequenceTable[i].stackID;

		// check for skip sequence
		if ( ExtID == EXnull && stackID == 0 ) {
#ifdef DEVEL
			printf("[%i] Skip element %u, length %u: ",
				i, sequencer->sequenceTable[i].inputType, inLength);
			DumpHex(inBuff,inLength);
#endif
			inBuff += inLength;
			inSize -= inLength;
			totalInLength += inLength;
			continue;
		}

		void *outRecord = sequencer->offsetCache[ExtID];
		if ( outRecord == NULL && ExtID != EXnull ) {
			// push element header
			elementHeader_t *elementHeader = (elementHeader_t *)outBuff;
			elementHeader->type = extensionTable[ExtID].id;
			outBuff += sizeof(elementHeader_t);

			// check for dyn length
			if (sequencer->sequenceTable[i].outputLength == VARLENGTH ) { 	// dyn length out record
				outLength = inLength;
				memset(outBuff, 0, outLength);
				elementHeader->length = sizeof(elementHeader_t) + outLength;
				sequencer->offsetCache[ExtID] = outRecord = outBuff;
				outBuff += outLength;
				totalOutLength += (sizeof(elementHeader_t) + outLength);
			} else {
				memset(outBuff, 0, sequencer->ExtSize[ExtID] - sizeof(elementHeader_t));
				elementHeader->length = sequencer->ExtSize[ExtID];
				sequencer->offsetCache[ExtID] = outRecord = outBuff;
				outBuff += sequencer->ExtSize[ExtID] - sizeof(elementHeader_t);
				totalOutLength += sequencer->ExtSize[ExtID];
			}
		}

		// check for placeholder sequence
		if (inLength == 0) {
			dbg_printf("[%i] put placeholder for extension: %u %s\n",
				i, ExtID, extensionTable[ExtID].name );
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
				printf("[%i] Read length: %u, val: %llu, outLength: %u\n", 
					i, sequencer->sequenceTable[i].inputLength, (long long unsigned)v, outLength);

			if ( sequencer->sequenceTable[i].inputLength == 16 )
				printf("[%i] Read length: %u, val: %llx %llx, outLength: %u\n",
					i, sequencer->sequenceTable[i].inputLength, (long long unsigned)vv[0], (long long unsigned)vv[1], outLength);
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
		inSize -= inLength;
		totalInLength += inLength;
	}

	int ret = 1;
	if ( totalInLength != sequencer->inLength ) {
		dbg_printf("SequencerRun() Error processing input stream. Expected %lu bytes, processed %u bytes\n",
			sequencer->inLength, totalInLength);
		ret = 0;
	}
	if ( totalOutLength != sequencer->outLength ) {
		dbg_printf("SequencerRun() Error processing output stream. Expected %lu bytes, processed %u bytes\n",
			sequencer->outLength, totalOutLength);
		ret = 0;
	}

	dbg_printf("SequencerRun() ended. inputLength: %u, outputLength: %u, returns %d\n",
		totalInLength, totalOutLength, ret);

	return ret;
} // End of sequencerRun

void PrintSequencer(sequencer_t *sequencer) {

	printf("Max elements  : %i\n", MAXELEMENTS);
	printf("Num elements  : %u\n", sequencer->numElements);
	printf("Num sequences : %u\n", sequencer->numSequences);
	printf("Has VarLength : %s\n", sequencer->hasVarLength ? "true" : "false");
	printf("Inlength      : %lu\n", sequencer->inLength);
	printf("Outlength     : %lu\n", sequencer->outLength);
	printf("Sequences\n");
	for (int i=0; i<sequencer->numSequences; i++) {
		printf("[%u] inputType: %u, inputLength: %d, extensionID: %u, outputLength: %u, offsetRel: %lu, stackID: %u\n",
		i, sequencer->sequenceTable[i].inputType, sequencer->sequenceTable[i].inputLength,
		sequencer->sequenceTable[i].extensionID, sequencer->sequenceTable[i].outputLength,
		sequencer->sequenceTable[i].offsetRel, sequencer->sequenceTable[i].stackID);
	}
	printf("\n");
}
