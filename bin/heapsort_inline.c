/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: heapsort_inline.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *  
 */

static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN);

static inline void siftDown(SortElement_t *SortElement, uint32_t root, uint32_t bottom);

static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN) {
int32_t	i, maxindex;

	for(i = array_size - 1; i >= 0; i--)
		siftDown(SortElement,array_size,i);

	/* 
	 * we are only interested in the first top N => skip sorting the rest
	 * For topN == 0 -> all flows gets sorted
	 */
    if ( (topN >= (array_size - 1)) || topN == 0 )
        maxindex = 0;
    else
        maxindex = array_size - 1 - topN;

	for(i = array_size-1; i > maxindex; i-- ) {
		SortElement_t temp = SortElement[0];
		SortElement[0] = SortElement[i];
		SortElement[i] = temp;
		siftDown(SortElement,i,0);
	}

} // End of heapSort

static inline void siftDown(SortElement_t *SortElement, uint32_t numbersSize, uint32_t node) {
uint32_t i, parent, child;

    parent = node;
    i = parent + 1;
    while( i != parent ) {
        i = parent;

        // Compare with left child node
		child = 2*i+1;
        if( (child) < numbersSize && SortElement[child].count > SortElement[parent].count)
            parent = child;

        // Compare with right child node
		child = 2*i+2;
        if( (child) < numbersSize && SortElement[child].count > SortElement[parent].count)
            parent = child;

        if ( i != parent ) {
            SortElement_t temp = SortElement[i];
            SortElement[i] = SortElement[parent];
            SortElement[parent] = temp;
        }
    }
} // End of siftDown
