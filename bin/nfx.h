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
 *  $Id: nfx.h 48 2010-01-02 08:06:27Z haag $
 *
 *  $LastChangedRevision: 48 $
 *	
 */

#ifndef _NFX_H
#define _NFX_H 1

// MAX_EXTENSION_MAPS must be a power of 2 
#define MAX_EXTENSION_MAPS	65536
#define EXTENSION_MAP_MASK (MAX_EXTENSION_MAPS-1)

typedef struct extension_descriptor_s {
	uint16_t	id;			// id number
	uint16_t	size;		// number of bytes
	uint32_t	user_index;	// index specified by the user to enable this extension
	uint32_t	enabled;	// extension is enabled or not
	char		*description;
} extension_descriptor_t;

typedef struct extension_info_s {
	struct extension_info_s *next;
	extension_map_t	*map;
	uint32_t		ref_count;
	uint32_t		*offset_cache;
	master_record_t	master_record;
} extension_info_t;

typedef struct extension_map_list_s {
	extension_info_t	*slot[MAX_EXTENSION_MAPS];
	extension_info_t	*map_list;
	extension_info_t	**last_map;
	uint32_t			max_used;
} extension_map_list_t;

#define NEEDS_EXTENSION_LIST 1
#define NO_EXTENSION_LIST    0
extension_map_list_t *InitExtensionMaps(int AllocateList);

void FreeExtensionMaps(extension_map_list_t *extension_map_list);

void PackExtensionMapList(extension_map_list_t *extension_map_list);

int Insert_Extension_Map(extension_map_list_t *extension_map_list, extension_map_t *map);

void SetupExtensionDescriptors(char *options);

void PrintExtensionMap(extension_map_t *map);

int VerifyExtensionMap(extension_map_t *map);

void DumpExMaps(char *filename);

#endif //_NFX_H
