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
 *  $Id: bookkeeper.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 *
 */

#ifndef _BOOKKEEPER_H
#define _BOOKKEEPER_H 1

enum { BOOKKEEPER_OK = 0, ERR_FAILED, ERR_NOTEXISTS, ERR_PATHACCESS, ERR_EXISTS };

#define DETACH_ONLY	0
#define DESTROY_BOOKKEEPER 1

typedef struct bookkeeper_s {
	// collector infos
	pid_t		nfcapd_pid;
	pid_t		launcher_pid;

	// track info
	uint64_t	sequence;

	// file infos
	time_t		first;
	time_t		last;
	uint64_t	numfiles;
	uint64_t	filesize;
	uint64_t	max_filesize;
	uint64_t	max_lifetime;


} bookkeeper_t;

// All bookkeepers are put into a linked list, to have all the shm_id,sem_id
typedef struct bookkeeper_list_s {
	struct bookkeeper_list_s	*next;

	bookkeeper_t	*bookkeeper;
	
	// shared parameters
	int			sem_id;
	int			shm_id;

} bookkeeper_list_t;

/* function prototypes */
int InitBookkeeper(bookkeeper_t **bookkeeper, char *path, pid_t nfcapd_pid, pid_t launcher_pid);

int AccessBookkeeper(bookkeeper_t **bookkeeper, char *path);

void ReleaseBookkeeper(bookkeeper_t *bookkeeper, int destroy);

void ClearBooks(bookkeeper_t *bookkeeper, bookkeeper_t *tmp_books);

int  LookBooks(bookkeeper_t *bookkeeper);

int  UnlookBooks(bookkeeper_t *bookkeeper);

uint64_t BookSequence(bookkeeper_t *bookkeeper);

void UpdateBooks(bookkeeper_t *bookkeeper, time_t when, uint64_t size);

void UpdateBooksParam(bookkeeper_t *bookkeeper, time_t lifetime, uint64_t maxsize);

void PrintBooks(bookkeeper_t *bookkeeper);

#endif //_BOOKKEEPER_H
