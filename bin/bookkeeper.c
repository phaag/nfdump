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
 *  $Id: bookkeeper.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef HAVE_SEMUN
union semun {
	int		val;			// value for SETVAL
	struct	semid_ds *buf;	// buffer for IPC_STAT & IPC_SET
	u_short	*array;			// array for GETALL & SETALL
};
#endif

#include "config.h"

#include "bookkeeper.h"

static bookkeeper_list_t *bookkeeper_list = NULL;

/* function prototypes */

/* 
 * bookkeeper.c is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps to the 
 * approriate logging channel - either stderr or syslog
 */
void LogError(char *format, ...);

static key_t _ftok(const char *path, int id);

static void sem_lock(int sem_set_id);

static void sem_unlock(int sem_set_id);

static inline bookkeeper_list_t *Get_bookkeeper_list_entry(bookkeeper_t *bookkeeper);

/* Create shared memory object and set its size */

/* our own ftok implementation - the standard C library ftok is not reliable enough */
static key_t _ftok(const char *path, int id) {
struct stat st;

    if (stat(path, &st) < 0)
        return (key_t)-1;

    return (key_t) ( ((st.st_dev & 0xffff) << 16) ^ st.st_ino ) + id;
}


// locks the semaphore, for exclusive access to the bookkeeping record
static void sem_lock(int sem_set_id) {
struct sembuf sem_op;

	/* wait on the semaphore, unless it's value is non-negative. */
	sem_op.sem_num =  0;
	sem_op.sem_op  = -1;
	sem_op.sem_flg =  0;
	if ( semop(sem_set_id, &sem_op, 1) == 0 )
		return;

	LogError("semop() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );

} // End of sem_lock

// sem_unlock. un-locks the semaphore.
static void sem_unlock(int sem_set_id) {
struct sembuf sem_op;

	/* signal the semaphore - increase its value by one. */
	sem_op.sem_num = 0;
	sem_op.sem_op  = 1;
	sem_op.sem_flg = 0;
	if ( semop(sem_set_id, &sem_op, 1) == 0 )
		return;

	LogError("semop() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );

} // End of sem_unlock

static inline bookkeeper_list_t *Get_bookkeeper_list_entry(bookkeeper_t *bookkeeper) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( bookkeeper == NULL ) 
		return NULL;

	bookkeeper_list_entry = bookkeeper_list;
	while ( bookkeeper_list_entry != NULL && bookkeeper_list_entry->bookkeeper != bookkeeper ) 
		bookkeeper_list_entry = bookkeeper_list_entry->next;

	return bookkeeper_list_entry;

} // End of Get_bookkeeper_list_entry

int InitBookkeeper(bookkeeper_t **bookkeeper, char *path, pid_t nfcapd_pid, pid_t launcher_pid) {
int sem_key, shm_key, shm_id, sem_id;
union semun sem_val;
bookkeeper_list_t	**bookkeeper_list_entry;

	*bookkeeper = NULL;

	shm_key = _ftok(path, 1); 
	if ( shm_key == - 1 ) 
		return ERR_PATHACCESS;

	// check if the shared memory is already allocated
	shm_id = shmget(shm_key, sizeof(bookkeeper_t), 0600);

	if ( shm_id >= 0 ) {
		// the segment already exists. Either a running process is active
		// or an unclean shutdown happened
		
		// map the segement and check the record
		*bookkeeper = (bookkeeper_t *)shmat(shm_id, NULL, 0);
		if ( *bookkeeper == (bookkeeper_t *)-1 ) {
			LogError("shmat() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAILED;
		}
		if ( (*bookkeeper)->nfcapd_pid <= 0 ) {
			// rubbish or invalid pid of nfcapd process.
			// Assume unclean shutdown or something else. We clean up and take this record.
			memset((void *)(*bookkeeper), 0, sizeof(bookkeeper_t));
		} else {
			// check if the process created this record is still alive
			int ret = kill((*bookkeeper)->nfcapd_pid, 0);
			if ( ret == - 1 ) {
				switch (errno) {
					case ESRCH:
						// process does not exist, we can clean up this record and use it
						memset((void *)(*bookkeeper), 0, sizeof(bookkeeper_t));
						break;
					case EPERM:
						// A process exists, but we are not allowed to signal this process
						LogError("Another collector with pid %i but different user ID is already running, and configured for '%s'",
							(*bookkeeper)->nfcapd_pid, path);
						return ERR_EXISTS;
						break;
					default:
						// This should never happen, but catch it anyway
						LogError("semop() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
						return ERR_FAILED;
				}
			} else {
				// process exists;
				LogError("Another collector with pid %i is already running, and configured for '%s'",
					(*bookkeeper)->nfcapd_pid, path);
				return ERR_EXISTS;
			}
			// if we pass this point, we have recycled an existing record

		}
	} else {
		// no valid shared segment was found
		switch (errno) {
			case ENOENT:
				// this is ok - no shared segemtn exists, we can create a new one below
				break;
			case EACCES:
				// there is such a segment, but we are not allowed to get it
				// Assume it's another nfcapd
				LogError("Access denied to collector bookkeeping record.");
				return ERR_EXISTS;
				break;
			default:
				// This should never happen, but catch it anyway
				LogError("semop() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				return ERR_FAILED;
		}
		// we now create a new segement, this hould not fail now
		shm_id = shmget(shm_key, sizeof(bookkeeper_t), IPC_CREAT | 0600);
		if ( shm_id == - 1 ) {
			// but did anyway - give up
			LogError("shmget() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAILED;
		}
		*bookkeeper = (bookkeeper_t *)shmat(shm_id, NULL, 0);
		if ( (*bookkeeper) == (bookkeeper_t *)-1 ) {
			LogError("shmget() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAILED;
		}
		memset((void *)(*bookkeeper), 0, sizeof(bookkeeper_t));
	}
	// at this point we now have a valid record and can proceed
	(*bookkeeper)->nfcapd_pid   = nfcapd_pid;
	(*bookkeeper)->launcher_pid = launcher_pid;
	(*bookkeeper)->sequence++;

	// create semaphore

	sem_key = _ftok(path, 2); 
	// this should never fail, as we aleady got a key for the shared memory
	if ( sem_key == - 1 ) {
		// .. but catch it anyway .. and release shared memory. something is fishy
		struct shmid_ds buf;
		shmdt((void *)(*bookkeeper));
		shmctl(shm_id, IPC_RMID, &buf);
		return ERR_FAILED;
	}
	
	// get the semaphore
	sem_id = semget(sem_key, 1, IPC_CREAT | 0600);
	if ( sem_id == - 1 ) {
		struct shmid_ds buf;

		// this should not have failed
		LogError("semget() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );

		// release shared memory 
		shmdt((void *)(*bookkeeper));
		shmctl(shm_id, IPC_RMID, &buf);
		return ERR_FAILED;
	}

	// initialize the semaphore
	sem_val.val = 1;
	if ( semctl(sem_id, 0, SETVAL, sem_val) == -1) {
		struct shmid_ds buf;

		// this should not have failed
		LogError("semctl() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );

		// release shared memory 
		shmdt((void *)(*bookkeeper));
		shmctl(shm_id, IPC_RMID, &buf);
		return ERR_FAILED;
	}

	bookkeeper_list_entry = &bookkeeper_list;
	while ( *bookkeeper_list_entry != NULL )
		bookkeeper_list_entry = &((*bookkeeper_list_entry)->next);

	(*bookkeeper_list_entry) = (bookkeeper_list_t *)malloc(sizeof(bookkeeper_list_t));
	if ( !*bookkeeper_list_entry ) {
		struct shmid_ds buf;

		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		shmdt((void *)(*bookkeeper));
		shmctl(shm_id, IPC_RMID, &buf);
		semctl( sem_id, 0, IPC_RMID );
		return ERR_FAILED;
	}
	memset((void *)*bookkeeper_list_entry, 0, sizeof(bookkeeper_list_t));

	(*bookkeeper_list_entry)->shm_id = shm_id;
	(*bookkeeper_list_entry)->sem_id = sem_id;
	(*bookkeeper_list_entry)->bookkeeper = *bookkeeper;
	(*bookkeeper_list_entry)->next = NULL;
	
	// we are done
	return BOOKKEEPER_OK;

} // End of InitBookkeeper

int AccessBookkeeper(bookkeeper_t **bookkeeper, char *path) {
bookkeeper_list_t	**bookkeeper_list_entry;
int sem_key, shm_key, shm_id, sem_id;

	*bookkeeper = NULL;

	shm_key = _ftok(path, 1); 
	if ( shm_key == - 1 ) 
		return ERR_PATHACCESS;

	// check if the shared memory is already allocated
	shm_id = shmget(shm_key, sizeof(bookkeeper_t), 0600);

	if ( shm_id < 0 ) {
		// the segment does not exists. Check why
		
		switch (errno) {
			case ENOENT:
				// no shared segemtn exists.
				return ERR_NOTEXISTS;
				break;
			case EACCES:
				// there is such a segment, but we are not allowed to get it
				// Assume it's another nfcapd
				LogError("Access denied to collector bookkeeping record.");
				return ERR_FAILED;
				break;
			default:
				// This should never happen, but catch it anyway
				LogError("semop() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
				return ERR_FAILED;
		}
		// not reached
	}
	// at this point we now have a valid record and can proceed

	// create semaphore
	sem_key = _ftok(path, 2); 
	// this should never fail, as we aleady got a key for the shared memory
	if ( sem_key == - 1 ) {
		// .. but catch it anyway .. and release shared memory. something is fishy
		return ERR_FAILED;
	}
	
	// get the semaphore
	sem_id = semget(sem_key, 1, 0600);
	if ( sem_id == - 1 ) {
		// this should not have failed
		LogError("semget() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );

		return ERR_FAILED;
	}

	// map the shared segment
	*bookkeeper = (bookkeeper_t *)shmat(shm_id, NULL, 0);
	if ( *bookkeeper == (bookkeeper_t *)-1 ) {
		LogError("shmat() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return ERR_FAILED;
	}

	bookkeeper_list_entry = &bookkeeper_list;
	while ( *bookkeeper_list_entry != NULL && (*bookkeeper_list_entry)->bookkeeper != NULL )
		bookkeeper_list_entry = &((*bookkeeper_list_entry)->next);

	// allocate new slot, else use unused slot
	if ( *bookkeeper_list_entry == NULL ) {
		(*bookkeeper_list_entry) = (bookkeeper_list_t *)malloc(sizeof(bookkeeper_list_t));
		if ( !*bookkeeper_list_entry ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return ERR_FAILED;
		}
		memset((void *)*bookkeeper_list_entry, 0, sizeof(bookkeeper_list_t));
	}

	(*bookkeeper_list_entry)->shm_id = shm_id;
	(*bookkeeper_list_entry)->sem_id = sem_id;
	(*bookkeeper_list_entry)->bookkeeper = *bookkeeper;
	(*bookkeeper_list_entry)->next = NULL;
	
	return BOOKKEEPER_OK;


} // End of AccessBookkeeper

void ReleaseBookkeeper(bookkeeper_t *bookkeeper, int destroy) {
bookkeeper_list_t	*bookkeeper_list_entry;
struct shmid_ds buf;

	if ( !bookkeeper )
		return;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return;
	}

	// detach from my process addr space memory
	if ( shmdt((void *)bookkeeper) == -1 ) {
		// ups .. 
		LogError("shmdt() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
	}
	bookkeeper = NULL;

	if ( destroy == 0 ) {
		// Entry no longer valid
		bookkeeper_list_entry->bookkeeper = NULL;
		bookkeeper_list_entry->shm_id = 0;
		bookkeeper_list_entry->sem_id = 0;
		return;
	}

	// prevent other proceeses to access the share memory, while we are removing it
	// try to clean up.
	sem_lock(bookkeeper_list_entry->sem_id);
	if ( shmctl(bookkeeper_list_entry->shm_id, IPC_RMID, &buf) ) {
		// ups .. 
		LogError("shmctl() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
	}
	sem_unlock(bookkeeper_list_entry->sem_id);

	if ( semctl( bookkeeper_list_entry->sem_id, 0, IPC_RMID ) == -1 ) {
		// ups .. 
		LogError("semctl() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
	}

	// Entry no longer valid
	bookkeeper_list_entry->bookkeeper = NULL;
	bookkeeper_list_entry->shm_id = 0;
	bookkeeper_list_entry->sem_id = 0;


} // End of ReleaseBookkeeper

int  LookBooks(bookkeeper_t *bookkeeper) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( !bookkeeper )
		return 0;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return 1;
	}

	sem_lock(bookkeeper_list_entry->sem_id);

	return 0;

} // End of LookBooks

int  UnlookBooks(bookkeeper_t *bookkeeper) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( !bookkeeper )
		return 0;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return 1;
	}

	sem_unlock(bookkeeper_list_entry->sem_id);

	return 0;

} // End of UnlookBooks

void ClearBooks(bookkeeper_t *bookkeeper, bookkeeper_t *tmp_books) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( !bookkeeper )
		return;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return;
	}

	sem_lock(bookkeeper_list_entry->sem_id);
	// backup copy
	if ( tmp_books != NULL ) {
		memcpy((void *)tmp_books, (void *)bookkeeper, sizeof(bookkeeper_t));
	}
	bookkeeper->first 	  = 0;
	bookkeeper->last  	  = 0;
	bookkeeper->numfiles  = 0;
	bookkeeper->filesize  = 0;
	bookkeeper->sequence++;
	sem_unlock(bookkeeper_list_entry->sem_id);

} // End of ClearBooks

uint64_t BookSequence(bookkeeper_t *bookkeeper) {
bookkeeper_list_t	*bookkeeper_list_entry;
uint64_t	seq;

	if ( !bookkeeper )
		return 0;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return 0;
	}

	sem_lock(bookkeeper_list_entry->sem_id);
	seq = bookkeeper->sequence;
	sem_unlock(bookkeeper_list_entry->sem_id);

	return seq;

} // End of BookSequence

void UpdateBooks(bookkeeper_t *bookkeeper, time_t when, uint64_t size) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( !bookkeeper )
		return;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return;
	}

	sem_lock(bookkeeper_list_entry->sem_id);
	if ( bookkeeper->first == 0 ) 
		bookkeeper->first = when;

	bookkeeper->last = when;
	bookkeeper->numfiles++;
	bookkeeper->filesize  += size;
	bookkeeper->sequence++;
	sem_unlock(bookkeeper_list_entry->sem_id);

} // End of UpdateBooks

void UpdateBooksParam(bookkeeper_t *bookkeeper, time_t lifetime, uint64_t maxsize) {
bookkeeper_list_t	*bookkeeper_list_entry;

	if ( !bookkeeper )
		return;

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return;
	}

	sem_lock(bookkeeper_list_entry->sem_id);
	bookkeeper->max_lifetime = lifetime;
	bookkeeper->max_filesize = maxsize;
	bookkeeper->sequence++;
	sem_unlock(bookkeeper_list_entry->sem_id);

} // End of UpdateBooksParam

void PrintBooks(bookkeeper_t *bookkeeper) {
bookkeeper_list_t	*bookkeeper_list_entry;
struct tm *ts;
time_t	t;
char	string[32];

	if ( !bookkeeper ) {
		printf("No bookkeeper record available!\n");
		return;
	}

	bookkeeper_list_entry = Get_bookkeeper_list_entry(bookkeeper);
	if ( !bookkeeper_list_entry ) {
		// this should never happen 
		LogError("Software error in %s line %d: %s", __FILE__, __LINE__, "Entry not found in list");
		return;
	}

	sem_lock(bookkeeper_list_entry->sem_id);
	printf("Collector process: %lu\n", (unsigned long)bookkeeper->nfcapd_pid);
	if ( bookkeeper->launcher_pid ) 
		printf("Launcher process: %lu\n", (unsigned long)bookkeeper->launcher_pid);
	else
		printf("Launcher process: <none>\n");
	printf("Record sequence : %llu\n", (unsigned long long)bookkeeper->sequence);

	t = bookkeeper->first;
    ts = localtime(&t);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
	string[31] = '\0';
	printf("First           : %s\n", bookkeeper->first ? string : "<not set>");

	t = bookkeeper->last;
    ts = localtime(&t);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
	string[31] = '\0';
	printf("Last            : %s\n", bookkeeper->last ? string : "<not set>");
	printf("Number of files : %llu\n", (unsigned long long)bookkeeper->numfiles);
	printf("Total file size : %llu\n", (unsigned long long)bookkeeper->filesize);
	printf("Max file size   : %llu\n", (unsigned long long)bookkeeper->max_filesize);
	printf("Max life time   : %llu\n", (unsigned long long)bookkeeper->max_lifetime);
	sem_unlock(bookkeeper_list_entry->sem_id);
		
} // End of PrintBooks

