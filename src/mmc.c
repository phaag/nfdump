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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "util.h"
#include "nffile.h"
#include "maxmind.h"

static void usage(char *name) {
        printf("usage %s [options] \n"
                    "-h\t\tthis text you see right here\n"
                    "-d <dir>\tDirectory containing the maxmind .csv files.\n"
                    "-w <file>\tName of output file.\n"
                    , name);
} /* usage */

static int LoadMaps(char *dirName) {

	DIR *dp = opendir (dirName);
	if (dp == NULL) {
		LogError("opendir() error: %s", strerror(errno));
		return 0;
	}
	char *cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		LogError("getcwd() error: %s", strerror(errno));
		return 0;
	}
	if (chdir(dirName) < 0) {
		LogError("chdir() error: %s", strerror(errno));
		return 0;
	}
	char *CityLocationFile   = NULL;
	char *CityBlocksIPv4File = NULL;
	char *CityBlocksIPv6File = NULL;
	char *ASNBlocksIPv4File  = NULL;
	char *ASNBlocksIPv6File  = NULL;
	struct dirent *ep;
	for (ep = readdir(dp); ep != NULL; ep = readdir(dp)) {
		struct stat stat_buf;
		if (stat(ep->d_name, &stat_buf) < 0) {
			LogError("stat() error: %s", strerror(errno));
			return 0;
		}
		if (!S_ISREG(stat_buf.st_mode) ) {
            LogError("Skip non file entry: %s", ep->d_name);
            continue;
        }
		char *extension = strstr(ep->d_name, ".csv");
		if (extension == NULL) {
			LogError("Skip non .csv file: %s",  ep->d_name);
			continue;
		}
		if (strstr(ep->d_name, "-City-Locations-") != NULL)
			CityLocationFile = strdup(ep->d_name);
		else if (strstr(ep->d_name, "-City-Blocks-IPv4.csv") != NULL)
			CityBlocksIPv4File = strdup(ep->d_name);
		else if (strstr(ep->d_name, "-City-Blocks-IPv6.csv") != NULL)
			CityBlocksIPv6File = strdup(ep->d_name);
		else if (strstr(ep->d_name, "-ASN-Blocks-IPv4.csv") != NULL)
			ASNBlocksIPv4File = strdup(ep->d_name);
		else if (strstr(ep->d_name, "-ASN-Blocks-IPv6.csv") != NULL)
			ASNBlocksIPv6File = strdup(ep->d_name);

		printf("Found entry: %s\n", ep->d_name);
	}
	closedir(dp);
	
	if (CityLocationFile) {
		loadLocalMap(CityLocationFile);
		printf("Local map loaded\n");
	}
	if (CityBlocksIPv4File) {
		loadIPV4tree(CityBlocksIPv4File);
		printf("IP Tree loaded\n");
	}
	if (CityBlocksIPv6File) {
		loadIPV6tree(CityBlocksIPv6File);
		printf("IP Tree loaded\n");
	}
	if (ASNBlocksIPv4File) {
		loadASV4tree(ASNBlocksIPv4File);
		printf("AS Tree loaded\n");
	}
	if (ASNBlocksIPv6File) {
		loadASV6tree(ASNBlocksIPv6File);
		printf("ASV6 Tree loaded\n");
	}

	if (chdir(cwd) < 0) {
		LogError("chdir() error: %s", strerror(errno));
		return 0;
	}

	return 1;

} // End of LoadMaps

static uint32_t getTick() {
    struct timespec ts;
    unsigned theTick = 0U;
    clock_gettime( CLOCK_REALTIME, &ts );
    theTick  = ts.tv_nsec / 1000000;
    theTick += ts.tv_sec * 1000;
    return theTick;
}

int main(int argc, char **argv) {

	char *dirName = NULL;
	char *wfile	  = "mmc.nf";
	int c;
	while ((c = getopt(argc, argv, "hd:w:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'd':
				if ( !CheckPath(optarg, S_IFDIR) )
					exit(254);
				dirName = strdup(optarg);
				break;
			case 'w':
				wfile = optarg;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}

	if (dirName == NULL) {
		usage(argv[0]);
		exit(0);
	}

	if ( !Init_nffile(NULL) || !Init_MaxMind() )
		exit(254);

	uint32_t t1 = getTick();
	LoadMaps(dirName);
	uint32_t t2 = getTick();
	printf("Load CSV time: %u\n", t2-t1);

	DoTest("80.219.226.184");
	DoTest("152.88.1.5");
	DoTest("2001:620:0:ff::5c");
	DoTest("2a04:4e42:1b::323");
	DoTest("2002:521c:8016::521c:8016");
	printf("Dump trees\n");

	t1 = getTick();
	SaveMaxMind(wfile);
	t2 = getTick();
	printf("Save to file time: %u\n", t2-t1);

 	Init_MaxMind();
	printf("Load trees\n");
	t1 = getTick();
	LoadMaxMind(wfile);
	t2 = getTick();
	printf("Load from file time: %u\n", t2-t1);

	DoTest("80.219.226.184");
	DoTest("2001:620:0:ff::5c");
	DoTest("2a04:4e42:1b::323");
	SaveMaxMind(wfile);


	t1 = getTick();
	DoLoop();
	t2 = getTick();
	printf("Loop IPv4 %u\n", t2-t1);

	t1 = getTick();
	DoLoop2();
	t2 = getTick();
	printf("Loop IPv6 %u\n", t2-t1);

	return 0;
}
