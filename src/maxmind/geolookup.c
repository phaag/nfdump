/*
 *  Copyright (c) 2024, Peter Haag
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

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "maxmind.h"
#include "mmcreate.h"
#include "mmhash.h"
#include "nfconf.h"
#include "nffile.h"
#include "util.h"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here.\n"
        "-G <dir>\tmaxmind GeoDB in nfdump format to lookup info.\n"
        "-d <dir>\tDirectory containing the maxmind .csv files to convert into nfdump GeoDB.\n"
        "-w <file>\tName of nfdump GeoDB file.\n",
        name);
} /* usage */

// Return a pointer to the trimmed string
static char *string_trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s) {
        char *p = s;
        while (*p) p++;
        while (isspace((unsigned char)*(--p)))
            ;
        p[1] = '\0';
    }

    return s;
}  // end of string_trim

static int valid_ipv4(char *s) {
    char *c = s;
    int i = 0;
    while (*c) {
        if ((!isdigit(*c) && *c != '.') || i > 15) {
            return 0;
        }
        c++;
        i++;
    }

    c = strdup(s);
    int numbers = 0;
    char *sep = ".";
    char *brkt;
    char *ns = strtok_r(c, sep, &brkt);
    while (ns) {
        int num = atoi(ns);
        if (num > 255) {
            free(c);
            return 0;
        }
        numbers++;
        ns = strtok_r(NULL, sep, &brkt);
    }

    free(c);
    return numbers == 4;
}

static int valid_ipv6(char *s) {
    char *c = s;
    int i = 0;
    while (*c) {
        if ((!isxdigit(*c) && *c != ':' && *c != '.') || i > 39) {
            return 0;
        }
        c++;  // point to next character
    }
    if (strchr(s, ':') == NULL) {
        return 0;
    }
    c = strdup(s);
    char *brkt;
    char *ns = strtok_r(c, ":", &brkt);
    while (ns) {
        int num = atoi(ns);
        if (num > 65535) {
            free(c);
            return 0;
        }
        ns = strtok_r(NULL, ":", &brkt);
    }

    free(c);
    uint64_t u[2];
    if (inet_pton(PF_INET6, s, u) != 1) {
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    char *dirName = NULL;
    char *geoFile = getenv("NFGEODB");
    char *wfile = "mmc.nf";
    int c;
    while ((c = getopt(argc, argv, "hd:G:w:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'd':
                if (!CheckPath(optarg, S_IFDIR)) exit(EXIT_FAILURE);
                dirName = strdup(optarg);
                break;
            case 'w':
                wfile = optarg;
                break;
            case 'G':
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                geoFile = strdup(optarg);
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (!Init_nffile(1, NULL) || !Init_MaxMind()) exit(EXIT_FAILURE);

    if (dirName && wfile) {
        if (LoadMaps(dirName) == 0 || SaveMaxMind(wfile) == 0) {
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    if (geoFile == NULL) {
        if (ConfOpen(NULL, "nfdump") < 0) exit(EXIT_FAILURE);
        geoFile = ConfGetString("geodb.path");
    }

    if (geoFile == NULL) {
        LogError("Missing nfdump geo DB. -G or NFGEODB env required");
        exit(EXIT_FAILURE);
    }

    if (!LoadMaxMind(geoFile)) {
        LogError("Failed to load nfdump geo DB");
        exit(EXIT_FAILURE);
    }

    if (argc - optind > 0) {
        while (argc - optind > 0) {
            char *arg = argv[optind++];
            if (strlen(arg) > 2 && (valid_ipv4(arg) || valid_ipv6(arg))) {
                LookupWhois(arg);
            } else {
                LogError("Not a valid IPv4 or IPv6: ", arg);
                exit(EXIT_FAILURE);
            }
        }
    } else {
        char *line = NULL;
        size_t linecap = 0;
        ssize_t lineLen;
        // read each line - trimm \n
        while ((lineLen = getline(&line, &linecap, stdin)) > 0) {
            if (lineLen > 1024) {
                LogError("Line length error");
                exit(EXIT_FAILURE);
            }
            char *eol = strchr(line, '\n');
            *eol = '\0';

            // split ' ' separated words and check, if it's an IPv4/v6
            char *sep = " ";
            char *word, *brkt;
            word = strtok_r(line, sep, &brkt);
            while (word) {
                if (valid_ipv4(word) || valid_ipv6(word)) {
                    LookupWhois(string_trim(word));
                }
                word = strtok_r(NULL, sep, &brkt);
            }
        }
    }

    return 0;
}
