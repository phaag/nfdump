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
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "conf/nfconf.h"
#include "nffile.h"
#include "tor/tor.h"
#include "util.h"

#define TAG_EXITNODE "ExitNode"
#define TAG_PUBLISHED "Published"
#define TAG_LASTSTATUS "LastStatus"
#define TAG_EXITADDRESS "ExitAddress"

static void usage(char *name);

static int traverseTree(char *const argv[]);

static int compare(const FTSENT **f1, const FTSENT **f2);

static int epoch_days(int y, int m, int d);

static time_t hms_to_time(int h, int m, int s);

static time_t ReadTime(char *timestring);

static int scanLine(char *line, torNode_t *torNode);

static int processFile(char *torFile);

static int traverseTree(char *const argv[]);

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here.\n"
        "-H <nodeDB>\ttor nodeDB in nfdump format to lookup tor info.\n"
        "-d <dir>\tDirectory containing ascii tor info files to be convert into nfdump tor nodeDB.\n"
        "-w <file>\tName of nfdump torDB file.\n",
        name);
}  // End of usage

// parse integer from string, up to eos char
// update string after reading
static int inline getNumber(char **timeString, char eos) {
    int number = 0;
    char *s = *timeString;

    char *eosp = strchr(s, eos);
    if (eosp) *eosp++ = '\0';
    while (*s != '\0') {
        if (*s >= '0' && *s <= '9') {
            number = 10 * number + (*s - 0x30);
        } else {
            return 0;
        }
        s++;
    }
    *timeString = eosp;
    return number;
}

/*
 * we would need timegm(), but that function is not portable and too slow
 * so we take a local implementation to convert a time string to UNIX epoch
 */
static int epoch_days(int y, int m, int d) {
    const uint32_t year_base = 4800; /* Before min year, multiple of 400. */
    const uint32_t m_adj = m - 3;    /* March-based month. */
    const uint32_t carry = m_adj > m ? 1 : 0;
    const uint32_t adjust = carry ? 12 : 0;
    const uint32_t y_adj = y + year_base - carry;
    const uint32_t month_days = ((m_adj + adjust) * 62719 + 769) / 2048;
    const uint32_t leap_days = y_adj / 4 - y_adj / 100 + y_adj / 400;
    return y_adj * 365 + leap_days + month_days + (d - 1) - 2472632;
}

static time_t hms_to_time(int h, int m, int s) { return (h * 3600) + (m * 60) + s; }

// expected tie format "%Y-%m-%d %H:%M:%S"
// example: 2010-12-28 07:35:55
static time_t ReadTime(char *timestring) {
    time_t epoch = 0;

    int year = getNumber(&timestring, '-');
    int mon = getNumber(&timestring, '-');
    int mday = getNumber(&timestring, ' ');
    int hour = getNumber(&timestring, ':');
    int min = getNumber(&timestring, ':');
    int sec = getNumber(&timestring, '\n');
    epoch = 86400 * epoch_days(year, mon, mday);
    epoch += hms_to_time(hour, min, sec);

    return epoch;
}

static int scanLine(char *line, torNode_t *torNode) {
    if (strstr(line, TAG_EXITNODE) != NULL) {
        memset((void *)torNode, 0, sizeof(torNode_t));
    } else if (strstr(line, TAG_PUBLISHED) != NULL) {
        char *timestring = line + strlen(TAG_PUBLISHED) + 1;
        time_t lastPublished = ReadTime(timestring);
        torNode->lastPublished = lastPublished;
        torNode->interval[0].firstSeen = torNode->lastPublished;
    } else if (strstr(line, TAG_LASTSTATUS) != NULL) {
        char *timestring = line + strlen(TAG_LASTSTATUS) + 1;
        time_t lastStatus = ReadTime(timestring);
        if (lastStatus > torNode->interval[0].lastSeen) torNode->interval[0].lastSeen = lastStatus;
    } else if (strstr(line, TAG_EXITADDRESS) != NULL) {
        char *ipstring = line + strlen(TAG_EXITADDRESS) + 1;
        char *timestring = strchr(ipstring, ' ');
        *timestring++ = '\0';
        uint32_t ip = 0;
        int ret = inet_pton(PF_INET, ipstring, &ip);
        if (ret == 1) {
            torNode->ipaddr = htonl(ip);
            time_t lastSeen = ReadTime(timestring);
            if (lastSeen > torNode->interval[0].lastSeen) torNode->interval[0].lastSeen = lastSeen;
            return 1;
        } else {
            LogError("Unpasable IP address: %s", ipstring);
        }
    }
    return 0;
}

static int processFile(char *torFile) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(torFile, "r");
    if (fp == NULL) return errno;

    torNode_t torNode = {0};
    while ((read = getline(&line, &len, fp)) != -1) {
        // printf("Next line: %s", line);
        int ipfound = scanLine(line, &torNode);
        if (ipfound) {
            UpdateTorNode(&torNode);
        }
    }

    fclose(fp);
    if (line) free(line);

    return 0;
}  // End of processFile

static int compare(const FTSENT **f1, const FTSENT **f2) { return strcmp((*f1)->fts_name, (*f2)->fts_name); }  // End of compare

/*
 * returns ok
 */
static int traverseTree(char *const argv[]) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    FTS *ftsp;
    FTSENT *p, *chp;
    int fts_options = FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR;
    int cnt = 0;

    // make stdout unbuffered for progress pointer
    setvbuf(stdout, (char *)NULL, _IONBF, 0);

    if ((ftsp = fts_open(argv, fts_options, compare)) == NULL) {
        LogError("fts_open(): %s:", strerror(errno));
        return 0;
    }
    /* Initialize ftsp with as many argv[] parts as possible. */
    chp = fts_children(ftsp, 0);
    if (chp == NULL) {
        LogError("fts_open(): %s:", "No files found");
        return 0; /* no files to traverse */
    }
    while ((p = fts_read(ftsp)) != NULL) {
        switch (p->fts_info) {
            case FTS_D:
                dbg_printf("d %s\n", p->fts_path);
                break;
            case FTS_F:
                printf("\r%c", spinner[cnt & 0x3]);
                cnt++;
                dbg_printf(" f %s\n", p->fts_path);
                int err = processFile(p->fts_path);
                if (err) return err;
                break;
            default:
                break;
        }
    }
    fts_close(ftsp);
    return 1;
}

// Return a pointer to the trimmed string
static char *string_trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s) {
        char *p = s;
        while (*p) p++;
        while (isspace((unsigned char)*(--p)));
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

int main(int argc, char **argv) {
    char *dirName = NULL;
    char *torFileDB = getenv("NFTORDB");
    char *wfile = "torDB.nf";
    int c;
    while ((c = getopt(argc, argv, "hd:H:w:")) != EOF) {
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
            case 'H':
                if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                torFileDB = strdup(optarg);
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (!Init_nffile(1, NULL)) exit(EXIT_FAILURE);

    if (dirName && wfile) {
        char *pathList[2] = {dirName, NULL};
        Init_TorLookup();
        if (traverseTree(pathList) == 0 || SaveTorTree(wfile) == 0) {
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    if (torFileDB == NULL) {
        if (ConfOpen(NULL, "nfdump") < 0) exit(EXIT_FAILURE);
        torFileDB = ConfGetString("tordb.path");
    }

    if (torFileDB == NULL) {
        LogError("Missing nfdump tor DB. -T or NFTORDB env required");
        exit(EXIT_FAILURE);
    }

    if (!LoadTorTree(torFileDB)) {
        LogError("Failed to load nfdump tor DB");
        exit(EXIT_FAILURE);
    }

    if (argc - optind > 0) {
        while (argc - optind > 0) {
            char *arg = argv[optind++];
            if (strlen(arg) > 2 && (valid_ipv4(arg))) {
                LookupIP(arg);
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
            char *sep = " (";
            char *word, *brkt;
            word = strtok_r(line, sep, &brkt);
            while (word) {
                if (valid_ipv4(word)) {
                    LookupIP(string_trim(word));
                }
                word = strtok_r(NULL, sep, &brkt);
            }
        }
    }

    exit(EXIT_SUCCESS);
}
