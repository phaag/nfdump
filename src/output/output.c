/*
 *  Copyright (c) 2022, Peter Haag
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

#include "output.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "nfconf.h"
#include "output_csv.h"
#include "output_fmt.h"
#include "output_json.h"
#include "output_pipe.h"
#include "output_raw.h"
#include "util.h"

// compare at most 16 chars
#define MAXMODELEN 16
#define MAXFORMATS 64

static void null_record(FILE *stream, void *record, int tag);

static void null_prolog(void);

static void null_epilog(void);

// Assign print functions for all output options -o
// Teminated with a NULL record
printmap_t printmap[MAXFORMATS] = {{"raw", raw_record, raw_prolog, raw_epilog, NULL},
                                   {"line", fmt_record, fmt_prolog, fmt_epilog, FORMAT_line},
                                   {"gline", fmt_record, fmt_prolog, fmt_epilog, FORMAT_gline},
                                   {"long", fmt_record, fmt_prolog, fmt_epilog, FORMAT_long},
                                   {"glong", fmt_record, fmt_prolog, fmt_epilog, FORMAT_glong},
                                   {"extended", fmt_record, fmt_prolog, fmt_epilog, FORMAT_extended},
                                   {"biline", fmt_record, fmt_prolog, fmt_epilog, FORMAT_biline},
                                   {"bilong", fmt_record, fmt_prolog, fmt_epilog, FORMAT_bilong},
                                   {"pipe", pipe_record, pipe_prolog, pipe_epilog, NULL},
                                   {"json", flow_record_to_json, json_prolog, json_epilog, NULL},
                                   {"csv", csv_record, csv_prolog, csv_epilog, NULL},
                                   {"null", null_record, null_prolog, null_epilog, NULL},
#ifdef NSEL
                                   {"nsel", fmt_record, fmt_prolog, fmt_epilog, FORMAT_nsel},
                                   {"nel", fmt_record, fmt_prolog, fmt_epilog, FORMAT_nel},
#endif
                                   // This is always the last line
                                   {NULL, NULL, NULL, NULL, ""}};

static PrologPrinter_t print_prolog;  // prints the output prolog
static PrologPrinter_t print_epilog;  // prints the output epilog

static void UpdateFormatList(void);

static void null_record(FILE *stream, void *record, int tag) {
    // empty - do not list any flows
}  // End of null_record

static void null_prolog() {
    // empty prolog
}  // End of null_prolog

static void null_epilog() {
    // empty epilog
}  // End of null_epilog

void AddFormat(char *name, char *fmtString) {
    int i = 0;
    while (printmap[i].printmode) {
        if (strncasecmp(name, printmap[i].printmode, MAXMODELEN) == 0) {
            // default format exists - overwrite
            printmap[i].Format = fmtString;
            printmap[i].func_record = fmt_record;
            printmap[i].func_prolog = fmt_prolog;
            printmap[i].func_epilog = fmt_epilog;
            dbg_printf("Overwrite format: %s\n", name);
            free(name);
            return;
        }
        i++;
    }
    // no match of existing name
    if ((i + 1) < MAXFORMATS) {
        printmap[i].printmode = name;
        printmap[i].Format = fmtString;
        printmap[i].func_record = fmt_record;
        printmap[i].func_prolog = fmt_prolog;
        printmap[i].func_epilog = fmt_epilog;
        i++;
        printmap[i].printmode = NULL;
        dbg_printf("Insert format: %s\n", name);
    } else {
        LogError("Number of print format slots exhaustet: %d", MAXFORMATS);
    }
}  // End of AddFormat

static void UpdateFormatList() {
    char *key = NULL;
    char *value = NULL;

    int ret;
    do {
        ret = ConfGetFMTentry(&key, &value);
        if (ret > 0) {
            dbg_printf("key: %s, value %s\n", key, value);
            AddFormat(key, value);
        } else {
            break;
        }
    } while (1);

}  // End of UpdateFormatList

RecordPrinter_t SetupOutputMode(char *print_format, outputParams_t *outputParams, bool HasGeoDB) {
    RecordPrinter_t print_record = NULL;

    // get user defined fmt formats from config file
    UpdateFormatList();

    if (print_format == NULL) print_format = HasGeoDB ? DefaultGeoMode : DefaultMode;

    if (strncasecmp(print_format, "fmt:", 4) == 0 || print_format[0] == '%') {
        // special user defined output format
        char *format = &print_format[4];                    // for 'fmt:%xxx'
        if (print_format[0] == '%') format = print_format;  // for '%xxx' - forgot to add fmt:
        if (strlen(format)) {
            if (!ParseOutputFormat(format, outputParams->printPlain, printmap)) exit(EXIT_FAILURE);
            print_record = fmt_record;
            print_prolog = fmt_prolog;
            print_epilog = fmt_epilog;
        } else {
            LogError("Missing format description for user defined output format!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        // predefined output format

        // Check for long_v6 mode
        size_t i = strlen(print_format);
        if (i > 2) {
            if (print_format[i - 1] == '6') {
                Setv6Mode(1);
                print_format[i - 1] = '\0';
            } else
                Setv6Mode(0);
        }

        i = 0;
        while (printmap[i].printmode) {
            if (strncasecmp(print_format, printmap[i].printmode, MAXMODELEN) == 0) {
                if (printmap[i].Format) {
                    if (!ParseOutputFormat(printmap[i].Format, outputParams->printPlain, printmap)) exit(EXIT_FAILURE);
                    // predefined custom format
                    print_record = printmap[i].func_record;
                    print_prolog = printmap[i].func_prolog;
                    print_epilog = printmap[i].func_epilog;
                } else {
                    // To support the pipe output format for element stats - check for pipe, and
                    // remember this
                    if (strncasecmp(print_format, "pipe", MAXMODELEN) == 0) {
                        outputParams->mode = MODE_PIPE;
                    } else if (strncasecmp(print_format, "csv", MAXMODELEN) == 0) {
                        outputParams->mode = MODE_CSV;
                    } else if (strncasecmp(print_format, "json", MAXMODELEN) == 0) {
                        outputParams->mode = MODE_JSON;
                    } else {
                        outputParams->mode = MODE_PLAIN;
                    }
                    // predefined static format
                    print_record = printmap[i].func_record;
                    print_prolog = printmap[i].func_prolog;
                    print_epilog = printmap[i].func_epilog;
                }
                break;
            }
            i++;
        }
    }

    return print_record;

}  // End of SetupOutputMode

void PrintProlog(outputParams_t *outputParams) {
    if (!outputParams->quiet) print_prolog();
}  // End of PrintProlog

void PrintEpilog(outputParams_t *outputParams) {
    if (!outputParams->quiet) print_epilog();
}  // End of PrintEpilog