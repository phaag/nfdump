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

#include "output.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "conf/nfconf.h"
#include "nfdump.h"
#include "output_csv.h"
#include "output_fmt.h"
#include "output_json.h"
#include "output_raw.h"
#include "util.h"

// compare at most 16 chars
#define MAXMODELEN 16
#define MAXFORMATS 64

#define FORMAT_line "%ts %td %pr %sap -> %dap %pkt %byt %fl"

#define FORMAT_gline "%ts %td %pr %gsap -> %gdap %pkt %byt %fl"

#define FORMAT_long "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %fl"

#define FORMAT_glong "%ts %td %pr %gsap -> %gdap %flg %tos %pkt %byt %fl"

#define FORMAT_extended "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %pps %bps %bpp %fl"

#define FORMAT_biline "%ts %td %pr %sap <-> %dap %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_bilong "%ts %td %pr %sap <-> %dap %flg %tos %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_nsel "%ts %evt %xevt %pr %sap -> %dap %xsap -> %xdap %ibyt %obyt"

#define FORMAT_nat "%ts %nevt %pr %sap -> %dap %nsap -> %ndap"

#ifdef NSEL
#define DefaultMode "nsel"
#else
#define DefaultMode "line"
#endif
#define DefaultGeoMode "gline"

static void AddFormat(char *format, char *name, char *fmtString);

static void null_record(FILE *stream, recordHandle_t *record, int tag);

static void null_prolog(void);

static void null_epilog(void);

// Assign print functions for all output options -o
// Terminated with a NULL record
printmap_t printmap[MAXFORMATS] = {{"raw", MODE_RAW, NULL, "Raw format - multi line"},
                                   {"line", MODE_FMT, FORMAT_line, "predefined"},
                                   {"gline", MODE_FMT, FORMAT_gline, "predefined"},
                                   {"long", MODE_FMT, FORMAT_long, "predefined"},
                                   {"glong", MODE_FMT, FORMAT_glong, "predefined"},
                                   {"extended", MODE_FMT, FORMAT_extended, "predefined"},
                                   {"biline", MODE_FMT, FORMAT_biline, "predefined"},
                                   {"bilong", MODE_FMT, FORMAT_bilong, "predefined"},
                                   {"nsel", MODE_FMT, FORMAT_nsel, "predefined"},
                                   {"nat", MODE_FMT, FORMAT_nat, "predefined"},
                                   {"json", MODE_JSON, NULL, "json output"},
                                   {"json-log", MODE_JSON_LOG, NULL, "json output for logging"},
                                   {"csv", MODE_CSV, NULL, "csv predefined"},
                                   {"null", MODE_NULL, NULL, "do not print any output"},

                                   // This is always the last line
                                   {NULL, MODE_NULL, "", NULL}};

// table with appropriate printer function for given format
static struct printerFunc_s {
    RecordPrinter_t func_record;  // prints the record
    PrologPrinter_t func_prolog;  // prints the output prolog
    PrologPrinter_t func_epilog;  // prints the output epilog
} printFuncMap[] = {[MODE_NULL] = {null_record, null_prolog, null_epilog},
                    [MODE_FMT] = {fmt_record, fmt_prolog, fmt_epilog},
                    [MODE_RAW] = {raw_record, raw_prolog, raw_epilog},
                    [MODE_CSV] = {csv_record, csv_prolog, csv_epilog},
                    [MODE_JSON] = {flow_record_to_json_human, json_prolog, json_epilog},
                    [MODE_JSON_LOG] = {flow_record_to_json_log, json_prolog, json_epilog}};

static PrologPrinter_t print_prolog;  // prints the output prolog
static PrologPrinter_t print_epilog;  // prints the output epilog

static void UpdateFormatList(void);

static void null_record(FILE *stream, recordHandle_t *record, int tag) {
    // empty - do not list any flows
}  // End of null_record

static void null_prolog(void) {
    // empty prolog
}  // End of null_prolog

static void null_epilog(void) {
    // empty epilog
}  // End of null_epilog

static void AddFormat(char *format, char *name, char *fmtString) {
    int csvMode = strcmp(format, "csv") == 0;
    int i = 0;
    while (printmap[i].printmode) {
        if (strncasecmp(name, printmap[i].printmode, MAXMODELEN) == 0) {
            // default format exists - overwrite
            printmap[i].Format = fmtString;
            printmap[i].outputMode = csvMode ? MODE_CSV : MODE_FMT;
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
        printmap[i].help = "user defined";
        printmap[i].outputMode = csvMode ? MODE_CSV : MODE_FMT;
        i++;
        printmap[i].printmode = NULL;
        dbg_printf("Insert format: %s - %s\n", csvMode ? "csv" : "fmt", name);
    } else {
        LogError("Number of print format slots exhaustet: %d", MAXFORMATS);
    }
}  // End of AddFormat

static void UpdateFormatList(void) {
    char *key = NULL;
    char *value = NULL;

    char *formats[2] = {"fmt", "csv"};

    for (int i = 0; i < 2; i++) {
        do {
            int ret = ConfGetFormatEntry(formats[i], &key, &value);
            if (ret > 0) {
                dbg_printf("format: %s, key: %s, value %s\n", formats[i], key, value);
                AddFormat(formats[i], key, value);
            } else {
                break;
            }
        } while (1);
    }

}  // End of UpdateFormatList

RecordPrinter_t SetupOutputMode(char *print_format, outputParams_t *outputParams) {
    RecordPrinter_t print_record = NULL;

    // get user defined fmt formats from config file
    UpdateFormatList();

    if (print_format == NULL) print_format = outputParams->hasGeoDB ? DefaultGeoMode : DefaultMode;

    int fmtFormat = strncasecmp(print_format, "fmt:", 4) == 0;
    int csvFormat = strncasecmp(print_format, "csv:", 4) == 0;
    if (fmtFormat || csvFormat || print_format[0] == '%') {
        // special user defined output format
        char *format = &print_format[4];  // for 'fmt:%xxx' or 'csv:%xxx'
        if (print_format[0] == '%') {
            fmtFormat = 1;
            format = print_format;  // for '%xxx' - forgot to add fmt: assume fmt
        }

        if (strlen(format)) {
            if (!ParseOutputFormat(csvFormat, format, outputParams->printPlain, printmap)) exit(EXIT_FAILURE);
            if (csvFormat) {
                print_record = csv_record;
                print_prolog = csv_prolog;
                print_epilog = csv_epilog;
            } else {
                print_record = fmt_record;
                print_prolog = fmt_prolog;
                print_epilog = fmt_epilog;
            }
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
                outputParams->mode = printmap[i].outputMode;
                if (printmap[i].Format) {
                    // predefined custom format
                    if (!ParseOutputFormat(outputParams->mode == MODE_CSV, printmap[i].Format, outputParams->printPlain, printmap))
                        exit(EXIT_FAILURE);
                }
                // else - predefined static format
                print_record = printFuncMap[outputParams->mode].func_record;
                print_prolog = printFuncMap[outputParams->mode].func_prolog;
                print_epilog = printFuncMap[outputParams->mode].func_epilog;
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

void PrintOutputHelp(void) {
    printf("Available output formats:\n");

    for (int i = 0; printmap[i].printmode != NULL; i++) {
        if (printmap[i].Format != NULL) {
            printf("%10s : %s -o fmt %s\n", printmap[i].printmode, printmap[i].help, printmap[i].Format);
        } else {
            printf("%10s : %s\n", printmap[i].printmode, printmap[i].help);
        }
    }
}  // ENd of PrintOutputHelp