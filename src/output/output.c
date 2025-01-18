/*
 *  Copyright (c) 2024-2025, Peter Haag
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

#include <ctype.h>
#include <errno.h>
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
#include "output_ndjson.h"
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

#define FORMAT_CSV "%ts,%td,%pr,%sa,%sp,%da,%dp,%pkt,%byt,%fl"

#ifdef NSEL
#define DefaultMode "nsel"
#else
#define DefaultMode "line"
#endif
#define DefaultGeoMode "gline"

static void AddFormat(char *format, char *name, char *fmtString);

static void null_record(FILE *stream, recordHandle_t *record, outputParams_t *outputParam);

static void null_prolog(outputParams_t *outputParam);

static void null_epilog(outputParams_t *outputParam);

// Assign print functions for all output options -o
// Terminated with a NULL record
static struct printmap_s {
    char *printmode;          // name of the output format
    outputMode_t outputMode;  // type of output mode
    char *Format;             // output format definition
    char *help;               // help text
} printmap[MAXFORMATS] = {{"raw", MODE_RAW, NULL, "Raw format - multi line"},
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
                          {"ndjson", MODE_NDJSON, NULL, "ndjson output formart"},
                          {"csv", MODE_CSV, FORMAT_CSV, "csv predefined"},
                          {"csv-fast", MODE_CSV_FAST, NULL, "csv fast predefined"},
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
                    [MODE_CSV_FAST] = {csv_record_fast, csv_prolog_fast, csv_epilog_fast},
                    [MODE_JSON] = {flow_record_to_json, json_prolog, json_epilog},
                    [MODE_NDJSON] = {flow_record_to_ndjson, ndjson_prolog, ndjson_epilog}};

static PrologPrinter_t print_prolog;  // prints the output prolog
static PrologPrinter_t print_epilog;  // prints the output epilog

static void UpdateFormatList(void);

static void null_record(FILE *stream, recordHandle_t *record, outputParams_t *outputParam) {
    // empty - do not list any flows
}  // End of null_record

static void null_prolog(outputParams_t *outputParam) {
    // empty prolog
}  // End of null_prolog

static void null_epilog(outputParams_t *outputParam) {
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

/*
 * expand predefined print format into given format, such as -o fmt "%line %ipl"
 */
static char *RecursiveReplace(char *format) {
    int i = 0;

    while (printmap[i].printmode) {
        char *s, *r;
        // check for printmode string
        s = strstr(format, printmap[i].printmode);
        if (s && printmap[i].Format && s != format) {
            int len = strlen(printmap[i].printmode);
            if (!isalpha((int)s[len])) {
                s--;
                if (s[0] == '%') {
                    int newlen = strlen(format) + strlen(printmap[i].Format);
                    r = malloc(newlen);
                    if (!r) {
                        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
                        exit(255);
                    }
                    s[0] = '\0';
                    snprintf(r, newlen, "%s%s%s", format, printmap[i].Format, &(s[len + 1]));
                    r[newlen - 1] = '\0';
                    free(format);
                    format = r;
                }
            }
        }
        i++;
    }

    return format;

}  // End of RecursiveReplace

RecordPrinter_t SetupOutputMode(char *print_format, outputParams_t *outputParams) {
    RecordPrinter_t print_record = NULL;

    // get user defined fmt formats from config file
    UpdateFormatList();

    if (print_format == NULL) print_format = outputParams->hasGeoDB ? DefaultGeoMode : DefaultMode;

    int fmtFormat = strncasecmp(print_format, "fmt:", 4) == 0;
    int csvFormat = strncasecmp(print_format, "csv:", 4) == 0;
    char *format = NULL;
    if (fmtFormat || csvFormat) {
        // for 'fmt:%xxx' or 'csv:%xxx'
        // replace %format inlines
        format = RecursiveReplace(strdup(&print_format[4]));
        dbg_printf("fmt: %d, csv: %d, format: %s\n", fmtFormat, csvFormat, format);
    } else if (print_format[0] == '%') {
        // for '%xxx' - forgot to add fmt: assume fmt
        fmtFormat = 1;
        // replace %format inlines
        format = RecursiveReplace(strdup(print_format));
        dbg_printf("explicit fmt, format: %s\n", format);
    } else {
        // predefined output formats %line, %long and %userdef formats ... etc.

        // Check for long_v6 mode
        size_t i = strlen(print_format);
        if (i >= 2) {
            if (print_format[i - 1] == '6') {
                Setv6Mode(1);
                print_format[i - 1] = '\0';
            } else
                Setv6Mode(0);
        }

        for (int i = 0; printmap[i].printmode != NULL; i++) {
            if (strncasecmp(print_format, printmap[i].printmode, MAXMODELEN) == 0) {
                outputParams->mode = printmap[i].outputMode;

                dbg_printf("Predefined format: %s\n", print_format);

                if (printmap[i].Format) {
                    // fmt or csv format
                    csvFormat = outputParams->mode == MODE_CSV;
                    fmtFormat = outputParams->mode == MODE_FMT;
                    format = printmap[i].Format;
                } else {
                    // else - predefined static format
                    print_record = printFuncMap[outputParams->mode].func_record;
                    print_prolog = printFuncMap[outputParams->mode].func_prolog;
                    print_epilog = printFuncMap[outputParams->mode].func_epilog;
                }

                break;
            }
        }
    }

    if (print_record) return print_record;

    dbg_printf("Parse format: %s\n", format);

    if (fmtFormat) {
        if (!ParseFMTOutputFormat(format, outputParams->printPlain)) exit(EXIT_FAILURE);
        print_record = fmt_record;
        print_prolog = fmt_prolog;
        print_epilog = fmt_epilog;
        outputParams->mode = MODE_FMT;
    }

    if (csvFormat) {
        if (!ParseCSVOutputFormat(format)) exit(EXIT_FAILURE);
        print_record = csv_record;
        print_prolog = csv_prolog;
        print_epilog = csv_epilog;
        outputParams->mode = MODE_CSV;
    }

    return print_record;

}  // End of SetupOutputMode

void PrintProlog(outputParams_t *outputParams) { print_prolog(outputParams); }  // End of PrintProlog

void PrintEpilog(outputParams_t *outputParams) { print_epilog(outputParams); }  // End of PrintEpilog

void PrintOutputHelp(void) {
    printf("Available output formats:\n");

    for (int i = 0; printmap[i].printmode != NULL; i++) {
        if (printmap[i].Format != NULL) {
            printf("%10s : %s -o %s %s\n", printmap[i].printmode, printmap[i].outputMode == MODE_CSV ? "csv" : "fmt", printmap[i].help,
                   printmap[i].Format);
        } else {
            printf("%10s : %s\n", printmap[i].printmode, printmap[i].help);
        }
    }
}  // ENd of PrintOutputHelp