/*
 *  Copyright (c) 2009-2023, Peter Haag
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
 */

#include "nfdump.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "exporter.h"
#include "flist.h"
#include "ifvrf.h"
#include "ipconv.h"
#include "ja3.h"
#include "maxmind.h"
#include "nbar.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nfconf.h"
#include "nffile.h"
#include "nflowcache.h"
#include "nfnet.h"
#include "nfprof.h"
#include "nfstat.h"
#include "nftree.h"
#include "nfx.h"
#include "nfxV3.h"
#include "output.h"
#include "util.h"
#include "version.h"

extern char *FilterFilename;

/* Local Variables */
static FilterEngine_t *Engine;

static uint64_t total_bytes = 0;
static uint32_t processed = 0;
static uint32_t passed = 0;
static bool HasGeoDB = false;
static uint32_t skipped_blocks = 0;
static uint64_t t_first_flow, t_last_flow;

extension_map_list_t *extension_map_list;

extern exporter_t **exporter_list;

// For automatic output format generation in case of custom aggregation
#define AggrPrependFmt "%ts %td "
#define AggrAppendFmt "%pkt %byt %bps %bpp %fl"

/* Function Prototypes */
static void usage(char *name);

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams);

static stat_record_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows, RecordPrinter_t print_record,
                                  timeWindow_t *timeWindow, uint64_t limitRecords, outputParams_t *outputParams, int compress);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_compat.c"
#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] [\"filter\"]\n"
        "-h\t\tthis text you see right here\n"
        "-V\t\tPrint version and exit.\n"
        "-a\t\tAggregate netflow data.\n"
        "-A <expr>[/net]\tHow to aggregate: ',' sep list of tags see nfdump(1)\n"
        "\t\tor subnet aggregation: srcip4/24, srcip6/64.\n"
        "-b\t\tAggregate netflow records as bidirectional flows.\n"
        "-B\t\tAggregate netflow records as bidirectional flows - Guess direction.\n"
        "-C <file>\tRead optional config file.\n"
        "-r <file>\tread input from file\n"
        "-w <file>\twrite output to file\n"
        "-f\t\tread netflow filter from file\n"
        "-n\t\tDefine number of top N for stat or sorted output.\n"
        "-c\t\tLimit number of matching records\n"
        "-D <dns>\tUse nameserver <dns> for host lookup.\n"
        "-G <geoDB>\tUse this nfdump geoDB to lookup country/location.\n"
        "-N\t\tPrint plain numbers\n"
        "-s <expr>[/<order>]\tGenerate statistics for <expr> any valid record element.\n"
        "\t\tand ordered by <order>: packets, bytes, flows, bps pps and bpp.\n"
        "-q\t\tQuiet: Do not print the header and bottom stat lines.\n"
        "-i <ident>\tChange Ident to <ident> in file given by -r.\n"
        "-J <num>\tModify file compression: 0: uncompressed - 1: LZO - 2: BZ2 - 3: LZ4 "
        "compressed.\n"
        "-z\t\tLZO compress flows in output file. Used in combination with -w.\n"
        "-y\t\tLZ4 compress flows in output file. Used in combination with -w.\n"
        "-j\t\tBZ2 compress flows in output file. Used in combination with -w.\n"
        "-l <expr>\tSet limit on packets for line and packed output format.\n"
        "\t\tkey: 32 character string or 64 digit hex string starting with 0x.\n"
        "-L <expr>\tSet limit on bytes for line and packed output format.\n"
        "-I \t\tPrint netflow summary statistics info from file or range of files (-r, -R).\n"
        "-g \t\tPrint gnuplot stat line for each nfcapd file (-r, -R).\n"
        "-M <expr>\tRead input from multiple directories.\n"
        "\t\t/dir/dir1:dir2:dir3 Read the same files from '/dir/dir1' '/dir/dir2' and "
        "'/dir/dir3'.\n"
        "\t\trequests either -r filename or -R firstfile:lastfile without pathnames\n"
        "-m\t\tdeprecated\n"
        "-O <order> Sort order for aggregated flows - tstart, tend, flows, packets bps pps bbp "
        "etc.\n"
        "-R <expr>\tRead input from sequence of files.\n"
        "\t\t/any/dir  Read all files in that directory.\n"
        "\t\t/dir/file Read all files beginning with 'file'.\n"
        "\t\t/dir/file1:file2: Read all files from 'file1' to file2.\n"
        "-o <mode>\tUse <mode> to print out netflow records:\n"
        "\t\t raw      Raw record dump.\n"
        "\t\t line     Standard output line format.\n"
        "\t\t long     Standard output line format with additional fields.\n"
        "\t\t extended Even more information.\n"
        "\t\t csv      ',' separated, machine parseable output format.\n"
        "\t\t json     json output format.\n"
        "\t\t pipe     '|' separated legacy machine parseable output format.\n"
        "\t\t null     no flow records, but statistics output.\n"
        "\t\t\tmode may be extended by '6' for full IPv6 listing. e.g.long6, extended6.\n"
        "-E <file>\tPrint exporter and sampling info for collected flows.\n"
        "-v <file>\tverify netflow data file. Print version and blocks.\n"
        "-x <file>\tverify extension records in netflow data file.\n"
        "-X\t\tDump Filtertable and exit (debug option).\n"
        "-Z\t\tCheck filter syntax and exit.\n"
        "-t <time>\ttime window for filtering packets\n"
        "\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n",
        name);
} /* usage */

static inline void ClearMasterRecord(master_record_t *record) {
    if (record->inPayload) free(record->inPayload);
    if (record->outPayload) free(record->outPayload);
    memset((void *)record, 0, sizeof(master_record_t));
}  // End of ClearMasterRecord

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams) {
    static double duration;
    uint64_t bps, pps, bpp;
    char byte_str[NUMBER_STRING_SIZE], packet_str[NUMBER_STRING_SIZE];
    char bps_str[NUMBER_STRING_SIZE], pps_str[NUMBER_STRING_SIZE], bpp_str[NUMBER_STRING_SIZE];

    bps = pps = bpp = 0;
    if (stat_record->lastseen) {
        duration = (stat_record->lastseen - stat_record->firstseen) / 1000.0;
    } else {
        // no flows to report
        duration = 0;
    }
    if (duration > 0 && stat_record->lastseen > 0) {
        bps = (stat_record->numbytes << 3) / duration;  // bits per second. ( >> 3 ) -> * 8 to convert octets into bits
        pps = stat_record->numpackets / duration;       // packets per second
        bpp = stat_record->numpackets ? stat_record->numbytes / stat_record->numpackets : 0;  // Bytes per Packet
    }
    if (outputParams->mode == MODE_CSV) {
        printf("Summary\n");
        printf("flows,bytes,packets,avg_bps,avg_pps,avg_bpp\n");
        printf("%llu,%llu,%llu,%llu,%llu,%llu\n", (long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes,
               (long long unsigned)stat_record->numpackets, (long long unsigned)bps, (long long unsigned)pps, (long long unsigned)bpp);
    } else {
        format_number(stat_record->numbytes, byte_str, outputParams->printPlain, VAR_LENGTH);
        format_number(stat_record->numpackets, packet_str, outputParams->printPlain, VAR_LENGTH);
        format_number(bps, bps_str, outputParams->printPlain, VAR_LENGTH);
        format_number(pps, pps_str, outputParams->printPlain, VAR_LENGTH);
        format_number(bpp, bpp_str, outputParams->printPlain, VAR_LENGTH);
        printf(
            "Summary: total flows: %llu, total bytes: %s, total packets: %s, avg bps: %s, avg pps: "
            "%s, avg bpp: %s\n",
            (unsigned long long)stat_record->numflows, byte_str, packet_str, bps_str, pps_str, bpp_str);
    }

}  // End of PrintSummary

static inline void AddGeoInfo(master_record_t *master_record) {
    if (!HasGeoDB || TestFlag(master_record->mflags, V3_FLAG_ENRICHED)) return;
    LookupCountry(master_record->V6.srcaddr, master_record->src_geo);
    LookupCountry(master_record->V6.dstaddr, master_record->dst_geo);
    if (master_record->srcas == 0) master_record->srcas = LookupAS(master_record->V6.srcaddr);
    if (master_record->dstas == 0) master_record->dstas = LookupAS(master_record->V6.dstaddr);
    // insert AS element in order to list
    int j = 0;
    uint32_t val = EXasRoutingID;
    while (j < master_record->numElements) {
        if (EXasRoutingID == master_record->exElementList[j]) {
            break;
        }
        if (val < master_record->exElementList[j]) {
            uint32_t _tmp = master_record->exElementList[j];
            master_record->exElementList[j] = val;
            val = _tmp;
        }
        j++;
    }
    if (j == master_record->numElements) {
        master_record->exElementList[j] = val;
        master_record->numElements++;
    }
    SetFlag(master_record->mflags, V3_FLAG_ENRICHED);

}  // End of AddGeoInfo

static inline record_header_t *AddFlowLabel(record_header_t *record, char *label) {
#define TMPSIZE 65536
    static char tmpRecord[TMPSIZE];
    size_t labelSize = strlen(label) + 1;
    recordHeaderV3_t *recordHeaderV3 = (recordHeaderV3_t *)record;
    if ((recordHeaderV3->size + sizeof(elementHeader_t) + labelSize) >= TMPSIZE) {
        LogError("AddFlowLabel() error in %s line %d", __FILE__, __LINE__);
        return record;
    }
    memcpy((void *)tmpRecord, (void *)record, recordHeaderV3->size);
    recordHeaderV3 = (recordHeaderV3_t *)tmpRecord;
    PushVarLengthPointer(recordHeaderV3, EXlabel, voidPtr, labelSize);
    memcpy(voidPtr, (void *)label, labelSize);
    return (record_header_t *)tmpRecord;
}

static stat_record_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows, RecordPrinter_t print_record,
                                  timeWindow_t *timeWindow, uint64_t limitRecords, outputParams_t *outputParams, int compress) {
    nffile_t *nffile_w, *nffile_r;
    stat_record_t stat_record;
    uint64_t twin_msecFirst, twin_msecLast;

    // time window of all matched flows
    memset((void *)&stat_record, 0, sizeof(stat_record_t));
    stat_record.firstseen = 0x7fffffffffffffffLL;

    if (timeWindow) {
        twin_msecFirst = timeWindow->first * 1000LL;
        if (timeWindow->last)
            twin_msecLast = timeWindow->last * 1000LL;
        else
            twin_msecLast = 0x7FFFFFFFFFFFFFFFLL;
    } else {
        twin_msecFirst = twin_msecLast = 0;
    }

    // do not print flows when doing any stats are sorting
    if (sort_flows || flow_stat || element_stat) {
        print_record = NULL;
    }

    // do not write flows to file, when doing any stats
    // -w may apply for flow_stats later
    int write_file = !(sort_flows || flow_stat || element_stat) && wfile;
    nffile_r = NULL;
    nffile_w = NULL;

    // Get the first file handle
    nffile_r = GetNextFile(NULL);
    if (!nffile_r) {
        LogError("GetNextFile() error in %s line %d", __FILE__, __LINE__);
        return stat_record;
    }
    if (nffile_r == EMPTY_LIST) {
        LogError("Empty file list. No files to process\n");
        return stat_record;
    }

    // preset time window of all processed flows to the stat record in first flow file
    t_first_flow = nffile_r->stat_record->firstseen;
    t_last_flow = nffile_r->stat_record->lastseen;

    // prepare output file if requested
    if (write_file) {
        nffile_w = OpenNewFile(wfile, NULL, CREATOR_NFDUMP, compress, NOT_ENCRYPTED);
        if (!nffile_w) {
            if (nffile_r) {
                CloseFile(nffile_r);
                DisposeFile(nffile_r);
            }
            return stat_record;
        }
        SetIdent(nffile_w, nffile_r->ident);
    }
    Engine->ident = nffile_r->ident;

    master_record_t *master_record = calloc(1, sizeof(master_record_t));
    if (!master_record) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return stat_record;
    }

    Engine->nfrecord = (uint64_t *)master_record;
    int done = 0;
    while (!done) {
        int i, ret;
        // get next data block from file
        ret = ReadBlock(nffile_r);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'\n", nffile_r->fileName);
                else
                    LogError("Read error in file '%s': %s\n", nffile_r->fileName, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF: {
                nffile_t *next = GetNextFile(nffile_r);
                if (next == EMPTY_LIST) {
                    done = 1;
                } else if (next == NULL) {
                    done = 1;
                    LogError("Unexpected end of file list\n");
                } else {
                    // Update global time span window
                    if (next->stat_record->firstseen < t_first_flow) t_first_flow = next->stat_record->firstseen;
                    if (next->stat_record->lastseen > t_last_flow) t_last_flow = next->stat_record->lastseen;
                    // continue with next file
                }
                Engine->ident = nffile_r->ident;
                continue;

            } break;  // not really needed
            default:
                // successfully read block
                total_bytes += ret;
        }

        if (nffile_r->block_header->type != DATA_BLOCK_TYPE_2 && nffile_r->block_header->type != DATA_BLOCK_TYPE_3) {
            if (nffile_r->block_header->type != DATA_BLOCK_TYPE_4) {  // skip array blocks
                if (nffile_r->block_header->type == DATA_BLOCK_TYPE_1)
                    LogError("nfdump 1.5.x block type 1 no longer supported. Skip block");
                else
                    LogError("Unknown block type %u. Skip block", nffile_r->block_header->type);
            }
            skipped_blocks++;
            continue;
        }

        uint32_t sumSize = 0;
        record_header_t *record_ptr = nffile_r->buff_ptr;
        dbg_printf("Block has %i records\n", nffile_r->block_header->NumRecords);
        for (i = 0; i < nffile_r->block_header->NumRecords && !done; i++) {
            record_header_t *process_ptr = record_ptr;
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(EXIT_FAILURE);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record:
                case CommonRecordType: {
                    int match;
                    ClearMasterRecord(master_record);
                    if (__builtin_expect(record_ptr->type == CommonRecordType, 0)) {
                        if (!ExpandRecord_v2(record_ptr, master_record)) {
                            goto NEXT;
                        }
                        dbg_printf("Convert v2 record\n");
                        process_ptr = ConvertRecordV2((common_record_t *)record_ptr);
                        if (!process_ptr) goto NEXT;
                    } else {
                        ExpandRecord_v3((recordHeaderV3_t *)record_ptr, master_record);
                    }

                    processed++;
                    master_record->flowCount = processed;
                    // Time based filter
                    // if no time filter is given, the result is always true
                    match = twin_msecFirst && (master_record->msecFirst < twin_msecFirst || master_record->msecLast > twin_msecLast) ? 0 : 1;

                    if (match) {
                        if (Engine->geoFilter) {
                            AddGeoInfo(master_record);
                        }

                        if (master_record->inPayloadLength && Engine->ja3Filter) {
                            ja3_t *ja3 = ja3Process((uint8_t *)master_record->inPayload, master_record->inPayloadLength);
                            if (ja3) {
                                memcpy((void *)master_record->ja3, ja3->md5Hash, 16);
                                ja3Free(ja3);
                            }
                        }

                        // filter netflow record with user supplied filter
                        match = (*Engine->FilterEngine)(Engine);
                        //						match = dofilter(master_record);
                    }
                    if (match == 0) {  // record failed to pass all filters
                        // go to next record
                        goto NEXT;
                    }

                    passed++;
                    // check if we are done, if -c option was set
                    if (limitRecords) done = passed >= limitRecords;

                    // Records passed filter -> continue record processing
                    // Update statistics
                    if (Engine->label) {
                        master_record->label = Engine->label;
                        process_ptr = AddFlowLabel(process_ptr, Engine->label);
                    }
#ifdef DEVEL
                    if (Engine->label) printf("Flow has label: %s\n", Engine->label);
#endif
                    UpdateStat(&stat_record, master_record);

                    if (flow_stat) {
                        AddFlowCache(process_ptr, master_record);
                        if (element_stat) {
                            if (TestFlag(element_stat, FLAG_GEO) && TestFlag(master_record->mflags, V3_FLAG_ENRICHED) == 0) {
                                AddGeoInfo(master_record);
                            }
                            AddElementStat(master_record);
                        }
                    } else if (element_stat) {
                        if (TestFlag(element_stat, FLAG_JA3) && master_record->ja3[0] == 0) {
                            // if we need ja3, calculate ja3 if payload exists and ja3 not yet set by filter
                            ja3_t *ja3 = ja3Process((uint8_t *)master_record->inPayload, master_record->inPayloadLength);
                            if (ja3) {
                                memcpy((void *)master_record->ja3, ja3->md5Hash, 16);
                                ja3Free(ja3);
                            }
                        }
                        // if we need geo, lookup geo if not yet set by filter
                        if (TestFlag(element_stat, FLAG_GEO) && TestFlag(master_record->mflags, V3_FLAG_ENRICHED) == 0) {
                            AddGeoInfo(master_record);
                        }
                        AddElementStat(master_record);
                    } else if (sort_flows) {
                        InsertFlow(process_ptr, master_record);
                    } else {
                        if (write_file) {
                            AppendToBuffer(nffile_w, (void *)process_ptr, process_ptr->size);
                        } else if (print_record) {
                            // if we need to print out this record
                            print_record(stdout, master_record, outputParams->doTag);
                        } else {
                            // mutually exclusive conditions should prevent executing this code
                            // this is buggy!
                            printf("Bug! - this code should never get executed in file %s line %d\n", __FILE__, __LINE__);
                            exit(EXIT_FAILURE);
                        }
                    }  // sort_flows - else
                } break;
                case ExtensionMapType: {
                    extension_map_t *map = (extension_map_t *)record_ptr;
                    if (Insert_Extension_Map(extension_map_list, map) < 0) {
                        LogError("Corrupt data file. Unable to decode at %s line %d\n", __FILE__, __LINE__);
                        exit(EXIT_FAILURE);
                    }
                } break;
                case ExporterInfoRecordType: {
                    int ret = AddExporterInfo((exporter_info_record_t *)record_ptr);
                    if (ret != 0) {
                        if (write_file && ret == 1) AppendToBuffer(nffile_w, (void *)record_ptr, record_ptr->size);
                    } else {
                        LogError("Failed to add Exporter Record\n");
                    }
                } break;
                case ExporterStatRecordType:
                    AddExporterStat((exporter_stats_record_t *)record_ptr);
                    break;
                case SamplerRecordType: {
                    int ret = AddSamplerInfo((sampler_record_t *)record_ptr);
                    if (ret != 0) {
                        if (write_file && ret == 1) AppendToBuffer(nffile_w, (void *)record_ptr, record_ptr->size);
                    } else {
                        LogError("Failed to add Sampler Record\n");
                    }
                } break;
                case NbarRecordType: {
                    arrayRecordHeader_t *nbarRecord = (arrayRecordHeader_t *)record_ptr;
#ifdef DEVEL
                    printf("Found nbar record: %u elements\n", nbarRecord->numElements);
                    PrintNbarRecord(nbarRecord);
#endif
                    AddNbarRecord(nbarRecord);
                } break;
                case IfNameRecordType: {
                    arrayRecordHeader_t *arrayRecordHeader = (arrayRecordHeader_t *)record_ptr;
                    AddIfNameRecord(arrayRecordHeader);
                } break;

                case VrfNameRecordType: {
                    arrayRecordHeader_t *arrayRecordHeader = (arrayRecordHeader_t *)record_ptr;
                    AddVrfNameRecord(arrayRecordHeader);
                } break;
                case LegacyRecordType1:
                case LegacyRecordType2:
                case CommonRecordV0Type:
                    LogError("Skip lagecy record type: %d", record_ptr->type);
                    break;
                default: {
                    LogError("Skip unknown record type %i\n", record_ptr->type);
                }
            }

        NEXT:
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((pointer_addr_t)record_ptr + record_ptr->size);

        }  // for all records

    }  // while

    CloseFile(nffile_r);

    // flush output file
    if (write_file) {
        // flush current buffer to disc
        if (nffile_w->block_header->NumRecords) {
            if (WriteBlock(nffile_w) <= 0) {
                LogError("Failed to write output buffer to disk: '%s'", strerror(errno));
            }
        }

        /* Copy stat info and close file */
        memcpy((void *)nffile_w->stat_record, (void *)&stat_record, sizeof(stat_record_t));
        CloseUpdateFile(nffile_w);
        DisposeFile(nffile_w);
    }

    DisposeFile(nffile_r);
    return stat_record;

}  // End of process_data

int main(int argc, char **argv) {
    struct stat stat_buff;
    stat_record_t sum_stat;
    outputParams_t *outputParams;
    RecordPrinter_t print_record;
    nfprof_t profile_data;
    char *wfile, *ffile, *filter, *tstring, *stat_type;
    char *byte_limit_string, *packet_limit_string, *print_format;
    char *print_order, *query_file, *geo_file, *configFile, *nameserver, *aggr_fmt;
    int ffd, element_stat, fdump;
    int flow_stat, aggregate, aggregate_mask, bidir;
    int print_stat, gnuplot_stat, syntax_only, compress;
    int GuessDir, ModifyCompress;
    uint32_t limitRecords;
    char Ident[IDENTLEN];
    flist_t flist;

    memset((void *)&flist, 0, sizeof(flist));
    wfile = ffile = filter = tstring = stat_type = NULL;
    byte_limit_string = packet_limit_string = NULL;
    fdump = aggregate = 0;
    aggregate_mask = 0;
    bidir = 0;
    syntax_only = 0;
    flow_stat = 0;
    print_stat = 0;
    gnuplot_stat = 0;
    element_stat = 0;
    limitRecords = 0;
    skipped_blocks = 0;
    compress = NOT_COMPRESSED;
    GuessDir = 0;
    nameserver = NULL;

    print_format = NULL;
    print_record = NULL;
    print_order = NULL;
    query_file = NULL;
    ModifyCompress = -1;
    aggr_fmt = NULL;

    configFile = NULL;
    geo_file = getenv("NFGEODB");

    outputParams = calloc(1, sizeof(outputParams_t));
    if (!outputParams) {
        LogError("calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    outputParams->topN = -1;

    Ident[0] = '\0';
    int c;
    while ((c = getopt(argc, argv, "6aA:Bbc:C:D:E:G:s:ghn:i:jf:qyzr:v:w:J:M:NImO:R:XZt:TVv:x:l:L:o:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'a':
                aggregate = 1;
                break;
            case 'A':
                CheckArgLen(optarg, 64);
                if (strlen(optarg) > 64) {
                    LogError("Aggregate mask format length error");
                    exit(EXIT_FAILURE);
                }
                if (aggregate_mask) {
                    LogError("Multiple aggregation masks not allowed");
                    exit(EXIT_FAILURE);
                }
                aggr_fmt = optarg;
                aggregate_mask = 1;
                break;
            case 'B':
                GuessDir = 1;
            case 'b':
                if (!SetBidirAggregation()) {
                    exit(EXIT_FAILURE);
                }
                bidir = 1;
                // implies
                aggregate = 1;
                break;
            case 'C':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, NOCONF) == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'D':
                CheckArgLen(optarg, 2);
                nameserver = optarg;
                if (!set_nameserver(nameserver)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'E': {
                CheckArgLen(optarg, MAXPATHLEN);
                if (!InitExporterList()) {
                    exit(EXIT_FAILURE);
                }
                flist.single_file = strdup(optarg);
                queue_t *fileList = SetupInputFileSequence(&flist);
                if (!fileList || !Init_nffile(fileList)) exit(EXIT_FAILURE);
                PrintExporters();
                exit(EXIT_SUCCESS);
            } break;
            case 'g':
                gnuplot_stat = 1;
                break;
            case 'G':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, "none") != 0 && !CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                geo_file = strdup(optarg);
                break;
            case 'X':
                fdump = 1;
                break;
            case 'Z':
                syntax_only = 1;
                break;
            case 'q':
                outputParams->quiet = 1;
                break;
            case 'j':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                compress = BZ2_COMPRESSED;
                break;
            case 'y':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                compress = LZ4_COMPRESSED;
                break;
            case 'z':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(EXIT_FAILURE);
                }
                compress = LZO_COMPRESSED;
                break;
            case 'c':
                CheckArgLen(optarg, 16);
                limitRecords = atoi(optarg);
                if (!limitRecords) {
                    LogError("Option -c needs a number > 0\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                CheckArgLen(optarg, 64);
                stat_type = optarg;
                if (!SetStat(stat_type, &element_stat, &flow_stat)) {
                    ListStatTypes();
                    exit(EXIT_FAILURE);
                }
                break;
            case 'V': {
                printf("%s: %s\n", argv[0], versionString());
                exit(EXIT_SUCCESS);
            } break;
            case 'l':
                CheckArgLen(optarg, 128);
                packet_limit_string = optarg;
                break;
            case 'L':
                CheckArgLen(optarg, 128);
                byte_limit_string = optarg;
                break;
            case 'N':
                outputParams->printPlain = 1;
                break;
            case 'f':
                CheckArgLen(optarg, MAXPATHLEN);
                ffile = optarg;
                break;
            case 't':
                CheckArgLen(optarg, 32);
                tstring = optarg;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.single_file = strdup(optarg);
                break;
            case 'm':
                print_order = "tstart";
                Parse_PrintOrder(print_order);
                LogError("Option -m deprecated. Use '-O tstart' instead");
                break;
            case 'M':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.multiple_dirs = strdup(optarg);
                break;
            case 'I':
                print_stat++;
                break;
            case 'o':  // output mode
                CheckArgLen(optarg, 512);
                print_format = optarg;
                // limit input chars
                break;
            case 'O': {  // stat order by
                CheckArgLen(optarg, 32);
                int ret;
                print_order = optarg;
                ret = Parse_PrintOrder(print_order);
                if (ret < 0) {
                    LogError("Unknown print order '%s'", print_order);
                    ListPrintOrder();
                    exit(EXIT_FAILURE);
                }
            } break;
            case 'R':
                CheckArgLen(optarg, MAXPATHLEN);
                if (!flist.multiple_files) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("Multiple files option already set: %s", flist.multiple_files);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            case 'n':
                CheckArgLen(optarg, 16);
                outputParams->topN = atoi(optarg);
                if (outputParams->topN < 0) {
                    LogError("TopnN number %i out of range", outputParams->topN);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'T':
                outputParams->doTag = 1;
                break;
            case 'i':
                CheckArgLen(optarg, IDENTLEN);
                strncpy(Ident, optarg, IDENTLEN);
                Ident[IDENTLEN - 1] = 0;
                if (strchr(Ident, ' ')) {
                    LogError("Ident must not contain spaces");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'J':
                CheckArgLen(optarg, 8);
                ModifyCompress = atoi(optarg);
                if ((ModifyCompress < 0) || (ModifyCompress > 3)) {
                    LogError("Expected -J <num>, 0: uncompressed, 1: LZO, 2: BZ2, 3: LZ4 compressed");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'x': {
                CheckArgLen(optarg, MAXPATHLEN);
                InitExtensionMaps(NO_EXTENSION_LIST);
                flist.single_file = strdup(optarg);
                queue_t *fileList = SetupInputFileSequence(&flist);
                if (!fileList || !Init_nffile(fileList)) exit(EXIT_FAILURE);
                DumpExMaps();
                exit(EXIT_SUCCESS);
            } break;
            case 'v':
                CheckArgLen(optarg, MAXPATHLEN);
                query_file = optarg;
                if (!QueryFile(query_file, fdump))
                    exit(EXIT_FAILURE);
                else
                    exit(EXIT_SUCCESS);
                break;
            case '6':  // print long IPv6 addr
                Setv6Mode(1);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (argc - optind > 0) {
        filter = strdup(argv[optind++]);
        while (argc - optind > 0) {
            char *arg = argv[optind++];
            CheckArgLen(arg, 128);
            filter = realloc(filter, strlen(filter) + strlen(arg) + 2);
            if (!filter) {
                LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                exit(EXIT_FAILURE);
            }
            strcat(filter, " ");
            strcat(filter, arg);
        }
    }

    if (!filter && ffile) {
        if (stat(ffile, &stat_buff)) {
            LogError("Can't stat filter file '%s': %s", ffile, strerror(errno));
            exit(EXIT_FAILURE);
        }
        filter = (char *)malloc(stat_buff.st_size + 1);
        if (!filter) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(EXIT_FAILURE);
        }
        ffd = open(ffile, O_RDONLY);
        if (ffd < 0) {
            LogError("Can't open filter file '%s': %s", ffile, strerror(errno));
            exit(EXIT_FAILURE);
        }
        ssize_t ret = read(ffd, (void *)filter, stat_buff.st_size);
        if (ret < 0) {
            LogError("Error reading filter file %s: %s", ffile, strerror(errno));
            close(ffd);
            exit(EXIT_FAILURE);
        }
        filter[stat_buff.st_size] = 0;
        close(ffd);

        FilterFilename = ffile;
    }

    // if no filter is given, set the default ip filter which passes through every flow
    if (!filter || strlen(filter) == 0) filter = "any";

    Engine = CompileFilter(filter);
    if (!Engine) exit(254);

    if (fdump) {
        printf("StartNode: %i Engine: %s\n", Engine->StartNode, Engine->Extended ? "Extended" : "Fast");
        DumpEngine(Engine);
        exit(EXIT_SUCCESS);
    }

    if (syntax_only) exit(EXIT_SUCCESS);

    if (ConfOpen(configFile, "nfdump") < 0) exit(EXIT_FAILURE);

    if (outputParams->topN < 0) {
        if (flow_stat || element_stat) {
            outputParams->topN = 10;
        } else {
            outputParams->topN = 0;
        }
    }
    if (wfile) outputParams->quiet = 1;

    if ((element_stat && !flow_stat) && aggregate_mask) {
        LogError("Warning: Aggregation ignored for element statistics\n");
        aggregate_mask = 0;
    }

    if (!flow_stat && aggregate_mask) {
        aggregate = 1;
    }

    extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
    if (!InitExporterList()) {
        exit(EXIT_FAILURE);
    }

    if (tstring) {
        flist.timeWindow = ScanTimeFrame(tstring);
        if (!flist.timeWindow) exit(EXIT_FAILURE);
    }

    if (flist.multiple_dirs == NULL && flist.single_file == NULL && flist.multiple_files == NULL) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (geo_file == NULL) {
        geo_file = ConfGetString("geodb.path");
    }
    if (geo_file && strcmp(geo_file, "none") == 0) {
        geo_file = NULL;
    }
    if (geo_file) {
        if (!CheckPath(geo_file, S_IFREG) || !Init_MaxMind() || !LoadMaxMind(geo_file)) {
            LogError("Error reading geo location DB file %s", geo_file);
            exit(EXIT_FAILURE);
        }
        HasGeoDB = true;
        outputParams->hasGeoDB = true;
    }
    if (!HasGeoDB && Engine->geoFilter > 1) {
        LogError("Can not filter according geo elements without a geo location DB");
        exit(EXIT_FAILURE);
    }
    if (aggr_fmt) {
        aggr_fmt = ParseAggregateMask(aggr_fmt, HasGeoDB);
        if (!aggr_fmt) {
            exit(EXIT_FAILURE);
        }
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(fileList)) exit(EXIT_FAILURE);

    // Modify compression
    if (ModifyCompress >= 0) {
        if (!flist.single_file && !flist.multiple_files) {
            LogError("Expected -r <file> or -R <dir> to change compression\n");
            exit(EXIT_FAILURE);
        }
        ModifyCompressFile(ModifyCompress);
        exit(EXIT_SUCCESS);
    }

    // Change Ident only
    if (flist.single_file && strlen(Ident) > 0) {
        ChangeIdent(flist.single_file, Ident);
        exit(EXIT_SUCCESS);
    }

    if (print_stat) {
        nffile_t *nffile;
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s).\n");
            exit(EXIT_FAILURE);
        }

        memset((void *)&sum_stat, 0, sizeof(stat_record_t));
        sum_stat.firstseen = 0x7fffffffffffffff;
        nffile = GetNextFile(NULL);
        if (!nffile) {
            LogError("Error open file: %s\n", strerror(errno));
            exit(250);
        }
        char *ident = NULL;
        if (nffile->ident) {
            ident = strdup(nffile->ident);
        }
        while (nffile && nffile != EMPTY_LIST) {
            SumStatRecords(&sum_stat, nffile->stat_record);
            nffile = GetNextFile(nffile);
        }
        PrintStat(&sum_stat, ident);
        free(ident);
        exit(EXIT_SUCCESS);
    }

    if (gnuplot_stat) {
        nffile_t *nffile;
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s).\n");
            exit(EXIT_FAILURE);
        }

        nffile = GetNextFile(NULL);
        if (!nffile) {
            LogError("Error open file: %s\n", strerror(errno));
            exit(250);
        }
        printf("# yyyy-mm-dd HH:MM:SS,flows,packets,bytes\n");
        while (nffile && nffile != EMPTY_LIST) {
            PrintGNUplotSumStat(nffile);
            nffile = GetNextFile(nffile);
        }
        exit(EXIT_SUCCESS);
    }

    // handle print mode
    if (!print_format) {
        // automatically select an appropriate output format for custom aggregation
        // aggr_fmt is compiled by ParseAggregateMask
        if (aggr_fmt) {
            size_t len = strlen(AggrPrependFmt) + strlen(aggr_fmt) + strlen(AggrAppendFmt) + 7;  // +7 for 'fmt:', 2 spaces and '\0'
            print_format = malloc(len);
            if (!print_format) {
                LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
                exit(EXIT_FAILURE);
            }
            snprintf(print_format, len, "fmt:%s %s %s", AggrPrependFmt, aggr_fmt, AggrAppendFmt);
            print_format[len - 1] = '\0';
        } else if (bidir) {
            print_format = "biline";
        }
    }

    print_record = SetupOutputMode(print_format, outputParams);

    if (!print_record) {
        LogError("Unknown output mode '%s'\n", print_format);
        exit(EXIT_FAILURE);
    }

    if (aggregate && (flow_stat || element_stat)) {
        aggregate = 0;
        LogError("Command line switch -s overwrites -a\n");
    }

    if (print_order && flow_stat) {
        printf("-s record and -O (-m) are mutually exclusive options\n");
        exit(EXIT_FAILURE);
    }

    if ((aggregate || flow_stat || print_order) && !Init_FlowCache()) exit(250);

    if (element_stat && !Init_StatTable()) exit(250);

    SetLimits(element_stat || aggregate || flow_stat, packet_limit_string, byte_limit_string);

    if (!(flow_stat || element_stat)) {
        PrintProlog(outputParams);
    }

    nfprof_start(&profile_data);
    sum_stat = process_data(wfile, element_stat, aggregate || flow_stat, print_order != NULL, print_record, flist.timeWindow, limitRecords,
                            outputParams, compress);
    nfprof_end(&profile_data, processed);

    if (passed == 0) {
        printf("No matching flows\n");
    }

    if (aggregate || print_order) {
        if (wfile) {
            nffile_t *nffile = OpenNewFile(wfile, NULL, CREATOR_NFDUMP, compress, NOT_ENCRYPTED);
            if (!nffile) exit(EXIT_FAILURE);
            if (ExportFlowTable(nffile, aggregate, bidir, GuessDir)) {
                CloseUpdateFile(nffile);
            } else {
                CloseFile(nffile);
                unlink(wfile);
            }
            DisposeFile(nffile);
        } else {
            PrintFlowTable(print_record, outputParams, GuessDir);
        }
    }

    if (flow_stat) {
        PrintFlowStat(print_record, outputParams);
    }

    if (element_stat) {
        PrintElementStat(&sum_stat, outputParams, print_record);
    }

    PrintEpilog(outputParams);

    if (!outputParams->quiet) {
        switch (outputParams->mode) {
            case MODE_PLAIN:
                PrintSummary(&sum_stat, outputParams);
                if (t_last_flow == 0) {
                    printf("Time window: <unknown>\n");
                } else {
                    t_first_flow /= 1000LL;
                    t_last_flow /= 1000LL;
                    if (flist.timeWindow) {
                        if (flist.timeWindow->first && (flist.timeWindow->first > t_first_flow)) t_first_flow = flist.timeWindow->first;
                        if (flist.timeWindow->last && (flist.timeWindow->last < t_last_flow)) t_last_flow = flist.timeWindow->last;
                    }
                    printf("Time window: %s\n", TimeString(t_first_flow, t_last_flow));
                }
                printf("Total flows processed: %u, passed: %u, Blocks skipped: %u, Bytes read: %llu\n", processed, passed, skipped_blocks,
                       (unsigned long long)total_bytes);
                nfprof_print(&profile_data, stdout);
                break;
            case MODE_PIPE:
                break;
            case MODE_CSV:
                PrintSummary(&sum_stat, outputParams);
                break;
            case MODE_JSON:
                break;
        }

    }  // else - no output

#ifdef DEVEL
    DumpNbarList();
#endif

    Dispose_FlowTable();
    Dispose_StatTable();
    FreeExtensionMaps(extension_map_list);

    return 0;
}
