#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "nffileV3/nffileV3.h"

static void CheckBlocks(int expected, const char *where) {
    int actual = ReportBlocks();
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d live blocks, got %d\n", where, expected, actual);
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    InitLog(0, "stderr", 0, 1);
    threadConfig_t tc = {.writers = 2};
    if (!Init_nffile(tc, NULL)) return EXIT_FAILURE;

    // Each public allocation must have exactly one matching release.
    dataBlockV3_t *block = NewDataBlock(BLOCK_SIZE_V3);
    if (!block) return EXIT_FAILURE;
    CheckBlocks(1, "NewDataBlock");
    FreeDataBlock(block);
    CheckBlocks(0, "FreeDataBlock");

    queue_t *queue = queue_init(8);
    if (!queue) return EXIT_FAILURE;
    block = NewDataBlock(BLOCK_SIZE_V3);
    if (!block) return EXIT_FAILURE;
    PushBlockV3(queue, block);  // zero rawSize: must be released
    CheckBlocks(0, "empty push");
    queue_close(queue);
    PushBlockV3(queue, NewFlowBlock(BLOCK_SIZE_V3));
    CheckBlocks(0, "rejected push");
    nffileV3_t closedFile = {.processQueue = queue};
    FlushBlockV3(&closedFile, NewFlowBlock(BLOCK_SIZE_V3));
    CheckBlocks(0, "rejected flush");
    queue_free(queue);

    char dir[] = "/tmp/nfdump-rotation.XXXXXX";
    if (!mkdtemp(dir)) return EXIT_FAILURE;
    char path[256];
    snprintf(path, sizeof(path), "%s/current", dir);
    const uint16_t compression[] = {NOT_COMPRESSED, LZ4_COMPRESSED};
    for (unsigned mode = 0; mode < sizeof(compression) / sizeof(compression[0]); mode++) {
        for (int cycle = 0; cycle < 32; cycle++) {
            nffileV3_t *file = OpenNewFileV3(path, CREATOR_NFCAPD, compression[mode], 0, NULL);
            if (!file) return EXIT_FAILURE;
            file->ident = strdup("rotation-test");
            if (!file->ident) return EXIT_FAILURE;
            file->stat_record->msecFirstSeen = 1000;
            file->stat_record->msecLastSeen = 1000;
            // Alternate idle cycles and cycles with queued flow/exporter blocks.
            if (cycle % 2) {
                PushBlockV3(file->processQueue, NewFlowBlock(BLOCK_SIZE_V3));
                expBlockV3_t *exporters = NULL;
                InitDataBlock(exporters, BLOCK_SIZE_V3);
                if (!exporters) return EXIT_FAILURE;
                PushBlockV3(file->processQueue, exporters);
            }
            if (!FlushFileV3(file)) return EXIT_FAILURE;
            CloseFileV3(file);
            CheckBlocks(0, "rotation close");
            unlink(path);
        }
    }
    rmdir(dir);
    puts("Rotation block ownership checks passed");
    return EXIT_SUCCESS;
}
