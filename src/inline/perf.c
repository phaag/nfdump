#include <stdint.h>
#include <time.h>

struct perf_s {
    uint64_t start;
    uint64_t sum;
    uint32_t entries;
#define NumPerf 16
} perf[NumPerf] = {0};

static void perfStart(int index) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    perf[index].start = 1000000000LL * start.tv_sec + start.tv_nsec;
}  // End of perfStart

static void perfStop(int index) {
    struct timespec stop;
    clock_gettime(CLOCK_MONOTONIC, &stop);
    uint64_t end = 1000000000LL * stop.tv_sec + stop.tv_nsec;
    perf[index].sum += (end - perf[index].start);
    perf[index].entries++;
}  // End of perfStart

static void perfReport(void) {
    for (int i = 0; i < NumPerf; i++) {
        if (perf[i].sum) {
            printf("%4d %4u entries: %.6f second\n", i, perf[i].entries, (double)perf[i].sum / 1000000000LL);
        }
    }
}  // End of perfReport
