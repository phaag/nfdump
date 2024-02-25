#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct SortRecord {
    void *record;
    uint64_t count;
} SortRecord_t;

void blocksort(SortRecord_t *data, int len);

#define swap(a, b)             \
    {                          \
        SortRecord_t _h = (a); \
        (a) = (b);             \
        (b) = _h;              \
    }

#define min(a, b) ((a) < (b) ? (a) : (b))

#define sort3fast(a, b, c)               \
    if ((b).count < (a).count) {         \
        if ((c).count < (a).count) {     \
            if ((c).count < (b).count) { \
                swap(a, c);              \
            } else {                     \
                SortRecord_t h = (a);    \
                (a) = (b);               \
                (b) = (c);               \
                (c) = h;                 \
            }                            \
        } else {                         \
            swap((a), (b));              \
        }                                \
    } else {                             \
        if ((c).count < (b).count) {     \
            if ((c).count < (a).count) { \
                SortRecord_t h = (c);    \
                (c) = (b);               \
                (b) = (a);               \
                (a) = h;                 \
            } else {                     \
                swap((b), (c));          \
            }                            \
        }                                \
    }

static int max_threads;
static int n_threads;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// static void init(SortRecord_t *data, int len);

static void qusort(SortRecord_t *left, SortRecord_t *right);

static void insert_sort(SortRecord_t *left, SortRecord_t *right);

static void partition(SortRecord_t *left0, SortRecord_t *right0, SortRecord_t **l1, SortRecord_t **r1, SortRecord_t **l2, SortRecord_t **r2);

static void *sort_thr(void *arg);

void insert_sort(SortRecord_t *left, SortRecord_t *right) {
    // put minimum to left position, so we can save
    // one inner loop comparison for insert sort
    for (SortRecord_t *pi = left + 1; pi <= right; pi++) {
        if (pi->count < left->count) {
            swap(*pi, *left);
        }
    }
    for (SortRecord_t *pi = left + 2; pi <= right; pi++) {
        SortRecord_t h = *pi;
        SortRecord_t *pj = pi - 1;
        while (h.count < pj->count) {
            *(pj + 1) = *pj;
            pj -= 1;
        }
        *(pj + 1) = h;
    }
}

static void partition(SortRecord_t *left0, SortRecord_t *right0, SortRecord_t **l1, SortRecord_t **r1, SortRecord_t **l2, SortRecord_t **r2) {
    SortRecord_t *left = left0 + 1;
    SortRecord_t *right = right0;

    SortRecord_t *mid = left0 + (right0 - left0) / 2;
    SortRecord_t piv = *mid;
    *mid = *left;
    sort3fast(*left0, piv, *right0);
    *left = piv;

    while (1) {
        do left += 1;
        while (left->count < piv.count);
        do right -= 1;
        while (right->count > piv.count);
        if (left >= right) break;
        swap(*left, *right);
    }
    *(left0 + 1) = *right;
    *right = piv;

    if (right < mid) {
        *l1 = left0;
        *r1 = right - 1;
        *l2 = right + 1;
        *r2 = right0;
    } else {
        *l1 = right + 1;
        *r1 = right0;
        *l2 = left0;
        *r2 = right - 1;
    }
}

/*
static void partition(SortRecord_t *left0, SortRecord_t *right0,
                SortRecord_t **l1, SortRecord_t **r1,
                SortRecord_t **l2, SortRecord_t **r2) {

    SortRecord_t *mid = left0 + (right0 - left0) / 2;
    SortRecord_t piv = *mid;
    *mid = *(left0 + 1);
    sort3fast(*left0, piv, *right0);
    *(left0 + 1) = piv;

    SortRecord_t *left, *right;
    #define BSZ 256
    if (right0 - left0 > 2 * BSZ + 3) {

        left = left0 + 2;
        right = right0 - 1;
        SortRecord_t *offl[BSZ];
        SortRecord_t *offr[BSZ];
        SortRecord_t **ol = offl;
        SortRecord_t **or = offr;
        do {
            if (ol == offl) {
                SortRecord_t *pd = left;
                do {
                    *ol = pd;
                    ol += (piv.count < pd->count);
                    pd += 1;
                }
                while (pd < left + BSZ);
            }
            if (or == offr) {
                SortRecord_t* pd = right;
                do {
                    *or = pd;
                    or += (piv.count > pd->count);
                    pd -= 1;
                }
                while (pd > right - BSZ);
            }
            int min = min(ol - offl, or - offr);
            ol -= min;
            or -= min;
            for (int i = 0; i < min; i++) {
                swap(**(ol + i), **(or + i));
            }
            if (ol == offl) left += BSZ;
            if (or == offr) right -= BSZ;
        }
        while (right - left > 2 * BSZ);
        left -= 1;
        right += 1;
    }
    else {
        left = left0 + 1;
        right = right0;
    }
    while (1) {
        do left += 1; while(left->count < piv.count);
        do right -= 1; while (right->count > piv.count);
        if (left >= right) break;
        swap(*left, *right);
    }
    *(left0 + 1) = *right;
    *right = piv;

    if (right < mid) {
        *l1 = left0; *r1 = right - 1;
        *l2 = right + 1; *r2 = right0;
    }
    else {
        *l1 = right + 1; *r1 = right0;
        *l2 = left0; *r2 = right - 1;
    }
}
*/

static void *sort_thr(void *arg) {
    SortRecord_t **par = (SortRecord_t **)arg;
    qusort(par[0], par[1]);
    free(arg);
    pthread_mutex_lock(&mutex);
    n_threads--;
    if (n_threads <= 0) {
        pthread_cond_signal(&cond);
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

static void qusort_single(SortRecord_t *left, SortRecord_t *right) {
    SortRecord_t *l, *r;
    while (right - left >= 50) {
        partition(left, right, &l, &r, &left, &right);
        qusort(l, r);
    }
    insert_sort(left, right);
}

static void qusort(SortRecord_t *left, SortRecord_t *right) {
    while (right - left >= 50) {
        SortRecord_t *l, *r;
        partition(left, right, &l, &r, &left, &right);

        if (right - left > 100000 && n_threads < max_threads) {
            // start a new thread - max_threads is a soft limit
            pthread_t thread;
            SortRecord_t **param = (SortRecord_t **)malloc(2 * sizeof(SortRecord_t *));
            if (!param) abort();
            param[0] = left;
            param[1] = right;
            pthread_mutex_lock(&mutex);
            n_threads++;
            pthread_mutex_unlock(&mutex);
            pthread_create(&thread, NULL, sort_thr, param);
            left = l;
            right = r;
        } else {
            qusort(l, r);
        }
    }
    insert_sort(left, right);
}

void blocksort(SortRecord_t *data, int len) {
    // shortcut for few entries
    if (len < 50) {
        SortRecord_t *left = data;
        SortRecord_t *right = data + len - 1;
        qusort_single(left, right);
        return;
    }

    int n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpus > 0)
        max_threads = n_cpus * 2;
    else
        max_threads = 8;

    pthread_t thread;
    SortRecord_t **param = (SortRecord_t **)malloc(2 * sizeof(SortRecord_t *));
    if (!param) abort();
    param[0] = data;
    param[1] = data + len - 1;
    pthread_create(&thread, NULL, sort_thr, param);

    pthread_mutex_lock(&mutex);
    n_threads++;
    while (n_threads > 0) pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
}

/*
static double t(void) {

    static double t0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double h = t0;
    t0 = tv.tv_sec + tv.tv_usec / 1000000.0;
    return t0 - h;
}

static void init(SortRecord_t *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i].count = rand();
    }
}

static void test(SortRecord_t *data, int len) {
    for (int i = 1; i < len; i++) {
        if (data[i].count < data[i - 1].count) {
            printf("ERROR\n");
            break;
        }
    }
}


int main(void) {

        size_t size = 50 * 1000000;

        SortRecord_t *data = malloc(size * sizeof(SortRecord_t));
        if ( !data ) {
                perror("malloc() failed: ");
                exit(255);
        }
    init(data, size);
    printf("Sorting %lu million numbers with Quicksort ...\n", size / 1000000);
    t();

    blocksort(data, size);
    printf("%.2fs\n", t());
    test(data, size);
    return 0;
}
*/
