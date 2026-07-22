/*
 *  Copyright (c) 2011-2026, Peter Haag
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

#pragma once

#include <stdatomic.h>

/* Lock variable type and initialiser. */
typedef _Atomic int spinlock_t;
#define SPINLOCK_INIT 0

/*
 * cpu_relax() — spin-wait hint.
 *
 * x86 / amd64 : PAUSE reduces pipeline stalls and bus traffic while spinning;
 *               without it repeated CAS operations cause memory-order violations
 *               that stall the out-of-order engine of the waiting core.
 * AArch64     : YIELD hints to the microarchitecture that this is a spin loop,
 *               allowing the core to favour its sibling SMT thread or reduce power.
 * Other       : falls back to a no-op (correct, slightly sub-optimal).
 */
#if defined(__x86_64__) || defined(__i386__)
#define cpu_relax() __asm__ volatile("pause" ::: "memory")
#elif defined(__aarch64__)
#define cpu_relax() __asm__ volatile("yield" ::: "memory")
#else
#define cpu_relax() ((void)0)
#endif

/*
 * spin_lock — test-and-test-and-set (TTAS) with acquire semantics.
 *
 * The outer relaxed load gates the CAS: while the lock is visibly held we
 * spin with cpu_relax() without generating write-invalidation traffic on the
 * cache coherence bus.  Only when the lock *looks* free do we attempt the CAS.
 *
 * The successful CAS uses memory_order_acquire so that all reads and writes
 * inside the critical section observe stores made by the previous holder before
 * it released the lock.  The failure order is memory_order_relaxed because no
 * ordering guarantee is needed when we did not acquire anything.
 */
#define spin_lock(lck)                                                                                                          \
    do {                                                                                                                        \
        for (;;) {                                                                                                              \
            if (atomic_load_explicit(&(lck), memory_order_relaxed) == 0) {                                                      \
                int zero = 0;                                                                                                   \
                if (atomic_compare_exchange_weak_explicit(&(lck), &zero, 1, memory_order_acquire, memory_order_relaxed)) break; \
            }                                                                                                                   \
            cpu_relax();                                                                                                        \
        }                                                                                                                       \
    } while (0)

/*
 * spin_unlock — release semantics.
 *
 * memory_order_release ensures all writes inside the critical section are
 * visible to the next thread that successfully acquires the lock.
 */
#define spin_unlock(lck) atomic_store_explicit(&(lck), 0, memory_order_release)
