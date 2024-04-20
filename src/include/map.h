/*
 * Based on the idea of
 * https://github.com/mystborn/GenericDataStructures
 *
 *  Copyright (c) 2020, Peter Haag
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
 *   * Neither the name of the auhor nor the names of its contributors may be
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

#ifndef GENERIC_DATA_STRUCTURES_MAP_H
#define GENERIC_DATA_STRUCTURES_MAP_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define ___fib_hash(hash, shift) ((hash) * 2654435769U) >> (shift)

#define MAP_DEFINE_H(type_name, function_prefix, key_type, value_type)                                                     \
    typedef struct type_name##Cell {                                                                                       \
        key_type key;                                                                                                      \
        value_type value;                                                                                                  \
        uint32_t hash;                                                                                                     \
        uint32_t active;                                                                                                   \
    } type_name##Cell;                                                                                                     \
                                                                                                                           \
    typedef struct {                                                                                                       \
        type_name##Cell* cells;                                                                                            \
        uint32_t count;                                                                                                    \
        uint32_t capacity;                                                                                                 \
        uint32_t mask;                                                                                                     \
        uint32_t load_factor;                                                                                              \
        uint32_t shift;                                                                                                    \
    } type_name;                                                                                                           \
                                                                                                                           \
    static inline uint32_t __attribute__((unused)) function_prefix##_count(type_name* map) { return map->count; }          \
    static inline uint32_t __attribute__((unused)) function_prefix##_capacity(type_name* map) { return map->load_factor; } \
    static inline uint32_t __attribute__((unused)) function_prefix##_allocated(type_name* map) { return map->capacity; }   \
    static inline void __attribute__((unused)) function_prefix##_free(type_name* map) {                                    \
        free(map->cells);                                                                                                  \
        free(map);                                                                                                         \
    }                                                                                                                      \
    static inline void __attribute__((unused)) function_prefix##_free_resources(type_name* map) { free(map->cells); }      \
                                                                                                                           \
    type_name* function_prefix##_create(void);                                                                             \
    bool function_prefix##_init(type_name* map);                                                                           \
    value_type* function_prefix##_add(type_name* map, key_type key, int* insert);                                          \
    void function_prefix##_set(type_name* map, key_type key, value_type value);                                            \
    value_type function_prefix##_get(type_name* map, key_type key);                                                        \
    bool function_prefix##_try_get(type_name* map, key_type key, value_type* out_value);                                   \
    bool function_prefix##_remove(type_name* map, key_type key);                                                           \
    bool function_prefix##_get_and_remove(type_name* map, key_type key, key_type* out_key, value_type* out_value);         \
    void function_prefix##_clear(type_name* map, bool reset_capacity);

// TODO: Add more safety in case the map fails to resize.

#define MAP_DEFINE_C(type_name, function_prefix, key_type, value_type, hash_fn, compare_fn)                                \
    type_name* function_prefix##_create(void) {                                                                            \
        type_name* map = malloc(sizeof(type_name));                                                                        \
        if (!map) return NULL;                                                                                             \
        if (!function_prefix##_init(map)) {                                                                                \
            free(map);                                                                                                     \
            return NULL;                                                                                                   \
        }                                                                                                                  \
        return map;                                                                                                        \
    }                                                                                                                      \
                                                                                                                           \
    bool function_prefix##_init(type_name* map) {                                                                          \
        map->shift = 25;                                                                                                   \
        map->capacity = 128;                                                                                               \
        map->mask = map->capacity - 1;                                                                                     \
        map->count = 0;                                                                                                    \
        map->load_factor = 64;                                                                                             \
        return (map->cells = calloc(map->capacity, sizeof(type_name##Cell))) != NULL;                                      \
    }                                                                                                                      \
                                                                                                                           \
    static void function_prefix##_resize(type_name* map) {                                                                 \
        int capacity = map->load_factor = map->capacity;                                                                   \
        map->capacity = 1 << (32 - (--map->shift));                                                                        \
        map->mask = map->capacity - 1;                                                                                     \
        type_name##Cell* old = map->cells;                                                                                 \
        type_name##Cell* new = calloc(map->capacity, sizeof(type_name##Cell));                                             \
        assert(new);                                                                                                       \
                                                                                                                           \
        for (int i = 0; i < capacity; i++) {                                                                               \
            if (old[i].active) {                                                                                           \
                uint32_t cell = ___fib_hash(old[i].hash, map->shift);                                                      \
                while (new[cell].active) {                                                                                 \
                    cell = (cell + 1) & map->mask;                                                                         \
                }                                                                                                          \
                new[cell] = old[i];                                                                                        \
            }                                                                                                              \
        }                                                                                                                  \
        free(old);                                                                                                         \
        map->cells = new;                                                                                                  \
    }                                                                                                                      \
                                                                                                                           \
    value_type* function_prefix##_add(type_name* map, key_type key, int* insert) {                                         \
        uint32_t hash, cell;                                                                                               \
        if (map->count == map->load_factor) function_prefix##_resize(map);                                                 \
                                                                                                                           \
        hash = hash_fn(key);                                                                                               \
        cell = ___fib_hash(hash, map->shift);                                                                              \
        int step = 0;                                                                                                      \
        while (true) {                                                                                                     \
            if (!map->cells[cell].active) {                                                                                \
                map->cells[cell].active = 1;                                                                               \
                map->cells[cell].key = key;                                                                                \
                map->cells[cell].hash = hash;                                                                              \
                map->count++;                                                                                              \
                *insert = 1;                                                                                               \
                return &(map->cells[cell].value);                                                                          \
            } else if (map->cells[cell].hash == hash && compare_fn(map->cells[cell].key, key) == 1) {                      \
                *insert = 0;                                                                                               \
                return &(map->cells[cell].value);                                                                          \
            }                                                                                                              \
            cell += ++step;                                                                                                \
            if (cell >= map->capacity) cell = 0;                                                                           \
        }                                                                                                                  \
                                                                                                                           \
        return false;                                                                                                      \
    }                                                                                                                      \
                                                                                                                           \
    void function_prefix##_set(type_name* map, key_type key, value_type value) {                                           \
        uint32_t hash, cell;                                                                                               \
                                                                                                                           \
        if (map->count == map->load_factor) function_prefix##_resize(map);                                                 \
                                                                                                                           \
        hash = hash_fn(key);                                                                                               \
        cell = ___fib_hash(hash, map->shift);                                                                              \
                                                                                                                           \
        while (true) {                                                                                                     \
            if (!map->cells[cell].active) {                                                                                \
                map->cells[cell].active = 1;                                                                               \
                map->cells[cell].key = key;                                                                                \
                map->cells[cell].value = value;                                                                            \
                map->cells[cell].hash = hash;                                                                              \
                map->count++;                                                                                              \
                break;                                                                                                     \
            } else if (map->cells[cell].hash == hash && compare_fn(map->cells[cell].key, key) == 1) {                      \
                map->cells[cell].value = value;                                                                            \
                break;                                                                                                     \
            }                                                                                                              \
            if (++cell == map->capacity) cell = 0;                                                                         \
        }                                                                                                                  \
    }                                                                                                                      \
                                                                                                                           \
    static inline bool function_prefix##_find_cell(type_name* map, key_type key, uint32_t* out_hash, uint32_t* out_cell) { \
        uint32_t hash, cell;                                                                                               \
        hash = hash_fn(key);                                                                                               \
        cell = ___fib_hash(hash, map->shift);                                                                              \
                                                                                                                           \
        while (true) {                                                                                                     \
            if (!map->cells[cell].active) return false;                                                                    \
                                                                                                                           \
            if (map->cells[cell].hash == hash && compare_fn(map->cells[cell].key, key) == 1) {                             \
                *out_hash = hash;                                                                                          \
                *out_cell = cell;                                                                                          \
                return true;                                                                                               \
            }                                                                                                              \
                                                                                                                           \
            cell = (cell + 1) & map->mask;                                                                                 \
        }                                                                                                                  \
    }                                                                                                                      \
                                                                                                                           \
    value_type function_prefix##_get(type_name* map, key_type key) {                                                       \
        uint32_t cell, hash;                                                                                               \
        if (function_prefix##_find_cell(map, key, &hash, &cell))                                                           \
            return map->cells[cell].value;                                                                                 \
        else                                                                                                               \
            return (value_type){0};                                                                                        \
    }                                                                                                                      \
                                                                                                                           \
    bool function_prefix##_try_get(type_name* map, key_type key, value_type* out_value) {                                  \
        uint32_t cell, hash;                                                                                               \
        if (function_prefix##_find_cell(map, key, &hash, &cell)) {                                                         \
            if (out_value != NULL) *out_value = map->cells[cell].value;                                                    \
            return true;                                                                                                   \
        } else {                                                                                                           \
            return false;                                                                                                  \
        }                                                                                                                  \
    }                                                                                                                      \
                                                                                                                           \
    static inline void function_prefix##_replace_cell(type_name* map, uint32_t cell, uint32_t hash) {                      \
        uint32_t start = cell;                                                                                             \
                                                                                                                           \
        while (true) {                                                                                                     \
            cell = (cell + 1) & map->mask;                                                                                 \
                                                                                                                           \
            if (!map->cells[cell].active) break;                                                                           \
                                                                                                                           \
            uint32_t preferred_cell = ___fib_hash(map->cells[cell].hash, map->shift);                                      \
            if (preferred_cell <= start || preferred_cell > cell) {                                                        \
                map->cells[start] = map->cells[cell];                                                                      \
                start = cell;                                                                                              \
            }                                                                                                              \
        }                                                                                                                  \
        map->cells[start].active = 0;                                                                                      \
    }                                                                                                                      \
                                                                                                                           \
    bool function_prefix##_remove(type_name* map, key_type key) {                                                          \
        uint32_t cell, hash;                                                                                               \
        if (!function_prefix##_find_cell(map, key, &hash, &cell)) return false;                                            \
                                                                                                                           \
        function_prefix##_replace_cell(map, cell, hash);                                                                   \
        map->count--;                                                                                                      \
        return true;                                                                                                       \
    }                                                                                                                      \
                                                                                                                           \
    bool function_prefix##_get_and_remove(type_name* map, key_type key, key_type* out_key, value_type* out_value) {        \
        uint32_t cell, hash;                                                                                               \
        if (!function_prefix##_find_cell(map, key, &hash, &cell)) return false;                                            \
                                                                                                                           \
        if (out_key != NULL) *out_key = map->cells[cell].key;                                                              \
        if (out_value != NULL) *out_value = map->cells[cell].value;                                                        \
                                                                                                                           \
        function_prefix##_replace_cell(map, cell, hash);                                                                   \
        map->count--;                                                                                                      \
        return true;                                                                                                       \
    }                                                                                                                      \
                                                                                                                           \
    void function_prefix##_clear(type_name* map, bool reset_capacity) {                                                    \
        if (reset_capacity) {                                                                                              \
            free(map->cells);                                                                                              \
            function_prefix##_init(map);                                                                                   \
        } else {                                                                                                           \
            map->count = 0;                                                                                                \
            for (uint32_t i = 0; i < map->capacity; i++) map->cells[i].active = 0;                                         \
        }                                                                                                                  \
    }

#endif  // GENERIC_MAP_GENERIC_MAP_H