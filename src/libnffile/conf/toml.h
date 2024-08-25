/*
 * MIT License
 *
 * Copyright (c) CK Tan
 * https://github.com/cktan/tomlc99
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TOML_H
#define TOML_H
#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif
#ifdef __cplusplus
#define TOML_EXTERN extern "C"
#else
#define TOML_EXTERN extern
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct toml_table_t toml_table_t;
typedef struct toml_array_t toml_array_t;
typedef struct toml_value_t toml_value_t;
typedef struct toml_timestamp_t toml_timestamp_t;
typedef struct toml_keyval_t toml_keyval_t;
typedef struct toml_arritem_t toml_arritem_t;

// TOML table.
struct toml_table_t {
    const char *key;  // Key for this table
    int keylen;       // length of key.
    bool implicit;    // Table was created implicitly
    bool readonly;    // No more modification allowed

    int nkval;  // key-values in the table
    toml_keyval_t **kval;
    int narr;  // arrays in the table
    toml_array_t **arr;
    int ntab;  // tables in the table
    toml_table_t **tab;
};

// TOML array.
struct toml_array_t {
    const char *key;  // key to this array
    int keylen;       // length of key.
    int kind;         // element kind: 'v'alue, 'a'rray, or 't'able, 'm'ixed
    int type;         // for value kind: 'i'nt, 'd'ouble, 'b'ool, 's'tring, 't'ime, 'D'ate, 'T'imestamp, 'm'ixed
    int nitem;        // number of elements
    toml_arritem_t *item;
};
struct toml_arritem_t {
    int valtype;  // for value kind: 'i'nt, 'd'ouble, 'b'ool, 's'tring, 't'ime, 'D'ate, 'T'imestamp
    char *val;
    toml_array_t *arr;
    toml_table_t *tab;
};

// TOML key/value pair.
struct toml_keyval_t {
    const char *key;  // key to this value
    int keylen;       // length of key.
    const char *val;  // the raw value
};

// Parsed TOML value.
//
// The string value s is a regular NULL-terminated C string, but the string
// length is also given in sl since TOML values may contain NULL bytes. The
// value is guaranteed to be correct UTF-8.
struct toml_value_t {
    bool ok;  // Was this value present?
    union {
        toml_timestamp_t *ts;  // datetime; must be freed after use.
        char *s;               // string value; must be freed after use
        int sl;                // string length, excluding NULL.
        bool b;                // bool value
        int64_t i;             // int value
        double d;              // double value
    } u;
};

// Timestamp type; some values may be empty depending on the value of kind.
struct toml_timestamp_t {
    // 'd'atetime
    // 'l'local-datetime
    // 'D'ate-local
    // 't'ime-local
    char kind;
    int year, month, day;
    int hour, minute, second, millisec;
    char *z;
};

// toml_parse() parses a TOML document from a string. Returns 0 on error, with
// the error message stored in errbuf.
//
// toml_parse_file() is identical, but reads from a file descriptor.
//
// Use toml_free() to free the return value; this will invalidate all handles
// for this table.
TOML_EXTERN toml_table_t *toml_parse(char *toml, char *errbuf, int errbufsz);
TOML_EXTERN toml_table_t *toml_parse_file(FILE *fp, char *errbuf, int errbufsz);
TOML_EXTERN void toml_free(toml_table_t *table);

// Table functions.
//
// toml_table_len() gets the number of direct keys for this table;
// toml_table_key() gets the nth direct key in this table.
TOML_EXTERN int toml_table_len(const toml_table_t *table);
TOML_EXTERN const char *toml_table_key(const toml_table_t *table, int keyidx, int *keylen);
TOML_EXTERN toml_value_t toml_table_string(const toml_table_t *table, const char *key);
TOML_EXTERN toml_value_t toml_table_bool(const toml_table_t *table, const char *key);
TOML_EXTERN toml_value_t toml_table_int(const toml_table_t *table, const char *key);
TOML_EXTERN toml_value_t toml_table_double(const toml_table_t *table, const char *key);
TOML_EXTERN toml_value_t toml_table_timestamp(const toml_table_t *table, const char *key);
TOML_EXTERN toml_array_t *toml_table_array(const toml_table_t *table, const char *key);
TOML_EXTERN toml_table_t *toml_table_table(const toml_table_t *table, const char *key);

// Array functions.
TOML_EXTERN int toml_array_len(const toml_array_t *array);
TOML_EXTERN toml_value_t toml_array_string(const toml_array_t *array, int idx);
TOML_EXTERN toml_value_t toml_array_bool(const toml_array_t *array, int idx);
TOML_EXTERN toml_value_t toml_array_int(const toml_array_t *array, int idx);
TOML_EXTERN toml_value_t toml_array_double(const toml_array_t *array, int idx);
TOML_EXTERN toml_value_t toml_array_timestamp(const toml_array_t *array, int idx);
TOML_EXTERN toml_array_t *toml_array_array(const toml_array_t *array, int idx);
TOML_EXTERN toml_table_t *toml_array_table(const toml_array_t *array, int idx);

#endif  // TOML_H