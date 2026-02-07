/*
 *  Copyright (c) 2026, Peter Haag, Murilo Chianfa
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

#ifndef _RECORD_CALLBACK_H
#define _RECORD_CALLBACK_H 1

#include "nfxV3.h"

// Callback function type for processing decoded flow records
// Called for each flow record after it's been decoded and before it's written
// recordHeaderV3: pointer to the complete V3 record
// userData: user-provided context pointer
typedef void (*record_callback_t)(recordHeaderV3_t *recordHeaderV3, void *userData);

// Global callback registration
// callback: function to call for each record (NULL to disable)
// userData: context pointer passed to the callback
void SetRecordCallback(record_callback_t callback, void *userData);

// Get the currently registered callback
record_callback_t GetRecordCallback(void);

// Get the user data for the callback
void *GetRecordCallbackUserData(void);

// Helper macro to call the callback if registered
#define CALL_RECORD_CALLBACK(recordHeader) do { \
    record_callback_t cb = GetRecordCallback(); \
    if (cb) { \
        cb(recordHeader, GetRecordCallbackUserData()); \
    } \
} while(0)

#endif  // _RECORD_CALLBACK_H
