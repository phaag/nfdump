/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: inline.c 40 2009-12-16 10:41:44Z haag $
 *
 *  $LastChangedRevision: 40 $
 *	
 */

static inline uint16_t	Get_val16(void *p);

static inline uint32_t	Get_val24(void *p);

static inline uint32_t	Get_val32(void *p);

static inline uint64_t	Get_val40(void *p);

static inline uint64_t	Get_val48(void *p);

static inline uint64_t	Get_val56(void *p);

static inline uint64_t	Get_val64(void *p);

static inline void	Put_val16(uint16_t v, void *p);

static inline void	Put_val24(uint32_t v, void *p);

static inline void	Put_val32(uint32_t v, void *p);

// static inline void	Put_val40(uint64_t v, void *p);

static inline void	Put_val48(uint64_t v, void *p);

// static inline void	Put_val56(uint64_t v, void *p);

static inline void	Put_val64(uint64_t v, void *p);

static inline uint16_t	Get_val16(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
#else
	mask.val.val8[0] = in[1];
	mask.val.val8[1] = in[0];
#endif
	return mask.val.val16[0];

} // End of Get_val16

static inline uint32_t	Get_val24(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = 0;
	mask.val.val8[1] = in[0];
	mask.val.val8[2] = in[1];
	mask.val.val8[3] = in[2];
#else
	mask.val.val8[0] = in[2];
	mask.val.val8[1] = in[1];
	mask.val.val8[2] = in[0];
	mask.val.val8[3] = 0;
#endif
	return mask.val.val32[0];

} // End of Get_val24

static inline uint32_t	Get_val32(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
	mask.val.val8[2] = in[2];
	mask.val.val8[3] = in[3];
#else
	mask.val.val8[0] = in[3];
	mask.val.val8[1] = in[2];
	mask.val.val8[2] = in[1];
	mask.val.val8[3] = in[0];
#endif

	return mask.val.val32[0];

} // End of Get_val32

static inline uint64_t	Get_val40(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = 0;
	mask.val.val8[1] = 0;
	mask.val.val8[2] = 0;
	mask.val.val8[3] = in[0];
	mask.val.val8[4] = in[1];
	mask.val.val8[5] = in[2];
	mask.val.val8[6] = in[3];
	mask.val.val8[7] = in[4];
#else
	mask.val.val8[0] = in[4];
	mask.val.val8[1] = in[3];
	mask.val.val8[2] = in[2];
	mask.val.val8[3] = in[1];
	mask.val.val8[4] = in[0];
	mask.val.val8[5] = 0;
	mask.val.val8[6] = 0;
	mask.val.val8[7] = 0;
#endif

	return mask.val.val64;

} // End of Get_val40

static inline uint64_t	Get_val48(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = 0;
	mask.val.val8[1] = 0;
	mask.val.val8[2] = in[0];
	mask.val.val8[3] = in[1];
	mask.val.val8[4] = in[2];
	mask.val.val8[5] = in[3];
	mask.val.val8[6] = in[4];
	mask.val.val8[7] = in[5];
#else
	mask.val.val8[0] = in[5];
	mask.val.val8[1] = in[4];
	mask.val.val8[2] = in[3];
	mask.val.val8[3] = in[2];
	mask.val.val8[4] = in[1];
	mask.val.val8[5] = in[0];
	mask.val.val8[6] = 0;
	mask.val.val8[7] = 0;
#endif

	return mask.val.val64;

} // End of Get_val48

static inline uint64_t	Get_val56(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = 0;
	mask.val.val8[1] = in[0];
	mask.val.val8[2] = in[1];
	mask.val.val8[3] = in[2];
	mask.val.val8[4] = in[3];
	mask.val.val8[5] = in[4];
	mask.val.val8[6] = in[5];
	mask.val.val8[7] = in[6];
#else
	mask.val.val8[0] = in[6];
	mask.val.val8[1] = in[5];
	mask.val.val8[2] = in[4];
	mask.val.val8[3] = in[3];
	mask.val.val8[4] = in[2];
	mask.val.val8[5] = in[1];
	mask.val.val8[6] = in[0];
	mask.val.val8[7] = 0;
#endif

	return mask.val.val64;

} // End of Get_val56

static inline uint64_t	Get_val64(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

#ifdef WORDS_BIGENDIAN
	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
	mask.val.val8[2] = in[2];
	mask.val.val8[3] = in[3];
	mask.val.val8[4] = in[4];
	mask.val.val8[5] = in[5];
	mask.val.val8[6] = in[6];
	mask.val.val8[7] = in[7];
#else
	mask.val.val8[0] = in[7];
	mask.val.val8[1] = in[6];
	mask.val.val8[2] = in[5];
	mask.val.val8[3] = in[4];
	mask.val.val8[4] = in[3];
	mask.val.val8[5] = in[2];
	mask.val.val8[6] = in[1];
	mask.val.val8[7] = in[0];
#endif

	return mask.val.val64;

} // End of Get_val64

static inline void	Put_val16(uint16_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val16[0] = v;
	out[0] = mask.val.val8[0];
	out[1] = mask.val.val8[1];

} // End of Put_val16

static inline void	Put_val24(uint32_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val32[0] = v;
	out[0] = mask.val.val8[1];
	out[1] = mask.val.val8[2];
	out[2] = mask.val.val8[3];

} // End of Put_val24

static inline void	Put_val32(uint32_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val32[0] = v;
	out[0] = mask.val.val8[0];
	out[1] = mask.val.val8[1];
	out[2] = mask.val.val8[2];
	out[3] = mask.val.val8[3];

} // End of Put_val32

/*
 * not yet used
 *
static inline void	Put_val40(uint64_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val64 = v;
	out[0] = mask.val.val8[3];
	out[1] = mask.val.val8[4];
	out[2] = mask.val.val8[5];
	out[3] = mask.val.val8[6];
	out[4] = mask.val.val8[7];

} // End of Put_val40
 *
 */

static inline void	Put_val48(uint64_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val64 = v;
	out[0] = mask.val.val8[2];
	out[1] = mask.val.val8[3];
	out[2] = mask.val.val8[4];
	out[3] = mask.val.val8[5];
	out[4] = mask.val.val8[6];
	out[5] = mask.val.val8[7];

} // End of Put_val48

/*
 * not yet used
 *
static inline void	Put_val56(uint64_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val64 = v;
	out[0] = mask.val.val8[1];
	out[1] = mask.val.val8[2];
	out[2] = mask.val.val8[3];
	out[3] = mask.val.val8[4];
	out[4] = mask.val.val8[5];
	out[5] = mask.val.val8[6];
	out[6] = mask.val.val8[7];

} // End of Put_val56
 *
 */

static inline void	Put_val64(uint64_t v, void *p) {
uint8_t		*out = (uint8_t *)p;
type_mask_t mask;

	mask.val.val64 = v;
	out[0] = mask.val.val8[0];
	out[1] = mask.val.val8[1];
	out[2] = mask.val.val8[2];
	out[3] = mask.val.val8[3];
	out[4] = mask.val.val8[4];
	out[5] = mask.val.val8[5];
	out[6] = mask.val.val8[6];
	out[7] = mask.val.val8[7];

} // End of Put_val64


