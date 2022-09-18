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
 *  $NfDump Author:$
 *
 *  $Id: rijndael.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

/* Original disclaimer
 * Atlanta, Georgia 30332.
 * All Rights Reserved
 * 
 * The following Software is posted on the Internet by the Georgia
 * Tech Research Corporation (GTRC). It was developed by employees
 * of the Georgia Institute of Technology in the College of Computing.
 * GTRC hereby grants to the user a non-exclusive, royalty-free
 * license to utilize such Software for the User's own purposes
 * pursuant to the following conditions.
 * 
 * 
 * THE SOFTWARE IS LICENSED ON AN "AS IS" BASIS. GTRC MAKES NO WARRANTY
 * THAT ALL ERRORS CAN BE OR HAVE BEEN ELIMINATED FROM THE SOFTWARE.
 * GTRC SHALL NOT BE RESPONSIBLE FOR LOSSES OF ANY KIND RESULTING FROM
 * THE USE OF THE SOFTWARE AND ITS ACCOMPANYING DOCUMENTATION, AND CAN 
 * IN NO WAY PROVIDE COMPENSATION FOR ANY LOSSES SUSTAINED, INCLUDING 
 * BUT NOT LIMITED TO ANY OBLIGATION, LIABILITY, RIGHT, CLAIM OR REMEDY 
 * FOR TORT, OF FOR ANY ACTUAL OR ALLEGED INFRINGEMENT OF PATENTS, COPYRIGHTS,
 * TRADE SECRETS, OR SIMILAR RIGHTS OF THIRD PARTIES, NOR ANY BUSINESS 
 * EXPENSE, MACHINE DOWNTIME, OR DAMAGES CAUSED LICENSEE BY ANY DEFICIENCY,
 * DEFECT OR ERROR IN THE SOFTWARE OR MALFUNCTION THEREOF, NOR ANY 
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES, HOWEVER CAUSED. GTRC DISCLAIMS
 * ALL WARRANTIES, BOTH EXPRESS AND IMPLIED RESPECTING THE USE AND
 * OPERATION OF THE SOFTWARE AND ANY ACCOMPANYING DOCUMENTATION,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * PARTICULAR PURPOSE AND ANY IMPLIED WARRANTY ARISING FROM COURSE
 * OF PERFORMANCE, COURSE OF DEALING OR USAGE OF TRADE. GTRC MAKES NO
 * WARRANTY THAT THE SOFTWARE IS ADEQUATELY OR COMPLETELY DESCRIBED 
 * IN, OR BEHAVES IN ACCORDANCE WITH ANY OF THE ACCOMPANYING 
 * DOCUMENTATION. THE USER OF THE SOFTWARE IS EXPECTED TO MAKE THE FINAL
 * EVALUATION OF THE SOFTWARE'S USEFULNESS IN USER'S OWN ENVIRONMENT.
 * 
 *
 */

#ifndef _RIJNDAEL_H_
#define _RIJNDAEL_H_ 1
//
// File : rijndael.h
// Creation date : Sun Nov 5 2000 03:21:05 CEST
// Author : Szymon Stefanek (stefanek@tin.it)
//
// Another implementation of the Rijndael cipher.
// This is intended to be an easily usable library file.
// This code is public domain.
// Based on the Vincent Rijmen and K.U.Leuven implementation 2.4.
//

//
// Original Copyright notice:
//
//    rijndael-alg-fst.c   v2.4   April '2000
//    rijndael-alg-fst.h
//    rijndael-api-fst.c
//    rijndael-api-fst.h
//
//    Optimised ANSI C code
//
//    authors: v1.0: Antoon Bosselaers
//             v2.0: Vincent Rijmen, K.U.Leuven
//             v2.3: Paulo Barreto
//             v2.4: Vincent Rijmen, K.U.Leuven
//
//    This code is placed in the public domain.
//

//
// This implementation works on 128 , 192 , 256 bit keys
// and on 128 bit blocks
//

//
// Example of usage:
//
//  // Input data
//  unsigned char key[32];                       // The key
//  initializeYour256BitKey();                   // Obviously initialized with sth
//  const unsigned char * plainText = getYourPlainText(); // Your plain text
//  int plainTextLen = strlen(plainText);        // Plain text length
//
//  // Encrypting
//  Rijndael rin;
//  unsigned char output[plainTextLen + 16];
//
//  rin.init(Rijndael::CBC,Rijndael::Encrypt,key,Rijndael::Key32Bytes);
//  // It is a good idea to check the error code
//  int len = rin.padEncrypt(plainText,len,output);
//  if(len >= 0)useYourEncryptedText();
//  else encryptError(len);
//
//  // Decrypting: we can reuse the same object
//  unsigned char output2[len];
//  rin.init(Rijndael::CBC,Rijndael::Decrypt,key,Rijndael::Key32Bytes));
//  len = rin.padDecrypt(output,len,output2);
//  if(len >= 0)useYourDecryptedText();
//  else decryptError(len);
//

#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

// Error codes
#define RIJNDAEL_SUCCESS 0
#define RIJNDAEL_UNSUPPORTED_MODE -1
#define RIJNDAEL_UNSUPPORTED_DIRECTION -2
#define RIJNDAEL_UNSUPPORTED_KEY_LENGTH -3
#define RIJNDAEL_BAD_KEY -4
#define RIJNDAEL_NOT_INITIALIZED -5
#define RIJNDAEL_BAD_DIRECTION -6
#define RIJNDAEL_CORRUPTED_DATA -7


enum Direction { Encrypt , Decrypt };
enum Mode { ECB , CBC , CFB1 };
enum KeyLength { Key16Bytes , Key24Bytes , Key32Bytes };

//////////////////////////////////////////////////////////////////////////////////////////
// API
//////////////////////////////////////////////////////////////////////////////////////////

// init(): Initializes the crypt session
// Returns RIJNDAEL_SUCCESS or an error code
// mode      : ECB, CBC or CFB1
//             You have to use the same mode for encrypting and decrypting
// dir       : Encrypt or Decrypt
//             A cipher instance works only in one direction
//             (Well , it could be easily modified to work in both
//             directions with a single init() call, but it looks
//             useless to me...anyway , it is a matter of generating
//             two expanded keys)
// key       : array of unsigned octets , it can be 16 , 24 or 32 bytes long
//             this CAN be binary data (it is not expected to be null terminated)
// keyLen    : Key16Bytes , Key24Bytes or Key32Bytes
// initVector: initialization vector, you will usually use 0 here
int Rijndael_init(int mode,int dir,const uint8_t * key,int keyLen,uint8_t * initVector);
// Encrypts the input array (can be binary data)
// The input array length must be a multiple of 16 bytes, the remaining part
// is DISCARDED.
// so it actually encrypts inputLen / 128 blocks of input and puts it in outBuffer
// Input len is in BITS!
// outBuffer must be at least inputLen / 8 bytes long.
// Returns the encrypted buffer length in BITS or an error code < 0 in case of error
int Rijndael_blockEncrypt(const uint8_t *input, int inputLen, uint8_t *outBuffer);
// Encrypts the input array (can be binary data)
// The input array can be any length , it is automatically padded on a 16 byte boundary.
// Input len is in BYTES!
// outBuffer must be at least (inputLen + 16) bytes long
// Returns the encrypted buffer length in BYTES or an error code < 0 in case of error
int Rijndael_padEncrypt(const uint8_t *input, int inputOctets, uint8_t *outBuffer);
// Decrypts the input vector
// Input len is in BITS!
// outBuffer must be at least inputLen / 8 bytes long
// Returns the decrypted buffer length in BITS and an error code < 0 in case of error
int Rijndael_blockDecrypt(const uint8_t *input, int inputLen, uint8_t *outBuffer);
// Decrypts the input vector
// Input len is in BYTES!
// outBuffer must be at least inputLen bytes long
// Returns the decrypted buffer length in BYTES and an error code < 0 in case of error
int Rijndael_padDecrypt(const uint8_t *input, int inputOctets, uint8_t *outBuffer);
#endif
