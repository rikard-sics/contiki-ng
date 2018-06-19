/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      An implementation of the CBOR Object Signing and Encryption (RFC).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#ifndef _COSE_H
#define _COSE_H
#include <inttypes.h>

#define COSE_Algorithm_AES_CCM_64_64_128 12
#define COSE_Algorithm_AES_CCM_16_64_128 10

#define COSE_algorithm_AES_CCM_16_64_128_KEY_LEN 16
#define COSE_algorithm_AES_CCM_16_64_128_IV_LEN  13


#define COSE_algorithm_AES_CCM_64_64_128_KEY_LEN 16
#define COSE_algorithm_AES_CCM_64_64_128_IV_LEN  7


/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {

  uint8_t alg;

  uint8_t *key;
  int key_len;

  uint8_t *partial_iv;
  int partial_iv_len;

  uint8_t *key_id;
  int key_id_len;

  uint8_t *kid_context;
  int kid_context_len;

  uint8_t *nonce;
  int nonce_len;

  uint8_t *aad;
  int aad_len;

  uint8_t *external_aad;
  int external_aad_len;

  uint8_t *plaintext;
  int plaintext_len;

  uint8_t *ciphertext;
  int ciphertext_len;
} cose_encrypt0_t;

/* Return length */
int cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer);

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);
void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, int key_size);

void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, int ciphertext_len);
int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, int plaintext_len);

#endif /* _COSE_H */
