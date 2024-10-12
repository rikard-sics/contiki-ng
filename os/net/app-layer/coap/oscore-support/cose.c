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
 *      An implementation of the CBOR Object Signing and Encryption (RFC8152).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */


#include "cose.h"
#include "oscore-crypto.h"
#include "string.h"

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr)
{
  memset(ptr, 0, sizeof(cose_encrypt0_t));
}
void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
  ptr->alg = alg;
}
void
cose_encrypt0_set_content(cose_encrypt0_t *ptr, uint8_t *buffer, uint16_t size)
{
  ptr->content = buffer;
  ptr->content_len = size;
}

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  if(size > 8){
	  return;
  }
  memcpy(ptr->partial_iv, buffer, size);
  ptr->partial_iv_len = size;
}
/* Return length */
int
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->partial_iv;
  return ptr->partial_iv_len;
}
void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, const uint8_t *buffer, uint8_t size)
{
  ptr->key_id = buffer;
  ptr->key_id_len = size;
}
/* Return length */
uint8_t
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
  *buffer = ptr->key_id;
  return ptr->key_id_len;
}

int cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer){
  *buffer = ptr->kid_context;
  return ptr->kid_context_len;
}

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, int size){
  ptr->kid_context = buffer;
  ptr->kid_context_len = size;
} 


void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->aad = buffer;
  ptr->aad_len = size;
}
/* Returns 1 if successfull, 0 if key is of incorrect length. */
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, int key_size)
{
  if(key_size != 16) {
    return 0;
  }

  ptr->key = key;
  ptr->key_len = key_size;

  return 1;
}
void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->nonce = buffer;
  ptr->nonce_len = size;
}
int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr)
{
  if(ptr->key == NULL || ptr->key_len != 16) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != 13) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->content == NULL ) {
    return -4;
  }

  return encrypt(ptr->alg,
    ptr->key, ptr->key_len,
    ptr->nonce, ptr->nonce_len,
    ptr->aad, ptr->aad_len,
    ptr->content, ptr->content_len);
}
int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr)
{
  if(ptr->key == NULL || ptr->key_len != 16) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != 13) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->content == NULL ) {
    return -4;
  }

  return decrypt(ptr->alg,
    ptr->key, ptr->key_len,
    ptr->nonce, ptr->nonce_len,
    ptr->aad, ptr->aad_len,
    ptr->content, ptr->content_len);
}
