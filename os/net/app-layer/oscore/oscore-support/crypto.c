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
 *      An implementation of the Hash Based Key Derivation Function (RFC) and wrappers for AES-CCM*.
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */



#include "crypto.h"
#include "ccm-star.h"
#include <string.h>
#include "cose.h"

#include <stdio.h>
#include "dtls-hmac.h"
//#include "dtls.h"

void
kprintf_hex(unsigned char *data, unsigned int len)
{
  unsigned int i = 0;
  for(i = 0; i < len; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
}
/* Returns 0 if failure to encrypt. Ciphertext length, otherwise.
   Tag-length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint8_t plaintext_len, uint8_t *ciphertext_buffer)
{

  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len != 16 || nonce_len != 13) {
    return -5;
  }
  uint8_t tag_len = 8;
  uint8_t encryption_buffer[plaintext_len + tag_len];

  memcpy(encryption_buffer, plaintext_buffer, plaintext_len);

  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, encryption_buffer, plaintext_len, aad, aad_len, &(encryption_buffer[plaintext_len]), tag_len, 1);

 /*  printf("Encrypt:\n");
   printf("Key:\n");
   kprintf_hex(key, key_len);
   printf("IV:\n");
   kprintf_hex(nonce, nonce_len);
   printf("AAD:\n");
   kprintf_hex(aad, aad_len);
   printf("Plaintext:\n");
   kprintf_hex(plaintext_buffer, plaintext_len);
   printf("Ciphertext&Tag:\n");
   kprintf_hex(encryption_buffer, plaintext_len + 8);
 */
  memcpy(ciphertext_buffer, encryption_buffer, plaintext_len + tag_len);
  return plaintext_len + tag_len;
}
/* Return 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that plaintext buffer is of the correct length. */
int
decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint8_t ciphertext_len, uint8_t *plaintext_buffer)
{

  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len != 16 || nonce_len != 13) {
    return -5;
  }

  uint8_t tag_len = 8;
  int plaintext_len = ciphertext_len - tag_len;
  uint8_t decryption_buffer[plaintext_len];
  uint8_t tag_buffer[tag_len];

  memcpy(decryption_buffer, ciphertext_buffer, plaintext_len);
  CCM_STAR.set_key(key);
 /*    printf("Decrypt:\n");
     printf("Key:\n");
     kprintf_hex(key, key_len);
     printf("IV:\n");
     kprintf_hex(nonce, nonce_len);
     printf("AAD:\n");
     kprintf_hex(aad, aad_len);
     printf("Ciphertext&Tag:\n");
     kprintf_hex(decryption_buffer, ciphertext_len);
   */
  CCM_STAR.aead(nonce, decryption_buffer, plaintext_len, aad, aad_len, tag_buffer, tag_len, 0);

  if(memcmp(tag_buffer, &(ciphertext_buffer[plaintext_len]), tag_len) != 0) {
    return 0; /* Decryption failure */
  }
  
  memcpy(plaintext_buffer, decryption_buffer, plaintext_len);
  printf("Plaintext:\n");
  kprintf_hex(plaintext_buffer, plaintext_len);
  return plaintext_len;
}
/* only works with key_len <= 64 bytes */
void
hmac_sha256(const uint8_t *key, uint8_t key_len, const uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
  dtls_hmac_context_t ctx;
  dtls_hmac_init(&ctx, key, key_len);
  dtls_hmac_update(&ctx, data, data_len);
  dtls_hmac_finalize(&ctx, hmac);

}

int
hkdf_extract( const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len, uint8_t *prk_buffer)
{
  uint8_t zeroes[32];
  memset(zeroes, 0, 32);
  
  if(salt == NULL || salt_len == 0){
    hmac_sha256(zeroes, 32, ikm, ikm_len, prk_buffer);
  } else { 
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk_buffer);
  }
  return 0;
}
int
hkdf_expand( const uint8_t *prk, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{
  int N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t aggregate_buffer[32 + info_len + 1];
  uint8_t out_buffer[okm_len + 32]; /* 32 extra bytes to fit the last block */
  int i;
  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_len);
  aggregate_buffer[info_len] = 0x01;
  hmac_sha256(prk, 32, aggregate_buffer, info_len + 1, &(out_buffer[0]));

  /* Compose T(2) -> T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), 32);
  for(i = 1; i < N; i++) {
    memcpy(&(aggregate_buffer[32]), info, info_len);
    aggregate_buffer[32 + info_len] = i + 1;
    hmac_sha256(prk, 32, aggregate_buffer, 32 + info_len + 1, &(out_buffer[i * 32]));
    memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
  }

  memcpy(okm, out_buffer, okm_len);
  return 0;
}

int
hkdf(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{

  uint8_t prk_buffer[32];
  hkdf_extract(salt, salt_len, ikm, ikm_len, prk_buffer);
  hkdf_expand(prk_buffer, info, info_len, okm, okm_len);
  return 0;
}
