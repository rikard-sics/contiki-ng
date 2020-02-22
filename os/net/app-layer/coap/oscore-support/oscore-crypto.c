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
 *      An implementation of the Hash Based Key Derivation Function (RFC5869) and wrappers for AES-CCM*.
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */



#include "oscore-crypto.h"
#include "ccm-star.h"
#include <string.h>
#include "cose.h"

#include <stdio.h>
#include "dtls-hmac.h"
#include "uECC.h"

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
        uint8_t *aad, uint8_t aad_len, uint8_t *buffer, uint16_t plaintext_len)
{

  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len !=  COSE_algorithm_AES_CCM_16_64_128_KEY_LEN 
		  || nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    return -5;
  }

  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, &(buffer[plaintext_len]), COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
/*
   printf("Encrypt:\n");
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
  return plaintext_len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
}
/* Return 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that plaintext buffer is of the correct length. */
int
decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *buffer, uint16_t ciphertext_len)
{

  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN
		|| nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    return -5;
  }

  uint8_t tag_buffer[COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  
  CCM_STAR.set_key(key);
    printf("Decrypt:\n");
     printf("Key:\n");
     kprintf_hex(key, key_len);
     printf("IV:\n");
     kprintf_hex(nonce, nonce_len);
     printf("AAD:\n");
     kprintf_hex(aad, aad_len);
     printf("Ciphertext&Tag:\n");
     kprintf_hex(buffer, ciphertext_len);
 
  uint16_t plaintext_len = ciphertext_len - COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);

  if(memcmp(tag_buffer, &(buffer[plaintext_len]), COSE_algorithm_AES_CCM_16_64_128_TAG_LEN) != 0) {
      	  return 0; /* Decryption failure */
  }
  
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
  if( info_len > HKDF_INFO_MAXLEN) {
	  return -1;
  }
  if( okm_len > HKDF_OUTPUT_MAXLEN) {
	  return -2;
  }
  int N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t aggregate_buffer[32 + HKDF_INFO_MAXLEN + 1];
  uint8_t out_buffer[HKDF_OUTPUT_MAXLEN + 32]; /* 32 extra bytes to fit the last block */
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

#ifdef WITH_GROUPCOM
/* Return 0 if key pair generation failure. Key lengths are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */
int
oscore_edDSA_keypair(int8_t alg, int8_t alg_param, uint8_t *private_key, uint8_t *public_key, uint8_t *es256_seed)
{
   if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
       return 0;
    }
 //   es256_create_keypair(public_key, private_key, es256_seed);
/*
  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"\nKeyPair:\n");
    fprintf(stderr,"Public Key:\n");
    for (uint u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
    fprintf(stderr,"\nPrivate Key:\n");
    for (uint u = 0 ; u < Ed25519_PRIVATE_KEY_LEN; u++)
                fprintf(stderr," %02x",private_key[u]);
    fprintf(stderr,"\nseed \n");
    for (uint u = 0 ; u < Ed25519_SEED_LEN; u++)
                fprintf(stderr," %02x",ed25519_seed[u]);
    fprintf(stderr, "\n");
  }*/

  return 1;
}

/* For ECDSA-Deterministic */
#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32
typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    dtls_sha256_ctx ctx;
} SHA256_HashContext;

static void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    //SHA256_Init(&context->ctx);
    dtls_sha256_init(&context->ctx);
}

static void update_SHA256(uECC_HashContext *base,
                          const uint8_t *message,
                          unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    //SHA256_Update(&context->ctx, message, message_size);
    dtls_sha256_update(&context->ctx, message, message_size);
}

static void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    //SHA256_Final(hash_result, &context->ctx);
    dtls_sha256_final(hash_result, &context->ctx);
}


int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *private_key, uint8_t *public_key){
   if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }

  printf("\nAlgorithms OK!");
  printf("\nPrinting private_key;...\n");
  kprintf_hex(private_key, 32);
  //printf("\nLen of ciphertext (var): %d", ciphertext_len);
  //printf("\nLen of ciphertext: %d", strlen(ciphertext));
  //printf("\nLen of priv_k: %d", strlen(private_key));
  //printf("\nLen of pub_k: %d", strlen(public_key));
  //printf("\nLen of signature: %d", strlen(signature));
  printf("\nEverything good!");

  uint8_t message_hash[SHA256_DIGEST_LENGTH];
  dtls_sha256_ctx msg_hash_ctx;
  dtls_sha256_init(&msg_hash_ctx);
  dtls_sha256_update(&msg_hash_ctx, ciphertext, ciphertext_len);
  dtls_sha256_final(message_hash, &msg_hash_ctx);
  printf("\nPrinting message_hash after dtls_sha256_final:\n");
  kprintf_hex(message_hash, SHA256_DIGEST_LENGTH);
  uint8_t tmp[32 + 32 + 64];//32+32+64
  SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  printf("\nAfter all shas... Now uEECsign deterministic...");
  uECC_sign_deterministic(private_key, message_hash, &ctx.uECC, signature);

/*
  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"Sign:\n");
    fprintf(stderr,"Public Key:\n");
    for (uint u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Private Key:\n");
    for (uint u = 0 ; u < Ed25519_PRIVATE_KEY_LEN; u++)
                fprintf(stderr," %02x",private_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"incoming ciphertext \n");
    for (uint u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",ciphertext[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Signature:\n");
    for (uint u = 0 ; u < Ed25519_SIGNATURE_LEN; u++)
                fprintf(stderr," %02x",signature[u]);
    fprintf(stderr,"\n");
  } 
  */  
    return 1;
}

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, uint8_t *public_key){
  if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }
/*
  if (coap_get_log_level() >= LOG_INFO){
     fprintf(stderr,"Verify:\n");
     fprintf(stderr,"Public Key:\n");
     for (uint u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
     fprintf(stderr,"\n");
     fprintf(stderr,"incoming ciphertext \n");
     for (uint u = 0 ; u < plaintext_len; u++)
                fprintf(stderr," %02x",plaintext[u]);
     fprintf(stderr,"\n");
     fprintf(stderr,"Signature:\n");
     for (uint u = 0 ; u < Ed25519_SIGNATURE_LEN; u++)
                fprintf(stderr," %02x",signature[u]);
     fprintf(stderr,"\n");
  }
*/
  printf("public key\n");
  kprintf_hex(public_key, 64); 
  printf("bytes to verify\n");
  kprintf_hex(plaintext, plaintext_len);
  printf("signature bytes\n");
  kprintf_hex(signature, 64);
  uint8_t message_hash[SHA256_DIGEST_LENGTH];
  dtls_sha256_ctx msg_hash_ctx;
  dtls_sha256_init(&msg_hash_ctx);
  dtls_sha256_update(&msg_hash_ctx, plaintext, plaintext_len);
  dtls_sha256_final(message_hash, &msg_hash_ctx);
  
  int res = uECC_verify(public_key, message_hash, signature);
  return res;  
}

#endif /*WITH_GROUPCOM*/
