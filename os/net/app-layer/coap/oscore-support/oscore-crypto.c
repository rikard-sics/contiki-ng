/*
 * Copyright (c) 2024, RISE AB
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
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>, Rikard Höglund <rikard.hoglund@ri.se>
 *
 */

#include "oscore-crypto.h"
#include "ccm-star.h"
#include <string.h>
#include "cose.h"
#include <stdio.h>
#include "dtls-hmac.h"
#include "assert.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "oscore-crypto"
#define LOG_LEVEL LOG_LEVEL_COAP

/* SW/HW crypto libraries */
#ifdef OSCORE_WITH_HW_CRYPTO
#include "sys/pt-sem.h"
process_event_t oscore_pe_crypto_lock_released;
static struct pt_sem oscore_crypto_processor_mutex;

#ifdef CONTIKI_TARGET_ZOUL
#include "dev/sha256.h"
#endif /* CONTIKI_TARGET_ZOUL*/

#ifdef CONTIKI_TARGET_SIMPLELINK
#include "ti/drivers/SHA2.h"
#include "ti/drivers/AESCCM.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#endif /* CONTIKI_TARGET_SIMPLELINK */

#ifdef CONTIKI_TARGET_NATIVE
#error "Cannot run HW crypto on native!"
#endif /* CONTIKI_TARGET_NATIVE */

#else /* OSCORE_WITH_HW_CRYPTO */
#include "lib/ccm-star.h"
#endif /* OSCORE_WITH_HW_CRYPTO */

/* Utilities */
/*---------------------------------------------------------------------------*/
#ifdef OSCORE_WITH_HW_CRYPTO
void
reverse_endianness(uint8_t *a, unsigned int len) {
	uint8_t i, tmp[len];
	memcpy(tmp, a, len);
	for(i = 0; i < len; i++) {
		 a[len - 1 - i] = tmp[i];
	}
}
/*---------------------------------------------------------------------------*/
static inline
uint32_t
uint8x4_to_uint32(const uint8_t *field)
{/* left */
  return ((uint32_t)field[0] << 24)
         | ((uint32_t)field[1] << 16)
         | ((uint32_t)field[2] << 8)
         | ((uint32_t)field[3]);
}
/*---------------------------------------------------------------------------*/
static void
ec_uint8v_to_uint32v(uint32_t *result, const uint8_t *data, size_t size)
{
  /* data is expected to be encoded in big-endian */
  for(int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--) {
    *result = uint8x4_to_uint32(&data[i * sizeof(uint32_t)]);
    result++;
  }
}
/*---------------------------------------------------------------------------*/
static inline void
uint32_to_uint8x4(uint8_t *field, uint32_t data)
{
#ifdef CONTIKI_TARGET_SIMPLELINK
	/* right */
	field[3] = (uint8_t)((data & 0xFF000000) >> 24);
	field[2] = (uint8_t)((data & 0x00FF0000) >> 16);
	field[1] = (uint8_t)((data & 0x0000FF00) >>  8);
	field[0] = (uint8_t)((data & 0x000000FF)      );
#elif CONTIKI_TARGET_ZOUL
	/* left */
	field[0] = (uint8_t)((data & 0xFF000000) >> 24);
	field[1] = (uint8_t)((data & 0x00FF0000) >> 16);
	field[2] = (uint8_t)((data & 0x0000FF00) >>  8);
	field[3] = (uint8_t)((data & 0x000000FF)      );
#endif/* CONTIKI_TARGET_SIMPLELINK */

}
/*---------------------------------------------------------------------------*/
static void
ec_uint32v_to_uint8v(uint8_t *result, const uint32_t *data, size_t size)
{
	for (int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--)
	{
		uint32_to_uint8x4(result, data[i]);
		result += sizeof(uint32_t);
	}
}
/*---------------------------------------------------------------------------*/
void convert_simplelink(uint8_t *a, size_t len) {
	uint8_t i, len_32 = len / sizeof(uint32_t);
	uint32_t a_32[len_32], a_32_rev[len_32];
	ec_uint8v_to_uint32v(a_32, a, len);
	/* reverse endianness within 32-bit words */
	for(i = 0; i < len_32; i++) {
		a_32_rev[len_32 - 1 - i] = a_32[i];
	}
	ec_uint32v_to_uint8v(a, a_32_rev, len);
}
#endif /*OSCORE_WITH_HW_CRYPTO*/
/*OSCORE crypto functions*/
/*---------------------------------------------------------------------------*/

/* Returns 0 if failure to encrypt. Ciphertext length, otherwise.
   Tag-length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
encrypt(uint8_t alg,
        const uint8_t *key, uint8_t key_len,
        const uint8_t *nonce, uint8_t nonce_len,
        const uint8_t *aad, uint8_t aad_len,
        uint8_t *buffer, uint16_t plaintext_len)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128) {
    LOG_ERR("Unsupported algorithm %u\n", alg);
    return OSCORE_CRYPTO_UNSUPPORTED_ALGORITHM;
  }

  if(key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    LOG_ERR("Invalid key length %u != %u\n", key_len, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    return OSCORE_CRYPTO_INVALID_KEY_LEN;
  }

  if(nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    LOG_ERR("Invalid nonce length %u != %u\n", nonce_len, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
    return OSCORE_CRYPTO_INVALID_NONCE_LEN;
  }

  uint8_t* tag_buffer = &buffer[plaintext_len];

  LOG_DBG("Encrypting:\n");
  LOG_DBG("Key (len %u) [0x", key_len);
  LOG_DBG_BYTES(key, key_len);
  LOG_DBG_("]\n");
  LOG_DBG("IV (len %u) [0x", nonce_len);
  LOG_DBG_BYTES(nonce, nonce_len);
  LOG_DBG_("]\n");
  LOG_DBG("ADD (len %u) [0x", aad_len);
  LOG_DBG_BYTES(aad, aad_len);
  LOG_DBG_("]\n");
  LOG_DBG("Plaintext (len %u) [0x", plaintext_len);
  LOG_DBG_BYTES(buffer, plaintext_len);
  LOG_DBG_("]\n");
  LOG_DBG("Tag (len %u) [0x", COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  LOG_DBG_BYTES(tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  LOG_DBG_("]\n");
  
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
  cc2538_ccm_star_driver.set_key(key);
  cc2538_ccm_star_driver.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
#elif CONTIKI_TARGET_SIMPLELINK 
  AESCCM_Handle handle;
  CryptoKey cryptoKey;
  int_fast16_t encryptionResult;
  uint8_t mac[COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  uint8_t output[plaintext_len];

  handle = AESCCM_open(0, NULL);
 
  if (handle == NULL) {
      LOG_ERR("\nCould not open AESCCM handle!\n");
      return -1;
  }

  CryptoKeyPlaintext_initKey(&cryptoKey, key, key_len);
 
  AESCCM_Operation operation;
  AESCCM_Operation_init(&operation);

  operation.key               = &cryptoKey;
  operation.aad               = aad;
  operation.aadLength         = aad_len;
  operation.input             = buffer;
  operation.output            = output;
  operation.inputLength       = plaintext_len;
  operation.nonce             = nonce;
  operation.nonceLength       = nonce_len;
  operation.mac               = mac;
  operation.macLength         = COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

  encryptionResult = AESCCM_oneStepEncrypt(handle, &operation);

  if (encryptionResult != AESCCM_STATUS_SUCCESS) {
    LOG_ERR("\nAESCCM encryption failed with code: %d\n", encryptionResult);
    return -1;
  }
  memcpy(buffer, output, plaintext_len);
  memcpy(&(buffer[plaintext_len]), mac,  COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  AESCCM_close(handle);
#endif /* CONTIKI_TARGET_ZOUL or CONTIKI_TARGET_SIMPLELINK */
#else /* not OSCORE_WITH_HW_CRYPTO  */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
#endif /* OSCORE_WITH_HW_CRYPTO */

#ifdef OSCORE_ENC_DEC_DEBUG
  printf_hex("Tag'", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  printf_hex("Ciphertext", buffer, plaintext_len);
#endif

  return plaintext_len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
}
/*---------------------------------------------------------------------------*/
/* Return 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that plaintext buffer is of the correct length. */
int
decrypt(uint8_t alg,
        const uint8_t *key, uint8_t key_len,
        const uint8_t *nonce, uint8_t nonce_len,
        const uint8_t *aad, uint8_t aad_len,
        uint8_t *buffer, uint16_t ciphertext_len)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128) {
    LOG_ERR("Unsupported algorithm %u\n", alg);
    return OSCORE_CRYPTO_UNSUPPORTED_ALGORITHM;
  }

  if(key_len != COSE_algorithm_AES_CCM_16_64_128_KEY_LEN) {
    LOG_ERR("Invalid key length %u != %u\n", key_len, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    return OSCORE_CRYPTO_INVALID_KEY_LEN;
  }

  if(nonce_len != COSE_algorithm_AES_CCM_16_64_128_IV_LEN) {
    LOG_ERR("Invalid nonce length %u != %u\n", nonce_len, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
    return OSCORE_CRYPTO_INVALID_NONCE_LEN;
  }

  uint8_t tag_buffer[COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  uint16_t plaintext_len = ciphertext_len - COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

  LOG_DBG("Decrypting:\n");
  LOG_DBG("Key (len %u) [0x", key_len);
  LOG_DBG_BYTES(key, key_len);
  LOG_DBG_("]\n");
  LOG_DBG("IV (len %u) [0x", nonce_len);
  LOG_DBG_BYTES(nonce, nonce_len);
  LOG_DBG_("]\n");
  LOG_DBG("ADD (len %u) [0x", aad_len);
  LOG_DBG_BYTES(aad, aad_len);
  LOG_DBG_("]\n");
  LOG_DBG("Ciphertext (len %u) [0x", plaintext_len);
  LOG_DBG_BYTES(buffer, plaintext_len);
  LOG_DBG_("]\n");
  LOG_DBG("Tag (len %u) [0x", COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  LOG_DBG_BYTES(&buffer[plaintext_len], COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  LOG_DBG_("]\n");

#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
  cc2538_ccm_star_driver.set_key(key);
  cc2538_ccm_star_driver.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);
#elif CONTIKI_TARGET_SIMPLELINK 
  AESCCM_Operation operation;
  AESCCM_Handle handle;
  AESCCM_Params params;
  CryptoKey cryptoKey;
  int_fast16_t decryptionResult;
  uint8_t output[plaintext_len];
  AESCCM_Params_init(&params);

  handle = AESCCM_open(0, &params);
  if (handle == NULL) {
    LOG_ERR("Could not open AESCCM handle!\n");
    return -1; 
  }

  CryptoKeyPlaintext_initKey(&cryptoKey, key, key_len);

  AESCCM_Operation_init(&operation);

  operation.key               = &cryptoKey;
  operation.aad               = aad;
  operation.aadLength         = aad_len;
  operation.input             = buffer;
  operation.output            = output;
  operation.inputLength       = plaintext_len;
  operation.nonce             = nonce;
  operation.nonceLength       = nonce_len;
  operation.mac               = &(buffer[plaintext_len]);
  operation.macLength         = COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

  decryptionResult = AESCCM_oneStepDecrypt(handle, &operation);

  if (decryptionResult != AESCCM_STATUS_SUCCESS) {
       LOG_ERR("Decryption in HW failed with code %d\n", decryptionResult);
       return 0;
  }
  memcpy(buffer, output, plaintext_len);
  AESCCM_close(handle);
  return plaintext_len;
#endif /* CONTIKI_TARGET_ZOUL or CONTIKI_TARGET_SIMPLELINK */
#else /* not OSCORE_WITH_HW_CRYPTO  */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);
#endif /* OSCORE_WITH_HW_CRYPTO */

#ifdef OSCORE_ENC_DEC_DEBUG
  printf_hex("Tag'", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  printf_hex("Plaintext", buffer, plaintext_len);
#endif

  if(memcmp(tag_buffer, &(buffer[plaintext_len]), COSE_algorithm_AES_CCM_16_64_128_TAG_LEN) != 0) {
    return OSCORE_CRYPTO_DECRYPTION_FAILURE; /* Decryption failure */
  }
  return plaintext_len;
}
/*---------------------------------------------------------------------------*/
/* only works with key_len <= 64 bytes */
void
hmac_sha256(const uint8_t *key, uint8_t key_len, const uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
  assert(key_len <= 64);

  dtls_hmac_context_t ctx;
  dtls_hmac_init(&ctx, key, key_len);
  dtls_hmac_update(&ctx, data, data_len);
  dtls_hmac_finalize(&ctx, hmac);
}
/*---------------------------------------------------------------------------*/
static void
hkdf_extract(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len, uint8_t *prk_buffer)
{
  uint8_t zeroes[DTLS_SHA256_DIGEST_LENGTH];
  memset(zeroes, 0, sizeof(zeroes));

  if(salt == NULL || salt_len == 0){
    salt = zeroes;
    salt_len = sizeof(zeroes);
  }
  
  hmac_sha256(salt, salt_len, ikm, ikm_len, prk_buffer);
}
/*---------------------------------------------------------------------------*/
static int
hkdf_expand(const uint8_t *prk, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{
  if(info_len > HKDF_INFO_MAXLEN) {
    return OSCORE_CRYPTO_HKDF_INVALID_INFO_LEN;
  }
  if(okm_len > HKDF_OUTPUT_MAXLEN) {
    return OSCORE_CRYPTO_HKDF_INVALID_OKM_LEN;
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
/*---------------------------------------------------------------------------*/
int
hkdf(
  const uint8_t *salt, uint8_t salt_len,
  const uint8_t *ikm, uint8_t ikm_len,
  const uint8_t *info, uint8_t info_len,
  uint8_t *okm, uint8_t okm_len)
{
  uint8_t prk_buffer[DTLS_SHA256_DIGEST_LENGTH];
  hkdf_extract(salt, salt_len, ikm, ikm_len, prk_buffer);
  return hkdf_expand(prk_buffer, info, info_len, okm, okm_len);
}
/*---------------------------------------------------------------------------*/

