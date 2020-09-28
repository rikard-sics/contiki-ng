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

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "coap-uip"
#define LOG_LEVEL  LOG_LEVEL_COAP

#include "sys/rtimer.h"
#ifdef WITH_GROUPCOM
#include "sys/pt.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"
#include "random.h"
/*SW/HW crypto libraries*/
#ifdef OSCORE_WITH_HW_CRYPTO

#ifdef CONTIKI_TARGET_ZOUL
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "dev/sha256.h"
#endif

#ifdef CONTIKI_TARGET_SIMPLELINK
#include <ti/drivers/SHA2.h>
#include "ti/drivers/ECDSA.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#endif

#ifdef CONTIKI_TARGET_NATIVE
#error "Cannot run HW crypto on native!"
#endif

#else /*SW crypto*/

#include "uECC.h"

#endif /*OSCORE_WITH_HW_CRYPTO*/

#ifdef OSCORE_WITH_HW_CRYPTO
#include "sys/pt-sem.h"
process_event_t pe_crypto_lock_released;
static struct pt_sem crypto_processor_mutex;
#endif //OSCORE_WITH_HW_CRYPTO

process_event_t pe_message_signed;
process_event_t pe_message_verified;

PROCESS(signer, "signer");
PROCESS(verifier, "verifier");
#endif
void
kprintf_hex(unsigned char *data, unsigned int len)
{
  LOG_DBG("%s (len=%u): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}
#ifdef WITH_GROUPCOM
/*---------------------------------------------------------------------------*/
static inline
uint32_t
uint8x4_to_uint32(const uint8_t *field)
{//left
  return ((uint32_t)field[0] << 24)
         | ((uint32_t)field[1] << 16)
         | ((uint32_t)field[2] << 8)
         | ((uint32_t)field[3]);
}
/*---------------------------------------------------------------------------*/
#ifdef OSCORE_WITH_HW_CRYPTO
static void
ec_uint8v_to_uint32v(uint32_t *result, const uint8_t *data, size_t size)
{
  /* `data` is expected to be encoded in big-endian */
  for(int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--) {
    *result = uint8x4_to_uint32(&data[i * sizeof(uint32_t)]);
    result++;
  }
}
#endif
/*---------------------------------------------------------------------------*/
static inline void
uint32_to_uint8x4(uint8_t *field, uint32_t data)
{//left
	field[0] = (uint8_t)((data & 0xFF000000) >> 24);
	field[1] = (uint8_t)((data & 0x00FF0000) >> 16);
	field[2] = (uint8_t)((data & 0x0000FF00) >>  8);
	field[3] = (uint8_t)((data & 0x000000FF)      );
}
/*---------------------------------------------------------------------------*/
#ifdef OSCORE_WITH_HW_CRYPTO
static void
ec_uint32v_to_uint8v(uint8_t *result, const uint32_t *data, size_t size)
{
	for (int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--)
	{
		uint32_to_uint8x4(result, data[i]);
		result += sizeof(uint32_t);
	}
}
#endif

void
oscore_crypto_init(void)
{
#ifdef OSCORE_WITH_HW_CRYPTO	
#ifdef CONTIKI_TARGET_ZOUL
	//initialise the HW AES/SHA/PKA
	crypto_init();
	crypto_disable();
	pka_init();
	pka_disable();
#elif CONTIKI_TARGET_SIMPLELINK
#endif	
	PT_SEM_INIT(&crypto_processor_mutex, 1);
	pe_crypto_lock_released = process_alloc_event();
#endif //OSCORE_WITH_HW_CRYPTO
	pe_message_signed = process_alloc_event();
	pe_message_verified = process_alloc_event();

	process_start(&signer, NULL);
	process_start(&verifier, NULL);
	printf("OSCORE crypto initialised.\n");
}

typedef struct {
	struct pt pt;
	struct process *process;
#ifdef OSCORE_WITH_HW_CRYPTO 
#ifdef CONTIKI_TARGET_ZOUL
	ecc_dsa_sign_state_t ecc_sign_state;
#endif /* CONTIKI_TARGET_ZOUL */
#else /* not OSCORE_WITH_HW_CRYPTO */
	struct pt sign_deterministic_pt;
#endif /* OSCORE_WITH_HW_CRYPTO */
	uint16_t sig_len;

} sign_state_t;

PT_THREAD(ecc_sign(sign_state_t *state, uint8_t *buffer, size_t buffer_len, size_t msg_len, uint8_t *private_key, uint8_t *public_key, uint8_t *signature));

typedef struct {
	struct pt pt;
	struct process *process;
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
	ecc_dsa_verify_state_t ecc_verify_state;
#endif /* CONTIKI_TARGET_ZOUL */
#else /* not OSCORE_WITH_HW_CRYPTO */
	struct pt verify_sw_pt;
#endif /* OSCORE_WITH_HW_CRYPTO */

} verify_state_t;

PT_THREAD(ecc_verify(verify_state_t *state, uint8_t *public_key, const uint8_t *buffer, size_t buffer_len, uint8_t *signature));

#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_SIMPLELINK

static uint8_t
sha2_hash(uint8_t *message, size_t len, uint8_t *hash)
{
	SHA2_Handle handle;
	int_fast16_t result;
	SHA2_Params params;

	SHA2_init();
	SHA2_Params_init(&params);
	params.returnBehavior = SHA2_RETURN_BEHAVIOR_BLOCKING;
	handle = SHA2_open(0, NULL);
	if(!handle)
	{
		printf("SHA2: could not open handle!\n");
		return -5;
	}
	result = SHA2_setHashType(handle, SHA2_HASH_TYPE_256);
	if(result != SHA2_STATUS_SUCCESS)
	{
		printf("SHA2: could not set hash type! %u\n", result);
		goto final;
	}
	result = SHA2_addData(handle, message, len);
	if(result != SHA2_STATUS_SUCCESS)
	{
		printf("SHA2: could not add data! %u\n", result);
		goto final;
	}
	result = SHA2_finalize(handle, hash);
	if(result != SHA2_STATUS_SUCCESS)
	{
		printf("SHA2: failed with the code %u!\n", result);
		goto final;
	}
final:
	SHA2_close(handle);
	return (uint8_t) result;

}

#endif //CONTIKI_TARGET_SIMPLELINK
#ifdef CONTIKI_TARGET_ZOUL
bool
crypto_fill_random(uint8_t *buffer, size_t size_in_bytes)
{
	if (buffer == NULL)
	{
		return false;
	}

	uint16_t *buffer_u16 = (uint16_t *)buffer;

	for (size_t i = 0; i < size_in_bytes / sizeof(uint16_t); i++)
	{
		buffer_u16[i] = random_rand();
	}

	if ((size_in_bytes % sizeof(uint16_t)) != 0)
	{
		buffer[size_in_bytes - 1] = (uint8_t)random_rand();
	}

	return true;

}

static uint8_t
sha256_hash(const uint8_t *buffer, size_t len, uint8_t *hash)
{
	sha256_state_t sha256_state;

	bool enabled = CRYPTO_IS_ENABLED();
	if (!enabled)
	{
		crypto_enable();
	}

	uint8_t ret;

	ret = sha256_init(&sha256_state);
	if (ret != CRYPTO_SUCCESS)
	{
		printf("sha256_init failed with %u\n", ret);
		goto end;
	}

	ret = sha256_process(&sha256_state, buffer, len);
	if (ret != CRYPTO_SUCCESS)
	{
		printf("sha256_process failed with %u\n", ret);
		goto end;
	}

	ret = sha256_done(&sha256_state, hash);
	if (ret != CRYPTO_SUCCESS)
	{
		printf("sha256_done failed with %u\n", ret);
		goto end;
	}

end:
	if (enabled)
	{
		crypto_disable();
	}

	return ret;
}
#endif //CONTIKI_TARGET_ZOUL
#endif //OSCORE_WITH_HW_CRYPTO
#endif //WITH_GROUPCOM (line 77)
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
   /*
   printf("Encrypt:\n");
   printf("Key:\n");
   kprintf_hex(key, key_len);
   printf("IV:\n");
   kprintf_hex(nonce, nonce_len);
   printf("AAD:\n");
   kprintf_hex(aad, aad_len);
   printf("Plaintext:\n");
   kprintf_hex(buffer, plaintext_len);
   */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, &(buffer[plaintext_len]), COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 1);
   /*
   printf("Ciphertext&Tag:\n");
   kprintf_hex(buffer, plaintext_len + 8);
   */
  return plaintext_len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
}

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
  
  CCM_STAR.set_key(key);
  /*  printf("Decrypt:\n");
     printf("Key:\n");
     kprintf_hex(key, key_len);
     printf("IV:\n");
     kprintf_hex(nonce, nonce_len);
     printf("AAD:\n");
     kprintf_hex(aad, aad_len);
     printf("Ciphertext&Tag:\n");
     kprintf_hex(buffer, ciphertext_len);
   */
  uint16_t plaintext_len = ciphertext_len - COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;

#ifdef OSCORE_ENC_DEC_DEBUG
  LOG_DBG("Decrypt:\n");
  printf_hex("Key", key, key_len);
  printf_hex("IV", nonce, nonce_len);
  printf_hex("AAD", aad, aad_len);
  printf_hex("Ciphertext", buffer, plaintext_len);
  printf_hex("Tag", &buffer[plaintext_len], COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
#endif

  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, buffer, plaintext_len, aad, aad_len, tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN, 0);

#ifdef OSCORE_ENC_DEC_DEBUG
  printf_hex("Tag'", tag_buffer, COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  printf_hex("Plaintext", buffer, plaintext_len);
#endif

  if(memcmp(tag_buffer, &buffer[plaintext_len], COSE_algorithm_AES_CCM_16_64_128_TAG_LEN) != 0) {
    return OSCORE_CRYPTO_DECRYPTION_FAILURE; /* Decryption/Authentication failure */
  }
  
  return plaintext_len;
}

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

/* For ECDSA-Deterministic - SW crypto only*/
#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32
#ifndef OSCORE_WITH_HW_CRYPTO

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

PT_THREAD(ecc_sign_deterministic(sign_state_t *state, uint8_t *private_key, uint8_t *message_hash, uECC_HashContext *hash_context, uint8_t *signature))
{
	PT_BEGIN(&state->sign_deterministic_pt);
	uint8_t res = -1;
	printf("Inside the deterministic pt: let's go.\n");
	res = uECC_sign_deterministic(private_key, message_hash, hash_context, signature);
	printf("Deterministic sign yielded %d\n", res);
	printf("signature is here %p\n", signature);
	printf_hex(signature, 64);
	PT_END(&state->sign_deterministic_pt);
}

PT_THREAD(ecc_verify_sw(verify_state_t *state, uint8_t *public_key, uint8_t *message_hash, uint8_t *signature))
{
	PT_BEGIN(&state->verify_sw_pt);
	uint8_t res = -1;
	printf("Inside the verify_sw pt: let's go.\n");
        res = uECC_verify(public_key, message_hash, signature);
	printf("uECC verify yielded %d\n", res);
	PT_END(&state->verify_sw_pt);
}
#endif /*OSCORE_WITH_HW_CRYPTO*/

PT_THREAD(ecc_sign(sign_state_t *state, uint8_t *buffer, size_t buffer_len, size_t msg_len, uint8_t *private_key, uint8_t *public_key, uint8_t *signature))
{
	PT_BEGIN(&state->pt);
//FIXME buffer_len!!!
/*	if (buffer_len - msg_len < ES256_PUBLIC_KEY_LEN * 2)
	{
		LOG_ERR("Insufficient buffer space\n");
#ifdef CONTIKI_TARGET_ZOUL
		state->ecc_sign_state.result = PKA_STATUS_INVALID_PARAM;
#endif
		PT_EXIT(&state->pt);
	}
*/
#ifdef OSCORE_WITH_HW_CRYPTO
	printf("Waiting for crypto processor to become available (sign) ...\n");
	PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
	printf("Crypto processor available (sign)!\n");
#endif /* OSCORE_WITH_HW_CRYPTO */
	state->sig_len = 0;

	//hash the message with sha256
	uint8_t message_hash[SHA256_DIGEST_LENGTH];//==SHA56_DIGEST_LEN_BYTES
#ifndef OSCORE_WITH_HW_CRYPTO /*SW crypto is used */
	printf("Using dtls_sha256\n");
	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, msg_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);

	uint8_t tmp[ES256_PRIVATE_KEY_LEN + ES256_PRIVATE_KEY_LEN + ES256_SIGNATURE_LEN];//32+32+64
	SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

	printf("Scheduling deterministic sign in SW\n");
	printf("msg to sign len %d, buffer len %d\n", msg_len, buffer_len);
	printf_hex(buffer, msg_len);
	PT_SPAWN(&state->pt, &state->sign_deterministic_pt, ecc_sign_deterministic(state, private_key, message_hash, &ctx.uECC, signature));

	state->sig_len = ES256_SIGNATURE_LEN;

#else /* SW crypto is not used */
#ifdef CONTIKI_TARGET_SIMPLELINK
	printf("Using dtls_sha256\n");

	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, buffer_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);
	/*printf("Target=SIMPLELINK: using SHA2\n");

	uint8_t sha_result = sha2_hash(buffer, msg_len, message_hash);
	if (sha_result != SHA2_STATUS_SUCCESS)
	{
		printf("SHA2 failed! Code: %u", sha_result);
		PT_EXIT(&state->pt);
	}
*/
	printf("Initialising ECDSA\n");
	ECDSA_init();
	ECDSA_Params params;
	ECDSA_Params_init(&params);
	uint8_t pmsn[32]                     = {0xAE, 0x50, 0xEE, 0xFA, 0x27, 0xB4, 0xDB, 0x14,
						0x9F, 0xE1, 0xFB, 0x04, 0xF2, 0x4B, 0x50, 0x58,
						0x91, 0xE3, 0xAC, 0x4D, 0x2A, 0x5D, 0x43, 0xAA,
						0xCA, 0xC8, 0x7F, 0x79, 0x52, 0x7E, 0x1A, 0x7A};
	CryptoKey myPrivateKey;
	CryptoKey pmsnKey;
	ECDSA_Handle ecdsaHandle;
	ECDSA_OperationSign operationSign;
	int_fast16_t operationResult;
	//uint8_t r[32] = {0};
	//uint8_t s[32] = {0};
	//open the handle with default parameters
	ecdsaHandle = ECDSA_open(0, NULL);
	if (!ecdsaHandle)
	{
		//TODO handle error
		PT_EXIT(&state->pt);
	}

	CryptoKeyPlaintext_initKey(&myPrivateKey, private_key, ES256_PRIVATE_KEY_LEN);
	CryptoKeyPlaintext_initKey(&pmsnKey, pmsn, sizeof(pmsn));

	//TODO sha part
	ECDSA_OperationSign_init(&operationSign);
	operationSign.curve = &ECCParams_NISTP256;
	operationSign.myPrivateKey = &myPrivateKey;
	operationSign.pmsn = &pmsnKey;
	operationSign.hash = message_hash;
	operationSign.r = signature;
	operationSign.s = signature + 32;
	printf("Ready to run ECDSA_sign...\n");
	operationResult = ECDSA_sign(ecdsaHandle, &operationSign);

	if (operationResult != ECDSA_STATUS_SUCCESS)
	{
		//TODO handle error
		printf("Sign failed with the following code: %d", operationResult);
		PT_EXIT(&state->pt);
	}

	printf("Sign diag: printing r:\n");
	kprintf_hex(signature, 32);
	printf("Sign diag: printing s:\n");
	kprintf_hex((signature + 32), 32);

	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

	state->sig_len = ES256_SIGNATURE_LEN;

#endif /*CONTIKI_TARGET_SIMPLELINK */
#ifdef CONTIKI_TARGET_ZOUL
	printf("TARGET=ZOUL, using sha256\n");
	uint8_t sha256_ret = sha256_hash(buffer, msg_len, message_hash);
	if (sha256_ret != CRYPTO_SUCCESS)
	{
		printf("sha256_hash failed with %u\n", sha256_ret);
		state->ecc_sign_state.result = sha256_ret;
		PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
		PT_EXIT(&state->pt);
	}

	ec_uint8v_to_uint32v(state->ecc_sign_state.hash, message_hash, sizeof(message_hash));

	state->ecc_sign_state.process = state->process;
	state->ecc_sign_state.curve_info = &nist_p_256;

	ec_uint8v_to_uint32v(state->ecc_sign_state.secret, private_key, ES256_PRIVATE_KEY_LEN);

	crypto_fill_random((uint8_t *) state->ecc_sign_state.k_e, ES256_PRIVATE_KEY_LEN);

	printf("SHA256 and random number generation successful. About to run HW signing...\n");
	pka_enable();
	PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
	pka_disable();

	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

	if (state->ecc_sign_state.result != PKA_STATUS_SUCCESS)
	{
		printf("Failed to sign message with %d\n", state->ecc_sign_state.result);
		PT_EXIT(&state->pt);
	}
	else
	{
		printf("Message sign success!\n");
	}
	//Add signature to the message
	ec_uint32v_to_uint8v(signature, state->ecc_sign_state.point_r.x, ES256_PRIVATE_KEY_LEN);
	ec_uint32v_to_uint8v(signature + ES256_PRIVATE_KEY_LEN, state->ecc_sign_state.signature_s, ES256_PRIVATE_KEY_LEN);
	state->sig_len = ES256_SIGNATURE_LEN;
	
	//self-check
	/*printf("Performing sign self-check...\n");
	static verify_state_t test;
	test.process = state->process;
	PT_SPAWN(&state->pt, &test.pt, ecc_verify(&test, public_key, buffer, msg_len + state->sig_len));
	*/
#endif /*CONTIKI_TARGET_ZOUL*/
#endif /*OSCORE_WITH_HW_CRYPTO*/
	PT_END(&state->pt);

}

PT_THREAD(ecc_verify(verify_state_t *state, uint8_t *public_key, const uint8_t *buffer, size_t buffer_len, uint8_t *signature))
{
	PT_BEGIN(&state->pt);
//FIXME debug printouts
/*
  printf("ecc_verify:Signature\n");
  kprintf_hex(signature, ES256_SIGNATURE_LEN);
  printf("Plaintext\n");
  kprintf_hex(buffer, buffer_len);
  printf("Public key\n");
  kprintf_hex(public_key, ES256_PUBLIC_KEY_LEN);
*/
/*	
	if (buffer_len < ES256_SIGNATURE_LEN)
	{
		LOG_ERR("No signature\n");
#ifdef CONTIKI_TARGET_ZOUL
		state->ecc_verify_state.result = PKA_STATUS_INVALID_PARAM;
#endif
		PT_EXIT(&state->pt);
	}
*/
#ifdef OSCORE_WITH_HW_CRYPTO
	printf("Waiting for crypto processor to become available (verify) ...\n");
	PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
	printf("Crypto processor available (verify)!\n");

	//const size_t msg_len = buffer_len - ES256_SIGNATURE_LEN;

	const uint8_t *sig_r = signature;//buffer + msg_len;
	const uint8_t *sig_s = signature + ES256_PRIVATE_KEY_LEN;//buffer + msg_len + ES256_PRIVATE_KEY_LEN;
	//FIXME
/*	printf("Signature r\n");
	kprintf_hex(sig_r, (uint8_t) (ES256_SIGNATURE_LEN / 2));
	printf("Signature s\n");
	kprintf_hex(sig_s, (uint8_t) (ES256_SIGNATURE_LEN / 2));
*/
#endif
	uint8_t message_hash[SHA256_DIGEST_LENGTH];

#ifndef OSCORE_WITH_HW_CRYPTO
	printf("Using dtls_sha256\n");

	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, buffer_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);
	printf("Spawning a sw verify process\n");
	PT_SPAWN(&state->pt, &state->verify_sw_pt, ecc_verify_sw(state, public_key, message_hash, signature));

#else //HW crypto

#ifdef CONTIKI_TARGET_SIMPLELINK
	printf("Using dtls_sha256\n");

	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, buffer_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);
	/*printf("Simplelink: using SHA2\n");
	uint8_t sha_result = sha2_hash(buffer, buffer_len, message_hash);
	if (sha_result != SHA2_STATUS_SUCCESS)
	{
		printf("Sha2 failed with the code: %u!\n", sha_result);
		PT_EXIT(&state->pt);
	}*/
	printf("SHA2 completed. Initialising ECDSA\n");
	ECDSA_init();
	ECDSA_Params params;
	ECDSA_Params_init(&params);
	CryptoKey theirPublicKey;
	ECDSA_Handle ecdsaHandle;
	int_fast16_t operationResult;
	ECDSA_OperationVerify operationVerify;

	ecdsaHandle = ECDSA_open(0, NULL);

	if(!ecdsaHandle)
	{
		printf("Could not open ECDSA handle!\n");
		PT_EXIT(&state->pt);
	}

	CryptoKeyPlaintext_initKey(&theirPublicKey, public_key, ES256_PUBLIC_KEY_LEN);

	ECDSA_OperationVerify_init(&operationVerify);

	operationVerify.curve = &ECCParams_NISTP256;
	operationVerify.theirPublicKey = &theirPublicKey;
	operationVerify.hash = message_hash;
	operationVerify.r = signature;
	operationVerify.s = signature + ES256_PRIVATE_KEY_LEN;
	printf("Ready to run ECDSA_verify...\n");
	operationResult = ECDSA_verify(ecdsaHandle, &operationVerify);

	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

	if (operationResult != ECDSA_STATUS_SUCCESS)
	{
		//TODO handle error
		printf("Verify failed with the following code: %d", operationResult);
		PT_EXIT(&state->pt);
	}

#endif //CONTIKI_TARGET_SIMPLELINK

#ifdef CONTIKI_TARGET_ZOUL
	//extract signature from buffer
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_r, sig_r, ES256_PRIVATE_KEY_LEN);
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_s, sig_s, ES256_PRIVATE_KEY_LEN);
	printf("Using sha256\n");

	/*dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, buffer, msg_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);*/
	uint8_t sha256_ret = sha256_hash(buffer, buffer_len, message_hash);
	if (sha256_ret != CRYPTO_SUCCESS)
	{
		printf("sha256_hash failed with %u\n", sha256_ret);
		state->ecc_verify_state.result = sha256_ret;
		PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
		PT_EXIT(&state->pt);
	}

	ec_uint8v_to_uint32v(state->ecc_verify_state.hash, message_hash, sizeof(message_hash));

	state->ecc_verify_state.process = state->process;
	state->ecc_verify_state.curve_info = &nist_p_256;

	printf("SHA256 successful. Ready for the verification in HW...\n");

	pka_enable();
	PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
	pka_disable();

	PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

	if (state->ecc_verify_state.result != PKA_STATUS_SUCCESS)
	{
		printf("Failed to verify message with %d\n", state->ecc_verify_state.result);
		PT_EXIT(&state->pt);
	}
	else
	{
		printf("Message verify success!\n");
	}
#endif /*CONTIKI_TARGET_ZOUL*/
#endif //OSCORE_WITH_HW_CRYPTO
	PT_END(&state->pt);

}	

QUEUE(messages_to_sign);
MEMB(messages_to_sign_memb, messages_to_sign_entry_t, MSGS_TO_SIGN_SIZE);

QUEUE(messages_to_verify);
MEMB(messages_to_verify_memb, messages_to_verify_entry_t, MSGS_TO_VERIFY_SIZE);

bool
queue_message_to_sign(struct process *process, uint8_t *private_key, uint8_t *public_key, uint8_t *message, uint16_t message_buffer_len, uint16_t message_len, uint8_t *signature)
{
	messages_to_sign_entry_t *item = memb_alloc(&messages_to_sign_memb);
	if (!item)
	{
		printf("queue_message_to_sign: out of memory\n");
		return false;
	}

	item->process = process;
	item->private_key = private_key;
	item->public_key = public_key;
//	item->message = message;
	memcpy(item->message, message, message_len);
	item->message_buffer_len = 250;
//	item->message_buffer_len = message_buffer_len;
	item->message_len = message_len;
	item->signature = signature;
	
	queue_enqueue(messages_to_sign, item);

	printf("Queue_message_to_sign: enqueued, about to poll the signer...\n");
	//process_poll(&signer);

	process_post_synch(&signer, PROCESS_EVENT_CONTINUE, NULL);

	return true;
}

void
queue_message_to_sign_done(messages_to_sign_entry_t *item)
{
	memb_free(&messages_to_sign_memb, item);
}

PROCESS_THREAD(signer, ev, data)
{
	PROCESS_BEGIN();

	queue_init(messages_to_sign);
	memb_init(&messages_to_sign_memb);

	printf("Process signer started!\n");
	while (1){
		PROCESS_YIELD_UNTIL(!queue_is_empty(messages_to_sign));
		printf("Signer: the queue is not empty!\n");
		while(!queue_is_empty(messages_to_sign)){
			static messages_to_sign_entry_t *item;
			item = (messages_to_sign_entry_t *) queue_dequeue(messages_to_sign);
			static sign_state_t state;
			state.process = &signer;
			PROCESS_PT_SPAWN(&state.pt, ecc_sign(&state, item->message, item->message_buffer_len, item->message_len, item->private_key, item->public_key, item->signature));
#if defined OSCORE_WITH_HW_CRYPTO && defined CONTIKI_TARGET_ZOUL
			item->result = state.ecc_sign_state.result;

			printf("Signer: the result of the sign is %d.\n", state.ecc_sign_state.result);
#endif /* OSCORE_WITH_HW_CRYPTO && CONTIKI_TARGET_ZOUL */
 			if (process_post(PROCESS_BROADCAST, pe_message_signed, item) != PROCESS_ERR_OK){ //TODO PROCESS_BROADCAST -> item->process
				printf("Failed to post pe_message_signed to %s\n", item->process->name);
			} else {
				printf("Successfully posted pe_message_signed!\n");
			}
		}
#ifdef OSCORE_WITH_HW_CRYPTO
		//notify release for other processes in the semaphore
		process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
#endif /* OSCORE_WITH_HW_CRYPTO */
	}

	PROCESS_END();
}


bool
queue_message_to_verify(struct process *process, uint8_t *signature, uint8_t *message, uint16_t message_len, uint8_t *public_key)
{
	messages_to_verify_entry_t *item = memb_alloc(&messages_to_verify_memb);
	if (!item)
	{
		printf("queue_message_to_verify: out of memory\n");
		return false;
	}
	item->process = process;
	item->signature = signature;
	item->message = message;
	item->message_len = message_len;
	item->public_key = public_key;

	queue_enqueue(messages_to_verify, item);

	printf("Queue_message_to_verify: enqueued, about to synch_post to the verifier...\n");
	process_post_synch(&verifier, PROCESS_EVENT_CONTINUE, NULL);

	return true;
}

void
queue_message_to_verify_done(messages_to_verify_entry_t *item)
{
	memb_free(&messages_to_verify_memb, item);
}

PROCESS_THREAD(verifier, ev, data)
{
	PROCESS_BEGIN();

	queue_init(messages_to_verify);
	memb_init(&messages_to_verify_memb);

	printf("Process verifier started!\n");
	while (1)
	{
		PROCESS_YIELD_UNTIL(!queue_is_empty(messages_to_verify));

		printf("Verifier: the queue is not empty!\n");
		while(!queue_is_empty(messages_to_verify))
		{
			static messages_to_verify_entry_t *item;
			item = (messages_to_verify_entry_t *) queue_dequeue(messages_to_verify);

			static verify_state_t state;
			state.process = &verifier;
			PROCESS_PT_SPAWN(&state.pt, ecc_verify(&state, item->public_key, item->message, item->message_len, item->signature));
#ifdef OSCORE_WITH_HW_CRYPTO
#ifdef CONTIKI_TARGET_ZOUL
			item->result = state.ecc_verify_state.result;
			printf("Verifier: the result of the verify is %d.\n", state.ecc_verify_state.result);
#endif
#endif			//if (process_post(item->process, pe_message_verified, item) != PROCESS_ERR_OK)
			if (process_post(PROCESS_BROADCAST, pe_message_verified, item) != PROCESS_ERR_OK)
			{
				printf("Failed to post pe_message_verified to %s\n", item->process->name);
			}
		}
#ifdef OSCORE_WITH_HW_CRYPTO
		//notify release for other processes in the semaphore
		process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
#endif
	}

	PROCESS_END();
}

int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *private_key, uint8_t *public_key){
   if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }
  
  if (!queue_message_to_sign(PROCESS_CURRENT(), private_key, public_key, ciphertext, 0, ciphertext_len, signature)) //FIXME buffer length cannot be 0!
  {
	  printf("Could not queue the message to sign!\n");
	  return 0;
  }
  printf("\noscore_ecDSA_sign: returning...\n");
  return 1;
  /*
  printf("Printing private_key;...\n");
  kprintf_hex(private_key, 32);
  printf("Printing public_key;...\n");
  kprintf_hex(public_key, 64);
  printf("ciphertext:\n");
  kprintf_hex(ciphertext, ciphertext_len);
  */
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
   // return 1;
}

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, uint8_t *public_key){
  if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }

  printf("-------------------\nEntered oscore_edDSA_verify\n");

  if(!queue_message_to_verify(PROCESS_CURRENT(), signature, plaintext, plaintext_len, public_key))
  {
	  printf("Could not queue message to verify\n");
	  return 0;
  }
  printf("oscore_edDSA_verify: returning...\n");
  return 1;
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
}*/
}
#endif /*WITH_GROUPCOM*/
