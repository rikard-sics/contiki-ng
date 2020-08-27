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

#include "sys/rtimer.h"
#include "sys/pt.h"
#include "sys/pt-sem.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"
#include "random.h"
/*the rest of the includes are moved to oscore-crypto.h file.*/

static struct pt_sem crypto_processor_mutex;

process_event_t pe_message_signed;
process_event_t pe_message_verified;
process_event_t pe_crypto_lock_released;

PROCESS(signer, "signer");
PROCESS(verifier, "verifier");

void
kprintf_hex(unsigned char *data, unsigned int len)
{
  LOG_DBG("%s (len=%u): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}

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
static void
ec_uint8v_to_uint32v(uint32_t *result, const uint8_t *data, size_t size)
{
  /* `data` is expected to be encoded in big-endian */
  for(int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--) {
    *result = uint8x4_to_uint32(&data[i * sizeof(uint32_t)]);
    result++;
  }
}
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
static void
ec_uint32v_to_uint8v(uint8_t *result, const uint32_t *data, size_t size)
{
	for (int i = (size / sizeof(uint32_t)) - 1; i >= 0; i--)
	{
		uint32_to_uint8x4(result, data[i]);
		result += sizeof(uint32_t);
	}
}


void
oscore_crypto_init(void)
{
	
#ifdef CONTIKI_TARGET_ZOUL
	//initialise the HW AES/SHA/PKA
	crypto_init();
	crypto_disable();
	pka_init();
	pka_disable();
#endif	

	PT_SEM_INIT(&crypto_processor_mutex, 1);

	pe_message_signed = process_alloc_event();
	pe_message_verified = process_alloc_event();
	pe_crypto_lock_released = process_alloc_event();

	process_start(&signer, NULL);
	process_start(&verifier, NULL);
	printf("OSCORE crypto initialised.\n");
}

typedef struct {
	struct pt pt;
	struct process *process;

	ecc_dsa_sign_state_t ecc_sign_state;

	uint16_t sig_len;

} sign_state_t;

PT_THREAD(ecc_sign(sign_state_t *state, uint8_t *buffer, size_t buffer_len, size_t msg_len, uint8_t *private_key, uint8_t *public_key));

typedef struct {
	struct pt pt;
	struct process *process;

	ecc_dsa_verify_state_t ecc_verify_state;

} verify_state_t;

PT_THREAD(ecc_verify(verify_state_t *state, const uint8_t *public_key, const uint8_t *buffer, size_t buffer_len));


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

/* For ECDSA-Deterministic */
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

#endif

PT_THREAD(ecc_sign(sign_state_t *state, uint8_t *buffer, size_t buffer_len, size_t msg_len, uint8_t *private_key, uint8_t *public_key))
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
	printf("Waiting for crypto processor to become available (sign) ...\n");
	PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
	printf("Crypto processor available (sign)!\n");

	state->sig_len = 0;

	//hash the message with sha256
	//TODO cleanup the preprocessor mess and organise the sanity checks for each platform
	uint8_t message_hash[SHA256_DIGEST_LENGTH];//==SHA56_DIGEST_LEN_BYTES
#ifdef CONTIKI_TARGET_NATIVE
	dtls_sha256_ctx msg_hash_ctx;
	dtls_sha256_init(&msg_hash_ctx);
	dtls_sha256_update(&msg_hash_ctx, ciphertext, ciphertext_len);
	dtls_sha256_final(message_hash, &msg_hash_ctx);


	//these lines remaining for NATIVE
	/*uint8_t tmp[32 + 32 + 64];//32+32+64
	SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
	uECC_sign_deterministic(private_key, message_hash, &ctx.uECC, signature);*/
#endif
#ifdef CONTIKI_TARGET_ZOUL
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

	ec_uint8v_to_uint32v(state->ecc_sign_state.secret, private_key, sizeof(private_key));

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
	ec_uint32v_to_uint8v(buffer + msg_len, state->ecc_sign_state.point_r.x, ES256_PRIVATE_KEY_LEN);
	ec_uint32v_to_uint8v(buffer + msg_len + ES256_PRIVATE_KEY_LEN, state->ecc_sign_state.signature_s, ES256_PRIVATE_KEY_LEN);
	state->sig_len = ES256_SIGNATURE_LEN;
	

	
	//self-check
	printf("Performing sign self-check...\n");
	static verify_state_t test;
	test.process = state->process;
	PT_SPAWN(&state->pt, &test.pt, ecc_verify(&test, public_key, buffer, msg_len + state->sig_len));

#endif /*CONTIKI_TARGET_ZOUL*/

	PT_END(&state->pt);

}

PT_THREAD(ecc_verify(verify_state_t *state, const uint8_t *public_key, const uint8_t *buffer, size_t buffer_len))
{
	PT_BEGIN(&state->pt);

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
	printf("Waiting for crypto processor to become available (verify) ...\n");
	PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
	printf("Crypto processor available (verify)!\n");

	const size_t msg_len = buffer_len - ES256_SIGNATURE_LEN;

	const uint8_t *sig_r = buffer + msg_len;
	const uint8_t *sig_s = buffer + msg_len + ES256_PRIVATE_KEY_LEN;
	//extract signature from buffer
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_r, sig_r, ES256_PRIVATE_KEY_LEN);
	ec_uint8v_to_uint32v(state->ecc_verify_state.signature_s, sig_s, ES256_PRIVATE_KEY_LEN);

	uint8_t message_hash[SHA256_DIGEST_LENGTH];
#ifdef CONTIKI_TARGET_ZOUL
	uint8_t sha256_ret = sha256_hash(buffer, msg_len, message_hash);
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
		//PT_EXIT(&state->pt);
	}
	else
	{
		printf("Message verify success!\n");
	}

	PT_END(&state->pt);
#endif /*CONTIKI_TARGET_ZOUL*/
}	

QUEUE(messages_to_sign);
MEMB(messages_to_sign_memb, messages_to_sign_entry_t, MSGS_TO_SIGN_SIZE);

QUEUE(messages_to_verify);
MEMB(messages_to_verify_memb, messages_to_verify_entry_t, MSGS_TO_VERIFY_SIZE);

bool
queue_message_to_sign(struct process *process, uint8_t *private_key, uint8_t *public_key, uint8_t *message, uint16_t message_buffer_len, uint16_t message_len)
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
	item->message = message;
	item->message_buffer_len = message_buffer_len;
	item->message_len = message_len;

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
	while (1)
	{
		PROCESS_YIELD_UNTIL(!queue_is_empty(messages_to_sign));

		printf("Signer: the queue is not empty!\n");
		while(!queue_is_empty(messages_to_sign))
		{
			static messages_to_sign_entry_t *item;
			item = (messages_to_sign_entry_t *) queue_dequeue(messages_to_sign);

			static sign_state_t state;
			state.process = &signer;
			PROCESS_PT_SPAWN(&state.pt, ecc_sign(&state, item->message, item->message_buffer_len, item->message_len, item->private_key, item->public_key));

			item->result = state.ecc_sign_state.result;

			printf("Signer: the result of the sign is %d.\n", state.ecc_sign_state.result);

			if (process_post(item->process, pe_message_signed, item) != PROCESS_ERR_OK)
			{
				printf("Failed to post pe_message_signed to %s\n", item->process->name);
			}
		}
		//notify release for other processes in the semaphore
		process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
	}

	PROCESS_END();
}


bool
queue_message_to_verify(struct process *process, void *data, uint8_t *message, uint16_t message_len, const uint8_t *public_key)
{
	messages_to_verify_entry_t *item = memb_alloc(&messages_to_verify_memb);
	if (!item)
	{
		printf("queue_message_to_verify: out of memory\n");
		return false;
	}

	item->process = process;
	item->data = data;
	item->message = message;
	item->message_len = message_len;
	item->public_key = public_key;

	queue_enqueue(messages_to_verify, item);

	printf("Queue_message_to_verify: enqueued, about to synch_post to the verifier...\n");
	//process_poll(&verifier);
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
			PROCESS_PT_SPAWN(&state.pt, ecc_verify(&state, item->public_key, item->message, item->message_len));

			item->result = state.ecc_verify_state.result;
			printf("Verifier: the result of the verify is %d.\n", state.ecc_verify_state.result);

			//if (process_post(item->process, pe_message_verified, item) != PROCESS_ERR_OK)
			if (process_post(PROCESS_BROADCAST, pe_message_verified, item) != PROCESS_ERR_OK)
			{
				printf("Failed to post pe_message_verified to %s\n", item->process->name);
			}
		}
		//notify release for other processes in the semaphore
		process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
	}

	PROCESS_END();
}

int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *private_key, uint8_t *public_key){
   if(alg != COSE_Algorithm_ES256 || alg_param != COSE_Elliptic_Curve_P256)  {
    return 0;
  }
  printf("\noscore_ecDSA_sign: queueing the message...\n");
  if (!queue_message_to_sign(PROCESS_CURRENT(), private_key, public_key, ciphertext, 0, ciphertext_len)) //FIXME buffer length cannot be 0!
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
  //Operations common across architectures: message hashing,
/*  uint8_t message_hash[SHA256_DIGEST_LENGTH];
  dtls_sha256_ctx msg_hash_ctx;
  dtls_sha256_init(&msg_hash_ctx);
  dtls_sha256_update(&msg_hash_ctx, ciphertext, ciphertext_len);
  dtls_sha256_final(message_hash, &msg_hash_ctx);*/
//#ifndef CONTIKI_TARGET_NATIVE
#ifdef CONTIKI_TARGET_SIMPLELINK
#ifdef OSCORE_WITH_HW_CRYPTO
  //simplelink code goes here
  //- initialise memory for workzone (275 words for window size 3)
  //Code based on romdriver
  /*printf("\nCC1352 crypto: initialisation...");
  uint32_t workzone_buf[275];
  memset(workzone_buf, 0, 275 * sizeof(uint32_t)); 
  //- initialise ecc
  ECC_initialize(workzone_buf);
  //- sign
  uint32_t *rand = { 0x94A949FA, 0x401455A1, 0xAD7294CA, 0x896A33BB,
                 0x7A80E714, 0x4321435B, 0x51247A14, 0x41C1CB6B };

  uint32_t *sign1, *sign2; //outputs, signature parts
  printf(" Done.About to run the signing function...\n");
  uint8_t status = ECC_ECDSA_sign((uint32_t *) private_key, (uint32_t *) message_hash, rand, sign1, sign2);
  //filling the return pointer with the calculated signature
  printf("Signed! Filling the signature pointer...\n");
  uint8_t i;
  for (i = 0; i < 32; i++)
	  *(signature + i) = *sign1++;
  for (i = 0; i< 32; i++)
	  *(signature + i + 32) = *sign2++;
  */
 /*uint8_t pmsn[32]                     = {0xAE, 0x50, 0xEE, 0xFA, 0x27, 0xB4, 0xDB, 0x14,
                                         0x9F, 0xE1, 0xFB, 0x04, 0xF2, 0x4B, 0x50, 0x58,
                                         0x91, 0xE3, 0xAC, 0x4D, 0x2A, 0x5D, 0x43, 0xAA,
                                         0xCA, 0xC8, 0x7F, 0x79, 0x52, 0x7E, 0x1A, 0x7A};
 uint8_t r[32] = {0};
 uint8_t s[32] = {0};
 ECDSA_init();
 //ECDSA_Params_init();
 ECDSA_OperationSign operationSign;
 //ECDSA_OperationSign_init(operationSign);
 CryptoKey pmsnKey, myPrivateKey;
 ECDSA_Handle ecdsaHandle;
 int_fast16_t operationResult;
 
 ecdsaHandle = ECDSA_open(0, NULL);

 if(!ecdsaHandle)
	 printf("\nERROR: failed to create ecdsa handle!!!\n");

 CryptoKeyPlaintext_initKey(&myPrivateKey, private_key, sizeof(private_key));
 CryptoKeyPlaintext_initKey(&pmsnKey, pmsn, sizeof(pmsn));

 ECDSA_OperationSign_init(&operationSign);

 operationSign.curve = &ECCParams_NISTP256;
 operationSign.myPrivateKey = &myPrivateKey;
 operationSign.pmsn = &pmsnKey;
 operationSign.hash = message_hash;
 operationSign.r = r;
 operationSign.s = s;
 printf("\nSIMPLELINK crypto: everything initialised, about to sign...\n");
 watchdog_periodic();
 operationResult = ECDSA_sign(ecdsaHandle, &operationSign);
 watchdog_periodic();
 if(operationResult != ECDSA_STATUS_SUCCESS)
 	printf("\nERROR: sign operation failed! %d\n", operationResult);
 ECDSA_close(ecdsaHandle);*/
#else /*no crypto*/
/*  rtimer_clock_t start = RTIMER_NOW();
  uint8_t tmp[32 + 32 + 64];//32+32+64
  SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  uECC_sign_deterministic(private_key, message_hash, &ctx.uECC, signature);
  
 // watchdog_periodic();
  rtimer_clock_t stop = RTIMER_NOW();
  printf("\nsigning took %lu ticks, %lu s\n", (stop - start), (stop - start)/RTIMER_SECOND );*/
#endif /*OSCORE_WITH_HW_CRYPTO*/
#endif /*CONTIKI_TARGET_SIMPLELINK*/
#ifdef CONTIKI_TARGET_ZOUL
#ifdef OSCORE_WITH_HW_CRYPTO
  //uint8_t tmp[32 + 32 + 64];//32+32+64
 /* 
  pka_init();
  printf("\nPKA initialised.");
  //convert the private key to uint_32
  uint32_t private_key32[8];
  printf("\nNow, converting the priv key to uint32...");
  ec_uint8v_to_uint32v(private_key32, private_key, 32);
  uint32_t *pkey32 = private_key32;
  static ecc_dsa_sign_state_t state = {
//    .process = PROCESS_CURRENT(),//&er_example_server,
    .curve_info = &nist_p_256,
    .k_e     = { 0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314,
                 0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304 },
  };
  state.process = PROCESS_CURRENT();
  printf("\necc structs initialised. Will memcpy msg hash now...");
  memcpy(state.hash, message_hash, 32);
  memcpy(state.secret, pkey32, 32);
  PT_SPAWN((state.process->pt), &(state.pt), ecc_dsa_sign(&state));
#else
 // watchdog_periodic();
  rtimer_clock_t start = RTIMER_NOW();
  uint8_t tmp[32 + 32 + 64];//32+32+64
  SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  uECC_sign_deterministic(private_key, message_hash, &ctx.uECC, signature);
  
 // watchdog_periodic();
  rtimer_clock_t stop = RTIMER_NOW();
  printf("signing took %lu ticks, %lu s\n", (stop - start), (stop - start)/RTIMER_SECOND );*/
#endif /*OSCORE_WITH_HW_CRYPTO */
#endif /*CONTIKI_TARGET_ZOUL*/
#ifdef CONTIKI_TARGET_NATIVE
/*  uint8_t tmp[32 + 32 + 64];//32+32+64
  SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
  uECC_sign_deterministic(private_key, message_hash, &ctx.uECC, signature);
*/
#endif /* CONTIKI_TARGET_NATIVE */

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

  if(!queue_message_to_verify(PROCESS_CURRENT(), NULL, plaintext, plaintext_len, public_key))
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
*/
  //printf("public key\n");
  //kprintf_hex(public_key, 64); 
  //printf("bytes to verify\n");
  //kprintf_hex(plaintext, plaintext_len);
  //printf("signature bytes\n");
  //kprintf_hex(signature, 64);
/*  uint8_t message_hash[SHA256_DIGEST_LENGTH];
  dtls_sha256_ctx msg_hash_ctx;
  dtls_sha256_init(&msg_hash_ctx);
  dtls_sha256_update(&msg_hash_ctx, plaintext, plaintext_len);
  dtls_sha256_final(message_hash, &msg_hash_ctx);
  int res; //return variable*/
#ifdef CONTIKI_TARGET_SIMPLELINK
#ifdef OSCORE_WITH_HW_CRYPTO
/*  printf("\nSimplelink crypto verify: init\n");
  ECDSA_init();
  printf("ECDSA_init ");
  //ECDSA_Params *params;
 // ECDSA_Params_init(* params);
  printf("ECDSA_Params_init ");
  ECDSA_OperationVerify operationVerify;
  //ECDSA_OperationVerify_init(operationVerify);
  printf("ECDSA_OperationVerify_init ");
  ECDSA_Handle ecdsaHandle;
//  int_fast16_t operationResult;
  CryptoKey theirPublicKey;

  ecdsaHandle = ECDSA_open(0, NULL);

  if(!ecdsaHandle)
	  printf("ERROR: Failed to create ECDSA handle!!!\n");
  printf("ECDSA_open ");
  CryptoKeyPlaintext_initKey(&theirPublicKey, public_key, sizeof(public_key));
  printf("CryptoKeyPlaintext_initKey ");
  ECDSA_OperationVerify_init(&operationVerify);
  printf("ECDSA_OperationVerify_init ");
  printf("\nSIMPLELINK crypto: after init, copying signature to r and s...\n");
  uint8_t r[32], s[32];
  int i = 0;
  while(i < 32)
  {r[i] = *(signature + i); i++;}
  while(i < 64)
  {s[i - 32] = *(signature + i); i++;}
  operationVerify.curve = &ECCParams_NISTP256;
  operationVerify.theirPublicKey = &theirPublicKey;
  operationVerify.hash = message_hash;
  operationVerify.r = (uint32_t *) r;
  operationVerify.s = (uint32_t *) s;
  printf("\nSIMPLELINK crypto: ready to verify...\n");
  i = 0;
  while (i < 32)
	  printf("%x ", operationVerify.r[i++]);
  i = 0;
  while (i < 32)
	  printf("%x ", operationVerify.s[i++]);
  watchdog_periodic();
  res = (int) ECDSA_verify(ecdsaHandle, &operationVerify);
  watchdog_periodic();
  if(res != ECDSA_STATUS_SUCCESS)
	  printf("\nERROR!!! Signature verification failed! %d\n", res);
  ECDSA_close(ecdsaHandle);*/
#endif /*OSCORE_WITH_HW_CRYPTO (SIMPLELINK)*/
#endif /*CONTIKI_TARGET_SIMPLELINK*/
#ifdef CONTIKI_TARGET_ZOUL
#ifdef OSCORE_WITH_HW_CRYPTO
/*//Zoul HW goes here
pka_init();
printf("\n pka initialised!");
  //converting the variables to uint32_t
  uint32_t signature32[16], signature_r[8], signature_s[8], public_key32[16];
  uint8_t tmp;
  static uint32_t public_x[8], public_y[8];
  printf("\n Converting the variables to uint32_t...");
  ec_uint8v_to_uint32v(signature32, signature, 64);
  ec_uint8v_to_uint32v(public_key32, public_key, 64);
  for(tmp = 0; tmp < 16; tmp++)
  {
	  if (tmp >= 8)
	  {
		  public_y[tmp-8] = public_key32[tmp];
		  signature_s[tmp-8] = signature32[tmp];
	  }
	  else
	  {
		  public_x[tmp] = public_key32[tmp];
		  signature_r[tmp] = signature32[tmp];
	  }
  }
  printf(" done. Setting up the structures");*/
  /*
   * Setup Variables
   */
/*  static ecc_dsa_verify_state_t state = {
    //.process = PROCESS_CURRENT(),//&er_example_server,
    .curve_info = &nist_p_256,
    //.signature_r = &signature_r,
    //.signature_s = &signature_s,
    .hash = { 0x65637572, 0x20612073, 0x68206F66, 0x20686173,
              0x69732061, 0x68697320, 0x6F2C2054, 0x48616C6C },
  };
  printf("\nAbout to memcpy...");
  state.process= PROCESS_CURRENT();
  memcpy(state.signature_r, signature_r, 32);
  memcpy(state.signature_s, signature_s, 32);
  memcpy(state.public.x, public_x, sizeof(public_x));
  memcpy(state.public.y, public_y, sizeof(public_y));
*/
  /*
   * Verify
   */
/*  printf("\nRunning the timer and spawning the process...");
  rtimer_clock_t time = RTIMER_NOW();
  //TODO how to get the status code from the spawned proces??
  PT_SPAWN(&(PROCESS_CURRENT()->pt), &(state.pt), ecc_dsa_verify(&state));
  time = RTIMER_NOW() - time;
  printf("ecc_dsa_verify(), %lu ms\n",
         (uint32_t)((uint64_t)time * 1000 / RTIMER_SECOND));
*/
#else
 // watchdog_periodic();
/*  rtimer_clock_t start = RTIMER_NOW();
  res = uECC_verify(public_key, message_hash, signature);
 // watchdog_periodic();
  rtimer_clock_t stop = RTIMER_NOW();
  printf("verify took %lu ticks %lu s\n", (stop - start), (stop - start)/RTIMER_SECOND);*/
#endif /*OSCORE_WITH_HW_CRYPTO */
#endif /*CONTIKI_TARGET_ZOUL*/ 
#ifdef CONTIKI_TARGET_NATIVE
 // res = uECC_verify(public_key, message_hash, signature);
#endif /* CONTIKI_TARGET_NATIVE */
 // return res;  
}

#endif /*WITH_GROUPCOM*/
