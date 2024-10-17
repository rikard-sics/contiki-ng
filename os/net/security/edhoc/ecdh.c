/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB (RISE), Stockholm, Sweden
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
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
 *         ecdh, an interface between the ECC and Secure Hash Algorithms with the EDHOC implementation.
 *         Interface the ECC key used library with the EDHOC implementation. New ECC libraries can be include it here.
 *         (UECC macro must be defined at config file) and with the CC2538 HW module
 *         Interface the Secure Hash Algorithms SH256 with the EDHOC implementation.
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */

#include "ecdh.h"
#include "contiki-lib.h"
#include <dev/watchdog.h>
#include "sys/rtimer.h"
#include "sys/process.h"
/* static rtimer_clock_t time; */

#ifndef HKDF_INFO_MAXLEN
#define HKDF_INFO_MAXLEN 255
#endif

#ifndef HKDF_OUTPUT_MAXLEN
#define HKDF_OUTPUT_MAXLEN 255
#endif

static uint8_t aggregate_buffer[HASH_LEN + HKDF_INFO_MAXLEN + 1];
static uint8_t out_buffer[HKDF_OUTPUT_MAXLEN + HASH_LEN];

uint8_t
generate_IKM(ecc_curve_t curve, const uint8_t *gx, const uint8_t *gy, const uint8_t *private_key, uint8_t *ikm)
{
  int er = 0;
#if ECC == UECC_ECC     /* use GX and Gy */
  er = uecc_generate_IKM(gx, gy, private_key, ikm, curve);
#endif
#if ECC == CC2538_ECC
  er = cc2538_generate_IKM(gx, gy, private_key, ikm, curve);
#endif
  return er;
}
static hmac_context_t *
hmac_sha256_init(const uint8_t *key, uint8_t key_sz)
{
  // hmac_storage_init();
  return hmac_new(key, key_sz);
}
static int
hmac_sha256_create(hmac_context_t **ctx, const uint8_t *key, uint8_t key_sz, const uint8_t *data, uint8_t data_sz, uint8_t *hmac)
{
  int er = hmac_update(*ctx, data, data_sz);
  if(er != 0) {
    LOG_ERR("hmac_update failed (%d)\n", er);
    return er;
  }
  er = hmac_finalize(*ctx, hmac);
  if(er <= 0) {
    LOG_ERR("hmac_finalize failed (%d)\n", er);
    return er;
  }
  return 0;
}
static void
hmac_sha256_reset(hmac_context_t **ctx, const unsigned char *key, size_t k_sz)
{
  hmac_init(*ctx, key, k_sz);
}
static void
hmac_sha256_free(hmac_context_t *ctx)
{
  hmac_free(ctx);
}
uint8_t
compute_th(uint8_t *in, uint8_t in_sz, uint8_t *hash, uint8_t hash_sz)
{
  int er = sha256(in, in_sz, hash);
  return er;
}
int8_t
hkdf_extract(const uint8_t *salt, uint8_t salt_sz, const uint8_t *ikm, uint8_t ikm_sz, uint8_t *hmac)
{
  hmac_context_t *ctx = hmac_sha256_init(salt, salt_sz);
  if(!ctx) {
    LOG_ERR("No context from hmac_sha256_init\n");
    return ERR_INFO_SIZE;
  }
  hmac_sha256_create(&ctx, salt, salt_sz, ikm, ikm_sz, hmac);
  hmac_sha256_free(ctx);
  return 1;
}
int8_t
hkdf_expand(const uint8_t *prk, uint16_t prk_sz, const uint8_t *info, uint16_t info_sz, uint8_t *okm, uint16_t okm_sz)
{
  if(info_sz > HKDF_INFO_MAXLEN) {
    LOG_ERR("error code (%d)\n ", ERR_INFO_SIZE);
    return ERR_INFO_SIZE;
  }
  if(okm_sz > HKDF_OUTPUT_MAXLEN) {
    LOG_ERR("error code (%d)\n ", ERR_OKM_SIZE);
    return ERR_OKM_SIZE;
  }
  int hash_sz = HASH_LEN;

  /*ceil */
  int N = (okm_sz + hash_sz - 1) / hash_sz;

  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_sz);
  aggregate_buffer[info_sz] = 0x01;

  hmac_context_t *ctx = hmac_sha256_init(prk, prk_sz);
  if(!ctx) {
    LOG_ERR("No context from hmac_sha256_init\n");
    return ERR_INFO_SIZE;
  }
  int er = hmac_sha256_create(&ctx, prk, prk_sz, aggregate_buffer, info_sz + 1, &(out_buffer[0]));
  if(er != 0) {
    LOG_ERR("hmac_sha256_create error code (%d)\n", er);
    return ERR_INFO_SIZE; // FIXME: make unique error code
  }

  /*Compose T(2) ... T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), hash_sz);
  for(int i = 1; i < N; i++) {
    hmac_sha256_reset(&ctx, prk, prk_sz);
    memcpy(&(aggregate_buffer[hash_sz]), info, info_sz);
    aggregate_buffer[hash_sz + info_sz] = i + 1;
    er = hmac_sha256_create(&ctx, prk, prk_sz, aggregate_buffer, hash_sz + info_sz + 1, &(out_buffer[i * hash_sz]));
    if(er != 0) {
      LOG_ERR("hmac_sha256_create error code (%d)\n", er);
      return ERR_INFO_SIZE; // FIXME: make unique error code
    }
    memcpy(aggregate_buffer, &(out_buffer[i * hash_sz]), hash_sz);
  }

  memcpy(okm, aggregate_buffer, okm_sz);
  hmac_sha256_free(ctx);
  return 1;
}

