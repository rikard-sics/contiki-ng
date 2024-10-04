/*
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
 *         hmac-sha, an HMAC implementation and an interface between the secure Hash Algorithms (SH256S) libraries with the EDHOC implementation.
 *         Interface the SHA library with the EDHOC implementation. New SHA libraries can be include in here.
 *         The EDHOC_CONFIG_SHA macro can be defined at config file to specify the used library for SH256
 *         Choose between: SHA software library from Oriol Pinol and SHA HW for CC2538_SH2 modules.
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */

#include "hmac-sha.h"
#include "contiki-lib.h"
#include "lib/memb.h"

MEMB(hmac_context_storage, hmac_context_t, HASH_MAX);

void encrypt0_storage_init(void);
static void sha_storage_init(void);

static inline hmac_context_t *
hmac_context_new(void)
{
  return memb_alloc(&hmac_context_storage);
}
static inline void
hmac_context_free(hmac_context_t *ctx)
{
  memb_free(&hmac_context_storage, ctx);
}
void
hmac_storage_init(void)
{
  memb_init(&hmac_context_storage);
  sha_storage_init();
  encrypt0_storage_init();
}
hmac_context_t *
hmac_new(const unsigned char *key, size_t klen)
{
  hmac_context_t *ctx;
  ctx = hmac_context_new();
  if(ctx) {
    int er = hmac_init(ctx, key, klen);
    if(er != 0) {
      LOG_ERR("hmac_init failed: %d\n", er);
      hmac_context_free(ctx);
      return NULL;
    }
  }
#ifdef CC2538_SH2
  crypto_init();
#endif
  return ctx;
}
MEMB(sha_context_storage, sha_context_t, HASH_MAX);

static inline sha_context_t *
sha_context_new(void)
{
  return memb_alloc(&sha_context_storage);
}
static inline void
sha_context_free(sha_context_t *ctx)
{
  memb_free(&sha_context_storage, ctx);
}
static void
sha_storage_init(void)
{
  memb_init(&sha_context_storage);
}
static int
sha_reset(sha_context_t *ctx)
{
  int er = 0;
#ifdef ECC_SH2
  er = SHA256Reset(&ctx->data);
#endif
#ifdef CC2538_SH2
  sha256_init(&ctx->data);
#endif
  return er;
}
static sha_context_t *
sha_new(void)
{
  sha_context_t *ctx;
  ctx = sha_context_new();
#ifdef CC2538_SH2
  LOG_DBG("SH256 for CC2538\n");
  crypto_init();
#endif
  if(ctx) {
    sha_reset(ctx);
  } else {
    LOG_ERR("Failed to allocate new SHA context\n");
  }
  return ctx;
}
static int
sha_input(sha_context_t *ctx, uint8_t *input, uint8_t input_sz)
{
#ifdef ECC_SH2
  int er = SHA256Input(&ctx->data, input, input_sz);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
  }
#endif

#ifdef CC2538_SH2
  int er = sha256_process(&ctx->data, (const void *)input, (uint32_t)input_sz);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
  }
#endif
  return er;
}
static int
sha_finalize(sha_context_t *ctx, uint8_t *hash)
{
#ifdef ECC_SH2
  int er = SHA256Result(&ctx->data, hash);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
#endif
#ifdef CC2538_SH2
  int er = sha256_done(&ctx->data, hash);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
#endif
  return er;
}
static void
sha_free(sha_context_t *ctx)
{
  if(ctx) {
    sha_context_free(ctx);
  }
#ifdef CC2538_SH2
  crypto_disable();
#endif
}
int
sha256(uint8_t *input, uint8_t input_sz, uint8_t *output)
{
  sha_context_t *ctx;
  ctx = sha_new();
  if(ctx) {
    int er = sha_input(ctx, input, input_sz);
    if(er != 0) {
      LOG_ERR("SHA error code (%d)\n", er);
      sha_free(ctx);
      return er;
    }
    er = sha_finalize(ctx, output);
    if(er != 0) {
      LOG_ERR("SHA error code (%d)\n", er);
      sha_free(ctx);
      return er;
    }
  }
  sha_free(ctx);
  return 0;
}
int
hmac_init(hmac_context_t *ctx, const unsigned char *key, size_t k_sz)
{
  memset(ctx, 0, sizeof(hmac_context_t));
  int er = sha_reset(&ctx->sha);
  if(er != 0) {
    LOG_ERR("sha_reset failed (%d)\n", er);
    return er;
  };
  if(k_sz > HMAC_BLOCKSIZE) {
    er = sha_input(&ctx->sha, (uint8_t *)key, k_sz);
    if(er != 0) {
      LOG_ERR("SHA error code (%d)\n", er);
      return er;
    }
    er = sha_finalize(&ctx->sha, ctx->pad);
    if(er != 0) {
      LOG_ERR("SHA error code (%d)\n", er);
      return er;
    }
  } else {
    memcpy(ctx->pad, key, k_sz);
  }

  /* create ipad: */
  for(int i = 0; i < HMAC_BLOCKSIZE; ++i) {
    ctx->pad[i] ^= 0x36;
  }
  er = sha_input(&ctx->sha, ctx->pad, HMAC_BLOCKSIZE);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
  /* create opad by xor-ing pad[i] with 0x36 ^ 0x5C: */
  for(int i = 0; i < HMAC_BLOCKSIZE; ++i) {
    ctx->pad[i] ^= 0x6A;
  }
  return 0;
}
int
hmac_update(hmac_context_t *ctx, const unsigned char *input, size_t input_sz)
{
  int er = 0;
  er = sha_input(&ctx->sha, (uint8_t *)input, input_sz);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
  return 0;
}
int
hmac_finalize(hmac_context_t *ctx, unsigned char *result)
{
  unsigned char buf[HMAC_DIGEST_SIZE];
  size_t len;
  int er = 0;
  len = HMAC_DIGEST_SIZE;
  er = sha_finalize(&ctx->sha, buf);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
  er = sha_reset(&ctx->sha);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
  er = sha_input(&ctx->sha, ctx->pad, HMAC_BLOCKSIZE);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }

  er = sha_input(&ctx->sha, buf, HMAC_DIGEST_SIZE);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }

  er = sha_finalize(&ctx->sha, result);
  if(er != 0) {
    LOG_ERR("SHA error code (%d)\n", er);
    return er;
  }
  return len;
}
void
hmac_free(hmac_context_t *ctx)
{
  if(ctx) {
    hmac_context_free(ctx);
  }
}
