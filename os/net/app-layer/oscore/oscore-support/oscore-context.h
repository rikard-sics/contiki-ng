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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-12) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */



#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include <inttypes.h>
#include "coap-constants.h"
#include "coap-endpoint.h"

#define CONTEXT_KEY_LEN 16
#define CONTEXT_INIT_VECT_LEN 13
#define CONTEXT_SEQ_LEN sizeof(uint32_t)

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef struct oscore_sender_ctx_t oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_t oscore_recipient_ctx_t;
typedef struct oscore_ctx_t oscore_ctx_t;
typedef struct oscore_exchange_t oscore_exchange_t;
typedef struct ep_ctx_t ep_ctx_t;

struct oscore_sender_ctx_t {
  uint8_t sender_key[CONTEXT_KEY_LEN];
  uint8_t token[COAP_TOKEN_LEN];
  uint32_t seq;
  uint8_t *sender_id;
  uint8_t sender_id_len;
  uint8_t token_len;
};

struct oscore_recipient_ctx_t {
  uint32_t last_seq;
  uint32_t highest_seq;
  uint32_t sliding_window;
  uint32_t rollback_sliding_window;
  uint32_t rollback_last_seq;
  oscore_recipient_ctx_t *recipient_context; /* This field facilitates easy integration of OSCOAP multicast */
  uint8_t recipient_key[CONTEXT_KEY_LEN];
  uint8_t *recipient_id;
  uint8_t recipient_id_len;
  uint8_t replay_window_size;
  uint8_t initial_state;
};

struct oscore_ctx_t {
  uint8_t *master_secret;
  uint8_t *master_salt;
  uint8_t common_iv[CONTEXT_INIT_VECT_LEN];
  uint8_t *id_context;
  oscore_sender_ctx_t *sender_context;
  oscore_recipient_ctx_t *recipient_context;
  oscore_ctx_t *next_context;
  uint8_t master_secret_len;
  uint8_t master_salt_len;
  uint8_t id_context_len;
  uint8_t alg;
};

struct oscore_exchange_t {
  uint8_t token[8];
  uint8_t token_len;
  uint32_t seq;
  oscore_ctx_t *context;
  oscore_exchange_t *next;
};

struct ep_ctx_t {
  coap_endpoint_t *ep;
  char *uri;
  oscore_ctx_t *ctx;
  ep_ctx_t *next;
};
void oscore_ctx_store_init();

//replay window default is 32
oscore_ctx_t *oscore_derive_ctx(uint8_t *master_secret, uint8_t master_secret_len, uint8_t *master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t *sid, uint8_t sid_len, uint8_t *rid, uint8_t rid_len, uint8_t *id_context, uint8_t id_context_len, uint8_t replay_window);

int oscore_free_ctx(oscore_ctx_t *ctx);

oscore_ctx_t *oscore_find_ctx_by_rid(uint8_t *rid, uint8_t rid_len);

/* Token <=> SEQ association */
void oscore_exchange_store_init();
oscore_ctx_t* oscore_get_exchange(uint8_t *token, uint8_t token_len, uint32_t *seq);
uint8_t oscore_set_exchange(uint8_t *token, uint8_t token_len, uint32_t seq, oscore_ctx_t *context);
void oscore_remove_exchange(uint8_t *token, uint8_t token_len);

/* URI <=> CTX association */
void oscore_ep_ctx_store_init();
uint8_t oscore_ep_ctx_set_association(coap_endpoint_t *ep, char *uri, oscore_ctx_t *ctx);
oscore_ctx_t *oscore_get_context_from_ep(coap_endpoint_t *ep, const char *uri);

#endif /* _OSCORE_CONTEXT_H */
