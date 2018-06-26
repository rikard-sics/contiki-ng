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


#include "oscore-context.h"
#include <stddef.h>
#include "lib/memb.h"
#include "cbor.h"
#include <string.h>
#include "crypto.h"

oscore_ctx_t *common_context_list = NULL;
oscore_exchange_t *exchange_list = NULL;
ep_ctx_t *ep_ctx_list = NULL;

MEMB(common_context_memb, oscore_ctx_t, CONTEXT_NUM);
MEMB(sender_context_memb, oscore_sender_ctx_t, CONTEXT_NUM);
MEMB(recipient_context_memb, oscore_recipient_ctx_t, CONTEXT_NUM);

MEMB(exchange_memb, oscore_exchange_t, TOKEN_SEQ_NUM);
MEMB(ep_ctx_memb, ep_ctx_t, 2);

void
oscore_ctx_store_init()
{

  memb_init(&common_context_memb);
  memb_init(&sender_context_memb);
  memb_init(&recipient_context_memb);
}
static uint8_t
compose_info(uint8_t *buffer, uint8_t alg, uint8_t *id, uint8_t id_len, uint8_t *id_context, uint8_t id_context_len, uint8_t out_len)
{
  uint8_t ret = 0;
  ret += cbor_put_array(&buffer, 5);
  ret += cbor_put_bytes(&buffer, id, id_len);
  if(id_context != NULL && id_context_len > 0){
  	ret += cbor_put_bytes(&buffer, id_context, id_context_len);
  } else {
	ret += cbor_put_nil(&buffer); 
  }
  ret += cbor_put_unsigned(&buffer, alg);
  char *text;
  uint8_t text_len;
  if(out_len != 16) {
    text = "IV";
    text_len = 2;
  } else {
    text = "Key";
    text_len = 3;
  }

  ret += cbor_put_text(&buffer, text, text_len);
  ret += cbor_put_unsigned(&buffer, out_len);
  return ret;
}
uint8_t
bytes_equal(uint8_t *a_ptr, uint8_t a_len, uint8_t *b_ptr, uint8_t b_len)
{
  if(a_len != b_len) {
    return 0;
  }

  if(memcmp(a_ptr, b_ptr, a_len) == 0) {
    return 1;
  } else {
    return 0;
  }
}
oscore_ctx_t *
oscore_derive_ctx(uint8_t *master_secret, uint8_t master_secret_len, uint8_t *master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t *sid, uint8_t sid_len, uint8_t *rid, uint8_t rid_len, uint8_t *id_context, uint8_t id_context_len, uint8_t replay_window)
{

  oscore_ctx_t *common_ctx = memb_alloc(&common_context_memb);
  if(common_ctx == NULL) {
    return 0;
  }

  oscore_recipient_ctx_t *recipient_ctx = memb_alloc(&recipient_context_memb);
  if(recipient_ctx == NULL) {
    return 0;
  }

  oscore_sender_ctx_t *sender_ctx = memb_alloc(&sender_context_memb);
  if(sender_ctx == NULL) {
    return 0;
  }

  uint8_t info_buffer[15];

  uint8_t info_len;

  /* sender_ key */
  info_len = compose_info(info_buffer, alg, sid, sid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->sender_key, CONTEXT_KEY_LEN);

  /* Receiver key */
  info_len = compose_info(info_buffer, alg, rid, rid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->recipient_key, CONTEXT_KEY_LEN);

  /* common IV */
  info_len = compose_info(info_buffer, alg, NULL, 0, id_context, id_context_len, CONTEXT_INIT_VECT_LEN);
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->common_iv, CONTEXT_INIT_VECT_LEN);

  common_ctx->master_secret = master_secret;
  common_ctx->master_secret_len = master_secret_len;
  common_ctx->master_salt = master_salt;
  common_ctx->master_salt_len = master_salt_len;
  common_ctx->alg = alg;
  common_ctx->id_context = id_context;
  common_ctx->id_context_len = id_context_len;

  common_ctx->recipient_context = recipient_ctx;
  common_ctx->sender_context = sender_ctx;

  sender_ctx->sender_id = sid;
  sender_ctx->sender_id_len = sid_len;
  sender_ctx->seq = 0;

  recipient_ctx->recipient_id = rid;
  recipient_ctx->recipient_id_len = rid_len;
  recipient_ctx->last_seq = 0;
  recipient_ctx->highest_seq = 0;
  recipient_ctx->replay_window_size = replay_window;
  recipient_ctx->rollback_last_seq = 0;
  recipient_ctx->sliding_window = 0;
  recipient_ctx->rollback_sliding_window = 0;
  recipient_ctx->initial_state = 1;

  common_ctx->next_context = common_context_list;
  common_context_list = common_ctx;
  return common_ctx;
}
int
oscore_free_ctx(oscore_ctx_t *ctx)
{

  if(common_context_list == ctx) {
    common_context_list = ctx->next_context;
  } else {

    oscore_ctx_t *ctx_ptr = common_context_list;

    while(ctx_ptr->next_context != ctx) {
      ctx_ptr = ctx_ptr->next_context;
    }

    if(ctx_ptr->next_context->next_context != NULL) {
      ctx_ptr->next_context = ctx_ptr->next_context->next_context;
    } else {
      ctx_ptr->next_context = NULL;
    }
  }

  memset(ctx->master_secret, 0x00, ctx->master_secret_len);
  memset(ctx->master_salt, 0x00, ctx->master_salt_len);
  memset(ctx->sender_context->sender_key, 0x00, CONTEXT_KEY_LEN);
  memset(ctx->recipient_context->recipient_key, 0x00, CONTEXT_KEY_LEN);
  memset(ctx->common_iv, 0x00, CONTEXT_INIT_VECT_LEN);

  int ret = 0;
  ret += memb_free(&sender_context_memb, ctx->sender_context);
  ret += memb_free(&recipient_context_memb, ctx->recipient_context);
  ret += memb_free(&common_context_memb, ctx);

  return ret;
}
oscore_ctx_t *
oscore_find_ctx_by_rid(uint8_t *rid, uint8_t rid_len)
{
  if(common_context_list == NULL) {
    return NULL;
  }

  oscore_ctx_t *ctx_ptr = common_context_list;

  while(!bytes_equal(ctx_ptr->recipient_context->recipient_id, ctx_ptr->recipient_context->recipient_id_len, rid, rid_len)) {
    ctx_ptr = ctx_ptr->next_context;

    if(ctx_ptr == NULL) {
      return NULL;
    }
  }
  return ctx_ptr;
}
oscore_ctx_t *
oscore_find_ctx_by_token(uint8_t *token, uint8_t token_len)
{
  if(common_context_list == NULL) {
    return NULL;
  }

  oscore_ctx_t *ctx_ptr = common_context_list;

  while(!bytes_equal(ctx_ptr->sender_context->token, ctx_ptr->sender_context->token_len, token, token_len)) {
    ctx_ptr = ctx_ptr->next_context;

    if(ctx_ptr == NULL) {
      return NULL;
    }
  }
  return ctx_ptr;
}
/* Token <=> SEQ association */
void
oscore_exchange_store_init()
{
  memb_init(&exchange_memb);
}
oscore_ctx_t*
oscore_get_exchange(uint8_t *token, uint8_t token_len, uint32_t *seq)
{
  oscore_exchange_t *ptr = exchange_list;

  while(!bytes_equal(ptr->token, ptr->token_len, token, token_len)) {

    ptr = ptr->next;
    if(ptr == NULL) {
      return 0;
    }
  }

  *seq = ptr->seq;

  return ptr->context;
}
uint8_t
oscore_set_exchange(uint8_t *token, uint8_t token_len, uint32_t seq, oscore_ctx_t *context)
{
  oscore_exchange_t *exchange_memb_ptr = memb_alloc(&exchange_memb);
  if(exchange_memb_ptr == NULL) {
    return 0;
  }

  memcpy(exchange_memb_ptr->token, token, token_len);
  exchange_memb_ptr->token_len = token_len;
  exchange_memb_ptr->seq = seq;
  exchange_memb_ptr->context = context;
  exchange_memb_ptr->next = exchange_list;
  exchange_list = exchange_memb_ptr;
  return 1;
}
void
oscore_remove_exchange(uint8_t *token, uint8_t token_len)
{
  oscore_exchange_t *ptr = exchange_list;

  if(bytes_equal(ptr->token, ptr->token_len, token, token_len)) { /* first element */
    exchange_list = ptr->next;
    memb_free(&exchange_memb, ptr);
    return;
  }

  ptr = ptr->next;

  while(1) {
    if(ptr == NULL) {
      return;
    }

    if(bytes_equal(ptr->token, ptr->token_len, token, token_len)) {
      oscore_exchange_t *tmp = ptr->next;
      ptr->next = ptr->next->next;
      memb_free(&exchange_memb, tmp);
      return;
    }

    ptr = ptr->next;
  }
}
/* URI <=> RID association */
void
oscore_ep_ctx_store_init()
{
  memb_init(&ep_ctx_memb);
}
uint8_t
oscore_ep_ctx_set_association(coap_endpoint_t *ep, char *uri, oscore_ctx_t *ctx)
{
  ep_ctx_t *ep_ctx_ptr = memb_alloc(&ep_ctx_memb);
  if(ep_ctx_ptr == NULL) {
    return 0;
  }
  ep_ctx_ptr->ep = ep;
  ep_ctx_ptr->uri = uri;
  ep_ctx_ptr->ctx = ctx;
  ep_ctx_ptr->next = ep_ctx_list;
  ep_ctx_list = ep_ctx_ptr;
  return 1;
}

int _strcmp(const char *a, const char *b){
  if( a == NULL && b != NULL){
    return -1;
  } else if ( a != NULL && b == NULL) {
    return 1;
  } else if ( a == NULL && b == NULL) {
    return 0;
  }
  return strcmp(a,b);
}		



oscore_ctx_t *
oscore_get_context_from_ep(coap_endpoint_t *ep, const char *uri)
{
  ep_ctx_t *ptr = ep_ctx_list;
  while(((coap_endpoint_cmp(ep, ptr->ep) == 0) || (_strcmp(uri, ptr->uri) != 0))) {
    
    ptr = ptr->next;
    if(ptr == NULL) {
      return NULL;
    }
  }
  
  return ptr->ctx;
}
