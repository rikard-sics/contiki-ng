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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-15) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 */




#include "oscore.h"
#include "oscore-association.h"
#include "coap.h"
#include "coap-log.h"
#include "stdio.h"
#include "inttypes.h"
#include "assert.h"

#include "nanocbor/nanocbor.h"
#include "nanocbor-helper.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

/* Sets Alg, Partial IV Key ID and Key in COSE. */
static void
oscore_populate_cose(const coap_message_t *pkt, cose_encrypt0_t *cose, const oscore_ctx_t *ctx, bool sending);

/* Creates and sets External AAD */
static int
oscore_prepare_aad(const coap_message_t *coap_pkt, const cose_encrypt0_t *cose, nanocbor_encoder_t* enc, bool sending);

/*Return 1 if OK, Error code otherwise */
static bool
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, const cose_encrypt0_t *cose);

static void
printf_hex_detailed(const char* name, const uint8_t *data, size_t len)
{
  LOG_DBG("%s (len=%zu): ", name, len);
  LOG_DBG_BYTES(data, len);
  LOG_DBG_("\n");
}

static bool
coap_is_request(const coap_message_t *coap_pkt)
{
  return coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE;
}

bool
oscore_is_request_protected(const coap_message_t *request)
{
  return request != NULL && coap_is_option(request, COAP_OPTION_OSCORE);
}

void
oscore_protect_resource(coap_resource_t *resource)
{
  resource->oscore_protected = true;
}

bool oscore_is_resource_protected(const coap_resource_t *resource)
{
  return resource->oscore_protected;
}

static uint8_t
u64tob(uint64_t value, uint8_t *buffer)
{
  memset(buffer, 0, sizeof(uint64_t));
  uint8_t length = 0;
  for(int i = 0; i < 8; i++){
    uint8_t temp = (value >> (8*i)) & 0xFF;

    if(temp != 0){
      length = i+1;
    }
  }

  for (int i = 0; i < length; i++){
    buffer[length - i - 1] = (value >> (8*i)) & 0xFF;
  }  
  return length == 0 ? 1 : length;

}

static uint64_t
btou64(const uint8_t *bytes, size_t len)
{
  uint8_t buffer[sizeof(uint64_t)];
  memset(buffer, 0, sizeof(buffer)); /* function variables are not initializated to anything */
  int offset = sizeof(buffer) - len;
  uint64_t num;

  memcpy((uint8_t *)(buffer + offset), bytes, len);

  num =
    (uint64_t)buffer[0] << 56 |
    (uint64_t)buffer[1] << 48 |
    (uint64_t)buffer[2] << 40 |
    (uint64_t)buffer[3] << 32 |
    (uint64_t)buffer[4] << 24 |
    (uint64_t)buffer[5] << 16 |
    (uint64_t)buffer[6] << 8 |
    (uint64_t)buffer[7];

  return num;
}

static int
oscore_encode_option_value(uint8_t *option_buffer, const cose_encrypt0_t *cose, bool include_partial_iv)
{
  uint8_t offset = 1;
  if(cose->partial_iv_len > 5){
	  return 0;
  }
  option_buffer[0] = 0;
  if(cose->partial_iv_len > 0 && cose->partial_iv != NULL && include_partial_iv) {
    option_buffer[0] |= (0x07 & cose->partial_iv_len);
    memcpy(&(option_buffer[offset]), cose->partial_iv, cose->partial_iv_len);
    offset += cose->partial_iv_len;
  }

  if(cose->kid_context_len > 0 && cose->kid_context != NULL) {
    option_buffer[0] |= 0x10;
    option_buffer[offset] = cose->kid_context_len;
    offset++;
    memcpy(&(option_buffer[offset]), cose->kid_context, cose->kid_context_len);
    offset += cose->kid_context_len;
  }

  if(cose->key_id_len > 0 && cose->key_id != NULL) {
    option_buffer[0] |= 0x08;
    memcpy(&(option_buffer[offset]), cose->key_id, cose->key_id_len);
    offset += cose->key_id_len;
  }
  if(offset == 1 && option_buffer[0] == 0) { /* If option_value is 0x00 it should be empty. */
	  return 0;
  }
  return offset;
}

coap_status_t
oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose)
{
  if(option_len == 0){
    return NO_ERROR;
  } else if(option_len > 255 || option_len < 0 ||
            (option_value[0] & 0x06) == 6 ||
            (option_value[0] & 0x07) == 7 ||
            (option_value[0] & 0xE0) != 0) {
    return BAD_OPTION_4_02;
  }
#ifdef WITH_GROUPCOM
  /*h and k flags MUST be 1 in group OSCORE. h MUST be 1 only for requests. //TODO exclude h if client behaviour considered.*/  
  //LOG_INFO("\nTime to check h and k!\n");
  if ( (option_value[0] & 0x18) == 0) {
    return BAD_OPTION_4_02;
  }
#endif
  
  uint8_t partial_iv_len = (option_value[0] & 0x07);
  if(partial_iv_len != 0) {    
    if(offset + partial_iv_len > option_len) {
      return BAD_OPTION_4_02;
    }

    cose_encrypt0_set_partial_iv(cose, &(option_value[offset]), partial_iv_len);
    offset += partial_iv_len;
  }
  
  /* If h-flag is set KID-Context field is present. */
  if((option_value[0] & 0x10) != 0) {
    uint8_t kid_context_len = option_value[offset];
    offset++;
    if (offset + kid_context_len > option_len) {
      return BAD_OPTION_4_02;
    }

    cose_encrypt0_set_kid_context(cose, &(option_value[offset]), kid_context_len);
    offset += kid_context_len;
  }

  /* IF k-flag is set Key ID field is present. */
  if((option_value[0] & 0x08) != 0) {
    int kid_len = option_len - offset;
    if (kid_len <= 0 || kid_len > UINT8_MAX) {
      return BAD_OPTION_4_02;
    }
    cose_encrypt0_set_key_id(cose, &(option_value[offset]), (uint8_t)kid_len);
  }

  return NO_ERROR;
}

/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t
oscore_decode_message(coap_message_t *coap_pkt)
{
  cose_encrypt0_t cose[1];
  oscore_ctx_t *ctx = NULL;
  uint8_t aad_buffer[35];
  uint8_t nonce_buffer[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];
  uint8_t seq_buffer[CONTEXT_SEQ_LEN];
  cose_encrypt0_init(cose);

  printf_hex_detailed("object_security", coap_pkt->object_security, coap_pkt->object_security_len);

  /* Options are discarded later when they are overwritten. This should be improved */
	  coap_status_t ret = oscore_decode_option_value(coap_pkt->object_security, coap_pkt->object_security_len, cose);

  if( ret != NO_ERROR){
	 LOG_DBG_("OSCORE option value could not be parsed.\n");
	 coap_error_message = "OSCORE option could not be parsed.";
	 return ret;
  }

  if(coap_is_request(coap_pkt)) {
    uint8_t *key_id;
#ifdef WITH_GROUPCOM
    uint8_t *group_id; /*used to extract gid from OSCORE option*/
#endif
    int key_id_len = cose_encrypt0_get_key_id(cose, &key_id);
    ctx = oscore_find_ctx_by_rid(key_id, key_id_len);
    if(ctx == NULL) {
      LOG_ERR("OSCORE Security Context not found (rid='");
      LOG_ERR_BYTES(key_id, key_id_len);
      LOG_ERR_("' src='");
      LOG_ERR_COAP_EP(coap_pkt->src_ep);
      LOG_ERR_("').\n");
      coap_error_message = "Security context not found";
      return OSCORE_MISSING_CONTEXT; /* Will transform into UNAUTHORIZED_4_01 later */
    }
#ifdef WITH_GROUPCOM
    uint8_t gid_len = cose_encrypt0_get_kid_context(cose, &group_id);
    if(gid_len == 0) {
      LOG_DBG_("Gid length is 0.\n");
      return UNAUTHORIZED_4_01;
    } 
    else if (*(ctx->gid) != *(group_id)) {
      LOG_DBG_("Received gid does not match.\n");    
      return UNAUTHORIZED_4_01;
    }
    else {
      LOG_DBG_("Gid length=%d Value comes below.\n", gid_len);
      printf_hex(group_id, gid_len);
    }
#endif    
    /*4 Verify the ‘Partial IV’ parameter using the Replay Window, as described in Section 7.4. */
    if(!oscore_validate_sender_seq(&ctx->recipient_context, cose)) {
      LOG_WARN("OSCORE Replayed or old message\n");
      coap_error_message = "Replay detected";
      return UNAUTHORIZED_4_01;
    }

    cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  } else { /* Message is a response */

    /* try and find this exchange */
    oscore_exchange_t* exchange = oscore_get_exchange(coap_pkt->token, coap_pkt->token_len);
    if (exchange == NULL) {
      LOG_ERR("OSCORE exchange not found (token='");
      LOG_ERR_BYTES(coap_pkt->token, coap_pkt->token_len);
      LOG_ERR_("' src='");
      LOG_ERR_COAP_EP(coap_pkt->src_ep);
      LOG_ERR_("').\n");
      coap_error_message = "Security context not found";
      return UNAUTHORIZED_4_01;
    }

    const uint64_t seq = exchange->seq;
    ctx = exchange->context;

    /* Remove it, as we are done with this round of communication */
    oscore_remove_exchange(coap_pkt->token, coap_pkt->token_len);

    /* Check that the context is valid */
    if (ctx == NULL) {
      LOG_ERR("OSCORE exchange has no valid context (token='");
      LOG_ERR_BYTES(coap_pkt->token, coap_pkt->token_len);
      LOG_ERR_("' src='");
      LOG_ERR_COAP_EP(coap_pkt->src_ep);
      LOG_ERR_("').\n");
      coap_error_message = "Security context not found";
      return UNAUTHORIZED_4_01;
    }

    LOG_DBG("cose->partial_iv_len == %"PRIu16" (%"PRIu64")\n", cose->partial_iv_len, seq);

    /* If message contains a partial IV, the received is used. */
    if(cose->partial_iv_len == 0){
      uint8_t seq_len = u64tob(seq, seq_buffer);
      cose_encrypt0_set_partial_iv(cose, seq_buffer, seq_len);
    }
  }

  oscore_populate_cose(coap_pkt, cose, ctx, false);
  coap_pkt->security_context = ctx;

  // TODO: AAD should not be generated here, but should come from
  // the received message?
  nanocbor_encoder_t aad_enc;
  nanocbor_encoder_init(&aad_enc, aad_buffer, sizeof(aad_buffer));
  if (oscore_prepare_aad(coap_pkt, cose, &aad_enc, false) != NANOCBOR_OK) {
    return INTERNAL_SERVER_ERROR_5_00;
  }

  cose_encrypt0_set_aad(cose, aad_buffer, nanocbor_encoded_len(&aad_enc));
  cose_encrypt0_set_alg(cose, ctx->alg);
  
  oscore_generate_nonce(cose, coap_pkt, nonce_buffer, sizeof(nonce_buffer));
  cose_encrypt0_set_nonce(cose, nonce_buffer, sizeof(nonce_buffer));
  
  cose_encrypt0_set_content(cose, coap_pkt->payload, coap_pkt->payload_len);

  int res = cose_encrypt0_decrypt(cose);
  if(res <= 0) {
    LOG_ERR("OSCORE Decryption Failure, result code: %d\n", res);
    if(coap_is_request(coap_pkt)) {
      oscore_sliding_window_rollback(&ctx->recipient_context.sliding_window);
      coap_error_message = "Decryption failure";
      return BAD_REQUEST_4_00;
    } else {
      coap_error_message = "Decryption failure";
      return OSCORE_DECRYPTION_ERROR;
    }  
  }

  return oscore_parser(coap_pkt, cose->content, res, ROLE_CONFIDENTIAL);
}

static void
oscore_populate_cose(const coap_message_t *pkt, cose_encrypt0_t *cose, const oscore_ctx_t *ctx, bool sending)
{
  cose_encrypt0_set_alg(cose, ctx->alg);

  if(coap_is_request(pkt)) {
    if(sending){
      cose->partial_iv_len = u64tob(ctx->sender_context.seq, cose->partial_iv);
      cose_encrypt0_set_key_id(cose, ctx->sender_context.sender_id, ctx->sender_context.sender_id_len);
      cose_encrypt0_set_key(cose, ctx->sender_context.sender_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    } else { /* receiving */
      assert(cose->partial_iv_len > 0); /* Partial IV set by decode option value. */
      assert(cose->key_id != NULL); /* Key ID set by decode option value. */
      cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    }
  } else { /* coap is response */
    if(sending){
      cose->partial_iv_len = u64tob(ctx->recipient_context.sliding_window.recent_seq, cose->partial_iv);
      cose_encrypt0_set_key_id(cose, ctx->recipient_context.recipient_id, ctx->recipient_context.recipient_id_len);
      cose_encrypt0_set_key(cose, ctx->sender_context.sender_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    } else { /* receiving */
      assert(cose->partial_iv_len > 0); /* Partial IV set when getting seq from exchange. */
      cose_encrypt0_set_key_id(cose, ctx->sender_context.sender_id, ctx->sender_context.sender_id_len);
      cose_encrypt0_set_key(cose, ctx->recipient_context.recipient_key, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    }
  }
}

/* Prepares a new OSCORE message, returns the size of the message. */
size_t
oscore_prepare_message(coap_message_t *coap_pkt, uint8_t *buffer)
{
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);

  uint8_t content_buffer[COAP_MAX_CHUNK_SIZE + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
  uint8_t aad_buffer[35];
  uint8_t nonce_buffer[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];
  uint8_t option_value_buffer[15];

  /*  1 Retrieve the Sender Context associated with the target resource. */
  oscore_ctx_t *ctx = coap_pkt->security_context;
  if(ctx == NULL) {
    LOG_ERR("No context in OSCORE!\n");
    return PACKET_SERIALIZATION_ERROR;
  }

  oscore_populate_cose(coap_pkt, cose, coap_pkt->security_context, true);

  size_t plaintext_len = oscore_serializer(coap_pkt, content_buffer, ROLE_CONFIDENTIAL);
  if(plaintext_len > COAP_MAX_CHUNK_SIZE){
    LOG_ERR("OSCORE Message to large (%zu > %u) to process.\n", plaintext_len, COAP_MAX_CHUNK_SIZE);
    return PACKET_SERIALIZATION_ERROR;
  }

  cose_encrypt0_set_content(cose, content_buffer, plaintext_len);
  
  nanocbor_encoder_t aad_enc;
  nanocbor_encoder_init(&aad_enc, aad_buffer, sizeof(aad_buffer));
  if (oscore_prepare_aad(coap_pkt, cose, &aad_enc, true) != NANOCBOR_OK) {
    return INTERNAL_SERVER_ERROR_5_00;
  }

  cose_encrypt0_set_aad(cose, aad_buffer, nanocbor_encoded_len(&aad_enc));
  
  oscore_generate_nonce(cose, coap_pkt, nonce_buffer, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  cose_encrypt0_set_nonce(cose, nonce_buffer, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  
  if(coap_is_request(coap_pkt)) {
    if(!oscore_set_exchange(coap_pkt->token, coap_pkt->token_len, ctx->sender_context.seq, ctx)) {
      LOG_ERR("OSCORE Could not store exchange.\n");
      return PACKET_SERIALIZATION_ERROR;
    }
    oscore_increment_sender_seq(ctx);
  }

  int ciphertext_len = cose_encrypt0_encrypt(cose);
  if(ciphertext_len < 0){
    LOG_ERR("OSCORE internal error %d.\n", ciphertext_len);
    return PACKET_SERIALIZATION_ERROR;
  }
  
  // Partial IV shall NOT be included in responses if not a request
  const bool include_partial_iv = coap_is_request(coap_pkt);
  uint8_t option_value_len = oscore_encode_option_value(option_value_buffer, cose, include_partial_iv);
  
  coap_set_payload(coap_pkt, content_buffer, ciphertext_len);
  coap_set_header_object_security(coap_pkt, option_value_buffer, option_value_len);
  
  /* Overwrite the CoAP code. */
  if(coap_is_request(coap_pkt)) {
    coap_pkt->code = COAP_POST;
  } else {
    coap_pkt->code = CHANGED_2_04;
  }

  oscore_clear_options(coap_pkt);

  uint8_t serialized_len = oscore_serializer(coap_pkt, buffer, ROLE_COAP);

  return serialized_len;
}

/* Creates and sets External AAD */
static int
oscore_prepare_aad(const coap_message_t *coap_pkt, const cose_encrypt0_t *cose, nanocbor_encoder_t* enc, bool sending)
{
  uint8_t external_aad_buffer[25];

  nanocbor_encoder_t aad_enc;
  nanocbor_encoder_init(&aad_enc, external_aad_buffer, sizeof(external_aad_buffer));

  /* Serialize the External AAD*/
  NANOCBOR_CHECK(nanocbor_fmt_array(&aad_enc, 5));
  NANOCBOR_CHECK(nanocbor_fmt_uint(&aad_enc, 1)); /* Version, always for this version of the draft 1 */
  NANOCBOR_CHECK(nanocbor_fmt_array(&aad_enc, 1)); /* Algorithms array */
  NANOCBOR_CHECK(nanocbor_fmt_uint(&aad_enc, coap_pkt->security_context->alg)); /* Algorithm */

  /* When sending responses. */
  if(coap_is_request(coap_pkt)) {
    NANOCBOR_CHECK(nanocbor_put_bstr(&aad_enc, cose->key_id, cose->key_id_len));
  } else {
    if (sending) {
      NANOCBOR_CHECK(nanocbor_put_bstr(&aad_enc,
        coap_pkt->security_context->recipient_context.recipient_id,
        coap_pkt->security_context->recipient_context.recipient_id_len));
    } else {
      NANOCBOR_CHECK(nanocbor_put_bstr(&aad_enc,
        coap_pkt->security_context->sender_context.sender_id,
        coap_pkt->security_context->sender_context.sender_id_len));
    }
  }
  NANOCBOR_CHECK(nanocbor_put_bstr(&aad_enc, cose->partial_iv, cose->partial_iv_len));
  NANOCBOR_CHECK(nanocbor_put_bstr(&aad_enc, NULL, 0)); /* Put integrety protected option, at present there are none. */

  const size_t external_aad_len = nanocbor_encoded_len(&aad_enc);

  /* Begin creating the AAD */
  NANOCBOR_CHECK(nanocbor_fmt_array(enc, 3));
  NANOCBOR_CHECK(nanocbor_put_tstr(enc, "Encrypt0"));
  NANOCBOR_CHECK(nanocbor_put_bstr(enc, NULL, 0));
  NANOCBOR_CHECK(nanocbor_put_bstr(enc, external_aad_buffer, external_aad_len));

  return NANOCBOR_OK;
}

/* Creates Nonce */
void
oscore_generate_nonce(const cose_encrypt0_t *ptr, const coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size)
{
  printf_hex_detailed("key_id", ptr->key_id, ptr->key_id_len);
  printf_hex_detailed("partial_iv", ptr->partial_iv, ptr->partial_iv_len);
  printf_hex_detailed("common_iv", coap_pkt->security_context->common_iv, CONTEXT_INIT_VECT_LEN);

  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(ptr->key_id_len);
  memcpy(&(buffer[((size - 5) - ptr->key_id_len)]), ptr->key_id, ptr->key_id_len);
  memcpy(&(buffer[size - ptr->partial_iv_len]), ptr->partial_iv, ptr->partial_iv_len);
  int i;
  for(i = 0; i < size; i++) {
    buffer[i] ^= (uint8_t)coap_pkt->security_context->common_iv[i];
  }

  printf_hex_detailed("result", buffer, size);
}

/*Remove all protected options */
static void
oscore_clear_option(coap_message_t *coap_pkt, coap_option_t option)
{
  coap_pkt->options[option / COAP_OPTION_MAP_SIZE] &= ~(1 << (option % COAP_OPTION_MAP_SIZE));
}

void
oscore_clear_options(coap_message_t *coap_pkt)
{
  oscore_clear_option(coap_pkt, COAP_OPTION_IF_MATCH);
  /* URI-Host should be unprotected */
  oscore_clear_option(coap_pkt, COAP_OPTION_ETAG);
  oscore_clear_option(coap_pkt, COAP_OPTION_IF_NONE_MATCH);
  /* Observe should be duplicated */
  oscore_clear_option(coap_pkt, COAP_OPTION_LOCATION_PATH);
  oscore_clear_option(coap_pkt, COAP_OPTION_URI_PATH);
  oscore_clear_option(coap_pkt, COAP_OPTION_CONTENT_FORMAT);
  /* Max-Age shall me duplicated */
  oscore_clear_option(coap_pkt, COAP_OPTION_URI_QUERY);
  oscore_clear_option(coap_pkt, COAP_OPTION_ACCEPT);
  oscore_clear_option(coap_pkt, COAP_OPTION_LOCATION_QUERY);
  /* Block2 should be duplicated */
  /* Block1 should be duplicated */
  /* Size2 should be duplicated */
  /* Proxy-URI should be unprotected */
  /* Proxy-Scheme should be unprotected */
  /* Size1 should be duplicated */
}

/*Return 1 if OK, Error code otherwise */
bool
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, const cose_encrypt0_t *cose)
{
  const uint64_t incoming_seq = btou64(cose->partial_iv, cose->partial_iv_len);

  return oscore_sliding_window_validate(&ctx->sliding_window, incoming_seq);
}

/* Return 0 if SEQ MAX, return 1 if OK */
bool
oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
  LOG_DBG("Incrementing seq to %"PRIu64"\n", ctx->sender_context.seq + 1);

  ctx->sender_context.seq++;
  return ctx->sender_context.seq < OSCORE_SEQ_MAX;
}

void
oscore_init(void)
{
  oscore_ctx_store_init();

  /* Initialize the security_context storage and the protected resource storage. */
  oscore_exchange_store_init();

#ifdef OSCORE_EP_CTX_ASSOCIATION
  /* Initialize the security_context storage, the token - seq association storrage and the URI - security_context association storage. */
  oscore_ep_ctx_store_init();
#endif
}
