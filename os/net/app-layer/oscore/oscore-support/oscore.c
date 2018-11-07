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




#include "oscore.h"
#include "cbor.h"
#include "coap.h"
#include "stdio.h"
#include "inttypes.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "coap"
#define LOG_LEVEL  LOG_LEVEL_COAP

void
printf_hex(unsigned char *data, unsigned int len)
{
  unsigned int i = 0;
  for(i = 0; i < len; i++) {
    LOG_DBG_("%02x ", data[i]);
  }
  LOG_DBG_("\n");
}
uint8_t
coap_is_request(coap_message_t *coap_pkt)
{
  if(coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE) {
    return 1;
  } else {
    return 0;
  }
}
uint8_t
oscore_protected_request(void *request)
{
  if(request != NULL) {
    coap_message_t *coap_pkt = (coap_message_t *)request;
    if(coap_is_option(coap_pkt, COAP_OPTION_OSCORE)) {
      return 1;
    }
  }
  return 0;
}
void
oscore_protect_resource(coap_resource_t *resource)
{
  resource->oscore_protected = 1;
}
uint8_t
u64tob(uint64_t in, uint8_t *buffer)
{
   
  memcpy(buffer, &in, 8);
  
  uint8_t i;
  for( i = 7; i >= 0; i--){
    if( buffer[i] == 0 ){
 	break;
    }  
  }

  return 8 - i;
}
uint64_t
btou64(uint8_t *bytes, size_t len)
{
  uint8_t buffer[8];
  memset(buffer, 0, 8); /* function variables are not initializated to anything */
  int offset = 8 - len;
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
int
oscore_encode_option_value(uint8_t *option_buffer, cose_encrypt0_t *cose)
{
  uint8_t offset = 1;
  if(cose->partial_iv_len > 5){
	  return 0;
  }
  option_buffer[0] = 0;
  if(cose->partial_iv_len > 0 && cose->partial_iv != NULL) {
    option_buffer[0] |= (0x05 & cose->partial_iv_len);
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
  return offset;
}
int
oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose)
{
  
  if( option_len > 255 || option_len < 0 || (option_value[0] & 0x06) == 6 || (option_value[0] & 0x07) == 7 || (option_value[0] & 0xE0) != 0) {
    return BAD_OPTION_4_02;
  }

  uint8_t partial_iv_len = (option_value[0] & 0x05);
  uint8_t offset = 1;
  if(partial_iv_len != 0) {    
    if( offset + partial_iv_len > option_len) {
      return BAD_OPTION_4_02;
    }

    cose_encrypt0_set_partial_iv(cose, &(option_value[offset]), partial_iv_len);
    offset += partial_iv_len;
  }
  
  if((option_value[0] & 0x10) != 0) {
    uint8_t kid_context_len = option_value[offset];
    offset++;
    if (offset + kid_context_len > option_len) {
      return BAD_OPTION_4_02;
    }
    cose_encrypt0_set_kid_context(cose, &(option_value[offset]), kid_context_len);
  }

  if((option_value[0] & 0x08) != 0) {
    int kid_len = option_len - offset;
    if (kid_len <= 0) {
      return BAD_OPTION_4_02;
    }
    cose_encrypt0_set_key_id(cose, &(option_value[offset]), kid_len);
  }
  return 0;
}
/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t
oscore_decode_message(coap_message_t *coap_pkt)
{
  cose_encrypt0_t cose;
  oscore_ctx_t *ctx = NULL;
  uint8_t external_aad_buffer[25];
  uint8_t nonce_buffer[13];
  cose_encrypt0_init(&cose);
  /* Options are discarded later when they are overwritten. This should be improved */
  oscore_decode_option_value(coap_pkt->object_security, coap_pkt->object_security_len, &cose);

  if(coap_is_request(coap_pkt)) {
    uint8_t *key_id;
    int key_id_len = cose_encrypt0_get_key_id(&cose, &key_id);
    ctx = oscore_find_ctx_by_rid(key_id, key_id_len);
    if(ctx == NULL) {
      LOG_DBG_("OSCORE Security Context not found.\n");
      coap_error_message = "Security context not found";
      return UNAUTHORIZED_4_01;
    }
    /*4 Verify the ‘Partial IV’ parameter using the Replay Window, as described in Section 7.4. */
    if(!oscore_validate_sender_seq(ctx->recipient_context, &cose)) {
      LOG_DBG_("OSCORE Replayed or old message\n");
      coap_error_message = "Replay detected";
      return UNAUTHORIZED_4_01;
    }
    cose_encrypt0_set_key(&cose, ctx->recipient_context->recipient_key, 16);
  } else { /* Message is a response */
    uint64_t seq;
    uint8_t seq_buffer[8];
    ctx = oscore_get_exchange(coap_pkt->token, coap_pkt->token_len, &seq);
    if(ctx == NULL) {
      LOG_DBG_("OSCORE Security Context not found.\n");
      coap_error_message = "Security context not found";
      return UNAUTHORIZED_4_01;
    }
  
    /* If message contains a partial IV, the received is used. */
    if(cose.partial_iv_len == 0 && cose.partial_iv == NULL){
      uint8_t seq_len = u64tob(seq, seq_buffer);
      cose_encrypt0_set_partial_iv(&cose, seq_buffer, seq_len);
    }
    
    oscore_remove_exchange(coap_pkt->token, coap_pkt->token_len);
    cose_encrypt0_set_key(&cose, ctx->recipient_context->recipient_key, 16);
    cose_encrypt0_set_key_id(&cose, ctx->sender_context->sender_id, ctx->sender_context->sender_id_len);
  }
  coap_pkt->security_context = ctx;

  size_t external_aad_len = oscore_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 0);
  cose_encrypt0_set_external_aad(&cose, external_aad_buffer, external_aad_len);
  cose_encrypt0_set_alg(&cose, ctx->alg);
  
  oscore_generate_nonce(&cose, coap_pkt, nonce_buffer, 13);
  cose_encrypt0_set_nonce(&cose, nonce_buffer, 13);
  
  uint8_t plaintext_buffer[coap_pkt->payload_len - 8];
  cose_encrypt0_set_ciphertext(&cose, coap_pkt->payload, coap_pkt->payload_len);

  int res = cose_encrypt0_decrypt(&cose, plaintext_buffer, coap_pkt->payload_len - 8);
  if(res <= 0) {
    LOG_DBG_("OSCORE Decryption Failure, result code: %d\n", res);
    if(coap_is_request(coap_pkt)) {
      oscore_roll_back_seq(ctx->recipient_context);
      coap_error_message = "Decryption failure";
      return BAD_REQUEST_4_00;
    } else {
      coap_error_message = "Decryption failure";
      return OSCORE_DECRYPTION_FAILED;
    }  
  }

  /*Move the plaintext to the ciphtertext buffer so that it remains when this function returns and plaintext buffer is dealocated.*/
  memcpy(cose.ciphertext, plaintext_buffer, coap_pkt->payload_len - 8);
  cose.plaintext = cose.ciphertext;

  coap_status_t status = oscore_parser(coap_pkt, cose.plaintext, res, ROLE_CONFIDENTIAL);
  return status;
}
/* TODO  make partial IV a field in COSE_encrypt0 */
uint8_t
oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx)
{
  cose_encrypt0_set_alg(cose, ctx->alg);

  uint8_t partial_iv_buffer[8];
  uint8_t partial_iv_len;

  cose_encrypt0_set_key(cose, ctx->sender_context->sender_key, CONTEXT_KEY_LEN);

  if(coap_is_request(pkt)) {
    cose_encrypt0_set_key_id(cose, ctx->sender_context->sender_id, ctx->sender_context->sender_id_len);
    partial_iv_len = u64tob(ctx->sender_context->seq, partial_iv_buffer);
    cose_encrypt0_set_partial_iv(cose, partial_iv_buffer, partial_iv_len);
  } else {
    cose_encrypt0_set_key_id(cose, ctx->recipient_context->recipient_id, ctx->recipient_context->recipient_id_len);
    partial_iv_len = u64tob(ctx->recipient_context->last_seq, partial_iv_buffer);
    cose_encrypt0_set_partial_iv(cose, partial_iv_buffer, partial_iv_len);
  }

  return 0;
}
/* Prepares a new OSCORE message, returns the size of the message. */
size_t
oscore_prepare_message(coap_message_t *coap_pkt, uint8_t *buffer)
{
  cose_encrypt0_t cose;
  cose_encrypt0_init(&cose);
  uint8_t plaintext_buffer[COAP_MAX_HEADER_SIZE];
  uint8_t external_aad_buffer[25];
  uint8_t nonce_buffer[13];
/*  1 Retrieve the Sender Context associated with the target resource. */
  oscore_ctx_t *ctx = coap_pkt->security_context;
  if(ctx == NULL) {
    LOG_DBG_("No context in OSCORE!\n");
    return PACKET_SERIALIZATION_ERROR;
  }
  oscore_populate_cose(coap_pkt, &cose, coap_pkt->security_context);
/*  2 Compose the Additional Authenticated Data and the plaintext, as described in Section 5.4 and Section 5.3. */
  uint8_t plaintext_len = oscore_serializer(coap_pkt, plaintext_buffer, ROLE_CONFIDENTIAL);
  uint8_t external_aad_len = oscore_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 1);

  cose_encrypt0_set_plaintext(&cose, plaintext_buffer, plaintext_len);
  cose_encrypt0_set_external_aad(&cose, external_aad_buffer, external_aad_len);
/*  3 Compute the AEAD nonce from the Sender ID, Common IV, and Partial IV (Sender Sequence Number in network byte order) as described in Section 5.2 and (in one atomic operation, see Section 7.2) increment the Sender Sequence Number by one. */
  oscore_generate_nonce(&cose, coap_pkt, nonce_buffer, 13);
  cose_encrypt0_set_nonce(&cose, nonce_buffer, 13);
  if(coap_is_request(coap_pkt)){
    if(!oscore_set_exchange(coap_pkt->token, coap_pkt->token_len, ctx->sender_context->seq, ctx)){
	LOG_DBG_("OSCORE Could not store exchange.\n");
    }
    oscore_increment_sender_seq(ctx);
  }
/*  4 Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in Section 6. */
  uint8_t ciphertext_buffer[plaintext_len + 8];
  uint8_t ciphertext_len = cose_encrypt0_encrypt(&cose, ciphertext_buffer, plaintext_len + 8);
/*  5 Format the OSCORE message according to Section 4. The Object-Security option is added (see Section 4.2.2). */
  uint8_t option_value_buffer[15];
  uint8_t option_value_len = oscore_encode_option_value(option_value_buffer, &cose);
  coap_set_payload(coap_pkt, ciphertext_buffer, ciphertext_len);
  //printf_hex(option_value_buffer, option_value_len);
  coap_set_header_object_security(coap_pkt, option_value_buffer, option_value_len);

  if(coap_is_request(coap_pkt)) {
    coap_pkt->code = COAP_POST;
  } else {
    coap_pkt->code = CHANGED_2_04;
  }
  oscore_clear_options(coap_pkt);
  uint8_t serialized_len = oscore_serializer(coap_pkt, buffer, ROLE_COAP);
/*  6 Store the association Token - Security Context. The client SHALL be able to find the Recipient Context from the Token in the response. */

  return serialized_len;
}
/* Creates and sets External AAD */
size_t
oscore_prepare_external_aad(coap_message_t *coap_pkt, cose_encrypt0_t *cose, uint8_t *buffer, uint8_t sending)
{

  uint8_t ret = 0;
//  uint8_t seq_buffer[8];
  ret += cbor_put_array(&buffer, 5);
  ret += cbor_put_unsigned(&buffer, 1); /* Version, always for this version of the draft 1 */
  ret += cbor_put_array(&buffer, 1); /* Algoritms array */
  ret += cbor_put_unsigned(&buffer, (coap_pkt->security_context->alg)); /* Algorithm */

/*  if(sending == 1) {
    if(coap_is_request(coap_pkt)) { 
      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id, coap_pkt->security_context->sender_context->sender_id_len);
    } else { 
  //    ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id, coap_pkt->security_context->recipient_context->recipient_id_len);
    }
      ret += cbor_put_bytes(&buffer, cose->partial_iv, cose->partial_iv_len);
  
  } else {

    if(coap_is_request(coap_pkt)) { 

      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id, coap_pkt->security_context->recipient_context->recipient_id_len);
      uint8_t seq_len = u64tob(coap_pkt->security_context->recipient_context->last_seq, seq_buffer);
      ret += cbor_put_bytes(&buffer, seq_buffer, seq_len);
    } else { 
      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id, coap_pkt->security_context->sender_context->sender_id_len);
      ret += cbor_put_bytes(&buffer, cose->partial_iv, cose->partial_iv_len);
    }
  } */
  ret += cbor_put_bytes(&buffer, cose->key_id, cose->key_id_len);
  ret += cbor_put_bytes(&buffer, cose->partial_iv, cose->partial_iv_len);  

  ret += cbor_put_bytes(&buffer, NULL, 0); /* Put integrety protected option, at present there are none. */
  
  return ret;
}
/* Creates Nonce */
void
oscore_generate_nonce(cose_encrypt0_t *ptr, coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size)
{
  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(size - 5);
  memcpy(&(buffer[((size - 6) - ptr->key_id_len)]), ptr->key_id, ptr->key_id_len);
  memcpy(&(buffer[size - ptr->partial_iv_len]), ptr->partial_iv, ptr->partial_iv_len);
  int i;
  for(i = 0; i < size; i++) {
    buffer[i] ^= (uint8_t)coap_pkt->security_context->common_iv[i];
  }
}
/*Remove all protected options */
void
oscore_clear_options(coap_message_t *coap_pkt)
{
  coap_pkt->options[COAP_OPTION_IF_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_MATCH % COAP_OPTION_MAP_SIZE));
  /* URI-Host should be unprotected */
  coap_pkt->options[COAP_OPTION_ETAG / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ETAG % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_IF_NONE_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_NONE_MATCH % COAP_OPTION_MAP_SIZE));
  /* Observe should be duplicated */
  coap_pkt->options[COAP_OPTION_LOCATION_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_PATH % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_URI_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_PATH % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_CONTENT_FORMAT / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_CONTENT_FORMAT % COAP_OPTION_MAP_SIZE));
  /* Max-Age shall me duplicated */
  coap_pkt->options[COAP_OPTION_URI_QUERY / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_QUERY % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_ACCEPT / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ACCEPT % COAP_OPTION_MAP_SIZE));
  coap_pkt->options[COAP_OPTION_LOCATION_QUERY / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_QUERY % COAP_OPTION_MAP_SIZE));
  /* Block2 should be duplicated */
  /* Block1 should be duplicated */
  /* Size2 should be duplicated */
  /* Proxy-URI should be unprotected */
  /* Proxy-Scheme should be unprotected */
  /* Size1 should be duplicated */
}
/*Return 1 if OK, Error code otherwise */
uint8_t
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose)
{
  uint64_t incomming_seq = btou64(cose->partial_iv, cose->partial_iv_len);
 
  /* Special case since we do not use unisgned int for seq */
  if(ctx->initial_state == 1) {
      ctx->initial_state = 0;
      int shift = incomming_seq - ctx->last_seq;
      ctx->sliding_window = ctx->sliding_window << shift;
      ctx->last_seq = incomming_seq;
      return 1;
  }

  if(incomming_seq >= OSCORE_SEQ_MAX) {
    LOG_WARN("OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
    return 0;
  }

  ctx->rollback_last_seq = ctx->last_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  if(incomming_seq > ctx->last_seq) {
    /* Update the replay window */
    int shift = incomming_seq - ctx->last_seq;
    ctx->sliding_window = ctx->sliding_window << shift;
    ctx->last_seq = incomming_seq;
  } else if(incomming_seq == ctx->last_seq) {
      LOG_WARN("OSCORE Replay protextion, replayed SEQ.\n");
      return 0;
  } else { /* seq < recipient_seq */
    if(incomming_seq + ctx->replay_window_size < ctx->last_seq) {
      LOG_WARN("OSCORE Replay protection, SEQ outside of replay window.\n");
      return 0;
    }
    /* seq+replay_window_size > recipient_seq */
    int shift = ctx->last_seq - incomming_seq;
    uint32_t pattern = 1 << shift;
    uint32_t verifier = ctx->sliding_window & pattern;
    verifier = verifier >> shift;
    if(verifier == 1) {
      LOG_WARN("OSCORE Replay protection, replayed SEQ.\n");
      return 0;
    }
    ctx->sliding_window = ctx->sliding_window | pattern;
  }

  return 1;
}
/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t
oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
  ctx->sender_context->seq++;

  if(ctx->sender_context->seq >= OSCORE_SEQ_MAX) {
    return 0;
  } else {
    return 1;
  }
}
/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void
oscore_roll_back_seq(oscore_recipient_ctx_t *ctx)
{
	
  if(ctx->rollback_sliding_window != 0) {
    ctx->sliding_window = ctx->rollback_sliding_window;
    ctx->rollback_sliding_window = 0;
  }
  if(ctx->rollback_last_seq != 0) {
    ctx->last_seq = ctx->rollback_last_seq;
    ctx->rollback_last_seq = 0;
  }
}
/* Initialize the security_context storage and the protected resource storage. */
void
oscore_init_server()
{
  oscore_ctx_store_init();
  oscore_exchange_store_init();
}
/* Initialize the security_context storage, the token - seq association storrage and the URI - security_context association storage. */
void
oscore_init_client()
{
  oscore_ctx_store_init();
  oscore_ep_ctx_store_init();
}
