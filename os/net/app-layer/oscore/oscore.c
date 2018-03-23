#include "oscore.h"
#include "cbor.h"
#include "coap.h"
#include "stdio.h"
#include "inttypes.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "coap"
#define LOG_LEVEL  LOG_LEVEL_COAP

void printf_hex(unsigned char *data, unsigned int len){
  unsigned int i=0;
  for(i=0; i<len; i++)
  {
    LOG_DBG_("%02x ",data[i]);
  }
  LOG_DBG_("\n");
}



uint8_t coap_is_request(coap_message_t* coap_pkt){
	if(coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE){ 
		return 1;
	} else {
		return 0;
	}
}


void parse_int(uint64_t in, uint8_t* bytes, int out_len){ 
  int x = out_len - 1;
  while(x >= 0){
    bytes[x] = (in >> (x * 8)) & 0xFF;
    x--;
  }
}

uint8_t u32tob(uint32_t in, uint8_t* buffer){
//  PRINTF("in %" PRIu64 "\n", in);
  if(in == 0){
    return 0;
  }

  uint8_t outlen = 1;

  if(in > 255 && in <= 65535){
    outlen = 2;
  } else if( in > 65535 && in <= 16777215){
    outlen = 3;
  } else if( in > 16777215 ){
    outlen = 4;
  }

  parse_int(in, buffer, outlen);
  return outlen;
}

uint32_t btou32(uint8_t* bytes, size_t len){
  uint8_t buffer[4];
  memset(buffer, 0, 4); //function variables are not initializated to anything
  int offset = 4 - len;
  uint32_t num;
  
  memcpy((uint8_t*)(buffer + offset), bytes, len);

  num = 
      (uint32_t)buffer[0] << 24 |
      (uint32_t)buffer[1] << 16 |
      (uint32_t)buffer[2] << 8  |
      (uint32_t)buffer[3];

  return num;
}



int oscore_encode_option_value(uint8_t *option_buffer, cose_encrypt0_t *cose){
  int offset = 1;
	option_buffer[0] = 0;
  if(cose->partial_iv_len > 0 && cose->partial_iv != NULL){
		option_buffer[0] |= (0x07 & cose->partial_iv_len);
		memcpy(&(option_buffer[offset]), cose->partial_iv, cose->partial_iv_len);
		offset += cose->partial_iv_len;
	}
	if(cose->key_id_len > 0 && cose->key_id != NULL){
		option_buffer[0] |= 0x08;
		memcpy(&(option_buffer[offset]), cose->key_id, cose->key_id_len);
		offset += cose->key_id_len;
	}
	return offset;
}


int oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose){
	uint8_t partial_iv_len = (option_value[0] & 0x07);
	uint8_t offset = 1;
	if(partial_iv_len != 0){
		cose_encrypt0_set_partial_iv(cose, &(option_value[offset]), partial_iv_len);
		offset += partial_iv_len;
	}
	if((option_value[0] & 0x08) != 0){
		uint8_t kid_len = option_len - offset;
		cose_encrypt0_set_key_id(cose, &(option_value[offset]), kid_len);
	}
	return 0;
}


/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t oscore_decode_message(coap_message_t* coap_pkt){
	cose_encrypt0_t cose;
	oscore_ctx_t *ctx = NULL;
  uint8_t external_aad_buffer[25];
  uint8_t nonce_buffer[13];
  cose_encrypt0_init(&cose);

  // 1 Process Outer Block options according to [RFC7959], until all blocks of the request have been received (see Section 4.1.3.2).
  
  /* 2 Discard the message Code and all non-special Inner option message fields (marked with ‘x’ in column E of Figure 5) 
  present in the received message. For example, an If-Match Outer option is discarded, but an Uri-Host Outer option is not discarded. */
  /* 3 Decompress the COSE Object (Section 6) and retrieve the Recipient Context associated with the Recipient ID in the ‘kid’ parameter. 
  If either the decompression or the COSE message fails to decode, or the server fails to retrieve a Recipient Context with Recipient ID corresponding to the ‘kid’ parameter received, 
  then the server SHALL stop processing the request. If: either the decompression or the COSE message fails to decode, the server MAY respond with a 4.02 Bad Option error message.
  The server MAY set an Outer Max-Age option with value zero. The diagnostic payload SHOULD contain the string “Failed to decode COSE”.
  the server fails to retrieve a Recipient Context with Recipient ID corresponding to the ‘kid’ parameter received, the server MAY respond with a 4.01 Unauthorized error message. The server MAY set an Outer Max-Age option with value zero. The diagnostic payload SHOULD contain the string “Security context not found”.
  */
  //Options are discarded later when they are overwritten. This should be improved
  printf_hex(coap_pkt->object_security, coap_pkt->object_security_len);
  oscore_decode_option_value(coap_pkt->object_security, coap_pkt->object_security_len, &cose);

  if(coap_is_request(coap_pkt)){
    uint8_t *key_id;
    int key_id_len = cose_encrypt0_get_key_id(&cose, &key_id);
    ctx = oscore_find_ctx_by_rid(key_id, key_id_len);
    if(ctx == NULL){
      printf("errors HERE!\n");
    } else {
      printf("context FOUND!\n");
    }
    // 4 Verify the ‘Partial IV’ parameter using the Replay Window, as described in Section 7.4. 
    oscore_validate_sender_seq(ctx->recipient_context, &cose);  
    cose_encrypt0_set_key(&cose, ctx->recipient_context->recipient_key, 16);
  } else {
    ctx = oscore_find_ctx_by_token(coap_pkt->token, coap_pkt->token_len);
    if(ctx == NULL){
      printf("errors HERE!\n");
    } 
    cose_encrypt0_set_key(&cose, ctx->recipient_context->recipient_key, 16);
    //TODO find and fix all COSE parameters for responses
  }
  coap_pkt->security_context = ctx;

  // 5 Compose the Additional Authenticated Data, as described in Section 5.4.
  size_t external_aad_len =  oscore_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 0);
  cose_encrypt0_set_external_aad(&cose, external_aad_buffer, external_aad_len);
  cose_encrypt0_set_alg(&cose, ctx->alg);
  //6 Compute the AEAD nonce from the Recipient ID, Common IV, and the ‘Partial IV’ parameter, received in the COSE Object.
  oscore_generate_nonce(&cose, coap_pkt, nonce_buffer, 13);
  cose_encrypt0_set_nonce(&cose, nonce_buffer, 13);
   /*7 Decrypt the COSE object using the Recipient Key, as per [RFC8152] Section 5.3. (The decrypt operation includes the verification of the integrity.)
        If decryption fails, the server MUST stop processing the request and MAY respond with a 4.00 Bad Request error message. The server MAY set an Outer Max-Age option with value zero. The diagnostic payload SHOULD contain the “Decryption failed” string.
        If decryption succeeds, update the Replay Window, as described in Section 7. */
 // cose_encrypt0_set_ciphertext(&cose, coap_pkt->payload, coap_pkt->payload_len);
  uint8_t plaintext_buffer[coap_pkt->payload_len - 8];
  cose_encrypt0_set_ciphertext(&cose, coap_pkt->payload, coap_pkt->payload_len);

  int res = cose_encrypt0_decrypt(&cose, plaintext_buffer, coap_pkt->payload_len - 8);
  if(res <= 0){
    LOG_DBG_("DECRYPTION FAIURE!! res: %d\n", res);
    oscore_roll_back_seq(ctx->recipient_context);
    //TODO bail out with errors
  }

   /*8 For each decrypted option, check if the option is also present as an Outer option:
    if it is, discard the Outer. For example: the message contains a Max-Age Inner and a Max-Age Outer option.
    The Outer Max-Age is discarded. */
 
   /*9 Add decrypted code, options and payload to the decrypted request. 
   The Object-Security option is removed.*/
  //FISHY
  memcpy(cose.ciphertext, plaintext_buffer, coap_pkt->payload_len - 8);
  cose.plaintext = cose.ciphertext;

  coap_status_t status = oscore_parser(coap_pkt,  cose.plaintext, res, ROLE_CONFIDENTIAL);
  printf("status %d\n", (uint8_t)status);
   /*9 Add decrypted code, options and payload to the decrypted request. 
   The Object-Security option is removed.*/
   
   //10 The decrypted CoAP request is processed according to [RFC7252]

	return status;	
}

uint8_t oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx){
  cose_encrypt0_set_alg(cose, ctx->alg);
  uint8_t partial_iv_buffer[5];
  uint8_t partial_iv_len; 

  cose_encrypt0_set_key(cose, ctx->sender_context->sender_key, CONTEXT_KEY_LEN);
 
  if( coap_is_request(pkt) ) {
    cose_encrypt0_set_key_id(cose, ctx->sender_context->sender_id, ctx->sender_context->sender_id_len);
    partial_iv_len = u32tob(ctx->sender_context->seq, partial_iv_buffer);
    cose_encrypt0_set_partial_iv(cose, partial_iv_buffer, partial_iv_len);
  } else {  
    cose_encrypt0_set_key_id(cose, ctx->recipient_context->recipient_id, ctx->recipient_context->recipient_id_len);
    partial_iv_len = u32tob(ctx->recipient_context->last_seq, partial_iv_buffer);
    cose_encrypt0_set_partial_iv(cose, partial_iv_buffer, partial_iv_len);
  }

  return 0;
}

/* Prepares a new OSCORE message, returns the size of the message. */
size_t oscore_prepare_message(coap_message_t* coap_pkt, uint8_t *buffer){
  cose_encrypt0_t cose;
  cose_encrypt0_init(&cose);
  uint8_t plaintext_buffer[COAP_MAX_HEADER_SIZE];
  uint8_t external_aad_buffer[25];
  uint8_t nonce_buffer[13];
//  1 Retrieve the Sender Context associated with the target resource.
  oscore_ctx_t *ctx = coap_pkt->security_context;
  if(ctx == NULL){
    LOG_DBG_("No context in OSCORE!\n");
    return 0;
  }
  oscore_populate_cose(coap_pkt, &cose, coap_pkt->security_context);
//  2 Compose the Additional Authenticated Data and the plaintext, as described in Section 5.4 and Section 5.3.
  uint8_t plaintext_len = oscore_serializer(coap_pkt, plaintext_buffer, ROLE_CONFIDENTIAL);
  uint8_t external_aad_len = oscore_prepare_external_aad(coap_pkt, &cose, external_aad_buffer, 1);

  cose_encrypt0_set_plaintext(&cose, plaintext_buffer, plaintext_len);
  cose_encrypt0_set_external_aad(&cose, external_aad_buffer, external_aad_len);
//  3 Compute the AEAD nonce from the Sender ID, Common IV, and Partial IV (Sender Sequence Number in network byte order) as described in Section 5.2 and (in one atomic operation, see Section 7.2) increment the Sender Sequence Number by one.
  oscore_generate_nonce(&cose, coap_pkt, nonce_buffer, 13);
  cose_encrypt0_set_nonce(&cose, nonce_buffer, 13);
  oscore_increment_sender_seq(ctx);
//  4 Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in Section 6.
  uint8_t ciphertext_buffer[plaintext_len + 8];

  uint8_t ciphertext_len = cose_encrypt0_encrypt(&cose, ciphertext_buffer, plaintext_len + 8);
//  5 Format the OSCORE message according to Section 4. The Object-Security option is added (see Section 4.2.2).
  uint8_t option_value_buffer[15];
  uint8_t option_value_len = oscore_encode_option_value(option_value_buffer, &cose);
  coap_set_payload(coap_pkt, ciphertext_buffer, ciphertext_len);
  coap_set_header_object_security(coap_pkt, option_value_buffer, option_value_len);
  
  if(coap_is_request(coap_pkt)){
    coap_pkt->code = COAP_POST;
  } else {
    coap_pkt->code = CHANGED_2_04;
  }
  oscore_clear_options(coap_pkt);
  uint8_t serialized_len = oscore_serializer(coap_pkt, buffer, ROLE_COAP);
//  6 Store the association Token - Security Context. The client SHALL be able to find the Recipient Context from the Token in the response.

  if(coap_is_request(coap_pkt)){
    set_seq_from_token(coap_pkt->token, coap_pkt->token_len, ctx->sender_context->seq);
  }

  return serialized_len;
}

/*Sets Alg, Partial IV Key ID and Key in COSE. Returns status*/
//uint8_t oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx);
	
/* Creates and sets External AAD */
//void oscore_prepare_external_aad(cose_encrypt0_t *ptr, oscore_ctx_t *ctx);
size_t oscore_prepare_external_aad(coap_message_t* coap_pkt, cose_encrypt0_t* cose, uint8_t* buffer, uint8_t sending){

  uint8_t ret = 0;
  uint8_t seq_buffer[8];
  uint8_t protected_buffer[25];
  size_t  protected_len;
  ret += cbor_put_array(&buffer, 5);
  ret += cbor_put_unsigned(&buffer, 1); //Version, always for this version of the draft 1
  ret += cbor_put_unsigned(&buffer, (coap_pkt->security_context->alg)); // Algorithm

 // int32_t obs;
  // partial IV len 13 max, KID för 16 16 64 ger 7 bytes

  if(!coap_is_request(coap_pkt) && coap_is_option(coap_pkt, COAP_OPTION_OBSERVE)){
/*
    if( sending == 1){
      coap_set_header_observe(coap_pkt, observe_seq);
    } else {
      int s = coap_get_header_observe(coap_pkt, &obs);
    }
*/
    protected_len = 0; //oscore_serializer(coap_pkt, protected_buffer, ROLE_PROTECTED);
//  PRINTF("protected, len %d\n", protected_len);
    //  PRINTF_HEX(protected_buffer, protected_len);
  } else {
    protected_len = 0;
  }
  ret += cbor_put_bytes(&buffer, protected_buffer, protected_len); 



  if(sending == 1){
    if(coap_is_request(coap_pkt)) {
  
      uint8_t seq_len = 0; //to_bytes(coap_pkt->security_context->sender_context->seq, seq_buffer);

      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id, coap_pkt->security_context->sender_context->sender_id_len);
      ret += cbor_put_bytes(&buffer, seq_buffer, seq_len);
    } else {
      uint8_t seq_len = 0; //to_bytes(coap_pkt->security_context->recipient_context->last_seq, seq_buffer);
      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id, coap_pkt->security_context->recipient_context->recipient_id_len);
      ret += cbor_put_bytes(&buffer, seq_buffer, seq_len);
    } 
  } else {
    
    if(coap_is_request(coap_pkt)){
        uint8_t seq_len = 0; //to_bytes(coap_pkt->security_context->recipient_context->last_seq, seq_buffer);

        ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id, coap_pkt->security_context->recipient_context->recipient_id_len);
        ret += cbor_put_bytes(&buffer, seq_buffer, seq_len);
    } else {
        if( coap_is_option(coap_pkt, COAP_OPTION_OBSERVE) ){
   //       uint8_t seq_len = to_bytes(observing_seq, seq_buffer);
          
   //       ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id_len, coap_pkt->security_context->sender_context->sender_id);
   //       ret += cbor_put_bytes(&buffer, seq_len, seq_buffer);
        } else {
     //     uint8_t seq_len = to_bytes(coap_pkt->security_context->sender_context->seq, seq_buffer);
          
          ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id, coap_pkt->security_context->sender_context->sender_id_len);
          ret += cbor_put_bytes(&buffer, cose->partial_iv, cose->partial_iv_len);
        }
   
    }
  }
  return ret;
  
}

/* Creates Nonce */ 
void oscore_generate_nonce(cose_encrypt0_t *ptr, coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size){
	//TODO add length check so theat the buffer is long enough
	
	memset(buffer, 0, size);
	buffer[0] = (uint8_t)(ptr->key_id_len);
  printf("create nonce key_id_len %d\n", ptr->key_id_len);
  printf_hex(ptr->key_id, ptr->key_id_len);
	memcpy(&(buffer[((size - 6)- ptr->key_id_len)]), ptr->key_id, ptr->key_id_len);
	memcpy(&(buffer[size - ptr->partial_iv_len]), ptr->partial_iv, ptr->partial_iv_len);
	int i;
        for(i = 0; i < size; i++){
		buffer[i] ^= (uint8_t)coap_pkt->security_context->common_iv[i];
	}
}

/*Remove all protected options */
void oscore_clear_options(coap_message_t *coap_pkt){
    coap_pkt->options[COAP_OPTION_IF_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_MATCH % COAP_OPTION_MAP_SIZE));
    /* URI-Host should be unprotected */
    coap_pkt->options[COAP_OPTION_ETAG / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_ETAG % COAP_OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_IF_NONE_MATCH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_IF_NONE_MATCH % COAP_OPTION_MAP_SIZE));
    /* Observe should be duplicated */
    coap_pkt->options[COAP_OPTION_LOCATION_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_LOCATION_PATH % COAP_OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_URI_PATH / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_URI_PATH % COAP_OPTION_MAP_SIZE));
    coap_pkt->options[COAP_OPTION_CONTENT_FORMAT / COAP_OPTION_MAP_SIZE] &= ~(1 << (COAP_OPTION_CONTENT_FORMAT % COAP_OPTION_MAP_SIZE));
    /* Max-Age shall me duplicated */
    coap_pkt->options[COAP_OPTION_URI_QUERY / COAP_OPTION_MAP_SIZE] &=  ~(1 << (COAP_OPTION_URI_QUERY % COAP_OPTION_MAP_SIZE));
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
uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t* ctx, cose_encrypt0_t *cose){

  uint32_t incomming_seq = 0; //bytes_to_uint32(cose->partial_iv, cose->partial_iv_len);
  //  PRINTF("SEQ: incomming %" PRIu32 "\n", incomming_seq);
  //  PRINTF("SEQ: last %" PRIu32 "\n", ctx->last_seq);
  //  PRINTF_HEX(cose->partial_iv, cose->partial_iv_len);
   if (ctx->last_seq >= OSCORE_SEQ_MAX) {
            //  PRINTF("SEQ ERROR: wrapped\n");
          //  return OSCOAP_SEQ_WRAPPED;
   	return 0;
   }
  
  ctx->rollback_last_seq = ctx->last_seq; //recipient_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  if (incomming_seq > ctx->highest_seq) {
     //Update the replay window
     int shift = incomming_seq - ctx->last_seq;
     ctx->sliding_window = ctx->sliding_window << shift;
     ctx->highest_seq = incomming_seq;
            
            
  } else if (incomming_seq == ctx->highest_seq) {
     // Special case since we do not use unisgned int for seq
     if(ctx->initial_state == 1 ){ 
        ctx->initial_state = 0;
        int shift = incomming_seq - ctx->highest_seq;
        ctx->sliding_window = ctx->sliding_window << shift;
        ctx->highest_seq = incomming_seq;
        
     } else {
        //  PRINTF("SEQ ERROR: replay\n");
       // return OSCOAP_SEQ_REPLAY;
     	return 0;
     }
  } else { //seq < this.recipient_seq
     if (incomming_seq + ctx->replay_window_size < ctx->highest_seq) {
        //  PRINTF("SEQ ERROR: old\n");
     //   return OSCOAP_SEQ_OLD_MESSAGE;
     	return 0;
     }
     // seq+replay_window_size > recipient_seq
     int shift = ctx->highest_seq - incomming_seq;
     uint32_t pattern = 1 << shift;
     uint32_t verifier = ctx->sliding_window & pattern;
     verifier = verifier >> shift;
     if (verifier == 1) {
        //  PRINTF("SEQ ERROR: replay\n");
       // return OSCOAP_SEQ_REPLAY;
     	return 0;
     }
     ctx->sliding_window = ctx->sliding_window | pattern;
  }

  ctx->last_seq = incomming_seq;
  return 1;

}

/* Return 0 if SEQ MAX, return 1 if OK */	
uint8_t oscore_increment_sender_seq(oscore_ctx_t* ctx){
    ctx->sender_context->seq++; 
    
    if(ctx->sender_context->seq >= OSCORE_SEQ_MAX ){
      return 0;
    } else {
      return 1;
    }

}
	
/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void oscore_roll_back_seq(oscore_recipient_ctx_t* ctx) {
  if (ctx->rollback_sliding_window != 0) {
      ctx->sliding_window =  ctx->rollback_sliding_window; 
      ctx->rollback_sliding_window = 0;
  }
  if (ctx->rollback_last_seq != 0) {
      ctx->last_seq = ctx->rollback_last_seq;
      ctx->rollback_last_seq = 0;
  }

}

/*Compress and extract COSE messages as per the OSCORE standard. */
//uint8_t oscore_cose_compress(cose_encrypt0_t* cose, uint8_t* buffer);
//uint8_t oscore_cose_decompress(cose_encrypt0_t* cose, uint8_t* buffer, size_t buffer_len);

/* Start protected resource storage. */
//void oscore_protected_resource_store_init();
	
/* Mark a resource as protected by OSCORE, incoming COAP requests to that resource will be rejected. */
//uint8_t oscore_protect_resource(char uri);
	
/*Retuns 1 if the resource is protected by OSCORE, 0 otherwise. */
//uint8_t oscore_is_resource_protected(char uri);

/* Initialize the security_context storage and the protected resource storage. */
void oscore_init_server(){
	oscore_ctx_store_init();
	oscore_token_seq_store_init();
	//oscore_protected_resource_store_init();
}

/* Initialize the security_context storage, the token - seq association storrage and the URI - security_context association storage. */
void oscore_init_client(){
	oscore_ctx_store_init();
	oscore_uri_ctx_store_init();
}	

