#include "oscore.h"
#include "cbor.h"

uint8_t coap_is_request(coap_message_t* coap_pkt){
	if(coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_DELETE){ 
		return 1;
	} else {
		return 0;
	}
}

/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t oscore_decode_message(coap_message_t* coap_pkt);

/* Prepares a new OSCORE message, returns the size of the message. */
size_t oscore_prepare_message(void* packet, uint8_t *buffer);

/*Sets Alg, Partial IV Key ID and Key in COSE. Returns status*/
uint8_t oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx);
	
/* Creates and sets External AAD */
void oscore_prepare_external_aad(cose_encrypt0_t *ptr, oscore_ctx_t *ctx);
size_t oscoap_prepare_external_aad(coap_message_t* coap_pkt, cose_encrypt0_t* cose, uint8_t* buffer, uint8_t sending){

  uint8_t ret = 0;
  uint8_t seq_buffer[8];
  uint8_t protected_buffer[25];
  size_t  protected_len;
  ret += cbor_put_array(&buffer, 6);
  ret += cbor_put_unsigned(&buffer, 1); //version is always 1
  ret += cbor_put_unsigned(&buffer, (coap_pkt->code));
 // int32_t obs;

  if(!coap_is_request(coap_pkt) && coap_is_option(coap_pkt, COAP_OPTION_OBSERVE)){

    if( sending == 1){
   //   coap_set_header_observe(coap_pkt, observe_seq);
    } else {
 //     int s = coap_get_header_observe(coap_pkt, &obs);
    }
    protected_len = oscoap_serializer(coap_pkt, protected_buffer, ROLE_PROTECTED);
//  PRINTF("protected, len %d\n", protected_len);
    //  PRINTF_HEX(protected_buffer, protected_len);
 
  } else {
    protected_len = 0;
  }
  ret += cbor_put_bytes(&buffer, protected_len, protected_buffer); 
  ret += cbor_put_unsigned(&buffer, (coap_pkt->security_context->alg));


  if(sending == 1){
    if(coap_is_request(coap_pkt)) {
  
      uint8_t seq_len = to_bytes(coap_pkt->security_context->sender_context->seq, seq_buffer);

      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id_len, coap_pkt->security_context->sender_context->sender_id);
      ret += cbor_put_bytes(&buffer, seq_len, seq_buffer);
    } else {
        uint8_t seq_len = to_bytes(coap_pkt->security_context->recipient_context->last_seq, seq_buffer);
      ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id_len, coap_pkt->security_context->recipient_context->recipient_id);
      ret += cbor_put_bytes(&buffer, seq_len, seq_buffer);
    } 
  } else {
    
    if(coap_is_request(coap_pkt)){
        uint8_t seq_len = to_bytes(coap_pkt->security_context->recipient_context->last_seq, seq_buffer);

        ret += cbor_put_bytes(&buffer, coap_pkt->security_context->recipient_context->recipient_id_len, coap_pkt->security_context->recipient_context->recipient_id);
        ret += cbor_put_bytes(&buffer, seq_len, seq_buffer);
    } else {
        if( coap_is_option(coap_pkt, COAP_OPTION_OBSERVE) ){
   //       uint8_t seq_len = to_bytes(observing_seq, seq_buffer);
          
   //       ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id_len, coap_pkt->security_context->sender_context->sender_id);
   //       ret += cbor_put_bytes(&buffer, seq_len, seq_buffer);
        } else {
     //     uint8_t seq_len = to_bytes(coap_pkt->security_context->sender_context->seq, seq_buffer);
          
          ret += cbor_put_bytes(&buffer, coap_pkt->security_context->sender_context->sender_id_len, coap_pkt->security_context->sender_context->sender_id);
          ret += cbor_put_bytes(&buffer, cose->partial_iv_len, cose->partial_iv);
        }
   

  }
    
  return ret;
  
}

/* Creates and sets Nonce */ 
void oscore_generate_nonce(cose_encrypt0_t *ptr, coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size){
	//TODO add length check so theat the buffer is long enough
	
	memset(buffer, 0, size);
	buffer[0] = (uint8_t)(ptr->key_id_len);
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

  uint32_t incomming_seq = bytes_to_uint32(cose->partial_iv, cose->partial_iv_len);
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
uint8_t oscore_cose_compress(cose_encrypt0_t* cose, uint8_t* buffer);
uint8_t oscore_cose_decompress(cose_encrypt0_t* cose, uint8_t* buffer, size_t buffer_len);

/* Start protected resource storage. */
void oscore_protected_resource_store_init();
	
/* Mark a resource as protected by OSCORE, incoming COAP requests to that resource will be rejected. */
uint8_t oscore_protect_resource(char uri);
	
/*Retuns 1 if the resource is protected by OSCORE, 0 otherwise. */
uint8_t oscore_is_resource_protected(char uri);

/* Initialize the security_context storage and the protected resource storage. */
void oscore_init_server(){
	oscore_ctx_store_init();
	oscore_token_seq_store_init();
	oscore_protected_resource_store_init();
}

/* Initialize the security_context storage, the token - seq association storrage and the URI - security_context association storage. */
void oscore_init_client(){
	oscore_ctx_store_init();
	oscore_uri_rid_store_init();
}	

