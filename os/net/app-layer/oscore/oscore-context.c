#include "oscore-context.h"
#include <stddef.h>
#include "lib/memb.h"
#include "cbor.h"
#include <string.h>
#include "crypto.h"

oscore_ctx_t *common_context_store = NULL;
token_seq_t *token_seq_store = NULL;
uri_ctx_t *uri_ctx_store = NULL;

MEMB(common_context_memb, oscore_ctx_t, CONTEXT_NUM);
MEMB(sender_context_memb, oscore_sender_ctx_t, CONTEXT_NUM);
MEMB(recipient_context_memb, oscore_recipient_ctx_t, CONTEXT_NUM);

MEMB(token_seq_memb, token_seq_t, TOKEN_SEQ_NUM);
MEMB(uri_ctx_memb, uri_ctx_t, 2);

void oscore_ctx_store_init(){

  memb_init(&common_context_memb);
  memb_init(&sender_context_memb);
  memb_init(&recipient_context_memb);
}
	
static uint8_t compose_info(uint8_t* buffer, uint8_t alg, uint8_t* id, uint8_t id_len, uint8_t out_len){
    uint8_t ret = 0;
    ret += cbor_put_array(&buffer, 4);
    ret += cbor_put_bytes(&buffer, id, id_len);
    ret += cbor_put_unsigned(&buffer, alg);
    char* text;
    uint8_t text_len;
    if( out_len == 16 ){
        text = "Key";
        text_len = 3;
    } else {
        text = "IV";
        text_len = 2;
    }

    ret += cbor_put_text(&buffer, text, text_len);
    ret += cbor_put_unsigned(&buffer, out_len);
    return ret;
}

uint8_t bytes_equal(uint8_t* a_ptr, uint8_t a_len, uint8_t* b_ptr, uint8_t b_len){
	if(a_len != b_len){
		return 0;
	}
	
	if( memcmp(a_ptr, b_ptr, a_len) == 0){
		return 1;
	} else {
		return 0;
	}
}


oscore_ctx_t* oscore_derrive_ctx(uint8_t* master_secret, uint8_t master_secret_len, uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
       	uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window){

    oscore_ctx_t* common_ctx = memb_alloc(&common_context_memb);
    if(common_ctx == NULL) return 0;

    oscore_recipient_ctx_t* recipient_ctx = memb_alloc(&recipient_context_memb);
    if(recipient_ctx == NULL) return 0;

    oscore_sender_ctx_t* sender_ctx = memb_alloc(&sender_context_memb);
    if(sender_ctx == NULL) return 0;

    uint8_t zeroes[32];
    uint8_t info_buffer[15]; 

    uint8_t* salt;
    uint8_t  salt_len;

    if(master_secret_len == 0 || master_salt == NULL){
      memset(zeroes, 0x00, 32);
      salt = zeroes;
      salt_len = 32;
    } else {
      salt = master_salt;
      salt_len = master_salt_len;
    }
  
    uint8_t info_len;

    //sender_ key
    info_len = compose_info(info_buffer, alg, sid, sid_len, CONTEXT_KEY_LEN);
    hkdf(1, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->sender_key, CONTEXT_KEY_LEN );


    //Receiver key
    info_len = compose_info(info_buffer, alg, rid, rid_len, CONTEXT_KEY_LEN);
    hkdf(1, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->recipient_key, CONTEXT_KEY_LEN );

    //common IV
    info_len = compose_info(info_buffer, alg, NULL, 0, CONTEXT_INIT_VECT_LEN);
    hkdf(1, salt, salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->common_iv, CONTEXT_INIT_VECT_LEN );

    common_ctx->master_secret = master_secret;
    common_ctx->master_secret_len = master_secret_len;
    common_ctx->master_salt = master_salt;
    common_ctx->master_salt_len = master_salt_len;
    common_ctx->alg = alg;

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
   

    common_ctx->next_context = common_context_store;
    common_context_store = common_ctx;
    return common_ctx;

}
	
int oscore_free_ctx(oscore_ctx_t *ctx){

    if(common_context_store == ctx){
      common_context_store = ctx->next_context;

    }else{

      oscore_ctx_t *ctx_ptr = common_context_store;

      while(ctx_ptr->next_context != ctx){
        ctx_ptr = ctx_ptr->next_context;
      }

      if(ctx_ptr->next_context->next_context != NULL){
        ctx_ptr->next_context = ctx_ptr->next_context->next_context;
      }else{
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
	
oscore_ctx_t* oscore_find_ctx_by_rid(uint8_t* rid, uint8_t rid_len){
    if(common_context_store == NULL){
      return NULL;
    }


    oscore_ctx_t *ctx_ptr = common_context_store;
	
    while(!bytes_equal(ctx_ptr->recipient_context->recipient_id, ctx_ptr->recipient_context->recipient_id_len, rid, rid_len)){
       ctx_ptr = ctx_ptr->next_context;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

oscore_ctx_t* oscore_find_ctx_by_token(uint8_t* token, uint8_t token_len){
    if(common_context_store == NULL){
      return NULL;
    }

    oscore_ctx_t *ctx_ptr = common_context_store;
  
    while(!bytes_equal(ctx_ptr->sender_context->token, ctx_ptr->sender_context->token_len,  token, token_len)){
      ctx_ptr = ctx_ptr->next_context;
      
      if(ctx_ptr == NULL){
        return NULL;
      }
    }
    return ctx_ptr;
}

/* Token <=> SEQ association */
void oscore_token_seq_store_init(){
  memb_init(&token_seq_memb);
}

uint8_t get_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t* seq){
   token_seq_t* ptr = token_seq_store;

  while(!bytes_equal(ptr->token, ptr->token_len,  token, token_len)){
    
    ptr = ptr->next;
    if(ptr == NULL){
      return 0; 
    }

  }

  *seq = ptr->seq;

  return 1; 

}

uint8_t set_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t seq){
  token_seq_t* token_seq_memb_ptr = memb_alloc(&token_seq_memb);
  if(token_seq_memb_ptr == NULL){
    return 0;
  }

  memcpy(token_seq_memb_ptr->token, token, token_len);
  token_seq_memb_ptr->token_len = token_len;
  token_seq_memb_ptr->seq = seq;
  token_seq_memb_ptr->next = token_seq_store;
  token_seq_store = token_seq_memb_ptr;
  return 1;
}


void remove_seq_from_token(uint8_t* token, uint8_t token_len){
  token_seq_t* ptr = token_seq_store;


  if(bytes_equal(ptr->token, ptr->token_len, token, token_len)){ // first element
    token_seq_store = ptr->next;
    memb_free(&token_seq_memb, ptr);
    return;
  }

  ptr = ptr->next;
  
  while(1){
    if(ptr == NULL){
      return;
    }
    
    if(bytes_equal(ptr->next->token, ptr->token_len, token, token_len)){
      token_seq_t* tmp = ptr->next;
      ptr->next = ptr->next->next;
      memb_free(&token_seq_memb, tmp);
      return;
    }

    ptr = ptr->next;
    
  }


}

/* URI <=> RID association */
void oscore_uri_ctx_store_init(){
  memb_init(&uri_ctx_memb);
}
uint8_t oscore_uri_ctx_set_association(char* uri, oscore_ctx_t *ctx){
  uri_ctx_t* uri_ctx_ptr = memb_alloc(&uri_ctx_memb);
  if(uri_ctx_ptr == NULL){
    return 0;
  }
  uri_ctx_ptr->uri = uri;
  uri_ctx_ptr->ctx = ctx;
  return 1;

}
oscore_ctx_t* oscore_get_context_from_uri(char* uri){
  uri_ctx_t* ptr = uri_ctx_store;

  while(strcmp(uri,ptr->uri) != 0){
    
    ptr = ptr->next;
    if(ptr == NULL){
      return NULL; 
    }

  }

  return ptr->ctx;
}
	
