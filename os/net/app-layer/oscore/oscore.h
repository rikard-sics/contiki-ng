#ifndef _OSCORE_H
#define _OSCORE_H

#include "coap.h"
#include "cose.h"
#include "oscore-context.h"

/* Decodes a OSCORE message and passes it on to the COAP engine. */
coap_status_t oscore_decode_message(coap_message_t* coap_pkt);

/* Prepares a new OSCORE message, returns the size of the message. */
size_t oscore_prepare_message(void* packet, uint8_t *buffer);

/*Sets Alg, Partial IV Key ID and Key in COSE. Returns status*/
uint8_t oscore_populate_cose(coap_message_t *pkt, cose_encrypt0_t *cose, oscore_ctx_t *ctx);
	
/* Creates and sets External AAD */
void oscore_prepare_external_aad(cose_encrypt0_t *ptr, oscore_ctx_t *ctx);

/* Creates and sets Nonce */ 
////void oscore_generate_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size);
void oscore_generate_nonce(cose_encrypt0_t *ptr, coap_message_t *coap_pkt, uint8_t *buffer, uint8_t size);

/*Remove all protected options */
void oscore_clear_options(coap_message_t *ptr);
	

/*Return 1 if OK, Error code otherwise */
uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t* ctx, cose_encrypt0_t *cose);
	
/* Return 0 if SEQ MAX, return 1 if OK */	
uint8_t oscore_increment_sender_seq(oscore_ctx_t* ctx);
	
/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void oscore_roll_back_seq(oscore_recipient_ctx_t* ctx);

/*Compress and extract COSE messages as per the OSCORE standard. */
uint8_t oscore_cose_compress(cose_encrypt0_t* cose, uint8_t* buffer);
uint8_t oscore_cose_decompress(cose_encrypt0_t* cose, uint8_t* buffer, size_t buffer_len);

/* Start protected resource storage. */
void oscore_protected_resource_store_init();
	
/* Mark a resource as protected by OSCORE, incoming COAP requests to that resource will be rejected. */
uint8_t oscore_protect_resource(char uri);
	
/*Retuns 1 if the resource is protected by OSCORE, 0 otherwise. */
uint8_t oscore_is_resource_protected(char uri);

/* Initialize the context storage and the protected resource storage. */
void oscore_init_server();

/* Initialize the context storage, the token - seq association storrage and the URI - context association storage. */
void oscore_init_client();

#endif /* _OSCORE_H */	
