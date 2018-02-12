#include "cose.h"
#include "cbor.h"
#include "crypto.h"


/* Return length */
int cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer){
	int ret = 0;
	ret += cbor_put_array(&buffer, 3)
	ret += cbor_put_bytes(&buffer, 0, NULL);
	//ret += cose encode attributyes
	ret += cbor_put_bytes(&buffer, ptr->ciphertext, ptr->ciphertext_len);
	return ret;
}
	
/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size);

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);	

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg){
	ptr->alg = alg;
}
	
void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size){
	ptr->plaintext = buffer;
	ptr->plaintext_len = size;
}
	
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);
	
void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size){
	ptr->partial_iv = buffer;
	ptr->partial_iv_len = size;
}
	
/* Return length */
int cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer);
	
void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size){
	ptr->key_id = buffer;
	ptr->key_id_len = size;
}
	
/* Return length */	
int cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size){
	ptr->external_aad = buffer;
	ptr->external_aad_len = size;
}
	
/* Returns 1 if successfull, 0 if key is of incorrect length. */
int cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, uint8_t key_size);
	
void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, uint8_t size){
	ptr->nonce = buffer;
	ptr->nonce_len = size;
}

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *key, uint8_t key_len);
int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *key, uint8_t key_len);
