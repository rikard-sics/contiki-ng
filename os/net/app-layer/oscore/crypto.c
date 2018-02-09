#include "crypto.h"
#include "ccm-star.h"
#include <string.h>

int encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len, 
		uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint8_t plaintext_len, uint8_t *ciphertext_buffer){
	
	if(alg != 10 || key_len != 16 || nonce_len != 13){ //TODO change to COSE-alg-AES-CCM-16-64-128 
		return 0; 
	}	
	uint8_t tag_len = 8;  
	uint8_t encryption_buffer[plaintext_len + tag_len];

	memcpy(encryption_buffer, plaintext_buffer, plaintext_len);
	
	CCM_STAR.set_key(key);
	CCM_STAR.aead(nonce, encryption_buffer, plaintext_len, aad, aad_len, &(encryption_buffer[plaintext_len]), tag_len, 1);

	memcpy(ciphertext_buffer, encryption_buffer, plaintext_len + tag_len);	
	return plaintext_len + tag_len;
}
	
/* Return 0 if if decryption failure. Plaintext length otherwise. Tag-length and plaintext length is derived from algorithm. No check is done to ensure that plaintext buffer is of the correct length. */ 

int decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
	 uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint8_t ciphertext_len, uint8_t *plaintext_buffer){
	
	if(alg != 10 || key_len != 16 || nonce_len != 13){ //TODO change to COSE-alg-AES-CCM-16-64-128 
		return 0; 
	}	
	
	uint8_t tag_len = 8;
	int plaintext_len = ciphertext_len - tag_len;
	uint8_t decryption_buffer[plaintext_len];
	uint8_t tag_buffer[tag_len];
	
	memcpy(decryption_buffer, ciphertext_buffer, plaintext_len);
	
	CCM_STAR.set_key(key);
 	CCM_STAR.aead(nonce, decryption_buffer, plaintext_len, aad, aad_len, tag_buffer, tag_len, 0);
	
	if(memcmp(tag_buffer, &(ciphertext_buffer[plaintext_len]), tag_len) != 0){
		return 0; //Decryption failure
	}
	
	memcpy(plaintext_buffer, decryption_buffer, plaintext_len);
 	return plaintext_len;
}
