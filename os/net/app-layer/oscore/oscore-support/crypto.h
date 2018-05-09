#ifndef _CRYPTO_H
#define _CRYPTO_H
#include <inttypes.h>

/* Returns 0 if failure to encrypt. Ciphertext length, otherwise. Tag-length and ciphertext length is derived from algorithm. No check is done to ensure that ciphertext buffer is of the correct length. */

int encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len, uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint8_t plaintext_len, uint8_t *ciphertext_buffer);

/* Return 0 if if decryption failure. Plaintext length otherwise. Tag-length and plaintext length is derived from algorithm. No check is done to ensure that plaintext buffer is of the correct length. */

int decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len, uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint8_t ciphertext_len, uint8_t *plaintext_buffer);

/* int hkdf(uint8_t whichSha, const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,  uint8_t ikm_len, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t   okm_len); */
int hkdf(uint8_t whichSha, uint8_t *salt, uint8_t salt_len, uint8_t *ikm, uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len);

/* TEMP */
void hmac_sha256(uint8_t *key, uint8_t key_len, uint8_t *data, uint8_t data_len, uint8_t *hmac);
#endif /* _CRYPTO_H */
