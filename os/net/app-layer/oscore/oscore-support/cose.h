#ifndef _COSE_H
#define _COSE_H
#include <inttypes.h>

#define COSE_Algorithm_AES_CCM_64_64_128 12
#define COSE_Algorithm_AES_CCM_16_64_128 10

/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {

  uint8_t alg;

  uint8_t *key;
  int key_len;

  uint8_t *partial_iv;
  int partial_iv_len;

  uint8_t *key_id;
  int key_id_len;

  uint8_t *kid_context;
  int kid_context_len;

  uint8_t *nonce;
  int nonce_len;

  uint8_t *aad;
  int aad_len;

  uint8_t *external_aad;
  int external_aad_len;

  uint8_t *plaintext;
  int plaintext_len;

  uint8_t *ciphertext;
  int ciphertext_len;
} cose_encrypt0_t;

/* Return length */
int cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer);

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);
void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, int key_size);

void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, int ciphertext_len);
int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, int plaintext_len);

#endif /* _COSE_H */
