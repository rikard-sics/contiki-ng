#include "cose.h"
#include "cbor.h"
#include "crypto.h"
#include "string.h"

/* Return length */
int
cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer)
{
  int ret = 0;
  ret += cbor_put_array(&buffer, 3);
  ret += cbor_put_bytes(&buffer, NULL, 0);
  /* ret += cose encode attributyes */
  ret += cbor_put_bytes(&buffer, ptr->ciphertext, ptr->ciphertext_len);
  return ret;
}
/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr)
{
  memset(ptr, 0, sizeof(cose_encrypt0_t));
}
void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
  ptr->alg = alg;
}
void
cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->ciphertext = buffer;
  ptr->ciphertext_len = size;
}
void
cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->plaintext = buffer;
  ptr->plaintext_len = size;
}
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->partial_iv = buffer;
  ptr->partial_iv_len = size;
}
/* Return length */
int
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->partial_iv;
  return ptr->partial_iv_len;
}
void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->key_id = buffer;
  ptr->key_id_len = size;
}
/* Return length */
int
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->key_id;
  return ptr->key_id_len;
}
void
cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->external_aad = buffer;
  ptr->external_aad_len = size;
}
/* Returns 1 if successfull, 0 if key is of incorrect length. */
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, int key_size)
{
  if(key_size != 16) {
    return 0;
  }

  ptr->key = key;
  ptr->key_len = key_size;

  return 1;
}
void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->nonce = buffer;
  ptr->nonce_len = size;
}
int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, int ciphertext_len)
{
  if(ptr->key == NULL || ptr->key_len != 16) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != 13) {
    return -2;
  }
  if(ptr->external_aad == NULL || ptr->external_aad_len == 0) {
    return -3;
  }
  if(ptr->plaintext == NULL || ptr->plaintext_len < (ciphertext_len - 8)) {
    return -4;
  }

  return encrypt(ptr->alg, ptr->key, ptr->key_len, ptr->nonce, ptr->nonce_len, ptr->external_aad, ptr->external_aad_len, ptr->plaintext, ptr->plaintext_len, ciphertext_buffer);
}
int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, int plaintext_len)
{
  if(ptr->key == NULL || ptr->key_len != 16) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != 13) {
    return -2;
  }
  if(ptr->external_aad == NULL || ptr->external_aad_len == 0) {
    return -3;
  }
  if(ptr->ciphertext == NULL || ptr->ciphertext_len < (plaintext_len + 8)) {
    return -4;
  }

  return decrypt(ptr->alg, ptr->key, ptr->key_len, ptr->nonce, ptr->nonce_len, ptr->external_aad, ptr->external_aad_len, ptr->ciphertext, ptr->ciphertext_len, plaintext_buffer);
}