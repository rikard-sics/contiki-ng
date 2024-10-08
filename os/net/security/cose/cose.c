/*
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
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
 *         COSE, an implementation of COSE_Encrypt0 structure from: CBOR Object Signing and Encryption (COSE) (IETF RFC8152)
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Rikard Höglund, Marco Tiloca
 */

#include "cose.h"
#include "contiki-lib.h"
#include <os/lib/ccm-star.h>
#include <string.h>
#include "cose-log.h"

MEMB(encrypt0_storage, cose_encrypt0, 1);
MEMB(sign1_storage, cose_sign1, 1);

static inline cose_encrypt0 *
encrypt0_storage_new()
{
  return (cose_encrypt0 *)memb_alloc(&encrypt0_storage);
}
static inline void
encrypt0_free(cose_encrypt0 *enc)
{
  memb_free(&encrypt0_storage, enc);
}
void
encrypt0_storage_init(void)
{
  memb_init(&encrypt0_storage);
}
cose_encrypt0 *
cose_encrypt0_new()
{
  cose_encrypt0 *enc;
  enc = encrypt0_storage_new();
  return enc;
}
void
cose_encrypt0_finalize(cose_encrypt0 *enc)
{
  encrypt0_free(enc);
}

static inline cose_sign1 *
sign1_storage_new()
{
  return (cose_sign1 *)memb_alloc(&sign1_storage);
}
static inline void
sign1_free(cose_sign1 *sign)
{
  memb_free(&sign1_storage, sign);
}
void
sign1_storage_init(void)
{
  memb_init(&sign1_storage);
}
cose_sign1 *
cose_sign1_new()
{
  cose_sign1 *sign;
  sign = sign1_storage_new();
  return sign;
}
void
cose_sign1_finalize(cose_sign1 *sign)
{
  sign1_free(sign);
}

void
cose_print_key(cose_key *cose)
{
  LOG_DBG("kid: ");
  cose_print_buff_8_dbg(cose->kid.buf, cose->kid.len);
  LOG_DBG("identity: ");
  cose_print_char_8_dbg((uint8_t *)cose->identity.buf, cose->identity.len);
  LOG_DBG("kty: %d\n", cose->kty);
  LOG_DBG("crv: %d\n", cose->crv);
  LOG_DBG("x: ");
  cose_print_buff_8_dbg(cose->x.buf, cose->x.len);
  LOG_DBG("y: ");
  cose_print_buff_8_dbg(cose->y.buf, cose->y.len);
}
uint8_t
cose_encrypt0_set_key(cose_encrypt0 *enc, uint8_t alg, uint8_t *key, uint8_t key_sz, uint8_t *nonce, uint16_t nonce_sz)
{
  if(key_sz != KEY_LEN) {
    return 0;
  }
  if(nonce_sz != IV_LEN) {
    return 0;
  }
  enc->key_sz = key_sz;
  enc->nonce_sz = nonce_sz;
  memcpy(enc->key, key, key_sz);
  memcpy(enc->nonce, nonce, nonce_sz);
  return 1;
}
uint8_t
cose_sign1_set_key(cose_sign1 *sign1, uint8_t alg, uint8_t *key, uint8_t key_sz)
{
  if(key_sz > ECC_KEY_BYTE_LENGTH * 2) {
    return 0;
  }

  sign1->key_sz = key_sz;
  memcpy(sign1->key, key, key_sz);
  return 1;
}
uint8_t
cose_encrypt0_set_content(cose_encrypt0 *enc, uint8_t *plain, uint16_t plain_sz, uint8_t *add, uint8_t add_sz)
{
  if(plain_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(enc->plaintext, plain, plain_sz);
  memcpy(enc->external_aad, add, add_sz);
  enc->plaintext_sz = plain_sz;
  enc->external_aad_sz = add_sz;
  return 1;
}
uint8_t
cose_encrypt0_set_ciphertext(cose_encrypt0 *enc, uint8_t *ciphertext, uint16_t ciphertext_sz)
{
  if(ciphertext_sz > MAX_CIPHER) {
    return 0;
  }
  memcpy(enc->ciphertext, ciphertext, ciphertext_sz);
  enc->ciphertext_sz = ciphertext_sz;
  return 1;
}
uint8_t
cose_sign1_set_payload(cose_sign1 *sign1, uint8_t *payload, uint16_t payload_sz)
{
  if(payload_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(sign1->payload, payload, payload_sz);
  sign1->payload_sz = payload_sz;
  return 1;
}
uint8_t
cose_sign1_set_signature(cose_sign1 *sign1, uint8_t *signature, uint16_t signature_sz)
{
  if(signature_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(sign1->signature, signature, signature_sz);
  sign1->signature_sz = signature_sz;
  return 1;
}
void
cose_encrypt0_set_header(cose_encrypt0 *enc, uint8_t *prot, uint16_t prot_sz, uint8_t *unp, uint16_t unp_sz)
{
  memcpy(enc->protected_header, prot, prot_sz);
  memcpy(enc->unprotected_header, unp, unp_sz);
  enc->protected_header_sz = prot_sz;
  enc->unprotected_header_sz = unp_sz;
}
//TODO: Merge with above?
void
cose_sign1_set_header(cose_sign1 *sign1, uint8_t *prot, uint16_t prot_sz, uint8_t *unp, uint16_t unp_sz)
{
  memcpy(sign1->protected_header, prot, prot_sz);
  //memcpy(sign1->unprotected_header, unp, unp_sz);
  sign1->protected_header_sz = prot_sz;
  //sign1->unprotected_header_sz = unp_sz;
}
static char enc_rec[] = ENC0;
static uint8_t
encode_enc_structure(cose_encrypt0 *enc, uint8_t *cbor)
{
  uint8_t size = 0;

  size += cbor_put_array(&cbor, 3);
  size += cbor_put_text(&cbor, enc_rec, strlen(enc_rec));
  size += cbor_put_bytes(&cbor, enc->protected_header, enc->protected_header_sz);
  size += cbor_put_bytes(&cbor, enc->external_aad, enc->external_aad_sz);

  return size;
}
static char sig_rec[] = SIGN1;
static uint8_t
encode_sig_structure(cose_sign1 *sign1, uint8_t *cbor)
{
  uint8_t size = 0;

  size += cbor_put_array(&cbor, 4);
  size += cbor_put_text(&cbor, sig_rec, strlen(sig_rec));
  size += cbor_put_bytes(&cbor, sign1->protected_header, sign1->protected_header_sz);
  size += cbor_put_bytes(&cbor, sign1->external_aad, sign1->external_aad_sz);
  size += cbor_put_bytes(&cbor, sign1->payload, sign1->payload_sz);

  return size;
}
uint8_t
cose_decrypt(cose_encrypt0 *enc)
{
  uint8_t enc_struct_bytes[COSE_MAX_BUFFER];
  uint8_t str_sz = encode_enc_structure(enc, enc_struct_bytes);

  LOG_DBG("CBOR-encoded AAD for COSE_Encrypt0 decryption (%d bytes): ", str_sz);
  cose_print_buff_8_dbg(enc_struct_bytes, str_sz);

  uint8_t tag[TAG_LEN];

  CCM_STAR.set_key(enc->key);
  enc->plaintext_sz = enc->ciphertext_sz - TAG_LEN;

  CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, enc_struct_bytes, str_sz, tag, TAG_LEN, 0);
  memcpy(enc->plaintext, enc->ciphertext, enc->plaintext_sz);

  if (memcmp(tag, &(enc->ciphertext[enc->plaintext_sz]), TAG_LEN) != 0) {
    LOG_ERR("Decrypt msg error\n");
    return 0;  /* Decryption failure */
  }
  
  return 1;
}
uint8_t
cose_encrypt(cose_encrypt0 *enc)
{
  uint8_t enc_struct_bytes[COSE_MAX_BUFFER];
  uint8_t str_sz = encode_enc_structure(enc, enc_struct_bytes);

  LOG_DBG("CBOR-encoded AAD for COSE_Encrypt0 encryption (%d bytes): ", str_sz);
  cose_print_buff_8_dbg(enc_struct_bytes, str_sz);

  /* TODO: check the algorithm selected in enc */
  if (enc->key_sz != KEY_LEN || enc->nonce_sz != IV_LEN || enc->plaintext_sz > COSE_MAX_BUFFER || str_sz > (2 * COSE_MAX_BUFFER)) {
    LOG_ERR("The COSE parameters are not corresponding with the selected algorithm or buffer sizes\n");
    return 0;
  }

  // Set the key and copy plaintext to ciphertext buffer
  CCM_STAR.set_key(enc->key);
  memcpy(enc->ciphertext, enc->plaintext, enc->plaintext_sz);

  // Perform encryption
  CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, enc_struct_bytes, str_sz, &enc->ciphertext[enc->plaintext_sz], TAG_LEN, 1);
  enc->ciphertext_sz = enc->plaintext_sz + TAG_LEN;

  return enc->ciphertext_sz;
}
uint8_t
cose_sign(cose_sign1 *sign1)
{
  uint8_t sig_struct_bytes[2 * COSE_MAX_BUFFER];
  uint8_t sig_str_sz = encode_sig_structure(sign1, sig_struct_bytes);
  LOG_DBG("CBOR-encoded sig_structure for COSE_Sign1 signing (%d bytes): ", sig_str_sz);
  cose_print_buff_8_dbg(sig_struct_bytes, sig_str_sz);

  LOG_DBG("Using own private key for COSE_Sign1 signing: ");
  cose_print_buff_8_dbg(sign1->key, ECC_KEY_BYTE_LENGTH);

  uint8_t hash[HASH_LENGTH];
  sha256(sig_struct_bytes, sig_str_sz, hash);
  
  if (uECC_sign(sign1->key, hash, sizeof(hash), sign1->signature, uECC_secp256r1())) {
    sign1->signature_sz = P256_SIGNATURE_LEN;
    // LOG_DBG("Signature for COSE_Sign1 (%d bytes): ", sign1->signature_sz);
    // cose_print_buff_8_dbg(sign1->signature, sign1->signature_sz);
  } else {
    LOG_ERR("Error signing for COSE_Sign1");
    return 0;
  }
  return sign1->signature_sz;
}
uint8_t
cose_verify(cose_sign1 *sign1)
{
  // The other peer's public key must be in key (x concatenated with y making 64 bytes)
  uint8_t *public_key = sign1->key;

  LOG_DBG("Using peer's public key for COSE_Sign1 signature verification: ");
  cose_print_buff_8_dbg(public_key, ECC_KEY_BYTE_LENGTH * 2);

  // Recreate the sig_structure
  uint8_t sig_struct_bytes[2 * COSE_MAX_BUFFER];
  uint8_t sig_str_sz = encode_sig_structure(sign1, sig_struct_bytes);
  LOG_DBG("CBOR-encoded sig_structure for COSE_Sign1 verification (%d bytes): ", sig_str_sz);
  cose_print_buff_8_dbg(sig_struct_bytes, sig_str_sz);

  uint8_t hash[HASH_LENGTH];
  sha256(sig_struct_bytes, sig_str_sz, hash);

  // Verify the signature using the peer's public key
  int verify = uECC_verify(public_key, hash, sizeof(hash), sign1->signature, uECC_secp256r1());

  if (verify == 1) {
    LOG_DBG("Signature verification succeeded for COSE_Sign1\n");
    return 1;
  } else {
    LOG_ERR("Signature verification failed for COSE_Sign1\n");
    return 0;
  }
}

