/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB (RISE), Stockholm, Sweden
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
 *         EDHOC, an implementation of Ephemeral Diffie-Hellman Over COSE (EDHOC) (IETF RFC9528)
 * \author
 *         Lidia Pocero <pocero@isi.gr>
 *         Peter A Jonsson
 *         Rikard Höglund
 *         Marco Tiloca
 */
 
#include "edhoc.h"
#include "contiki-lib.h"
#include "edhoc-config.h"
#include "sys/rtimer.h"
#include "edhoc-msgs.h"
#include <assert.h>

#define MAC_2 2
#define MAC_3 3

edhoc_context_t *edhoc_ctx;

/* static rtimer_clock_t time; */

MEMB(edhoc_context_storage, edhoc_context_t, 1);

static inline edhoc_context_t *
context_new()
{
  return (edhoc_context_t *)memb_alloc(&edhoc_context_storage);
}
static inline void
context_free(edhoc_context_t *ctx)
{
  memb_free(&edhoc_context_storage, ctx);
}
void
edhoc_storage_init(void)
{
  memb_init(&edhoc_context_storage);
  hmac_storage_init();
}
void
edhoc_init(edhoc_context_t *ctx)
{
  ctx->session.cid = EDHOC_CID;
  
  /* Reverse order for the suite values */
  ctx->session.suite_num = 0;
  if (SUPPORTED_SUITE_4 > -1) {
      ctx->session.suite[ctx->session.suite_num] = SUPPORTED_SUITE_4;
      ctx->session.suite_num++;
  }
  if (SUPPORTED_SUITE_3 > -1) {
      ctx->session.suite[ctx->session.suite_num] = SUPPORTED_SUITE_3;
      ctx->session.suite_num++;
  }
  if (SUPPORTED_SUITE_2 > -1) {
      ctx->session.suite[ctx->session.suite_num] = SUPPORTED_SUITE_2;
      ctx->session.suite_num++;
  }
  if (SUPPORTED_SUITE_1 > -1) {
      ctx->session.suite[ctx->session.suite_num] = SUPPORTED_SUITE_1;
      ctx->session.suite_selected = SUPPORTED_SUITE_1;
      ctx->session.suite_num++;
  }

  if (ctx->session.suite_num == 0) {
    LOG_ERR("No supported cipher suites set (%d)\n", ERR_SUITE_NON_SUPPORT);
  }
  
  ctx->session.role = ROLE;  /* initiator I (U) or responder (V) */
  ctx->session.method = METHOD;
}
edhoc_context_t *
edhoc_new()
{
  edhoc_context_t *ctx;
  ctx = context_new();
  if(ctx) {
   edhoc_init(ctx);
  }
  return ctx;
}
void
edhoc_finalize(edhoc_context_t *ctx)
{
  context_free(ctx);
}
static size_t
generate_cred_x(cose_key_t *cose, uint8_t *cred)
{
  cose->kty = KEY_TYPE;
  cose->crv = KEY_CRV;

  size_t size = 0;
  size += cbor_put_map(&cred, 2);
  size += cbor_put_unsigned(&cred, 2);
  size += cbor_put_text(&cred, cose->identity, cose->identity_sz);
  size += cbor_put_unsigned(&cred, 8);
  size += cbor_put_map(&cred, 1);
  size += cbor_put_unsigned(&cred, 1);
  if(cose->crv == 1) {
    size += cbor_put_map(&cred, 5);
  } else {
    size += cbor_put_map(&cred, 4);
  }

  size += cbor_put_unsigned(&cred, 1);
  size += cbor_put_unsigned(&cred, cose->kty);
  size += cbor_put_unsigned(&cred, 2);
  size += cbor_put_bytes(&cred, cose->kid, cose->kid_sz);
  size += cbor_put_negative(&cred, 1);
  size += cbor_put_unsigned(&cred, cose->crv);
  size += cbor_put_negative(&cred, 2);
  size += cbor_put_bytes(&cred, cose->x, cose->x_sz);
  if(cose->crv == 1) {
    size += cbor_put_negative(&cred, 3);
    size += cbor_put_bytes(&cred, cose->y, cose->y_sz);
  }
  return size;
}
static size_t
generate_id_cred_x(cose_key_t *cose, uint8_t *cred)
{
  size_t size = 0;
  LOG_DBG("kid (%i bytes): ", cose->kid_sz);
  print_buff_8_dbg(cose->kid, cose->kid_sz);
 
  /* Include KID */
  if(AUTHENT_TYPE == CRED_KID) {
    size += cbor_put_map(&cred, 1);
    size += cbor_put_unsigned(&cred, 4);
    size += cbor_put_bytes(&cred, cose->kid, cose->kid_sz);
  }
  /* Include directly the credential used for authentication ID_CRED_X = CRED_X */
  if(AUTHENT_TYPE == CRED_INCLUDE) {
    size = generate_cred_x(cose, cred);
  }
  return size;
}
static size_t
generate_info(uint8_t info_label, const uint8_t *context, uint8_t context_sz, uint8_t length, uint8_t *info)
{
  size_t size = cbor_put_num(&info, info_label);
  size += cbor_put_bytes(&info, context, context_sz);
  size += cbor_put_unsigned(&info, length);
  return size;
}
static int8_t
set_rx_cid(edhoc_context_t *ctx, uint8_t *cidrx, uint8_t cidrx_sz)
{
  /* set connection id from rx */
  if(cidrx_sz == 1) {
    ctx->session.cid_rx = (uint8_t)edhoc_get_byte_identifier(&cidrx);
  }
  
  if(ctx->session.cid_rx == ctx->session.cid) {
    LOG_ERR("error code2 (%d)\n", ERR_CID_NOT_VALID);
    return ERR_CID_NOT_VALID;
  } else {
    return 0;
  }
}
static int8_t
check_rx_suite_i(edhoc_context_t *ctx, const uint8_t *suite_rx, size_t suite_rx_sz)
{
  /* Get the selected cipher suite (last element) */
  uint8_t peer_selected_suite = suite_rx[suite_rx_sz - 1];

  /* Check if the selected suite is supported */
  for (uint8_t i = 0; i < ctx->session.suite_num; i++) {
      if (ctx->session.suite[i] == peer_selected_suite) {
          ctx->session.suite_selected = peer_selected_suite;
          LOG_DBG("Selected cipher suite: %d\n", ctx->session.suite_selected);
          return 0;
      }
  }

  LOG_WARN("ERR_NEW_SUITE_PROPOSE\n");
  return ERR_NEW_SUITE_PROPOSE;  
}
void
set_rx_gx(edhoc_context_t *ctx, const uint8_t *gx)
{
  memcpy(ctx->session.gx, gx, ECC_KEY_LEN);
}
static int8_t
set_rx_method(edhoc_context_t *ctx, uint8_t method)
{
  if(method != METHOD) {
    LOG_ERR("error code (%d)\n", ERR_REJECT_METHOD);
    return ERR_REJECT_METHOD;
  }
  ctx->session.method = method;
  return 0;
}
static void
set_rx_msg(edhoc_context_t *ctx, const uint8_t *msg, uint8_t msg_sz)
{
  memcpy(ctx->msg_rx, msg, msg_sz);
  ctx->rx_sz = msg_sz;
}
static void
print_session_info(const edhoc_context_t *ctx)
{
  LOG_DBG("Session info print:\n");
  LOG_DBG("Using test vector: %s\n", TEST != 0 ? "true" : "false");
  LOG_DBG("Connection role: %d\n", (int)ctx->session.role);
  LOG_DBG("Connection method: %d\n", (int)ctx->session.method);
  LOG_DBG("Selected cipher suite: %d\n", ctx->session.suite_selected);
  LOG_DBG("My cID: %x\n", (uint8_t)ctx->session.cid);
  LOG_DBG("Other peer cID: %x\n", (uint8_t)ctx->session.cid_rx);
  LOG_DBG("Gx: ");
  print_buff_8_dbg(ctx->session.gx, ECC_KEY_LEN);
}
static int8_t
gen_th2(edhoc_context_t *ctx, const uint8_t *eph_pub, uint8_t *msg, uint16_t msg_sz)
{
  /* Create the input for TH_2 = H(G_Y, H(msg)), msg1 is in msg_rx */
  int h_buf_sz = cbor_bytestr_size(HASH_LEN) + cbor_bytestr_size(ECC_KEY_LEN);
  uint8_t h[h_buf_sz];
  uint8_t *h_ptr = h;
  
  LOG_DBG("Input to calculate H(msg1) (%d bytes): ", (int)msg_sz);
  print_buff_8_dbg(msg, msg_sz);
  
  uint8_t msg_1_hash[HASH_LEN];
  compute_th(msg, msg_sz, msg_1_hash, HASH_LEN);
  
  cbor_put_bytes(&h_ptr, eph_pub, ECC_KEY_LEN);
  cbor_put_bytes(&h_ptr, msg_1_hash, HASH_LEN);
  
  /* Compute TH */
  LOG_DBG("Input to TH_2 (%d): ", h_buf_sz);
  print_buff_8_dbg(h, h_buf_sz);
  uint8_t er = compute_th(h, h_buf_sz, ctx->session.th, HASH_LEN);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED H(G_Y, H(msg1))\n");
    return ERR_CODE;
  }
  
  LOG_DBG("TH_2 (%d bytes): ", (int)HASH_LEN);
  print_buff_8_dbg(ctx->session.th, HASH_LEN);
  return 0;
}
static uint8_t
gen_th3(edhoc_context_t *ctx, const uint8_t *cred, uint16_t cred_sz, const uint8_t *ciphertext, uint16_t ciphertext_sz)
{
  /* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
  int h_buf_sz = cbor_bytestr_size(HASH_LEN) + ciphertext_sz + cred_sz;
  uint8_t h[h_buf_sz];
  uint8_t *ptr = h;
  uint16_t h_sz = cbor_put_bytes(&ptr, ctx->session.th, HASH_LEN);
  LOG_DBG("TH_2 (%d): ", HASH_LEN);
  print_buff_8_dbg(ctx->session.th, HASH_LEN);
  memcpy(h + h_sz, ciphertext, ciphertext_sz);
  h_sz += ciphertext_sz;
  LOG_DBG("PLAINTEXT_2 (%d): ", ciphertext_sz);
  print_buff_8_dbg(ciphertext, ciphertext_sz);
  memcpy(h + h_sz, cred, cred_sz);
  h_sz += cred_sz;
  LOG_DBG("CRED_R (%d): ", cred_sz);
  print_buff_8_dbg(cred, cred_sz);
  LOG_DBG("input to calculate TH_3 (CBOR Sequence) (%d bytes): ", (int)h_sz);
  print_buff_8_dbg(h, h_sz);

  /* Compute TH */
  uint8_t er = compute_th(h, h_sz, ctx->session.th, HASH_LEN);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED TH_3\n");
    return ERR_CODE;
  }
  LOG_DBG("TH_3 (%d bytes): ", (int)HASH_LEN);
  print_buff_8_dbg(ctx->session.th, HASH_LEN);
  return 0;
}
static uint8_t
gen_th4(edhoc_context_t *ctx, const uint8_t *cred, uint16_t cred_sz, const uint8_t *ciphertext, uint16_t ciphertext_sz)
{
  /* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
  int h_buf_sz = cbor_bytestr_size(HASH_LEN) + ciphertext_sz + cred_sz;
  uint8_t h[h_buf_sz];
  uint8_t *ptr = h;
  uint16_t h_sz = cbor_put_bytes(&ptr, ctx->session.th, HASH_LEN);
  LOG_DBG("TH_3 (%d): ", HASH_LEN);
  print_buff_8_dbg(ctx->session.th, HASH_LEN);
  memcpy(h + h_sz, ciphertext, ciphertext_sz);
  h_sz += ciphertext_sz;
  LOG_DBG("PLAINTEXT_3 (%d): ", ciphertext_sz);
  print_buff_8_dbg(ciphertext, ciphertext_sz);
  memcpy(h + h_sz, cred, cred_sz);
  h_sz += cred_sz;
  LOG_DBG("CRED_I (%d): ", cred_sz);
  print_buff_8_dbg(cred, cred_sz);
  LOG_DBG("input to calculate TH_4 (CBOR Sequence) (%d bytes): ", (int)h_sz);
  print_buff_8_dbg(h, h_sz);

  /* Compute TH */
  uint8_t er = compute_th(h, h_sz, ctx->session.th, HASH_LEN);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED TH_4\n");
    return ERR_CODE;
  }
  LOG_DBG("TH_4 (%d bytes): ", (int)HASH_LEN);
  print_buff_8_dbg(ctx->session.th, HASH_LEN);
  return 0;
}
int16_t
edhoc_kdf(const uint8_t *prk, uint8_t info_label, const uint8_t *context, uint8_t context_sz, uint16_t length, uint8_t *result)
{
  size_t info_buf_sz = cbor_int_size(info_label) + cbor_bytestr_size(context_sz) + cbor_int_size(length);
  uint8_t info_buf[info_buf_sz];

  uint16_t info_sz = generate_info(info_label, context, context_sz, length, info_buf);
  if(info_sz == 0) {
    LOG_ERR("Error generating INFO");
    return info_sz;
  }
  
  return edhoc_expand(prk, info_buf, info_sz, length, result);
}
int16_t
edhoc_expand(const uint8_t *prk, const uint8_t *info, uint16_t info_sz, uint16_t length, uint8_t *result)
{
  LOG_DBG("INFO for HKDF_Expand (%d bytes): ", info_sz);
  print_buff_8_dbg(info, info_sz);
  int16_t er = hkdf_expand(prk, ECC_KEY_LEN, info, info_sz, result, length);
  if(er < 0) {
    LOG_ERR("Error calculating when calling hkdf_expand (%d)\n", er);
    return er;
  }
  return length;
}
static uint8_t
calc_mac(const edhoc_context_t *ctx, uint8_t mac_num, uint8_t mac_len, uint8_t *mac)
{

  if(mac_num == MAC_2) {
    
    /* RH: Build context_2 */
    size_t context_2_buf_sz = CID_LEN + ctx->session.id_cred_x_sz + cbor_bytestr_size(HASH_LEN) + ctx->session.cred_x_sz;
    uint8_t context_2[context_2_buf_sz];
    uint8_t *context_2_ptr = context_2;
    /* RH: Add C_R */
    if(ROLE == INITIATOR) {
      context_2_ptr[0] = (uint8_t) ctx->session.cid_rx;
    } else {
      context_2_ptr[0] = (uint8_t) ctx->session.cid;
    }
    context_2_ptr += CID_LEN;
    memcpy(context_2_ptr, ctx->session.id_cred_x, ctx->session.id_cred_x_sz);
    context_2_ptr += ctx->session.id_cred_x_sz;
    cbor_put_bytes(&context_2_ptr, ctx->session.th, HASH_LEN);
    memcpy(context_2_ptr, ctx->session.cred_x, ctx->session.cred_x_sz);
    context_2_ptr += ctx->session.cred_x_sz;
    LOG_DBG("CONTEXT_2 (%zu bytes): ", context_2_buf_sz);
    print_buff_8_dbg(context_2, context_2_buf_sz);
    
    /* RH: Use edhoc_kdf to generate MAC_2 */
    int16_t er = edhoc_kdf(ctx->session.prk_3e2m, MAC_2_LABEL, context_2, context_2_buf_sz, mac_len, mac);
    if (er < 0) {
      LOG_ERR("Failed to expand MAC_2\n");
      return 0;
    }

  } else if(mac_num == MAC_3) {
  
    /* RH: Build context_3 */
    size_t context_3_buf_sz = ctx->session.id_cred_x_sz + cbor_bytestr_size(HASH_LEN) + ctx->session.cred_x_sz;
    uint8_t context_3[context_3_buf_sz];
    uint8_t *context_3_ptr = context_3;
    memcpy(context_3_ptr, ctx->session.id_cred_x, ctx->session.id_cred_x_sz);
    context_3_ptr += ctx->session.id_cred_x_sz;
    cbor_put_bytes(&context_3_ptr, ctx->session.th, HASH_LEN);
    memcpy(context_3_ptr, ctx->session.cred_x, ctx->session.cred_x_sz);
    context_3_ptr += ctx->session.cred_x_sz;
    LOG_DBG("CONTEXT_3 (%zu bytes): ", context_3_buf_sz);
    print_buff_8_dbg(context_3, context_3_buf_sz);

    /* RH: Use edhoc_kdf to generate MAC_3 */
    int16_t er = edhoc_kdf(ctx->session.prk_4e3m, MAC_3_LABEL, context_3, context_3_buf_sz, mac_len, mac);
    if (er < 0) {
      LOG_ERR("Failed to expand MAC_3\n");
      return 0;
    }
  } else {
    LOG_ERR("Wrong MAC value\n");
    return 0;
  }

  return 1;
}
static uint8_t //RH: Added
get_edhoc_mac_len(uint8_t ciphersuite_id)
{
  switch (ciphersuite_id) {
    case EDHOC_CIPHERSUITE_1:
    case EDHOC_CIPHERSUITE_3:
    case EDHOC_CIPHERSUITE_4:
    case EDHOC_CIPHERSUITE_5:
    case EDHOC_CIPHERSUITE_6:
    case EDHOC_CIPHERSUITE_24:
    case EDHOC_CIPHERSUITE_25:
      return SUITE_1_3_4_5_6_24_25_MAC_LEN; // 16
    case EDHOC_CIPHERSUITE_0:
    case EDHOC_CIPHERSUITE_2:
      return SUITE_0_2_MAC_LEN; // 8
    default:
      LOG_ERR("Invalid EDHOC cipher suite specified when retrieving EDHOC MAC length (%d)\n", ERR_SUITE_NON_SUPPORT);        
      return -1;
  }
}
static uint8_t //RH: Added
get_edhoc_cose_enc_alg(uint8_t ciphersuite_id)
{
  switch (ciphersuite_id) {
    case EDHOC_CIPHERSUITE_1:
    case EDHOC_CIPHERSUITE_3:
      return COSE_ALG_AES_CCM_16_128_128;
    case EDHOC_CIPHERSUITE_0:
    case EDHOC_CIPHERSUITE_2:
      return COSE_ALG_AES_CCM_16_64_128;
    default:
      LOG_ERR("Invalid EDHOC cipher suite specified when retrieving COSE encryption algorithm (%d)\n", ERR_SUITE_NON_SUPPORT);        
      return -1;
  }
}
static uint8_t
gen_mac(const edhoc_context_t *ctx, uint8_t mac_len, uint8_t *mac)
{
  uint8_t mac_num;
  if(ROLE == INITIATOR) {
    mac_num = MAC_3;
  } else if(ROLE == RESPONDER) {
    mac_num = MAC_2;
  }

  if(!calc_mac(ctx, mac_num, mac_len, mac)) {
    LOG_ERR("Set MAC error\n");
    return 0;
  }

  return mac_len;
}
static uint16_t
check_mac(const edhoc_context_t *ctx, const uint8_t *received_mac, uint16_t received_mac_sz)
{
  uint8_t mac_num;
  if(ROLE == INITIATOR) {
    mac_num = MAC_2;
  } else if(ROLE == RESPONDER) {
    mac_num = MAC_3;
  }

  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  uint8_t mac[edhoc_mac_len];
  if(!calc_mac(ctx, mac_num, edhoc_mac_len, mac)) {
    LOG_ERR("Set MAC error\n");
    return 0;
  }
  
  LOG_DBG("Received MAC (%d): ", (int)received_mac_sz);
  print_buff_8_dbg(received_mac, received_mac_sz);

  LOG_DBG("Recalculated MAC (%d): ", (int)edhoc_mac_len);
  print_buff_8_dbg(mac, edhoc_mac_len);
  
  /* RH: Verify the MAC value */
  uint16_t mac_sz = edhoc_mac_len;
  uint8_t diff = 0;
  for(int i = 0 ; i < edhoc_mac_len ; i++) {
    diff |= (mac[i] ^ received_mac[i]);
  } 
  
  if(diff != 0) {
    LOG_ERR("error code in check mac (%d)\n", ERR_AUTHENTICATION);
    return 0;
  }
  
  return mac_sz;
}
static uint8_t
gen_gxy(edhoc_context_t *ctx, uint8_t *ikm)
{
  uint8_t er = generate_IKM(ctx->curve, ctx->session.gx, ctx->session.gy, ctx->ephemeral_key.private_key, ikm);
  if(er == 0) {
    LOG_ERR("error in generate shared secret\n");
    return 0;
  }
  LOG_DBG("GXY (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ikm, ECC_KEY_LEN);
  return 1;
}
static uint8_t
gen_prk_2e(edhoc_context_t *ctx)
{
  uint8_t ikm[ECC_KEY_LEN];
  uint8_t er = 0;
  
  watchdog_periodic();
  er = gen_gxy(ctx, ikm);
  watchdog_periodic();
  if(er == 0) {
    return 0;
  }
  er = hkdf_extract(ctx->session.th, HASH_LEN, ikm, ECC_KEY_LEN, ctx->session.prk_2e);
  if(er < 1) {
    LOG_ERR("Error in extract prk_2e\n");
    return 0;
  }
  LOG_DBG("PRK_2e (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session.prk_2e, HASH_LEN);
  return 1;
}
/* Derive KEYSTREAM_2 */
static int16_t
gen_ks_2e(edhoc_context_t *ctx, uint16_t length, uint8_t *ks_2e)
{
  int er = edhoc_kdf(ctx->session.prk_2e, KEYSTREAM_2_LABEL, ctx->session.th, HASH_LEN, length, ks_2e);
  if(er < 0) {
    return er;
  }
  LOG_DBG("KEYSTREAM_2 (%d bytes): ", length);
  print_buff_8_dbg(ks_2e, length);
  return 1;
}
static uint8_t
gen_prk_3e2m(edhoc_context_t *ctx, cose_key_t *cose_auth_key, uint8_t gen)
{
  uint8_t grx[ECC_KEY_LEN];
  int8_t er = 0;
 
  ecc_key authenticate;
  initialize_ecc_key_from_cose(&authenticate, cose_auth_key, ctx->curve);
  ecc_key *key_authenticate = &authenticate;

  if(gen) {
    er = generate_IKM(ctx->curve, ctx->session.gx, ctx->session.gy, key_authenticate->private_key, grx);
  } else {
    er = generate_IKM(ctx->curve, key_authenticate->public.x, key_authenticate->public.y, ctx->ephemeral_key.private_key, grx);
  }
  if(er == 0) {
    LOG_ERR("error in generate shared secret for prk_3e2m\n");
    return 0;
  }

  /* Use edhoc_kdf to generate SALT_3e2m */  
  uint8_t salt[HASH_LEN];
  er = edhoc_kdf(ctx->session.prk_2e, SALT_3E2M_LABEL, ctx->session.th, HASH_LEN, HASH_LEN, salt);
  if (er < 1) {
    LOG_ERR("Error calculating SALT_3e2m (%d)\n", er);
    return 0;
  }
  LOG_DBG("SALT_3e2m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(salt, HASH_LEN);
  
  er = hkdf_extract(salt, HASH_LEN, grx, ECC_KEY_LEN, ctx->session.prk_3e2m);
  if(er < 1) {
    LOG_ERR("error in extract for prk_3e2m\n");
    return 0;
  }
  LOG_DBG("PRK_3e2m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session.prk_3e2m, HASH_LEN);
  return 1;
}
static uint8_t
gen_prk_4e3m(edhoc_context_t *ctx, const cose_key_t *cose_auth_key, uint8_t gen)
{
  uint8_t giy[ECC_KEY_LEN];
  int8_t er = 0;
  
  ecc_key authenticate;
  initialize_ecc_key_from_cose(&authenticate, cose_auth_key, ctx->curve);
  ecc_key *key_authenticate = &authenticate;
  
  if(gen) {
    er = generate_IKM(ctx->curve, key_authenticate->public.x, key_authenticate->public.y, ctx->ephemeral_key.private_key, giy);
  } else {
    er = generate_IKM(ctx->curve, ctx->session.gx, ctx->session.gy, key_authenticate->private_key, giy);
  }
  LOG_DBG("G_IY (ECDH shared secret) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(giy, ECC_KEY_LEN);
  if(er == 0) {
    LOG_ERR("error in generate shared secret for prk_4e3m\n");
    return 0;
  }

  /* Use edhoc_kdf to generate SALT_4e3m */
  uint8_t salt[HASH_LEN];
  er = edhoc_kdf(ctx->session.prk_3e2m, SALT_4E3M_LABEL, ctx->session.th, HASH_LEN, HASH_LEN, salt);
  if (er < 1) {
    LOG_ERR("Error calculating SALT_4e3m (%d)\n", er);
    return 0;
  }
  LOG_DBG("SALT_4e3m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(salt, HASH_LEN);
  
  er = hkdf_extract(salt, HASH_LEN, giy, ECC_KEY_LEN, ctx->session.prk_4e3m);
  if(er < 1) {
    LOG_ERR("error in extract for prk_4e3m\n");
    return 0;
  }
  LOG_DBG("PRK_4e3m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session.prk_4e3m, HASH_LEN);
  return 1;
}
static int16_t
enc_dec_ciphertext_2(const edhoc_context_t *ctx, const uint8_t *ks_2e, uint8_t *plaintext, uint16_t plaintext_sz)
{
  for(int i = 0; i < plaintext_sz; i++) {
    plaintext[i] = plaintext[i] ^ ks_2e[i];
  }
  return plaintext_sz;
}
static uint16_t
decrypt_ciphertext_3(edhoc_context_t *ctx, const uint8_t *ciphertext, uint16_t ciphertext_sz, uint8_t *plaintext)
{
  cose_encrypt0 *cose = cose_encrypt0_new();
  
  /* set external AAD in cose */
  cose_encrypt0_set_content(cose, NULL, 0, NULL, 0);
  uint8_t *th3_ptr = cose->external_aad;
  memcpy(th3_ptr, ctx->session.th, HASH_LEN);
  cose->external_aad_sz = HASH_LEN;

  cose_encrypt0_set_ciphertext(cose, ciphertext, ciphertext_sz);
  /* COSE encrypt0 set header */
  cose_encrypt0_set_header(cose, NULL, 0, NULL, 0);
  
  /* generate K_3 */
  cose->alg = get_edhoc_cose_enc_alg(ctx->session.suite_selected);
  cose->key_sz = get_cose_key_len(cose->alg);
  int8_t er = edhoc_kdf(ctx->session.prk_3e2m, K_3_LABEL, ctx->session.th, HASH_LEN, cose->key_sz, cose->key);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  LOG_DBG("K_3 (%d bytes): ", cose->key_sz);
  print_buff_8_dbg(cose->key, cose->key_sz);

  /* generate IV_3 */
  cose->nonce_sz = get_cose_iv_len(cose->alg);
  er = edhoc_kdf(ctx->session.prk_3e2m, IV_3_LABEL, ctx->session.th, HASH_LEN, cose->nonce_sz, cose->nonce);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  LOG_DBG("IV_3 (%d bytes): ", cose->nonce_sz);
  print_buff_8_dbg(cose->nonce, cose->nonce_sz);

  /* Decrypt COSE */
  if(!cose_decrypt(cose)) {
    LOG_ERR("ciphertext 3 decrypt error\n");
    return 0;
  }

  for(int i = 0; i < cose->plaintext_sz; i++) {
    plaintext[i] = cose->plaintext[i];
  }

  /* Free memory */
  cose_encrypt0_finalize(cose);
  return cose->plaintext_sz;
}
static uint16_t
gen_plaintext(edhoc_context_t *ctx, const uint8_t *ad, size_t ad_sz, bool msg2, const uint8_t *mac_or_sig, uint8_t mac_or_signature_sz, uint8_t *plaintext_buf)
{
  uint8_t *pint = (ctx->session.id_cred_x);
  uint8_t *pout = plaintext_buf;
  uint8_t num = edhoc_get_maps_num(&pint);
  uint8_t *buf_ptr = &(plaintext_buf[0]);

  size_t size;
  if (msg2) {
      size = edhoc_put_byte_identifier(&buf_ptr, (uint8_t *)&ctx->session.cid, CID_LEN);
  } else {
      size = 0;
  }

  if(num == 1) {
    num = (uint8_t)edhoc_get_unsigned(&pint);
    size_t sz = edhoc_get_bytes(&pint, &pout);
    if(sz == 0) {
      LOG_ERR("error to get bytes\n");
      return 0;
    }
    if(sz == 1 && (pout[0] < 0x18 || (0x20 <= pout[0] && pout[0] <= 0x37))) {
      size += cbor_put_num(&buf_ptr, pout[0]);
    } else {
      size += cbor_put_bytes(&buf_ptr, pout, sz);
    }
  } else {
    memcpy(buf_ptr, ctx->session.id_cred_x, ctx->session.id_cred_x_sz);
    size += ctx->session.id_cred_x_sz;
  }

  size += cbor_put_bytes(&buf_ptr, &(mac_or_sig[0]), mac_or_signature_sz);
  if(ad_sz != 0) {
    size += cbor_put_bytes(&buf_ptr, ad, ad_sz);
  }

  return size;
}
static uint16_t
gen_ciphertext_3(edhoc_context_t *ctx, const uint8_t *ad, uint16_t ad_sz, const uint8_t *mac_or_sig, uint16_t mac_sz, uint8_t *ciphertext)
{
  int8_t er = 0;
  cose_encrypt0 *cose = cose_encrypt0_new();
  
  /* set external AAD in cose */
  uint8_t *th3_ptr = cose->external_aad;
  cose->external_aad_sz = HASH_LEN;
  memcpy(th3_ptr, ctx->session.th, HASH_LEN);

  cose->plaintext_sz = gen_plaintext(ctx, ad, ad_sz, false, mac_or_sig, mac_sz, cose->plaintext);
  LOG_DBG("PLAINTEXT_3 (%d bytes): ", (int)cose->plaintext_sz);
  print_buff_8_dbg(cose->plaintext, cose->plaintext_sz);

  /* RH: Save plaintext_3 for TH_3 */
  memcpy(ctx->session.plaintext_3, cose->plaintext, cose->plaintext_sz);
  ctx->session.plaintext_3_sz = cose->plaintext_sz;

  /* generate K_3 */
  cose->alg = get_edhoc_cose_enc_alg(ctx->session.suite_selected);
  cose->key_sz = get_cose_key_len(cose->alg);
  er = edhoc_kdf(ctx->session.prk_3e2m, K_3_LABEL, ctx->session.th, HASH_LEN, cose->key_sz, cose->key);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  LOG_DBG("K_3 (%d bytes): ", (int)cose->key_sz);
  print_buff_8_dbg(cose->key, cose->key_sz);

  /* generate IV_3 */
  uint8_t iv_len = get_cose_iv_len(cose->alg);
  er = edhoc_kdf(ctx->session.prk_3e2m, IV_3_LABEL, ctx->session.th, HASH_LEN, iv_len, cose->nonce);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  cose->nonce_sz = iv_len;
  LOG_DBG("IV_3 (%d bytes): ", (int)cose->nonce_sz);
  print_buff_8_dbg(cose->nonce, cose->nonce_sz);

  /* COSE encrypt0 set header */
  cose_encrypt0_set_header(cose, NULL, 0, NULL, 0);

  /* Encrypt COSE */
  cose_encrypt(cose);

  uint8_t *ptr = ciphertext;
  uint16_t ext = cbor_put_bytes(&ptr, cose->ciphertext, cose->ciphertext_sz);

  /* Free memory */
  cose_encrypt0_finalize(cose);
  return ext;
}
uint8_t
edhoc_get_authentication_key(edhoc_context_t *ctx)
{

#ifdef AUTH_SUBJECT_NAME
  cose_key_t *key;
  if(edhoc_check_key_list_identity(AUTH_SUBJECT_NAME, strlen(AUTH_SUBJECT_NAME), &key)) {
    memcpy(ctx->authen_key.private_key, key->private, ECC_KEY_LEN);
    memcpy(ctx->authen_key.public.x, key->x, ECC_KEY_LEN);
    memcpy(ctx->authen_key.public.y, key->y, ECC_KEY_LEN);
    memcpy(ctx->authen_key.kid, key->kid, key->kid_sz);
    ctx->authen_key.kid_sz = key->kid_sz;
    ctx->authen_key.identity = key->identity;
    ctx->authen_key.identity_sz = key->identity_sz;
    return 1;
  } else {
    LOG_ERR("Does not contains a key for the authentication key identity\n");
  }
#endif

#ifdef AUTH_KID
  cose_key_t *key;
  uint8_t key_id[sizeof(int)];
  int kid = AUTH_KID;
  int quotient = (AUTH_KID / 256);
  uint8_t key_id_sz = 1;
  while(quotient != 0) {
    key_id_sz++;
    quotient /= 256;
  }

  memcpy(key_id, (uint8_t *)&kid, key_id_sz);

  if(edhoc_check_key_list_kid(key_id, key_id_sz, &key)) {
    memcpy(ctx->authen_key.private_key, key->private, ECC_KEY_LEN);
    memcpy(ctx->authen_key.public.x, key->x, ECC_KEY_LEN);
    memcpy(ctx->authen_key.public.y, key->y, ECC_KEY_LEN);
    memcpy(ctx->authen_key.kid, key->kid, key->kid_sz);
    ctx->authen_key.kid_sz = key->kid_sz;
    ctx->authen_key.identity = key->identity;
    ctx->authen_key.identity_sz = key->identity_sz;
    return 1;
  } else {
    LOG_ERR("Does not contains a key for the key ID\n");
  }
#endif
  LOG_ERR("Not matching key found in the storage\n");
  return 0;
}
void
edhoc_gen_msg_1(edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz, bool suite_array)
{
  /* Generate message 1 */
  edhoc_msg_1 msg1 = {
    .method = ctx->session.method,
    .suites_i = ctx->session.suite,
    .suites_i_sz = ctx->session.suite_num,
    .g_x = (uint8_t *)&ctx->ephemeral_key.public.x,
    .c_i = (uint8_t *)&ctx->session.cid,
    .uad = (ead_data){ .ead_label = 0, .ead_value = ad, .ead_value_sz = ad_sz },
  };

  /* CBOR encode message in the buffer */
  size_t size = edhoc_serialize_msg_1(&msg1, ctx->msg_tx, suite_array);
  ctx->tx_sz = size;

  LOG_DBG("C_I chosen by Initiator (%d bytes): 0x", CID_LEN);
  print_buff_8_dbg(msg1.c_i, CID_LEN);
  LOG_DBG("AD_1 (%d bytes): ", (int)ad_sz);
  print_char_8_dbg((char *)ad, ad_sz);
  for(int i = 0; i < msg1.suites_i_sz; ++i) {
      LOG_DBG("SUITES_I[%d]: %d\n", i, (int) msg1.suites_i[i]);
  }
  LOG_DBG("message_1 (CBOR Sequence) (%d bytes): ", (int)ctx->tx_sz);
  print_buff_8_dbg(ctx->msg_tx, ctx->tx_sz);
  LOG_INFO("MSG1 sz: %d\n", (int)ctx->tx_sz);
}
uint8_t
edhoc_gen_msg_2(edhoc_context_t *ctx, const uint8_t *ad, size_t ad_sz)
{
  int8_t rv = gen_th2(ctx, ctx->ephemeral_key.public.x, ctx->msg_rx, ctx->rx_sz);
  if(rv < 0) {
    LOG_ERR("Failed to generate TH_2 (%d)\n", rv);
    return -1;
  }

  /* The COSE key include the authentication key */
  cose_key_t cose;
  convert_ecc_key_to_cose_key(&ctx->authen_key, &cose, ctx->authen_key.identity, ctx->authen_key.identity_sz);

  /* generate cred_x and id_cred_x */
  ctx->session.cred_x_sz = generate_cred_x(&cose, ctx->session.cred_x);
  LOG_DBG("CRED_R (%d bytes): ", (int)ctx->session.cred_x_sz);
  print_buff_8_dbg(ctx->session.cred_x, ctx->session.cred_x_sz);

  ctx->session.id_cred_x_sz = generate_id_cred_x(&cose, ctx->session.id_cred_x);
  LOG_DBG("ID_CRED_R (%d bytes): ", (int)ctx->session.id_cred_x_sz);
  print_buff_8_dbg(ctx->session.id_cred_x, ctx->session.id_cred_x_sz);

  gen_prk_2e(ctx);

  uint8_t mac_or_signature_sz = -1;

  /* Generate MAC or Signature */

#if ((METHOD == METH1) || (METHOD == METH3))
  /* generate prk_3e2m */
  gen_prk_3e2m(ctx, &cose, 1);
  
  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  uint8_t mac_or_sig[edhoc_mac_len];
  gen_mac(ctx, edhoc_mac_len, mac_or_sig);
  LOG_DBG("MAC_2 (%d bytes): ", edhoc_mac_len);
  print_buff_8_dbg(mac_or_sig, edhoc_mac_len);
  mac_or_signature_sz = edhoc_mac_len;
#endif

#if ((METHOD == METH0) || (METHOD == METH2))
  
  /* prk_3e2m is prk_2e */
  memcpy(ctx->session.prk_3e2m, ctx->session.prk_2e, HASH_LEN);

  // Derive MAC with HASH_LEN size (buf fits later signature)
  uint8_t mac_or_sig[P256_SIGNATURE_LEN];
  gen_mac(ctx, HASH_LEN, mac_or_sig);
  LOG_DBG("MAC_2 (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(mac_or_sig, HASH_LEN);

  /* Create signature from MAC and other data using COSE_Sign1 */
  
  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x, ctx->session.id_cred_x_sz, NULL, 0);
  
  // External AAD
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, ctx->session.th, HASH_LEN);
  aad_ptr += HASH_LEN;
  memcpy(aad_ptr, ctx->session.cred_x, ctx->session.cred_x_sz);
  cose_sign1->external_aad_sz = ctx->session.cred_x_sz + HASH_LEN;
  
  // Payload
  uint8_t er = cose_sign1_set_payload(cose_sign1, mac_or_sig, HASH_LEN);
  if(er == 0) {
    LOG_ERR("Failed to set payload in COSE_Sign1 object\n");
    return -1;
  }

  cose_sign1_set_key(cose_sign1, ES256, ctx->authen_key.private_key, ECC_KEY_LEN);
  er = cose_sign(cose_sign1);
  if(er == 0) {
    LOG_ERR("Failed to sign for COSE_Sign1 object\n");
    return -1;
  }

  cose_sign1_finalize(cose_sign1);

  LOG_DBG("Signature from COSE_Sign1 (%d bytes): ", P256_SIGNATURE_LEN);
  print_buff_8_dbg(cose_sign1->signature, P256_SIGNATURE_LEN);

  mac_or_signature_sz = P256_SIGNATURE_LEN;
  memcpy(mac_or_sig, cose_sign1->signature, cose_sign1->signature_sz);
#endif

  /* Generate and store the plaintext in the session */
  uint16_t plaint_sz = gen_plaintext(ctx, ad, ad_sz, true, mac_or_sig, mac_or_signature_sz, ctx->session.plaintext_2);
  LOG_DBG("PLAINTEXT_2 (%d bytes): ", (int)plaint_sz);
  print_buff_8_dbg(ctx->session.plaintext_2, plaint_sz);
  ctx->session.plaintext_2_sz = plaint_sz;

  /* Derive KEYSTREAM_2 */
  uint8_t ks_2e[plaint_sz];
  gen_ks_2e(ctx, plaint_sz, ks_2e);

  /* Encrypt the plaintext */
  uint8_t ciphertext[plaint_sz];
  memcpy(ciphertext, ctx->session.plaintext_2, plaint_sz);
  enc_dec_ciphertext_2(ctx, ks_2e, ciphertext, plaint_sz);
  LOG_DBG("CIPHERTEXT_2 (%d bytes): ", (int)plaint_sz);
  print_buff_8_dbg(ciphertext, plaint_sz);

  /* Set x and ciphertext in msg_tx */
  uint8_t *ptr = &(ctx->msg_tx[0]);
  int sz = cbor_put_bytes(&ptr, ctx->ephemeral_key.public.x, ECC_KEY_LEN);
  memcpy(ptr, ciphertext, plaint_sz);
  ctx->tx_sz = sz + plaint_sz;
  ctx->msg_tx[1] = ctx->tx_sz - 2;
  LOG_INFO("MSG2 sz: %d\n", ctx->tx_sz);

  return 1;
}
void
edhoc_gen_msg_3(edhoc_context_t *ctx, const uint8_t *ad, size_t ad_sz)
{
  /* gen TH_3 */
  gen_th3(ctx, ctx->session.cred_x, ctx->session.cred_x_sz, ctx->session.plaintext_2, ctx->session.plaintext_2_sz);
 
  /* Generate COSE authentication key */
  cose_key_t cose;
  convert_ecc_key_to_cose_key(&ctx->authen_key, &cose, ctx->authen_key.identity, ctx->authen_key.identity_sz);

  cose_print_key(&cose);
  LOG_DBG("SK_I (Initiator's private authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.private_key, ECC_KEY_LEN);

  LOG_DBG("G_I (x)(Initiator's public authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.public.x, ECC_KEY_LEN);

  LOG_DBG("(y) (Initiator's public authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.public.y, ECC_KEY_LEN);

  /* generate cred_x */
  ctx->session.cred_x_sz = generate_cred_x(&cose, ctx->session.cred_x);
  LOG_DBG("CRED_I (%d bytes): ", (int)ctx->session.cred_x_sz);
  print_buff_8_dbg(ctx->session.cred_x, ctx->session.cred_x_sz);

  /* generate id_cred_x */
  ctx->session.id_cred_x_sz = generate_id_cred_x(&cose, ctx->session.id_cred_x);
  LOG_DBG("ID_CRED_I (%d bytes): ", (int)ctx->session.id_cred_x_sz);
  print_buff_8_dbg(ctx->session.id_cred_x, ctx->session.id_cred_x_sz);

  uint8_t mac_or_signature_sz = -1;

#if ((METHOD == METH2) || (METHOD == METH3))
  /* Generate prk_4e3m */
  gen_prk_4e3m(ctx, &cose, 0);

  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  uint8_t mac_or_sig[edhoc_mac_len];
  gen_mac(ctx, edhoc_mac_len, mac_or_sig);
  LOG_DBG("MAC 3 (%d bytes): ", edhoc_mac_len);
  print_buff_8_dbg(mac_or_sig, edhoc_mac_len);
  mac_or_signature_sz = edhoc_mac_len;
#endif

#if ((METHOD == METH0) || (METHOD == METH1))

  /* prk_4e3m is prk_3e2m */
  memcpy(ctx->session.prk_4e3m, ctx->session.prk_3e2m, HASH_LEN);

  // Derive MAC with HASH_LEN size (buf fits later signature)
  uint8_t mac_or_sig[P256_SIGNATURE_LEN];
  gen_mac(ctx, HASH_LEN, mac_or_sig);
  LOG_DBG("MAC_3 (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(mac_or_sig, HASH_LEN);

  /* Create signature from MAC and other data using COSE_Sign1 */

  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x, ctx->session.id_cred_x_sz, NULL, 0);

  // External AAD
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, ctx->session.th, HASH_LEN);
  aad_ptr += HASH_LEN;
  memcpy(aad_ptr, ctx->session.cred_x, ctx->session.cred_x_sz);
  cose_sign1->external_aad_sz = ctx->session.cred_x_sz + HASH_LEN;

  // Payload
  uint8_t er = cose_sign1_set_payload(cose_sign1, mac_or_sig, HASH_LEN);
  if(er == 0) {
    LOG_ERR("Failed to set payload in COSE_Sign1 object\n");
    return;
  }

  cose_sign1_set_key(cose_sign1, ES256, ctx->authen_key.private_key, ECC_KEY_LEN);
  er = cose_sign(cose_sign1);
  if(er == 0) {
    LOG_ERR("Failed to sign for COSE_Sign1 object\n");
    return;
  }

  cose_sign1_finalize(cose_sign1);

  LOG_DBG("Signature from COSE_Sign1 (%d bytes): ", P256_SIGNATURE_LEN);
  print_buff_8_dbg(cose_sign1->signature, P256_SIGNATURE_LEN);

  mac_or_signature_sz = P256_SIGNATURE_LEN;
  memcpy(mac_or_sig, cose_sign1->signature, cose_sign1->signature_sz);
#endif

  /* time = RTIMER_NOW(); */
  /* Gen ciphertext_3 */
  uint16_t ciphertext_sz = gen_ciphertext_3(ctx, ad, ad_sz, mac_or_sig, mac_or_signature_sz, ctx->msg_tx);
  ctx->tx_sz = ciphertext_sz;
  
  /* Compute TH_4 WIP */
  gen_th4(ctx, ctx->session.cred_x, ctx->session.cred_x_sz, ctx->session.plaintext_3, ctx->session.plaintext_3_sz);
}

uint8_t
edhoc_gen_msg_error(uint8_t *msg_er, const edhoc_context_t *ctx, int8_t err)
{
  edhoc_msg_error msg;
  msg.err_code = 1;
  switch(err * (-1)) {
  default:
    msg.err_info = "ERR_UNKNOWN";
    msg.err_info_sz = strlen("ERR_UNKNOWN");
    break;
  case (ERR_SUITE_NON_SUPPORT * (-1)):
    msg.err_info = "ERR_SUITE_NON_SUPPORT";
    msg.err_info_sz = strlen("ERR_SUITE_NON_SUPPORT");
    break;
  case (ERR_MSG_MALFORMED * (-1)):
    msg.err_info = "ERR_MSG_MALFORMED";
    msg.err_info_sz = strlen("ERR_MSG_MALFORMED");
    break;
  case (ERR_REJECT_METHOD * (-1)):
    msg.err_info = "ERR_REJECT_METHOD";
    msg.err_info_sz = strlen("ERR_REJECT_METHOD");
    break;
  case (ERR_CID_NOT_VALID * (-1)):
    msg.err_info = "ERR_CID_NOT_VALID";
    msg.err_info_sz = strlen("ERR_CID_NOT_VALID");
    break;
  case (ERR_WRONG_CID_RX * (-1)):
    msg.err_info = "ERR_WRONG_CID_RX";
    msg.err_info_sz = strlen("ERR_WRONG_CID_RX");
    break;
  case (ERR_ID_CRED_X_MALFORMED * (-1)):
    msg.err_info = "ERR_ID_CRED_X_MALFORMED";
    msg.err_info_sz = strlen("ERR_ID_CRED_X_MALFORMED");
    break;
  case (ERR_AUTHENTICATION * (-1)):
    msg.err_info = "ERR_AUTHENTICATION";
    msg.err_info_sz = strlen("ERR_AUTHENTICATION");
    break;
  case (ERR_DECRYPT * (-1)):
    msg.err_info = "ERR_DECRYPT";
    msg.err_info_sz = strlen("ERR_DECRYPT");
    break;
  case (ERR_CODE * (-1)):
    msg.err_info = "ERR_CODE";
    msg.err_info_sz = strlen("ERR_CODE");
    break;
  case (ERR_NOT_ALLOWED_IDENTITY * (-1)):
    msg.err_info = "ERR_NOT_ALLOWED_IDENTITY";
    msg.err_info_sz = strlen("ERR_NOT_ALLOWED_IDENTITY");
    break;
  case (RX_ERR_MSG * (-1)):
    msg.err_info = "RX_ERR_MSG";
    msg.err_info_sz = strlen("RX_ERR_MSG");
    break;
  case (ERR_TIMEOUT * (-1)):
    msg.err_info = "ERR_TIMEOUT";
    msg.err_info_sz = strlen("ERR_TIMEOUT");
    break;
  case (ERR_CORRELATION * (-1)):
    msg.err_info = "ERR_CORRELATION";
    msg.err_info_sz = strlen("ERR_CORRELATION");
    break;
  case (ERR_NEW_SUITE_PROPOSE * (-1)):
    msg.err_code = 2;
    msg.err_info = (char *)ctx->session.suite;
    msg.err_info_sz = ctx->session.suite_num * sizeof(ctx->session.suite[0]);
    break;
  case (ERR_RESEND_MSG_1 * (-1)):
    msg.err_info = "ERR_RESEND_MSG_1";
    msg.err_info_sz = strlen("ERR_RESEND_MSG_1");
    break;
  }

  LOG_ERR("ERR MSG (%d): ", msg.err_code);
  if(msg.err_code == 1) {
    print_char_8_err(msg.err_info, msg.err_info_sz);
  } else {
    printf("\n");
  }

  size_t err_sz = edhoc_serialize_err(&msg, msg_er);
  LOG_DBG("ERR MSG CBOR: ");
  print_buff_8_dbg((uint8_t *)msg_er, err_sz);
  return err_sz;
}
static int8_t
edhoc_check_err_rx_msg(uint8_t *payload, uint8_t payload_sz)
{
  /* Check if the rx msg is an msg_err */
  uint8_t *msg_err = payload;
  edhoc_msg_error err;
  int8_t msg_err_sz = 0;
  msg_err_sz = edhoc_deserialize_err(&err, msg_err, payload_sz);
  if(msg_err_sz > 0) {
    LOG_ERR("RX MSG_ERR: ");
    print_char_8_err(err.err_info, err.err_info_sz);
    return RX_ERR_MSG;
  }
  if(msg_err_sz == -1) {
    LOG_ERR("RX MSG_ERROR WITH SUITE PROPOSE: ");
    print_char_8_err(err.err_info, err.err_info_sz);
    return RX_ERR_MSG;
  }
  return 0;
}
static int8_t
edhoc_check_err_rx_msg_2(uint8_t *payload, uint8_t payload_sz, const edhoc_context_t* ctx)
{
  /* Check if the rx msg is an msg_err */
  uint8_t *msg_err = payload;
  edhoc_msg_error err = { 0 };

  int8_t msg_err_sz = edhoc_deserialize_err(&err, msg_err, payload_sz);
  if(msg_err_sz < 0) {
    LOG_ERR("RX MSG_ERR: ");
    print_char_8_err(err.err_info, err.err_info_sz);
    return RX_ERR_MSG;
  }
  return 0;
}
int
edhoc_handler_msg_1(edhoc_context_t *ctx, uint8_t *payload, size_t payload_sz, uint8_t *ad)
{

  edhoc_msg_1 msg1 = { 0 };
  int er = 0;
  /* Decode MSG1 */
  set_rx_msg(ctx, payload, payload_sz);

  /* Check if the rx msg is an msg_err */
  er = edhoc_check_err_rx_msg(payload, payload_sz);
  if(er < 0) {
    return RX_ERR_MSG;
  } else if(er == 2){
    return ERR_NEW_SUITE_PROPOSE;
  }

  LOG_DBG("MSG1 (%d bytes): ", (int)ctx->rx_sz);
  print_buff_8_dbg(ctx->msg_rx, ctx->rx_sz);
  er = edhoc_deserialize_msg_1(&msg1, ctx->msg_rx, ctx->rx_sz);
  if(er < 0) {
    LOG_ERR("MSG1 malformed\n");
    return er;
  }
  print_msg_1(&msg1);

  /* check rx suite and set connection identifier of the other peer */
  er = check_rx_suite_i(ctx, msg1.suites_i, msg1.suites_i_sz);
  if(er < 0) {
    LOG_ERR("Rx Suite not supported\n");
    return er;
  }

  /* Check to not have the same cid */
  er = set_rx_cid(ctx, msg1.c_i, CID_LEN);
  if(er < 0) {
    LOG_ERR("Not support cid rx\n");
    return er;
  }

  /* Set EDHOC method */
  er = set_rx_method(ctx, msg1.method);
  if(er < 0) {
    LOG_ERR("Rx Method not supported\n");
    return er;
  }

  /* Set GX */
  set_rx_gx(ctx, msg1.g_x);
  print_session_info(ctx);

  LOG_DBG("MSG EAD (%d)", (int)msg1.uad.ead_value_sz);
  print_char_8_dbg((char *)msg1.uad.ead_value, msg1.uad.ead_value_sz);

  if(msg1.uad.ead_value_sz != 0) {
    memcpy(ad, msg1.uad.ead_value, msg1.uad.ead_value_sz);
  }

  return msg1.uad.ead_value_sz;
}
int
edhoc_handler_msg_2(edhoc_msg_2 *msg2, edhoc_context_t *ctx, uint8_t *payload, size_t payload_sz)
{
  int er = 0;
  set_rx_msg(ctx, payload, payload_sz);
  er = edhoc_check_err_rx_msg_2(payload, payload_sz, ctx);
  if(er < 0){
    LOG_DBG("MSG2 err: %d\n", er);
    return er;
  }
  er = edhoc_deserialize_msg_2(msg2, ctx->msg_rx, ctx->rx_sz);
  if(er < 0) {
    LOG_ERR("MSG2 malformed\n");
    return er;
  }
  print_msg_2(msg2);

  set_rx_gx(ctx, msg2->gy_ciphertext_2);
  gen_th2(ctx, msg2->gy_ciphertext_2, ctx->msg_tx, ctx->tx_sz);
  gen_prk_2e(ctx);
  
  /* Gen KS_2e */
  int ciphertext2_sz = msg2->gy_ciphertext_2_sz - ECC_KEY_LEN;
  uint8_t ks_2e[ciphertext2_sz];
  gen_ks_2e(ctx, ciphertext2_sz, ks_2e);

  /* Prepare ciphertext for decryption */
  memcpy(ctx->session.plaintext_2, msg2->gy_ciphertext_2 + ECC_KEY_LEN, ciphertext2_sz);
  LOG_DBG("CIPHERTEXT_2 (%d bytes): ", ciphertext2_sz);
  print_buff_8_dbg(ctx->session.plaintext_2, ciphertext2_sz);

  /* Actually decrypt the ciphertext */
  size_t plaint_sz = enc_dec_ciphertext_2(ctx, ks_2e, ctx->session.plaintext_2, ciphertext2_sz);
  ctx->session.plaintext_2_sz = plaint_sz;
  LOG_DBG("PLAINTEXT_2 (%lu bytes): ", plaint_sz);
  print_buff_8_dbg(ctx->session.plaintext_2 + ECC_KEY_LEN, plaint_sz);

  int cr_sz = CID_LEN;
  er = set_rx_cid(ctx, ctx->session.plaintext_2, cr_sz);
  if(er < 0) {
      return er;
  }
  LOG_DBG("cid (%d)\n", (uint8_t)ctx->session.cid_rx);
  
  return 1;
}

int
edhoc_get_auth_key(edhoc_context_t *ctx, uint8_t **pt, cose_key_t *key, bool msg2)
{
  /* Point to decrypted plaintext for id_cred_x retrieval */
  if(msg2) {
    *pt = ctx->session.plaintext_2 + CID_LEN;
  } else {
    *pt = ctx->session.plaintext_3;
  }

  int len = edhoc_get_id_cred_x(pt, ctx->session.id_cred_x, key);
  if(len == 0) {
    LOG_ERR("error code (%d)\n", ERR_ID_CRED_X_MALFORMED);
    return ERR_ID_CRED_X_MALFORMED;
  } else if(len < 0) {
    LOG_ERR("error code1 (%d)\n", ERR_CID_NOT_VALID);
    return ERR_CID_NOT_VALID;
  }
  ctx->session.id_cred_x_sz = len;
  LOG_DBG("ID_CRED_X (for MAC) (%zu): ", ctx->session.id_cred_x_sz);
  print_buff_8_dbg(ctx->session.id_cred_x, ctx->session.id_cred_x_sz);
  return 1;
}
int
edhoc_handler_msg_3(edhoc_msg_3 *msg3, edhoc_context_t *ctx, uint8_t *payload, size_t payload_sz)
{
  /* Decode MSG3 */
  set_rx_msg(ctx, payload, payload_sz);

  /* Check if the rx msg is an msg_err */
  if(edhoc_check_err_rx_msg(payload, payload_sz) < 0) {
    return RX_ERR_MSG;
  }

  int8_t er = edhoc_deserialize_msg_3(msg3, ctx->msg_rx, ctx->rx_sz);
  if(er < 0) {
    LOG_ERR("MSG3 malformed\n");
    return er;
  }
  print_msg_3(msg3);

  LOG_DBG("CIPHERTEXT_3 (%d bytes): ", (int)msg3->ciphertext_3_sz);
  print_buff_8_dbg(msg3->ciphertext_3, msg3->ciphertext_3_sz);
  
  LOG_DBG("MYSTERY DATA (%d bytes): ", (int)ctx->session.plaintext_2_sz);
  print_buff_8_dbg(ctx->session.plaintext_2, ctx->session.plaintext_2_sz);

  /* generate TH_3 */
  gen_th3(ctx, ctx->session.cred_x, ctx->session.cred_x_sz, ctx->session.plaintext_2, ctx->session.plaintext_2_sz);

  /* decrypt msg3 and check the TAG for verify the outer */
  uint16_t plaintext_sz = decrypt_ciphertext_3(ctx, msg3->ciphertext_3, msg3->ciphertext_3_sz, ctx->session.plaintext_3);
  ctx->session.plaintext_3_sz = plaintext_sz;
  if(plaintext_sz == 0) {
    LOG_ERR("Error in decrypt ciphertext 3\n");
    return ERR_DECRYPT;
  }
  LOG_DBG("PLAINTEXT_3 (%d): ", (int)plaintext_sz);
  print_buff_8_dbg(ctx->session.plaintext_3, plaintext_sz);

  return 1;
}
int
edhoc_authenticate_msg(edhoc_context_t *ctx, uint8_t **ptr, uint8_t cipher_len, uint8_t *ad, cose_key_t *key)
{
  uint8_t *in_ptr = *ptr;
  LOG_DBG("msg (%d bytes): ", cipher_len);
  print_buff_8_dbg(in_ptr, cipher_len);
  uint8_t *received_mac = NULL;

  /* Get MAC from the decrypt msg*/
  uint16_t received_mac_sz = edhoc_get_sign(ptr, &received_mac);
  uint16_t ad_sz = 0; //TODO

  /* Get the ad from the decrypt msg*/
  if(ad_sz) {
    ad_sz = edhoc_get_ad(ptr, ad);
  } else {
    ad = NULL;
    ad_sz = 0;
  }

  /* generate cred_x and id_cred_x */
  ctx->session.cred_x_sz = generate_cred_x(key, ctx->session.cred_x);
  LOG_DBG("CRED_R auth (%lu): ", ctx->session.cred_x_sz);
  print_buff_8_dbg(ctx->session.cred_x, ctx->session.cred_x_sz);
  
  ctx->session.id_cred_x_sz = generate_id_cred_x(key, ctx->session.id_cred_x);
  LOG_DBG("ID_CRED_R auth (%lu): ", ctx->session.id_cred_x_sz);
  print_buff_8_dbg(ctx->session.id_cred_x, ctx->session.id_cred_x_sz);

#if (METHOD == METH3) || INITIATOR_METH1 || RESPONDER_METH2
  /* Generate prk_3e2m or prk_4e3m */
  if(ROLE == INITIATOR) {
    gen_prk_3e2m(ctx, key, 0);
  } else if(ROLE == RESPONDER) {
    gen_prk_4e3m(ctx, key, 1);
  }

  if(check_mac(ctx, received_mac, received_mac_sz) == 0) {
    LOG_ERR("error code in handler (%d)\n", ERR_AUTHENTICATION);
    return ERR_AUTHENTICATION;
  }
#endif

#if (METHOD == METH0) || INITIATOR_METH2 || RESPONDER_METH1
  if(ROLE == INITIATOR) {
    /* prk_3e2m is prk_2e */
    memcpy(ctx->session.prk_3e2m, ctx->session.prk_2e, HASH_LEN);
  } else if(ROLE == RESPONDER) {
    /* prk_4e3m is prk_3e2m */
    memcpy(ctx->session.prk_4e3m, ctx->session.prk_3e2m, HASH_LEN);
  }

  /* Create signature from MAC and other data using COSE_Sign1 */

  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x, ctx->session.id_cred_x_sz, NULL, 0);

  // External AAD (CRED_I and TH)
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, ctx->session.th, HASH_LEN);
  aad_ptr += HASH_LEN;
  memcpy(aad_ptr, ctx->session.cred_x, ctx->session.cred_x_sz);
  cose_sign1->external_aad_sz = ctx->session.cred_x_sz + HASH_LEN;

  // Set received signature
  cose_sign1_set_signature(cose_sign1, received_mac, received_mac_sz);

  // Payload (MAC)
  uint8_t mac_num = -1;
  if(ROLE == INITIATOR) {
    mac_num = MAC_2;
  } else {
    mac_num = MAC_3;
  }
  uint8_t mac[HASH_LEN];
  calc_mac(ctx, mac_num, HASH_LEN, mac);
  LOG_DBG("MAC_%d (%d bytes): ", mac_num == 2 ? 2 : 3, HASH_LEN); // MAC_2 or 3
  print_buff_8_dbg(mac, HASH_LEN);
  int8_t er2 = cose_sign1_set_payload(cose_sign1, mac, HASH_LEN);
  if(er2 < 0) {
    LOG_ERR("Failed to set payload in COSE_Sign1 object\n");
    return ERR_AUTHENTICATION;
  }

  uint8_t other_public_key[ECC_KEY_LEN * 2];
  memcpy(other_public_key, key->x, key->x_sz);
  memcpy(other_public_key + key->x_sz, key->y, key->y_sz);

  // Set other peer public key and verify
  cose_sign1_set_key(cose_sign1, ES256, other_public_key, ECC_KEY_LEN * 2);
  er2 = cose_verify(cose_sign1);
  cose_sign1_finalize(cose_sign1);
  if(er2 <= 0) {
    LOG_ERR("Failed to check signature for COSE_Sign1 object\n");
    return ERR_AUTHENTICATION;
  }
#endif

  /* RH: Compute TH_4 WIP (after verifying MAC_3) */
  if(ROLE == RESPONDER) { 
    /* Calculate TH_4 */
    gen_th4(ctx, ctx->session.cred_x, ctx->session.cred_x_sz, ctx->session.plaintext_3, ctx->session.plaintext_3_sz);
  }  

  return ad_sz;
}

