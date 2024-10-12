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

#define MAC_2 2
#define MAC_3 3

edhoc_context_t *edhoc_ctx;

/* static rtimer_clock_t time; */

static uint8_t buf[MAX_BUFFER];
static uint8_t inf[MAX_BUFFER];
static uint8_t cred_x[MAX_BUFFER / 2];
static uint8_t id_cred_x[MAX_BUFFER / 2];
static uint8_t mac_or_sig[MAC_OR_SIG_BUF_LEN];

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
reconstruct_id_cred_x(uint8_t *cred_in, size_t cred_in_sz)
{
  size_t size = 0;
  uint8_t *ptr = id_cred_x;
  uint8_t num = edhoc_get_maps_num(&cred_in);
  if(num > 0) {
    cred_in--;
    memcpy(id_cred_x, cred_in, cred_in_sz);
    size = cred_in_sz;
  } else {
    if(cred_in_sz == 1) {
      uint8_t byte = *cred_in;
      size += cbor_put_map(&ptr, 1);
      size += cbor_put_unsigned(&ptr, 4);
      size += cbor_put_bytes(&ptr, &byte, 1);
    } else {
      uint8_t cred[sizeof(int) + 1];
      memcpy(cred, cred_in, cred_in_sz);
      size += cbor_put_map(&ptr, 1);
      size += cbor_put_unsigned(&ptr, 4);
      memcpy(ptr, cred, cred_in_sz);
      size += cred_in_sz;
    }
  }
  LOG_DBG("reconstruct id_cred_x (%zu bytes): ", size);
  print_buff_8_dbg(id_cred_x, size);
  return size;
}
static size_t
generate_info(uint8_t *info, uint8_t *context, uint8_t context_sz, uint8_t length, uint8_t value)
{
  size_t size = cbor_put_num(&info, value);
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
check_rx_suite_i(edhoc_context_t *ctx, bstr suiterx)
{
  /* Get the selected cipher suite (last element) */
  uint8_t peer_selected_suite = suiterx.buf[suiterx.len - 1];

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
set_rx_gx(edhoc_context_t *ctx, uint8_t *gx)
{
  memcpy(ctx->session_keys.gx, gx, ECC_KEY_LEN);
  ctx->session.Gx = (bstr){ (uint8_t *)ctx->session_keys.gx, ECC_KEY_LEN };
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
set_rx_msg(edhoc_context_t *ctx, uint8_t *msg, uint8_t msg_sz)
{
  memcpy(ctx->msg_rx, msg, msg_sz);
  ctx->rx_sz = msg_sz;
}
static void
print_session_info(edhoc_session *con)
{
  LOG_DBG("Session info print:\n");
  LOG_DBG("Using test vector: %s\n", TEST != 0 ? "true" : "false");
  LOG_DBG("Connection role: %d\n", (int)con->role);
  LOG_DBG("Connection method: %d\n", (int)con->method);
  LOG_DBG("Selected cipher suite: %d\n", con->suite_selected);
  LOG_DBG("My cID: %x\n", (uint8_t)con->cid);
  LOG_DBG("Other peer cID: %x\n", (uint8_t)con->cid_rx);
  LOG_DBG("Gx: ");
  print_buff_8_dbg(con->Gx.buf, con->Gx.len);
}
static int8_t
gen_th2(edhoc_context_t *ctx, uint8_t *eph_pub, uint8_t *msg, uint16_t msg_sz)
{
  /* Create the input for TH_2 = H(G_Y, H(msg)), msg1 is in msg_rx */
  int h_buffer_sz = cbor_bstr_size(HASH_LEN) + cbor_bstr_size(ECC_KEY_LEN);
  uint8_t h2[h_buffer_sz];
  uint8_t *h2_ptr = h2;
  
  LOG_DBG("Input to calculate H(msg1) (%d bytes): ", (int)msg_sz);
  print_buff_8_dbg(msg, msg_sz);
  
  uint8_t msg_1_hash[HASH_LEN];
  compute_th(msg, msg_sz, msg_1_hash, HASH_LEN);
  
  cbor_put_bytes(&h2_ptr, eph_pub, ECC_KEY_LEN);
  cbor_put_bytes(&h2_ptr, msg_1_hash, HASH_LEN);
  
  /* Compute TH */
  LOG_DBG("Input to TH_2 (%d): ", h_buffer_sz);
  print_buff_8_dbg(h2, h_buffer_sz);
  uint8_t er = compute_th(h2, h_buffer_sz, ctx->session.th.buf, ctx->session.th.len);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED H(G_Y, H(msg1))\n");
    return ERR_CODE;
  }
  
  LOG_DBG("TH_2 (%d bytes): ", (int)ctx->session.th.len);
  print_buff_8_dbg(ctx->session.th.buf, ctx->session.th.len);
  return 0;
}
static uint8_t
gen_th3(edhoc_context_t *ctx, uint8_t *cred, uint16_t cred_sz, uint8_t *ciphertext, uint16_t ciphertext_sz)
{
  /* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) */
  int h_buffer_sz = cbor_bstr_size(ctx->session.th.len) + ciphertext_sz + cred_sz;
  uint8_t h[h_buffer_sz];
  uint8_t *ptr = h;
  uint16_t h_sz = cbor_put_bytes(&ptr, ctx->session.th.buf, ctx->session.th.len);
  LOG_DBG("TH_2 (%zu): ", ctx->session.th.len);
  print_buff_8_dbg(ctx->session.th.buf, ctx->session.th.len);
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
  uint8_t er = compute_th(h, h_sz, ctx->session.th.buf, ctx->session.th.len);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED TH_3\n");
    return ERR_CODE;
  }
  LOG_DBG("TH_3 (%d bytes): ", (int)ctx->session.th.len);
  print_buff_8_dbg(ctx->session.th.buf, ctx->session.th.len);
  return 0;
}
static uint8_t
gen_th4(edhoc_context_t *ctx, uint8_t *cred, uint16_t cred_sz, uint8_t *ciphertext, uint16_t ciphertext_sz)
{
  /* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) */
  int h_buffer_sz = cbor_bstr_size(ctx->session.th.len) + ciphertext_sz + cred_sz;
  uint8_t h[h_buffer_sz];
  uint8_t *ptr = h;
  uint16_t h_sz = cbor_put_bytes(&ptr, ctx->session.th.buf, ctx->session.th.len);
  LOG_DBG("TH_3 (%zu): ", ctx->session.th.len);
  print_buff_8_dbg(ctx->session.th.buf, ctx->session.th.len);
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
  uint8_t er = compute_th(h, h_sz, ctx->session.th.buf, ctx->session.th.len);
  if(er != 0) {
    LOG_ERR("ERR COMPUTED TH_4\n");
    return ERR_CODE;
  }
  LOG_DBG("TH_4 (%d bytes): ", (int)ctx->session.th.len);
  print_buff_8_dbg(ctx->session.th.buf, ctx->session.th.len);
  return 0;
}
int16_t
edhoc_kdf(uint8_t *result, uint8_t *key, uint8_t info_label, bstr context, uint16_t length)
{
  uint16_t info_sz = generate_info(inf, context.buf, context.len, length, info_label);
  
  return edhoc_expand(result, key, inf, info_sz, length);
}
int16_t
edhoc_expand(uint8_t *result, uint8_t *key, uint8_t *info, uint16_t info_sz, uint16_t length)
{
  LOG_DBG("INFO for HKDF_Expand (%d bytes): ", info_sz);
  print_buff_8_dbg(info, info_sz);
  int16_t er = hkdf_expand(key, ECC_KEY_LEN, info, info_sz, result, length);
  if(er < 0) {
    LOG_ERR("Error calculating when calling hkdf_expand (%d)\n", er);
    return er;
  }
  return length;
}
static uint8_t
calc_mac(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t mac_num, uint8_t *mac, uint8_t mac_len)
{

  if(mac_num == MAC_2) {
    
    /* RH: Build context_2 */
    size_t context_2_buffer_sz = CID_LEN + ctx->session.id_cred_x.len + cbor_bstr_size(ctx->session.th.len) + ctx->session.cred_x.len;
    uint8_t context_2[context_2_buffer_sz];
    uint8_t *context_2_ptr = context_2;
    /* RH: Add C_R */
    if(ROLE == INITIATOR) {
      context_2_ptr[0] = (uint8_t) ctx->session.cid_rx;
    } else {
      context_2_ptr[0] = (uint8_t) ctx->session.cid;
    }
    context_2_ptr += CID_LEN;
    memcpy(context_2_ptr, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);
    context_2_ptr += ctx->session.id_cred_x.len;
    cbor_put_bytes(&context_2_ptr, ctx->session.th.buf, ctx->session.th.len);
    memcpy(context_2_ptr, ctx->session.cred_x.buf, ctx->session.cred_x.len);
    context_2_ptr += ctx->session.cred_x.len;
    LOG_DBG("CONTEXT_2 (%zu bytes): ", context_2_buffer_sz);
    print_buff_8_dbg(context_2, context_2_buffer_sz);
    
    /* RH: Create mac_info */
    size_t mac_info_buffer_sz = cbor_int_size(MAC_2_LABEL) + cbor_bstr_size(context_2_buffer_sz) + cbor_int_size(mac_len);
    uint8_t mac_info[mac_info_buffer_sz];
    size_t mac_info_sz = generate_info(mac_info, context_2, context_2_buffer_sz, mac_len, MAC_2_LABEL);
    LOG_DBG("info MAC_2 (%zu bytes): ", mac_info_sz);
    print_buff_8_dbg(mac_info, mac_info_sz);
  
    int8_t er = edhoc_expand(mac, ctx->session_keys.prk_3e2m, mac_info, mac_info_sz, mac_len);
    if(er < 0) {
      LOG_ERR("Failed to expand MAC_2\n");
      return 0;
    }
  } else if(mac_num == MAC_3) {
  
    /* RH: Build context_3 */
    size_t context_3_buffer_sz = ctx->session.id_cred_x.len + cbor_bstr_size(ctx->session.th.len) + ctx->session.cred_x.len;
    uint8_t context_3[context_3_buffer_sz];
    uint8_t *context_3_ptr = context_3;
    memcpy(context_3_ptr, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);
    context_3_ptr += ctx->session.id_cred_x.len;
    cbor_put_bytes(&context_3_ptr, ctx->session.th.buf, ctx->session.th.len);
    memcpy(context_3_ptr, ctx->session.cred_x.buf, ctx->session.cred_x.len);
    context_3_ptr += ctx->session.cred_x.len;
    LOG_DBG("CONTEXT_3 (%zu bytes): ", context_3_buffer_sz);
    print_buff_8_dbg(context_3, context_3_buffer_sz);

    /* RH: Create mac_info */
    size_t mac_info_buffer_sz = cbor_int_size(MAC_3_LABEL) + cbor_bstr_size(context_3_buffer_sz) + cbor_int_size(mac_len);
    uint8_t mac_info[mac_info_buffer_sz];
    size_t mac_info_sz = generate_info(mac_info, context_3, context_3_buffer_sz, mac_len, MAC_3_LABEL);
    LOG_DBG("info MAC_3 (%zu bytes): ", mac_info_sz);
    print_buff_8_dbg(mac_info, mac_info_sz);
 
    int8_t er = edhoc_expand(mac, ctx->session_keys.prk_4e3m, mac_info, mac_info_sz, mac_len);
     if(er < 0) {
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
gen_mac(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *mac, uint8_t mac_len)
{
  uint8_t mac_num = 0;
  if(ROLE == INITIATOR) {
    mac_num = MAC_3;
  } else if(ROLE == RESPONDER) {
    mac_num = MAC_2;
  }

  if(!calc_mac(ctx, ad, ad_sz, mac_num, mac, mac_len)) {
    LOG_ERR("Set MAC error\n");
    return 0;
  }

  return mac_len;
}
static uint16_t
check_mac(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *received_mac, uint16_t received_mac_sz, uint8_t *mac)
{
  uint8_t mac_num = 0;
  if(ROLE == INITIATOR) {
    mac_num = MAC_2;
  } else if(ROLE == RESPONDER) {
    mac_num = MAC_3;
  }

  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  if(!calc_mac(ctx, ad, ad_sz, mac_num, mac, edhoc_mac_len)) {
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
gen_gxy(edhoc_context_t *ctx)
{
  uint8_t er = generate_IKM(ctx->session_keys.gx, ctx->session_keys.gy, ctx->ephemeral_key.private_key, buf, ctx->curve);
  if(er == 0) {
    LOG_ERR("error in generate shared secret\n");
    return 0;
  }
  LOG_DBG("GXY (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(buf, ECC_KEY_LEN);
  return 1;
}
static uint8_t
gen_prk_2e(edhoc_context_t *ctx)
{
  uint8_t er = 0;
  watchdog_periodic();
  er = gen_gxy(ctx);
  watchdog_periodic();
  if(er == 0) {
    return 0;
  }
  er = hkdf_extract(ctx->session.th.buf, ctx->session.th.len, buf, ECC_KEY_LEN, ctx->session_keys.prk_2e);
  if(er < 1) {
    LOG_ERR("Error in extract prk_2e\n");
    return 0;
  }
  LOG_DBG("PRK_2e (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session_keys.prk_2e, HASH_LEN);
  return 1;
}
/* Derive KEYSTREAM_2 */
static int16_t
gen_ks_2e(edhoc_context_t *ctx, uint16_t length)
{
  int er = edhoc_kdf(ctx->session_keys.ks_2e, ctx->session_keys.prk_2e, KEYSTREAM_2_LABEL, ctx->session.th, length);
  if(er < 0) {
    return er;
  }
  LOG_DBG("KEYSTREAM_2 (%d bytes): ", length);
  print_buff_8_dbg(ctx->session_keys.ks_2e, length);
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
    er = generate_IKM(ctx->session_keys.gx, ctx->session_keys.gy, key_authenticate->private_key, grx, ctx->curve);
  } else {
    er = generate_IKM(key_authenticate->public.x, key_authenticate->public.y, ctx->ephemeral_key.private_key, grx, ctx->curve);
  }
  if(er == 0) {
    LOG_ERR("error in generate shared secret for prk_3e2m\n");
    return 0;
  }
  
  size_t salt_info_buffer_sz = cbor_int_size(SALT_3E2M_LABEL) + cbor_bstr_size(ctx->session.th.len) + cbor_int_size(HASH_LEN);
  uint8_t salt_info[salt_info_buffer_sz];
  size_t salt_info_sz = generate_info(salt_info, ctx->session.th.buf, ctx->session.th.len, HASH_LEN, SALT_3E2M_LABEL);
  LOG_DBG("info SALT_3e2m (%zu bytes): ", salt_info_sz);
  print_buff_8_dbg(salt_info, salt_info_sz);
  uint8_t salt[HASH_LEN];
  er = edhoc_expand(salt, ctx->session_keys.prk_2e, salt_info, salt_info_sz, HASH_LEN);
  if(er < 1) {
    LOG_ERR("Error calculating salt (%d)\n", er);
    return 0;
  }
  LOG_DBG("SALT_3e2m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(salt, HASH_LEN);
  er = hkdf_extract(salt, HASH_LEN, grx, ECC_KEY_LEN, ctx->session_keys.prk_3e2m);
  if(er < 1) {
    LOG_ERR("error in extract for prk_3e2m\n");
    return 0;
  }
  LOG_DBG("PRK_3e2m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session_keys.prk_3e2m, HASH_LEN);
  return 1;
}
static uint8_t
gen_prk_4e3m(edhoc_context_t *ctx, cose_key_t *cose_auth_key, uint8_t gen)
{
  uint8_t giy[ECC_KEY_LEN];
  int8_t er = 0;
  
  ecc_key authenticate;
  initialize_ecc_key_from_cose(&authenticate, cose_auth_key, ctx->curve);
  ecc_key *key_authenticate = &authenticate;
  
  if(gen) {
    er = generate_IKM(key_authenticate->public.x, key_authenticate->public.y, ctx->ephemeral_key.private_key, giy, ctx->curve);
  } else {
    er = generate_IKM(ctx->session_keys.gx, ctx->session_keys.gy, key_authenticate->private_key, giy, ctx->curve); /* G_IY = G_Y and I //Initiator (U):  //Initiator U */
  }
  LOG_DBG("G_IY (ECDH shared secret) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(giy, ECC_KEY_LEN);
  if(er == 0) {
    LOG_ERR("error in generate shared secret for prk_4e3m\n");
    return 0;
  }
  
  size_t salt_info_buffer_sz = cbor_int_size(SALT_4E3M_LABEL) + cbor_bstr_size(ctx->session.th.len) + cbor_int_size(HASH_LEN);
  uint8_t salt_info[salt_info_buffer_sz];
  size_t salt_info_sz = generate_info(salt_info, ctx->session.th.buf, ctx->session.th.len, HASH_LEN, SALT_4E3M_LABEL);
  LOG_DBG("info SALT_4e3m (%zu bytes): ", salt_info_sz);
  print_buff_8_dbg(salt_info, salt_info_sz);
  uint8_t salt[HASH_LEN];
  er = edhoc_expand(salt, ctx->session_keys.prk_3e2m, salt_info, salt_info_sz, HASH_LEN);
  if(er < 1) {
    LOG_ERR("Error calculating salt (%d)\n", er);
    return 0;
  }
  LOG_DBG("SALT_4e3m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(salt, HASH_LEN);
  er = hkdf_extract(salt, HASH_LEN, giy, ECC_KEY_LEN, ctx->session_keys.prk_4e3m);
  if(er < 1) {
    LOG_ERR("error in extract for prk_4e3m\n");
    return 0;
  }
  LOG_DBG("PRK_4e3m (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(ctx->session_keys.prk_4e3m, HASH_LEN);
  return 1;
}
static void
gen_ciphertext_2(edhoc_context_t *ctx, uint8_t *plaintext, uint16_t plaintext_sz)
{
  for(int i = 0; i < plaintext_sz; i++) {
    plaintext[i] = plaintext[i] ^ ctx->session_keys.ks_2e[i];
  }
}
static uint16_t
decrypt_ciphertext_3(edhoc_context_t *ctx, uint8_t *ciphertext, uint16_t ciphertext_sz, uint8_t *plaintext)
{
  cose_encrypt0 *cose = cose_encrypt0_new();
  /* set external AAD in cose */
  cose_encrypt0_set_content(cose, NULL, 0, NULL, 0);
  uint8_t *th3_ptr = cose->external_aad;
  memcpy(th3_ptr, ctx->session.th.buf, ctx->session.th.len);
  cose->external_aad_sz = ctx->session.th.len;

  cose_encrypt0_set_ciphertext(cose, ciphertext, ciphertext_sz);
  /* COSE encrypt0 set header */
  cose_encrypt0_set_header(cose, NULL, 0, NULL, 0);
  
  /* generate K_3 */
  cose->alg = get_edhoc_cose_enc_alg(ctx->session.suite_selected);
  cose->key_sz = get_cose_key_len(cose->alg);
  int8_t er = edhoc_kdf(cose->key, ctx->session_keys.prk_3e2m, K_3_LABEL, ctx->session.th, cose->key_sz);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  LOG_DBG("K_3 (%d bytes): ", cose->key_sz);
  print_buff_8_dbg(cose->key, cose->key_sz);

  /* generate IV_3 */
  cose->nonce_sz = get_cose_iv_len(cose->alg);
  er = edhoc_kdf(cose->nonce, ctx->session_keys.prk_3e2m, IV_3_LABEL, ctx->session.th, cose->nonce_sz);
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
gen_plaintext(uint8_t *buffer, edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz, bool msg2, uint8_t mac_or_signature_sz)
{
  uint8_t *pint = (ctx->session.id_cred_x.buf);
  uint8_t *pout = buffer;
  uint8_t num = edhoc_get_maps_num(&pint);
  uint8_t *buf_ptr = &(buffer[0]);

  size_t size;
  if (msg2) {
      size = edhoc_put_byte_identifier(&buf_ptr, (uint8_t *)&ctx->session.cid, CID_LEN);
  } else {
      size = 0;
  }

  if(num == 1) {
    num = (uint8_t)edhoc_get_unsigned(&pint);
    size_t sz = edhoc_get_bytes(&pint, &pout);
    if(sz == 0 || num < 0) {
      LOG_ERR("error to get bytes\n");
      return 0;
    }
    if(sz == 1 && (pout[0] < 0x18 || (0x20 <= pout[0] && pout[0] <= 0x37))) {
      size += cbor_put_num(&buf_ptr, pout[0]);
    } else {
      size += cbor_put_bytes(&buf_ptr, pout, sz);
    }
  } else {
    memcpy(buf_ptr, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);
    size += ctx->session.id_cred_x.len;
  }

  size += cbor_put_bytes(&buf_ptr, &(mac_or_sig[0]), mac_or_signature_sz);
  if(ad_sz != 0) {
    size += cbor_put_bytes(&buf_ptr, ad, ad_sz);
  }

  return size;
}
static uint16_t
gen_ciphertext_3(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *mac, uint16_t mac_sz, uint8_t *ciphertext)
{
  int8_t er = 0;
  cose_encrypt0 *cose = cose_encrypt0_new();
  /* set external AAD in cose */
  uint8_t *th3_ptr = cose->external_aad;
  cose->external_aad_sz = ctx->session.th.len;
  memcpy(th3_ptr, ctx->session.th.buf, ctx->session.th.len);

  cose->plaintext_sz = gen_plaintext(cose->plaintext, ctx, ad, ad_sz, false, mac_sz);
  LOG_DBG("PLAINTEXT_3 (%d bytes): ", (int)cose->plaintext_sz);
  print_buff_8_dbg(cose->plaintext, cose->plaintext_sz);

  /* RH: Modified to store plaintext 3 WIP */
  memcpy(buf, cose->plaintext, cose->plaintext_sz);
  ctx->session.plaintext_3.buf = buf;
  ctx->session.plaintext_3.len = cose->plaintext_sz;
  
  /* generate K_3 */
  cose->alg = get_edhoc_cose_enc_alg(ctx->session.suite_selected);
  cose->key_sz = get_cose_key_len(cose->alg);
  er = edhoc_kdf(cose->key, ctx->session_keys.prk_3e2m, K_3_LABEL, ctx->session.th, cose->key_sz);
  if(er < 1) {
    LOG_ERR("error in expand for decrypt ciphertext 3\n");
    return 0;
  }
  LOG_DBG("K_3 (%d bytes): ", (int)cose->key_sz);
  print_buff_8_dbg(cose->key, cose->key_sz);

  /* generate IV_3 */
  uint8_t iv_len = get_cose_iv_len(cose->alg);
  er = edhoc_kdf(cose->nonce, ctx->session_keys.prk_3e2m, IV_3_LABEL, ctx->session.th, iv_len);
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
    ctx->authen_key.identity_size = key->identity_sz;
    return 1;
  } else {
    LOG_ERR("Does not contains a key for the authentication key identity\n");
  }
#endif

#ifdef AUTH_KID
  cose_key_t *key;
  uint8_t key_id[sizeof(int)];
  uint8_t key_id_sz = 1;
  int kid = AUTH_KID;
  int quotient = (AUTH_KID / 256);
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
    ctx->authen_key.identity_size = key->identity_sz;
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
    .suites_i = { .buf = ctx->session.suite, .len = ctx->session.suite_num},
    .g_x = (bstr){ (uint8_t *)&ctx->ephemeral_key.public.x, ECC_KEY_LEN},
    .c_i = (bstr){ (uint8_t *)&ctx->session.cid, CID_LEN },
    .uad = (ead_data){ .ead_label = 0, .ead_value = (bstr){ ad, ad_sz }},
  };

  /* CBOR encode message in the buffer */
  size_t size = edhoc_serialize_msg_1(&msg1, ctx->msg_tx, suite_array);
  ctx->tx_sz = size;

  LOG_DBG("C_I chosen by Initiator (%d bytes): 0x", (int)msg1.c_i.len);
  print_buff_8_dbg(msg1.c_i.buf, msg1.c_i.len);
  LOG_DBG("AD_1 (%d bytes): ", (int)ad_sz);
  print_char_8_dbg((char *)ad, ad_sz);
  for(int i = 0; i < msg1.suites_i.len; ++i) {
      LOG_DBG("SUITES_I[%d]: %d\n", i, (int) msg1.suites_i.buf[i]);
  }
  LOG_DBG("message_1 (CBOR Sequence) (%d bytes): ", (int)ctx->tx_sz);
  print_buff_8_dbg(ctx->msg_tx, ctx->tx_sz);
  LOG_INFO("MSG1 sz: %d\n", (int)ctx->tx_sz);
}
uint8_t
edhoc_gen_msg_2(edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz)
{
  ctx->session.th.buf = ctx->session_keys.th;
  ctx->session.th.len = HASH_LEN;

  int8_t rv = gen_th2(ctx, ctx->ephemeral_key.public.x, ctx->msg_rx, ctx->rx_sz);
  if(rv < 0) {
    LOG_ERR("Failed to generate TH_2 (%d)\n", rv);
    return -1;
  }

  /* The COSE key include the authentication key */
  cose_key_t cose;
  convert_ecc_key_to_cose_key(&ctx->authen_key, &cose, ctx->authen_key.identity, ctx->authen_key.identity_size);

  /* generate id_cred_x and cred_x */
  ctx->session.cred_x.buf = cred_x;
  ctx->session.cred_x.len = generate_cred_x(&cose, ctx->session.cred_x.buf);
  LOG_DBG("CRED_R (%d bytes): ", (int)ctx->session.cred_x.len);
  print_buff_8_dbg(ctx->session.cred_x.buf, ctx->session.cred_x.len);

  ctx->session.id_cred_x.buf = id_cred_x;
  ctx->session.id_cred_x.len = generate_id_cred_x(&cose, ctx->session.id_cred_x.buf);
  LOG_DBG("ID_CRED_R (%d bytes): ", (int)ctx->session.id_cred_x.len);
  print_buff_8_dbg(ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);

  gen_prk_2e(ctx);

  /* generate prk_3e2m */
  gen_prk_3e2m(ctx, &cose, 1);

  uint8_t mac_or_signature_sz = -1;

  /* Generate MAC or Signature */

#if ((METHOD == METH1) || (METHOD == METH3))
  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  gen_mac(ctx, ad, ad_sz, mac_or_sig, edhoc_mac_len);
  LOG_DBG("MAC_2 (%d bytes): ", edhoc_mac_len);
  print_buff_8_dbg(mac_or_sig, edhoc_mac_len);
  mac_or_signature_sz = edhoc_mac_len;
#endif

#if ((METHOD == METH0) || (METHOD == METH2))
  // Derive MAC with HASH_LEN size
  gen_mac(ctx, ad, ad_sz, mac_or_sig, HASH_LEN);
  LOG_DBG("MAC_2 (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(mac_or_sig, HASH_LEN);

  /* Create signature from MAC and other data using COSE_Sign1 */
  
  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len, NULL, 0);
  
  // External AAD
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, ctx->session.cred_x.buf, ctx->session.cred_x.len);
  aad_ptr += ctx->session.cred_x.len;
  memcpy(aad_ptr, ctx->session.th.buf, ctx->session.th.len);
  cose_sign1->external_aad_sz = ctx->session.cred_x.len + ctx->session.th.len;
  
  // Payload
  uint8_t er = cose_sign1_set_payload(cose_sign1, mac_or_sig, HASH_LEN);
  if(er < 0) {
    LOG_ERR("Failed to set payload in COSE_Sign1 object\n");
    return -1;
  }

  cose_sign1_set_key(cose_sign1, ES256, ctx->authen_key.private_key, ECC_KEY_LEN);
  er = cose_sign(cose_sign1);
  if(er < 0) {
    LOG_ERR("Failed to sign for COSE_Sign1 object\n");
    return -1;
  }

  cose_sign1_finalize(cose_sign1);

  LOG_DBG("Signature from COSE_Sign1 (%d bytes): ", P256_SIGNATURE_LEN);
  print_buff_8_dbg(cose_sign1->signature, P256_SIGNATURE_LEN);

  mac_or_signature_sz = P256_SIGNATURE_LEN;
  memcpy(mac_or_sig, cose_sign1->signature, cose_sign1->signature_sz);
#endif

  uint16_t p_sz = gen_plaintext(buf, ctx, ad, ad_sz, true, mac_or_signature_sz);
  LOG_DBG("PLAINTEXT_2 (%d bytes): ", (int)p_sz);
  print_buff_8_dbg(buf, p_sz);
  gen_ks_2e(ctx, p_sz);

  gen_ciphertext_2(ctx, buf, p_sz);

  LOG_DBG("CIPHERTEXT_2 (%d bytes): ", (int)p_sz);
  print_buff_8_dbg(buf, p_sz);
  
  /* set ciphertext in msg tx */
  // TODO: Check why saving in ctx->session.plaintext
  uint8_t *ptr = &(ctx->msg_tx[0]);
  int sz = cbor_put_bytes(&ptr, ctx->ephemeral_key.public.x, ECC_KEY_LEN);
  ctx->session.plaintext_2.buf = ptr;
  memcpy(ptr, buf, p_sz);
  ctx->session.plaintext_2.len = p_sz;
  ctx->tx_sz = sz + ctx->session.plaintext_2.len;
  ctx->msg_tx[1] = ctx->tx_sz - 2;
  LOG_INFO("MSG2 sz: %d\n", ctx->tx_sz);
  
  return 1;
}
void
edhoc_gen_msg_3(edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz)
{
  /* gen TH_3 */
  /* Set the pointer to TH_2 */
  ctx->session.th.buf = ctx->session_keys.th;
  ctx->session.th.len = HASH_LEN;

  gen_th3(ctx, ctx->session.cred_x.buf, ctx->session.cred_x.len, ctx->session.plaintext_2.buf, ctx->session.plaintext_2.len);
  /* Generate COSE authentication key */
  cose_key_t cose;
  convert_ecc_key_to_cose_key(&ctx->authen_key, &cose, ctx->authen_key.identity, ctx->authen_key.identity_size);

  cose_print_key(&cose);
  LOG_DBG("SK_I (Initiator's private authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.private_key, ECC_KEY_LEN);

  LOG_DBG("G_I (x)(Initiator's public authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.public.x, ECC_KEY_LEN);

  LOG_DBG("(y) (Initiator's public authentication key) (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(ctx->authen_key.public.y, ECC_KEY_LEN);

  /* generate cred_x */
  ctx->session.cred_x.buf = cred_x;
  ctx->session.cred_x.len = generate_cred_x(&cose, ctx->session.cred_x.buf);
  LOG_DBG("CRED_I (%d bytes): ", (int)ctx->session.cred_x.len);
  print_buff_8_dbg(ctx->session.cred_x.buf, ctx->session.cred_x.len);

  /* generate id_cred_x */
  ctx->session.id_cred_x.buf = id_cred_x;
  ctx->session.id_cred_x.len = generate_id_cred_x(&cose, ctx->session.id_cred_x.buf);
  LOG_DBG("ID_CRED_I (%d bytes): ", (int)ctx->session.id_cred_x.len);
  print_buff_8_dbg(ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);

  /* Generate prk_4e3m */
  gen_prk_4e3m(ctx, &cose, 0);

  uint8_t mac_or_signature_sz = -1;

#if ((METHOD == METH0) || (METHOD == METH1))

  // Derive MAC with HASH_LEN size
  gen_mac(ctx, ad, ad_sz, mac_or_sig, HASH_LEN);
  LOG_DBG("MAC_3 (%d bytes): ", HASH_LEN);
  print_buff_8_dbg(mac_or_sig, HASH_LEN);

  /* Create signature from MAC and other data using COSE_Sign1 */

  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len, NULL, 0);

  // External AAD
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, ctx->session.cred_x.buf, ctx->session.cred_x.len);
  aad_ptr += ctx->session.cred_x.len;
  memcpy(aad_ptr, ctx->session.th.buf, ctx->session.th.len);
  cose_sign1->external_aad_sz = ctx->session.cred_x.len + ctx->session.th.len;

  // Payload
  uint8_t er = cose_sign1_set_payload(cose_sign1, mac_or_sig, HASH_LEN);
  if(er < 0) {
    LOG_ERR("Failed to set payload in COSE_Sign1 object\n");
    return;
  }

  cose_sign1_set_key(cose_sign1, ES256, ctx->authen_key.private_key, ECC_KEY_LEN);
  er = cose_sign(cose_sign1);
  if(er < 0) {
    LOG_ERR("Failed to sign for COSE_Sign1 object\n");
    return;
  }

  cose_sign1_finalize(cose_sign1);

  LOG_DBG("Signature from COSE_Sign1 (%d bytes): ", P256_SIGNATURE_LEN);
  print_buff_8_dbg(cose_sign1->signature, P256_SIGNATURE_LEN);

  mac_or_signature_sz = P256_SIGNATURE_LEN;
  memcpy(mac_or_sig, cose_sign1->signature, cose_sign1->signature_sz);
#endif

#if ((METHOD == METH2) || (METHOD == METH3))
  uint8_t edhoc_mac_len = get_edhoc_mac_len(ctx->session.suite_selected);
  gen_mac(ctx, ad, ad_sz, mac_or_sig, edhoc_mac_len);
  LOG_DBG("MAC 3 (%d bytes): ", edhoc_mac_len);
  print_buff_8_dbg(mac_or_sig, edhoc_mac_len);
  mac_or_signature_sz = edhoc_mac_len;
#endif

  /* time = RTIMER_NOW(); */
  /* Gen ciphertext_3 */
  uint16_t ciphertext_sz = gen_ciphertext_3(ctx, ad, ad_sz, mac_or_sig, mac_or_signature_sz, ctx->msg_tx);
  ctx->tx_sz = ciphertext_sz;
  
  /* Compute TH_4 WIP */
  gen_th4(ctx, ctx->session.cred_x.buf, ctx->session.cred_x.len, ctx->session.plaintext_3.buf, ctx->session.plaintext_3.len);
}

uint8_t
edhoc_gen_msg_error(uint8_t *msg_er, edhoc_context_t *ctx, int8_t err)
{
  edhoc_msg_error msg;
  msg.err_code = 1;
  switch(err * (-1)) {
  default:
    msg.err_info = (sstr){ "ERR_UNKNOWN", strlen("ERR_UNKNOWN") };
    break;
  case (ERR_SUITE_NON_SUPPORT * (-1)):
    msg.err_info = (sstr){ "ERR_SUITE_NON_SUPPORT", strlen("ERR_SUITE_NON_SUPPORT") };
    break;
  case (ERR_MSG_MALFORMED * (-1)):
    msg.err_info = (sstr){ "ERR_MSG_MALFORMED", strlen("ERR_MSG_MALFORMED") };
    break;
  case (ERR_REJECT_METHOD * (-1)):
    msg.err_info = (sstr){ "ERR_REJECT_METHOD", strlen("ERR_REJECT_METHOD") };
    break;
  case (ERR_CID_NOT_VALID * (-1)):
    msg.err_info = (sstr){ "ERR_CID_NOT_VALID", strlen("ERR_CID_NOT_VALID") };
    break;
  case (ERR_WRONG_CID_RX * (-1)):
    msg.err_info = (sstr){ "ERR_WRONG_CID_RX", strlen("ERR_WRONG_CID_RX") };
    break;
  case (ERR_ID_CRED_X_MALFORMED * (-1)):
    msg.err_info = (sstr){ "ERR_ID_CRED_X_MALFORMED", strlen("ERR_ID_CRED_X_MALFORMED") };
    break;
  case (ERR_AUTHENTICATION * (-1)):
    msg.err_info = (sstr){ "ERR_AUTHENTICATION", strlen("ERR_AUTHENTICATION") };
    break;
  case (ERR_DECRYPT * (-1)):
    msg.err_info = (sstr){ "ERR_DECRYPT", strlen("ERR_DECRYPT") };
    break;
  case (ERR_CODE * (-1)):
    msg.err_info = (sstr){ "ERR_CODE", strlen("ERR_CODE") };
    break;
  case (ERR_NOT_ALLOWED_IDENTITY * (-1)):
    msg.err_info = (sstr){ "ERR_NOT_ALLOWED_IDENTITY", strlen("ERR_NOT_ALLOWED_IDENTITY") };
    break;
  case (RX_ERR_MSG * (-1)):
    msg.err_info = (sstr){ "RX_ERR_MSG", strlen("RX_ERR_MSG") };
    break;
  case (ERR_TIMEOUT * (-1)):
    msg.err_info = (sstr){ "ERR_TIMEOUT", strlen("ERR_TIMEOUT") };
    break;
  case (ERR_CORRELATION * (-1)):
    msg.err_info = (sstr){ "ERR_CORRELATION", strlen("ERR_CORRELATION") };
    break;
  case (ERR_NEW_SUITE_PROPOSE * (-1)): {
    msg.err_code = 2;
    msg.err_info = (sstr) { (char *)ctx->session.suite, ctx->session.suite_num * sizeof(ctx->session.suite[0]) };
    break;
  }
  case (ERR_RESEND_MSG_1 * (-1)):
    msg.err_info = (sstr){ "ERR_RESEND_MSG_1", strlen("ERR_RESEND_MSG_1") };
    break;
  }

  LOG_ERR("ERR MSG (%d): ", msg.err_code);
  if(msg.err_code == 1) {
    print_char_8_err(msg.err_info.buf, msg.err_info.len);
  } else {
    printf("\n");
  }

  size_t err_sz = edhoc_serialize_err(&msg, msg_er);
  LOG_DBG("ERR MSG CBOR: ");
  print_buff_8_dbg((uint8_t *)msg_er, err_sz);
  return err_sz;
}
int8_t
edhoc_check_rx_msg(uint8_t *buffer, uint8_t buff_sz)
{
  /* Check if the rx msg is an msg_err */
  uint8_t *msg_err = buffer;
  edhoc_msg_error err;
  int8_t msg_err_sz = 0;
  msg_err_sz = edhoc_deserialize_err(&err, msg_err, buff_sz);
  if(msg_err_sz > 0) {
    LOG_ERR("RX MSG_ERR: ");
    print_char_8_err(err.err_info.buf, err.err_info.len);
    return RX_ERR_MSG;
  }
  if(msg_err_sz == -1) {
    LOG_ERR("RX MSG_ERROR WITH SUITE PROPOSE: ");
    print_char_8_err(err.err_info.buf, err.err_info.len);
    return RX_ERR_MSG;
  }
  return 0;
}
int8_t
edhoc_check_rx_msg_2(uint8_t *buffer, uint8_t buff_sz,edhoc_context_t* ctx)
{
  /* Check if the rx msg is an msg_err */
  uint8_t *msg_err = buffer;
  edhoc_msg_error err = { 0 };

  int8_t msg_err_sz = edhoc_deserialize_err(&err, msg_err, buff_sz);
  if(msg_err_sz < 0) {
    LOG_ERR("RX MSG_ERR: ");
    print_char_8_err(err.err_info.buf, err.err_info.len);
    return RX_ERR_MSG;
  }
  return 0;
}
int
edhoc_handler_msg_1(edhoc_context_t *ctx, uint8_t *buffer, size_t buff_sz, uint8_t *ad)
{

  edhoc_msg_1 msg1 = { 0 };
  int er = 0;
  /* Decode MSG1 */
  set_rx_msg(ctx, buffer, buff_sz);

  /* Check if the rx msg is an msg_err */
  er = edhoc_check_rx_msg(buffer, buff_sz);
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
  er = check_rx_suite_i(ctx, msg1.suites_i);
  if(er < 0) {
    LOG_ERR("Rx Suite not supported\n");
    return er;
  }

  /* Check to not have the same cid */
  er = set_rx_cid(ctx, msg1.c_i.buf, msg1.c_i.len);
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
  set_rx_gx(ctx, msg1.g_x.buf);
  print_session_info(&ctx->session);

  LOG_DBG("MSG EAD (%d)", (int)msg1.uad.ead_value.len);
  print_char_8_dbg((char *)msg1.uad.ead_value.buf, msg1.uad.ead_value.len);

  if(msg1.uad.ead_value.len != 0) {
    memcpy(ad, msg1.uad.ead_value.buf, msg1.uad.ead_value.len);
  } else {
    ad = NULL;
  }
  return msg1.uad.ead_value.len;
}
int
edhoc_handler_msg_2(edhoc_msg_2 *msg2, edhoc_context_t *ctx, uint8_t *buffer, size_t buff_sz)
{
  int er = 0;
  set_rx_msg(ctx, buffer, buff_sz);
  er = edhoc_check_rx_msg_2(buffer, buff_sz, ctx);
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

  set_rx_gx(ctx, msg2->g_y_ciphertext_2.buf);
  ctx->session.th.buf = ctx->session_keys.th;
  ctx->session.th.len = HASH_LEN;
  gen_th2(ctx, msg2->g_y_ciphertext_2.buf, ctx->msg_tx, ctx->tx_sz);
  gen_prk_2e(ctx);
  /* Gen KS_2e */
  int ciphertext2_sz = msg2->g_y_ciphertext_2.len - ECC_KEY_LEN;
  gen_ks_2e(ctx, ciphertext2_sz);

  /* Set ciphertext */
  // TODO: Check why saving in ctx->session.plaintext
  ctx->session.plaintext_2.buf = msg2->g_y_ciphertext_2.buf + ECC_KEY_LEN;
  ctx->session.plaintext_2.len = ciphertext2_sz;

  /* Decrypted cipher text */
  memcpy(buf, msg2->g_y_ciphertext_2.buf + ECC_KEY_LEN, ciphertext2_sz);
  LOG_DBG("CIPHERTEXT_2 (%d bytes): ", ciphertext2_sz);
  print_buff_8_dbg(buf, ciphertext2_sz);
  gen_ciphertext_2(ctx, buf, ciphertext2_sz);
  memcpy(msg2->g_y_ciphertext_2.buf + ECC_KEY_LEN, buf, ciphertext2_sz);
  LOG_DBG("PLAINTEXT_2 (%d bytes): ", ciphertext2_sz);
  print_buff_8_dbg(msg2->g_y_ciphertext_2.buf + ECC_KEY_LEN, ciphertext2_sz);

  int cr_sz = CID_LEN;
  er = set_rx_cid(ctx, buf, cr_sz);
  if(er < 0) {
    return er;
  }
  LOG_DBG("cid (%d)\n", (uint8_t)ctx->session.cid_rx);
  ctx->session.id_cred_x.buf = buf + cr_sz;
  LOG_DBG("ID_CRED_R (%d bytes): ", 1);
  print_buff_8_dbg(ctx->session.id_cred_x.buf, 1);
  print_session_info(&ctx->session);
  return 1;
}
int
edhoc_get_auth_key(edhoc_context_t *ctx, uint8_t **pt, cose_key_t *key)
{
  *pt = ctx->session.id_cred_x.buf;

  int len = edhoc_get_id_cred_x(pt, &ctx->session.id_cred_x.buf, key);
  if(len == 0) {
    LOG_ERR("error code (%d)\n", ERR_ID_CRED_X_MALFORMED);
    return ERR_ID_CRED_X_MALFORMED;
  } else if(len < 0) {
    LOG_ERR("error code1 (%d)\n", ERR_CID_NOT_VALID);
    return ERR_CID_NOT_VALID;
  }
  ctx->session.id_cred_x.len = len;
  LOG_DBG("ID_CRED_X (for MAC) (%zu): ", ctx->session.id_cred_x.len);
  print_buff_8_dbg(ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);
  return 1;
}
int
edhoc_handler_msg_3(edhoc_msg_3 *msg3, edhoc_context_t *ctx, uint8_t *buffer, size_t buff_sz)
{
  /* Decode MSG3 */
  set_rx_msg(ctx, buffer, buff_sz);

  /* Check if the rx msg is an msg_err */
  if(edhoc_check_rx_msg(buffer, buff_sz) < 0) {
    return RX_ERR_MSG;
  }

  int8_t er = edhoc_deserialize_msg_3(msg3, ctx->msg_rx, ctx->rx_sz);
  if(er < 0) {
    LOG_ERR("MSG3 malformed\n");
    return er;
  }
  print_msg_3(msg3);

  LOG_DBG("CIPHERTEXT_3 (%d bytes): ", (int)msg3->ciphertext_3.len);
  print_buff_8_dbg(msg3->ciphertext_3.buf, msg3->ciphertext_3.len);

  /* generate TH_3 */
  gen_ciphertext_2(ctx, ctx->session.plaintext_2.buf, ctx->session.plaintext_2.len);
  gen_th3(ctx, ctx->session.cred_x.buf, ctx->session.cred_x.len, ctx->session.plaintext_2.buf, ctx->session.plaintext_2.len);

  /* decrypt msg3 and check the TAG for verify the outer */
  uint16_t plaintext_sz = decrypt_ciphertext_3(ctx, msg3->ciphertext_3.buf, msg3->ciphertext_3.len, buf);
  if(plaintext_sz == 0) {
    LOG_ERR("Error in decrypt ciphertext 3\n");
    return ERR_DECRYPT;
  }
  LOG_DBG("PLAINTEXT_3 (%d): ", (int)plaintext_sz);
  print_buff_8_dbg(buf, plaintext_sz);
  ctx->session.id_cred_x.buf = buf; //RH: Why is this done?
  
  /* RH: Save the plaintext in the ctx object WIP */
  ctx->session.plaintext_3.buf = buf;
  ctx->session.plaintext_3.len = plaintext_sz;

  return 1;
}
static int //RH: Added this
retrieve_cred_i(edhoc_context_t *ctx, uint8_t *inf, bstr *cred_i)
{
  // Get the cose_key_t version of the auth cred  
  uint8_t *auth_key_buffer = NULL;
  cose_key_t auth_cose_key_t;
  int8_t er = edhoc_get_auth_key(ctx, &auth_key_buffer, &auth_cose_key_t);
  if(er != 1) {
    return er;
  }

  // Use inf buffer for CRED_I
  cred_i->buf = inf;
  cred_i->len = sizeof(inf);

  // Build the CRED_I value
  int cred_i_size = generate_cred_x(&auth_cose_key_t, cred_i->buf);
  if(cred_i_size <= 0) {
    return ERR_ID_CRED_X_MALFORMED;
  }
  cred_i->len = cred_i_size;

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
  uint16_t ad_sz = cipher_len - (*ptr - buf);

  /* Get the ad from the decrypt msg*/
  if(ad_sz) {
    ad_sz = edhoc_get_ad(ptr, ad);
  } else {
    ad = NULL;
    ad_sz = 0;
  }

  ctx->session.cred_x.buf = inf;
  ctx->session.cred_x.len = generate_cred_x(key, ctx->session.cred_x.buf);
  LOG_DBG("CRED_R auth (%zu): ", ctx->session.cred_x.len);
  print_buff_8_dbg(ctx->session.cred_x.buf, ctx->session.cred_x.len);

  if(ROLE == INITIATOR) {
    gen_prk_3e2m(ctx, key, 0);
  } else if(ROLE == RESPONDER) {
    gen_prk_4e3m(ctx, key, 1);
  }

  ctx->session.id_cred_x.len = reconstruct_id_cred_x(ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len);
  ctx->session.id_cred_x.buf = id_cred_x;

#if (METHOD == METH3) || INITIATOR_METH1 || RESPONDER_METH2
  if(check_mac(ctx, ad, ad_sz, received_mac, received_mac_sz, mac_or_sig) == 0) {
    LOG_ERR("error code in handler (%d)\n", ERR_AUTHENTICATION);
    return ERR_AUTHENTICATION;
  }
#endif
#if (METHOD == METH0) || INITIATOR_METH2 || RESPONDER_METH1
  /* Create signature from MAC and other data using COSE_Sign1 */

  // Protected
  cose_sign1 *cose_sign1 = cose_sign1_new();
  cose_sign1_set_header(cose_sign1, ctx->session.id_cred_x.buf, ctx->session.id_cred_x.len, NULL, 0);

  // External AAD (CRED_I and TH)
  bstr cred_i_sig;
  int8_t er2 = retrieve_cred_i(ctx, inf, &cred_i_sig);
  if(er2 != 1) {
    return ERR_AUTHENTICATION;
  }
  uint8_t *aad_ptr = cose_sign1->external_aad;
  memcpy(aad_ptr, cred_i_sig.buf, cred_i_sig.len);
  aad_ptr += cred_i_sig.len;
  memcpy(aad_ptr, ctx->session.th.buf, ctx->session.th.len);
  cose_sign1->external_aad_sz = cred_i_sig.len + ctx->session.th.len;

  // Set received signature
  cose_sign1_set_signature(cose_sign1, received_mac, received_mac_sz);

  // Payload (MAC)
  uint8_t mac_num = -1;
  if(ROLE == INITIATOR) {
    mac_num = MAC_2;
  } else {
    mac_num = MAC_3;
  }
  calc_mac(ctx, ad, ad_sz, mac_num, mac_or_sig, HASH_LEN);
  LOG_DBG("MAC_%d (%d bytes): ", mac_num == 2 ? 2 : 3, HASH_LEN); // MAC_2 or 3
  print_buff_8_dbg(mac_or_sig, HASH_LEN);
  er2 = cose_sign1_set_payload(cose_sign1, mac_or_sig, HASH_LEN);
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
    // Start by retrieving CRED_I
    bstr cred_i;
    int8_t er = retrieve_cred_i(ctx, inf, &cred_i);
    if(er != 1) {
      return ERR_AUTHENTICATION;
    }

    // Actually calculate TH_4
    gen_th4(ctx, cred_i.buf, cred_i.len, ctx->session.plaintext_3.buf, ctx->session.plaintext_3.len);
  }  

  return ad_sz;
}
uint8_t //RH: WIP
cbor_bstr_size(uint32_t len) {
  if (len <= 23) {
    return 1 + len; // 1 byte total for encoding
  } else if (len <= 255) {
    return 2 + len; // 1 byte for 0x18 + 1 byte for the length
  } else if (len <= 65535) {
    return 3 + len; // 1 byte for 0x19 + 2 bytes for the length
  } else if (len <= 4294967295) {
    return 5 + len; // 1 byte for 0x1A + 4 bytes for the length
  } else {
    return 9 + len; // 1 byte for 0x1B + 8 bytes for the length
  }
}
uint8_t //RH: WIP
cbor_int_size(int32_t num) {
  if (num >= -24 && num <= 23) {
    return 1;
  } else if (num >= -256 && num <= 255) {
    return 2;
  } else if (num >= -32768 && num <= 65535) {
    return 3;
  } else if (num >= -2147483648 && num <= 4294967295) {
    return 5;
  }
  return 0;
}

