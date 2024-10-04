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
 *         edhoc-msg serialize and deserialize the EDHOC msgs using the CBOR library
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */
#include "contiki-lib.h"
#include "edhoc-msgs.h"
#include "lib/random.h"

void
print_msg_1(edhoc_msg_1 *msg)
{
  LOG_DBG("Type: %d\n", msg->method);
  LOG_DBG("Suit I:");
  print_buff_8_dbg(msg->suites_i.buf,msg->suites_i.len);
  LOG_DBG("Gx: ");
  print_buff_8_dbg(msg->g_x.buf, msg->g_x.len);
  LOG_DBG("Ci: ");
  print_buff_8_dbg(msg->c_i.buf, msg->c_i.len);
  LOG_DBG("Uad (label: %d): ", msg->uad.ead_label);
  print_buff_8_dbg(msg->uad.ead_value.buf, msg->uad.ead_value.len);
}
void
print_msg_2(edhoc_msg_2 *msg)
{
  LOG_DBG("g_y_ciphertext_2: ");
  print_buff_8_dbg(msg->g_y_ciphertext_2.buf, msg->g_y_ciphertext_2.len);
}
void
print_msg_3(edhoc_msg_3 *msg)
{
  LOG_DBG("ciphertext_3: ");
  print_buff_8_dbg(msg->ciphertext_3.buf, msg->ciphertext_3.len);
}
static uint8_t
get_byte(uint8_t **in)
{
  uint8_t out = **in;
  (*in)++;
  return out;
}
int16_t
edhoc_get_unsigned(uint8_t **in)
{
  uint8_t byte = get_byte(in);

  if(byte < 0x18) {

    return byte;
  } else if(byte == 0x18) {
    return get_byte(in);
  } else {
     (*in)--;
    return -1;
  }
}
static int64_t
get_negative(uint8_t **in)
{
  uint8_t byte = get_byte(in);

  int64_t num = 0;
  if(byte < 0x38) {

    num = byte ^ 0x20;
  } else if(byte == 0x38) {
    byte = get_byte(in);
    num = byte ^ 0x20;
  } else {
    LOG_ERR("get not negative\n ");
    return 0;
  }
  num++;
  return num;
}
static uint8_t *
point_byte(uint8_t **in)
{
  uint8_t *out = *in;
  (*in)++;
  return out;
}
size_t
edhoc_get_bytes(uint8_t **in, uint8_t **out)
{
  uint8_t byte = get_byte(in);
  size_t size;
  if(byte == 0x58) {
    size = get_byte(in);
    *out = *in;
    *in = (*in + size);
    return size;
  } else if((0x40 <= byte) && (byte < 0x58)) {
    size = byte ^ 0x40;
    *out = *in;
    *in = (*in + size);
    return size;
  } else {
    (*in)--;
    return 0;
  }
}
uint8_t
edhoc_get_maps_num(uint8_t **in)
{
  uint8_t byte = get_byte(in);
  if((byte >= 0xa0) && (byte <= 0xaf)) { /*max of 15 maps */
    uint8_t num = byte ^ 0xa0;
    return num;
  } else {
    (*in)--;
    return 0;
  }
}
uint8_t
edhoc_get_array_num(uint8_t **in)
{
  uint8_t byte = get_byte(in);
  if((byte >= 0x80) && (byte <= 0x8f)) { /*max of 15 maps */
    uint8_t num = byte ^ 0x80;
    return num;
  } else {
    (*in)--;
    return 0;
  }
}
static int16_t
get_text(uint8_t **in, char **out)
{
  uint8_t byte = get_byte(in);
  size_t size;
  if(byte == 0x78) {
    size = get_byte(in);
    *out = (char *)*in;
    *in = (*in + size);
    return size;
  } else if((0x60 <= byte) && (byte < 0x78)) {
    size = byte ^ 0x60;
    *out = (char *)*in;
    *in = (*in + size);
    return size;
  } else {
    (*in)--;
    return -1;
  }
}
uint8_t
edhoc_get_byte_identifier(uint8_t **in)
{
  uint8_t input_byte = **in;
  (*in)++;

  // Check if the byte is in the range 0x00 to 0x17 (positive integers 0 to 23)
  // or in the range 0x20 to 0x37 (negative integers -1 to -24)
  if ((input_byte <= 0x17) || (input_byte >= 0x20 && input_byte <= 0x37)) {
    return input_byte;
  }

  // Else: FIXME: handle CBOR byte string CIDs
  // int out_sz = cbor_get_bytes(in, out);
  return 0;
}

size_t
edhoc_serialize_suites(unsigned char **buffer, const bstr *suites)
{
  if(suites->len == 1) {
    return cbor_put_unsigned(buffer, suites->buf[0]);
  }
  size_t size = cbor_put_array(buffer,suites->len);
  for(uint8_t i = 0; i < suites->len; ++i) {
    size += cbor_put_unsigned(buffer, suites->buf[i]);
  }
  return size;
}

void
edhoc_deserialize_suites(unsigned char **buffer, bstr *suites)
{
  suites->buf = (uint8_t*)*buffer;
  int8_t unint = (int8_t)edhoc_get_unsigned(buffer);
  if(unint < 0){
    unint = edhoc_get_array_num(buffer);
    suites->buf = (uint8_t*)*buffer;
    while(suites->len < unint){
      edhoc_get_unsigned(buffer);
      suites->len++;
    }
  } else{
    suites->len = 1;
  }
}

size_t
edhoc_serialize_msg_1(edhoc_msg_1 *msg, unsigned char *buffer, bool suit_array)
{
  size_t size = cbor_put_unsigned(&buffer, msg->method);
  size += edhoc_serialize_suites(&buffer, &msg->suites_i);
  size += cbor_put_bytes(&buffer, msg->g_x.buf, msg->g_x.len);
  size += edhoc_put_byte_identifier(&buffer, msg->c_i.buf, msg->c_i.len);
  // FIXME: send full ead if sending ead.
  if(msg->uad.ead_value.len > 0) {
    size += cbor_put_bytes(&buffer, msg->uad.ead_value.buf, msg->uad.ead_value.len);
  }
  return size;
}

size_t
edhoc_serialize_err(edhoc_msg_error *msg, unsigned char *buffer)
{
  int size = cbor_put_unsigned(&buffer, msg->err_code);
  switch(msg->err_code) {
    default:
      LOG_ERR("edhoc_serialize_err: unknown error code: %d\n", msg->err_code);
      break;
    case 1:
      size += cbor_put_text(&buffer, msg->err_info.buf, msg->err_info.len);
      break;
    case 2:
      // FIXME: strict aliasing violation.
      size += edhoc_serialize_suites(&buffer, (bstr *)&msg->err_info);
      break;
    case 3:
      size += cbor_put_num(&buffer, 0xf5);
      break;
  }
  return size;
}
int8_t
edhoc_deserialize_err(edhoc_msg_error *msg, unsigned char *buffer, uint8_t buff_sz)
{
  uint8_t *buff_f = buffer + buff_sz;
  if(buffer < buff_f) {
    int16_t rv = edhoc_get_unsigned(&buffer);
    if(rv < 0) {
      LOG_ERR("edhoc_deserialize_err got invalid error code\n");
      return 0;
    }
    msg->err_code = (uint8_t)rv;
  }
  if(buffer < buff_f) {
    if(msg->err_code == 2) {
      // FIXME: strict aliasing violation
      edhoc_deserialize_suites(&buffer, (bstr *)&msg->err_info);
      return ERR_NEW_SUIT_PROPOSE;
    }
    int16_t len = get_text(&buffer, &msg->err_info.buf);
    if(len > 0) {
      msg->err_info.len = len;
      LOG_ERR("Is an error msgs\n");
      return RX_ERR_MSG;
    }
    if(len == -1){
      return 0;
    }
    msg->err_info.len = (size_t)len;
  }
  return 0;
}
int8_t
edhoc_deserialize_msg_1(edhoc_msg_1 *msg, unsigned char *buffer, size_t buff_sz)
{
  /*Get the METHOD */
  uint8_t *p_out = NULL;
  size_t out_sz;
  uint8_t *buff_f = buffer + buff_sz;

  if(buffer < buff_f) {
    int8_t unint = (int8_t)edhoc_get_unsigned(&buffer);
    msg->method = unint;
  }
  /* Get the suit */
  if(buffer < buff_f) {
    edhoc_deserialize_suites(&buffer, &msg->suites_i);
  }
  /*Get Gx */
  if(buffer < buff_f) {
    out_sz = edhoc_get_bytes(&buffer, &p_out);
    if(out_sz == 0) {
      LOG_ERR("error code (%d)\n ", ERR_MSG_MALFORMED);
      return ERR_MSG_MALFORMED;
    }
    msg->g_x.buf = p_out;
    msg->g_x.len = out_sz;
  }
  /* Get the session_id (Ci) */
  if(buffer < buff_f) {
    msg->c_i.len = edhoc_get_bytes(&buffer, &msg->c_i.buf);
    if(msg->c_i.len == 0) {
      msg->c_i.buf = point_byte(&buffer);
      msg->c_i.len = 1;
    }
  }
  /* Get the decrypted msg */
  if(buffer < buff_f) {
    out_sz = edhoc_get_bytes(&buffer, &p_out);
    if(out_sz == 0) {
      LOG_ERR("error code (%d)\n ", ERR_MSG_MALFORMED);
      return ERR_MSG_MALFORMED;
    }
    // FIXME: add ead_label decoding.
    msg->uad.ead_value.buf = p_out;
    msg->uad.ead_value.len = out_sz;
  }
  return 1;
}
int8_t
edhoc_deserialize_msg_2(edhoc_msg_2 *msg, unsigned char *buffer, size_t buff_sz)
{
  msg->g_y_ciphertext_2.len = edhoc_get_bytes(&buffer, &msg->g_y_ciphertext_2.buf);
  if(msg->g_y_ciphertext_2.len == 0) {
    LOG_ERR("error code (%d)\n ", ERR_MSG_MALFORMED);
    return ERR_MSG_MALFORMED;
  }
  return 1;
}
int8_t
edhoc_deserialize_msg_3(edhoc_msg_3 *msg, unsigned char *buffer, size_t buff_sz)
{
  msg->ciphertext_3.len = edhoc_get_bytes(&buffer, &msg->ciphertext_3.buf);
  if(msg->ciphertext_3.len == 0) {
    LOG_ERR("error code (%d)\n ", ERR_MSG_MALFORMED);
    return ERR_MSG_MALFORMED;
  }
  return 1;
}
uint8_t
edhoc_get_cred_x_from_kid(uint8_t *kid, uint8_t kid_sz, cose_key_t **key)
{
  cose_key_t *auth_key;
  if(edhoc_check_key_list_kid(kid, kid_sz, &auth_key) == 0) {
    LOG_ERR("The authentication key id is not in the list\n");
    return ERR_NOT_ALLOWED_IDENTITY;
  }
  *key = auth_key;
  return ECC_KEY_BYTE_LENGTH;
}
int8_t
edhoc_get_id_cred_x(uint8_t **p, uint8_t **id_cred_x, cose_key_t *key)
{
  *id_cred_x = *p;
  uint8_t num = edhoc_get_maps_num(p);
  uint8_t label;
  int8_t key_sz = 0;
  uint8_t key_id_sz = 0;
  uint8_t *ptr = NULL;
  char* ch = NULL;

  cose_key_t *hkey;

  if(num > 0) {
    label = (uint8_t) edhoc_get_unsigned(p);
  } else {
    key->kid[0] = **p;
    (*p)++;
    key->kid_sz = 1;
    ptr = key->kid;
    if(key->kid[0] == 0) {
      key->kid_sz = edhoc_get_bytes(p, &ptr);
      memcpy(key->kid, ptr, key->kid_sz);
    }
    label = 0;
  }

  switch(label) {
  /*(PRK_ID) ID_CRED_R = KID byte identifier (KID 1 Byte)*/
  case 0:
    key_sz = edhoc_get_cred_x_from_kid(key->kid, key->kid_sz, &hkey);
    memcpy(key, hkey, sizeof(cose_key_t));
    if(key_sz == 0) {
      return 0;
    } else if(key_sz < 0) {
      return key_sz;
    }
    break;

  /*TODO: include cases for each different support authentication case */
  /*case 32:

     key_sz = edhoc_get_bytes(p, &ptr);
     memcpy(key->x, ptr, ECC_KEY_BYTE_LENGTH);
     get_text(p, &sn);
     key->kid_sz = 0;
     if(memcmp(sn, "subject name", strlen("subject name")) == 0) {
      key_id_sz = get_text(p, &sn);
      memcpy(key->identity, sn, key_id_sz);
      key->identity_sz = key_id_sz;
     } else {
      return 0;
      LOG_ERR("missing subject name");
      break;
     }
     break;*/
  /*(PRK_ID) ID_CRED_R = map(4:KID bstr)  (KID 4 Byte)*/
  case 4:
    key_id_sz = edhoc_get_bytes(p, &ptr);
    key_sz = edhoc_get_cred_x_from_kid(ptr, key_id_sz, &hkey);
    memcpy(key, hkey, sizeof(cose_key_t));
    if(key_sz == 0) {
      return 0;
    } else if(key_sz < 0) {
      return key_sz;
    }
    break;

  /*(PRKI_2) ID_CRED_R = CRED_R */
  case 1:
    key->kty = edhoc_get_unsigned(p);
    int param = get_negative(p);
    if(param != 1) {
      break;
    }
    key->crv = (uint8_t) edhoc_get_unsigned(p);

    param = get_negative(p);
    if(param != 2) {
      break;
    }
    key_sz = edhoc_get_bytes(p, &ptr);
    memcpy(key->x, ptr, ECC_KEY_BYTE_LENGTH);

    param = get_negative(p);
    if(param != 3) {
      break;
    }
    key_sz = edhoc_get_bytes(p, &ptr);
    memcpy(key->y, ptr, ECC_KEY_BYTE_LENGTH);

    //char *ch = key->identity;
    key->identity_sz = get_text(p, &ch);
    memcpy(key->identity,ch,key->identity_sz);
    ch = NULL;
    if(!memcmp(key->identity, "subject name", strlen("subject name"))) {
      key->identity_sz = get_text(p, &ch);
      memcpy(key->identity,ch,key->identity_sz);
    }

    if(key_sz == 0) {
      return 0;
    } else if(key_sz < 0) {
      return key_sz;
    }
    break;
  }
  if(key_sz != ECC_KEY_BYTE_LENGTH) {
    LOG_ERR("wrong key size\n ");
    return 0;
  }
  uint8_t id_cred_x_sz = *p - *id_cred_x;
  return id_cred_x_sz;
}
uint8_t
edhoc_get_sign(uint8_t **p, uint8_t **sign)
{
  uint8_t sign_sz = edhoc_get_bytes(p, sign);
  return sign_sz;
}
uint8_t
edhoc_get_ad(uint8_t **p, uint8_t *ad)
{
  uint8_t *ptr;
  uint8_t ad_sz = edhoc_get_bytes(p, &ptr);
  memcpy(ad, ptr, ad_sz);
  return ad_sz;
}
int 
edhoc_put_byte_identifier(uint8_t **buffer, uint8_t *bytes, uint8_t len)
{
  // For single byte values check whether they are a valid CBOR integer
  if (len == 1) {
    uint8_t byte = bytes[0];

    // Check if the byte is in the range 0x00 to 0x17 (positive integers 0 to 23)
    // or in the range 0x20 to 0x37 (negative integers -1 to -24)
    if ((byte <= 0x17) || (byte >= 0x20 && byte <= 0x37)) {
      **buffer = byte;
      (*buffer)++;
      return 1;
    }
  }
  
  // Else encode as a CBOR byte string
  return cbor_put_bytes(buffer, bytes, len);
}

