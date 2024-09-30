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
 *         ecdh-msg header
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */
#ifndef _EDHOC_MSGS_H__
#define _EDHOC_MSGS_H__

#include <stdint.h>
#include <stddef.h>
#include "cbor.h"
#include "edhoc-log.h"
#include "edhoc-key-storage.h"
#include "edhoc-config.h"

/*Error definitions*/
#define ERR_SUIT_NON_SUPPORT -2
#define ERR_MSG_MALFORMED -3
#define ERR_REJECT_METHOD -4
#define ERR_CID_NOT_VALID -5
#define ERR_WRONG_CID_RX -6
#define ERR_ID_CRED_X_MALFORMED -7
#define ERR_AUTHENTICATION -8
#define ERR_DECRYPT -9
#define ERR_CODE -10
#define ERR_NOT_ALLOWED_IDENTITY -11
#define RX_ERR_MSG -1
#define ERR_TIMEOUT -12
#define ERR_CORELLATION -13
#define ERR_NEW_SUIT_PROPOSE -14
#define ERR_RESEND_MSG_1 -15

/*NEW RFC */

typedef struct ead_data {
  uint8_t ead_label;
  bstr ead_value;
} ead_data;


typedef struct edhoc_msg_1 {
  uint8_t method;
  bstr suites_i; /* FIXME: array of int, or int */
  bstr g_x;
  bstr c_i; /* FIXME: alternatively -24..23 */
  ead_data uad; /* FIXME: optional */
} edhoc_msg_1;

typedef struct edhoc_msg_2 {
  bstr g_y_ciphertext_2;
} edhoc_msg_2;

typedef struct edhoc_msg_3 {
  bstr ciphertext_3;
} edhoc_msg_3;

typedef struct edhoc_msg_error {
  uint8_t err_code;
  sstr err_info;
} edhoc_msg_error;

void print_msg_1(edhoc_msg_1 *msg);
void print_msg_2(edhoc_msg_2 *msg);
void print_msg_3(edhoc_msg_3 *msg);

size_t edhoc_serialize_suites(unsigned char **buffer, const bstr *suites);

size_t edhoc_serialize_msg_1(edhoc_msg_1 *msg, unsigned char *buffer, bool suit_array);
#if 0
size_t edhoc_serialize_data_2(edhoc_data_2 *msg, unsigned char *buffer);
size_t edhoc_serialize_data_3(edhoc_data_3 *msg, unsigned char *buffer);
#endif
size_t edhoc_serialize_err(edhoc_msg_error *msg, unsigned char *buffer);

int8_t edhoc_deserialize_msg_1(edhoc_msg_1 *msg, unsigned char *buffer, size_t buff_sz);
int8_t edhoc_deserialize_msg_2(edhoc_msg_2 *msg, unsigned char *buffer, size_t buff_sz);
int8_t edhoc_deserialize_msg_3(edhoc_msg_3 *msg, unsigned char *buffer, size_t buff_sz);
int8_t edhoc_deserialize_err(edhoc_msg_error *msg, unsigned char *buffer, uint8_t buff_sz);
int8_t edhoc_get_id_cred_x(uint8_t **p, uint8_t **id_cred_x, cose_key_t *key);
uint8_t edhoc_get_cred_x_from_kid(uint8_t *kid, uint8_t kid_sz, cose_key_t **key);
uint8_t edhoc_get_sign(uint8_t **p, uint8_t **sign);
uint8_t edhoc_get_ad(uint8_t **p, uint8_t *ad);

uint8_t edhoc_get_byte_identifier(uint8_t **in);
uint8_t edhoc_get_maps_num(uint8_t **in);
size_t edhoc_get_bytes(uint8_t **in, uint8_t **out);
int16_t edhoc_get_unsigned(uint8_t **in);
uint8_t edhoc_get_array_num(uint8_t **in);

void edhoc_deserialize_suites(unsigned char **buffer, bstr *suites);

// static int16_t get_text(uint8_t **in, char **out);
// static int64_t get_negative(uint8_t **in);
// static uint8_t get_byte(uint8_t **in);

#endif
