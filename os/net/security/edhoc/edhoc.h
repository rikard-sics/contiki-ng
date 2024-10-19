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
 *         An implementation of Ephemeral Diffie-Hellman Over COSE (EDHOC)
 *         (RFC9528)
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 *         Christos Koulamas <cklm@isi.gr>
 */

/**
 * \defgroup EDHOC An EDHOC implementation (RFC9528)
 * @{
 *
 * This is an implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC)
 * a very compact, and lightweight authenticated Diffie-Hellman key exchange with
 * ephemeral keys that provide mutual authentication, perfect forward secrecy,
 * and identity protection as described in (RFC9528)
 *
 **/

#ifndef _EDHOC_H_
#define _EDHOC_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "ecdh.h"
#include "edhoc-msgs.h"

/**
 * \brief Set EDHOC connection identifier
 */
#ifndef EDHOC_CID
#define EDHOC_CID 0x1
#endif

/* EDHOC_KDF label values */
#define KEYSTREAM_2_LABEL    0
#define SALT_3E2M_LABEL      1
#define MAC_2_LABEL          2
#define K_3_LABEL            3
#define IV_3_LABEL           4
#define SALT_4E3M_LABEL      5
#define MAC_3_LABEL          6
#define PRK_OUT_LABEL        7
#define K_4_LABEL            8
#define IV_4_LABEL           9
#define PRK_EXPORTER_LABEL   10

/**
 * \brief EDHOC session struct
 */
typedef struct edhoc_session {
  uint8_t role;
  uint8_t method;
  uint8_t suite[5];
  uint8_t suite_num;
  uint8_t suite_selected;
  uint8_t cid;
  uint8_t cid_rx;

  uint8_t plaintext_2[MAX_BUFFER];
  size_t  plaintext_2_sz;
  uint8_t plaintext_3[MAX_BUFFER];
  size_t  plaintext_3_sz;
  uint8_t cred_x[MAX_BUFFER];
  size_t  cred_x_sz;
  uint8_t id_cred_x[MAX_BUFFER];
  size_t  id_cred_x_sz;
  
  uint8_t prk_2e[HASH_LEN];
  uint8_t prk_3e2m[HASH_LEN];
  uint8_t prk_4e3m[HASH_LEN];
  uint8_t gx[ECC_KEY_LEN];
  uint8_t gy[ECC_KEY_LEN];
  uint8_t th[HASH_LEN];
  
} edhoc_session;

/**
 * \brief EDHOC context struct
 */
typedef struct edhoc_context_t {
  cose_key_t       authen_key;
  ecc_key          ephemeral_key;
  edhoc_session    session;
  uint8_t          curve_new;
  uint8_t          msg_rx[MAX_PAYLOAD_LEN];
  uint8_t          msg_tx[MAX_PAYLOAD_LEN];
  uint16_t         rx_sz;
  uint16_t         tx_sz;
} edhoc_context_t;

/**
 * \brief EDHOC context struct used in the EDHOC protocol
 */
extern edhoc_context_t *edhoc_ctx;

/**
 * \brief Reserve memory for the EDHOC context struct
 *
 * Used by both Initiator and Responder EDHOC roles to reserve memory
 */
void edhoc_storage_init(void);

/**
 * \brief Create a new EDHOC context
 * \relates edhoc_storage_init
 * \return edhoc_ctx_t EDHOC context struct
 *
 * Used by both Initiator and Responder EDHOC roles to create a new EDHOC context
 * and allocate at the memory reserved before with the edhoc_storage_init function
 */
edhoc_context_t *edhoc_new();

/**
 * \brief Initialize the EDHOC ctx with the define EDHOC parameters
 * \return edhoc_ctx_t EDHOC context struct
 *
 * Used in the edho_new to set the default protocol definitions and in the Responder to
 * reset the initial values to prepare for a new EDHOC connection
 */

void setup_suites(edhoc_context_t *ctx);

/**
 * \brief Close the EDHOC context
 * \param ctx EDHOC context struct
 *
 * Used by both Initiator and Responder EDHOC roles to de-allocate the memory reserved
 * for the EDHOC context when EDHOC protocol finalize.
 */
void edhoc_finalize(edhoc_context_t *ctx);

/**
 * \brief Generate the EDHOC Message 1 and set it in the EDHOC context
 * \param ctx EDHOC Context struct
 * \param ad Application data to include in MSG1
 * \param ad_sz Application data length
 * \param suite_array If true the msg1 include an array of suites if have more than one suite if 0 msg1 includes an 
 * unique unsigned suite independently of the number of suites supported by the initiator 
 *
 * Generate an ephemeral ECDH key pair, determinate the cipher suite to use and the
 * connection identifier. Compose the EDHOC Message 1 as described in the (RFC9528) reference
 * for EHDOC Authentication with Asymmetric Keys and encoded as a CBOR sequence in the MSG1 element of the
 * ctx struct.
 * It is used by Initiator EDHOC role.
 *
 * - ctx->MSG1 = (METHOD_CORR:unsigned, SUITES_I:unsigned, G_X, C_I_identifier)
 *
 */
void edhoc_gen_msg_1(edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz, bool suite_array);

/**
 * \brief Generate the EDHOC Message 2 and set it in the EDHOC ctx
 * \param ctx EDHOC Context struct
 * \param ad Application data to include in MSG2
 * \param ad_sz Application data length
 * \retval -1 when message generation fails
 * \retval 1 when message generation succeeds
 *
 * It is used by EDHOC Responder role to processing the message 2
 * Generate an ephemeral ECDH key pair
 * Choose a connection identifier,
 * Compute the transcript hash 2 TH_2 = H(ctx->MSG1, data_2)
 * Compute MAC_2 (Message Authentication Code)
 * Compute CIPHERTEXT_2
 * Compose the EDHOC Message 2 as described in the (RFC9528) reference
 * for EHDOC Authentication with Asymmetric Keys and encoded as a CBOR sequence in the MSG2 element of the
 * ctx struct.
 * - ctx->MSG2 = (data_2, CIPHERTEXT_2)
 * - where: data_2 = (?C_I_identifier, G_Y)
 */
uint8_t edhoc_gen_msg_2(edhoc_context_t *ctx, const uint8_t *ad, size_t ad_sz);

/**
 * \brief Generate the EDHOC Message 3 and set it in the EDHOC ctx
 * \param ctx EDHOC Context struct
 * \param ad Application data to include in MSG3
 * \param ad_sz Application data length
 *
 * It is used by EDHOC Initiator role to processing the message 3.
 * Compute the transcript hash 3 TH_3 = H(TH_2, PLAINTEXT_2, data_3)
 * Compute MAC_3 (Message Authentication Code)
 * Compute CIPHERTEXT_3
 * Compose the EDHOC Message 3 as described in the (RFC9528) reference
 * for EHDOC Authentication with Asymmetric Keys and encoded as a CBOR sequence in the MSG3 element of the
 * ctx struct.
 *
 * - ctx->MSG3 = (data_3, CIPHERTEXT_3)
 * - where: data_3 = (?C_R_identifier)
 */
void edhoc_gen_msg_3(edhoc_context_t *ctx, const uint8_t *ad, size_t ad_sz);

/**
 * \brief Generate the EDHOC ERROR Message
 * \param msg_er A pointer to a buffer to copy the generated CBOR message error
 * \param ctx EDHOC Context struct
 * \param err EDHOC error number
 * \return err_sz CBOR Message Error size
 *
 * An EDHOC error message can be sent by both parties as a reply to any non-error
 * EDHOC message. If any verification step fails on the EDHOC protocol the Initiator
 * or Responder must send an EDHOC error message back that contains a brief human-readable
 * diagnostic message.
 * - msg_er = (?C_x_identifier, ERR_MSG:tstr)
 */
uint8_t edhoc_gen_msg_error(uint8_t *msg_er, const edhoc_context_t *ctx, int8_t err);

/**
 * \brief Get the authentication key from the rx msg
 * \param ctx EDHOC Context struct
 * \param pt A pointer to the ID_CRED_X on the Rx msg buffer.
 * \param key A pointer to a cose key struct
 * \retval ERR_CODE when an EDHOC ERROR is detected return a negative number corresponding to the specific error code
 * \retval 1 when EDHOC get success the authentication key
 *
 * Used by Initiator and Responder EDHOC role to get the authentication key from the received msg.
 *
 * If any verification step fails to return an EDHOC ERROR code and, if all the steps success return 1.
 */
int edhoc_get_auth_key(edhoc_context_t *ctx, uint8_t **pt, cose_key_t *key, bool msg2);

/**
 * \brief Authenticate the rx message
 * \param ctx EDHOC Context struct
 * \param pt A pointer to the SIGN on the Rx msg buffer.
 * \param cipher_len Length of the cipher msg
 * \param ad A pointer to a buffer to copy the Application Data of the rx message
 * \param key The other party authentication key, used for authentication
 * \retval ERR_CODE when an EDHOC ERROR is detected return a negative number corresponding to the specific error code
 * \retval ad_sz The length of the Application Data received in Message 2, when EDHOC success
 *
 * Used by Initiator and Responder EDHOC role to Authenticate the other party
 * - Verify that the EDHOC Responder role identity is among the allowed if it is necessary
 * - Verify MAC
 * - Pass Application data AD
 *
 * If any verification step fails to return an EDHOC ERROR code and, if all the steps success
 * the length of the Application Data receive on the Message is returned.
 */
int edhoc_authenticate_msg(edhoc_context_t *ctx, uint8_t **pt, uint8_t cipher_len, uint8_t *ad, cose_key_t *key);

/**
 * \brief Handle the EDHOC Message 1 received
 * \param ctx EDHOC Context struct
 * \param buffer A pointer to the buffer containing the EDHOC message received
 * \param buff_sz Size of the EDHOC message received
 * \param ad A pointer to a buffer to copy the Application Data received in Message 1
 * \retval negative number (EDHOC ERROR CODES) when an EDHOC ERROR is detected
 * \retval ad_sz The length of the Application Data received in Message 1, when EDHOC success
 *
 * Used by Responder EDHOC role to process the Message 1 received
 * - Decode the message 1
 * - Verify that cipher suite
 * - Pass Application data AD_1
 * - If any verification step fails to return an EDHOC ERROR code and, if all the steps success
 * - the length of the Application Data receive on the Message 1 is returned.
 */
int edhoc_handler_msg_1(edhoc_context_t *ctx, uint8_t *payload, size_t payload_sz, uint8_t *ad);

/**
 * \brief Handle the EDHOC Message 2 received
 * \param msg2 A pointer to the buffer containing the received EDHOC message 2
 * \param ctx EDHOC Context struct
 * \param buffer A pointer to the buffer containing the EDHOC message received
 * \param buff_sz Size of the EDHOC message received
 * \retval ERR_CODE when an EDHOC ERROR is detected return a negative number corresponding to the specific error code
 * \retval 1 when EDHOC decode and verify success
 *
 * Used by Initiator EDHOC role to process the Message 2 received
 * - Decode the message 2
 * - Verify the other peer through 5-tuple and/or connection identifier C_I
 *
 * If any verification step fails to return an EDHOC ERROR code and, if all the steps success return 1.
 */
int edhoc_handler_msg_2(edhoc_msg_2 *msg2, edhoc_context_t *ctx, uint8_t *buffer, size_t buff_sz);

/**
 * \brief Handle the EDHOC Message 3 received
 * \param msg3 A pointer to the buffer containing the received EDHOC message 3
 * \param ctx EDHOC Context struct
 * \param buffer A pointer to the buffer containing the EDHOC message received
 * \param buff_sz Size of the EDHOC message received
 * \retval negative number (EDHOC ERROR CODE) when an EDHOC ERROR is detected
 * \retval 1 when EDHOC decode and verify success
 *
 * Used by Responder EDHOC role to process the Message 3 receive
 * - Decode the message 3
 * - Verify the other peer through 5-tuple and/or connection identifier C_R
 *
 * If any verification step fails to return an EDHOC ERROR code and,if all the steps success return 1.
 */
int edhoc_handler_msg_3(edhoc_msg_3 *msg3, edhoc_context_t *ctx, uint8_t *buffer, size_t buff_sz);

/**
 * \brief EDHOC Key Derivation Function (KDF) based on HMAC-based Expand (RFC 5869)
 * \param result OKM (Output Keying Material) - the buffer where the derived key will be stored.
 * \param key PRK (Pseudorandom Key) - a pseudorandom key used as input to the key derivation, should be at least `HASH_LEN` bits.
 * \param info_label Label used to generate the CBOR-based info input for key derivation.
 * \param context Context data used to generate the info input for key derivation.
 * \param length Desired length of the output key material (OKM) in bits.
 * \return 1 if key derivation is successful, or a negative error code on failure.
 *
 * This function combines the PRK, info_label, and context to generate an input info
 * parameter that is used for HKDF-Expand as defined in RFC 5869. It is used by both 
 * the Initiator and Responder in the EDHOC protocol to generate keying material. 
 * Internally, this function calls `edhoc_expand` to compute the final OKM.
 * 
 * The function performs the following steps:
 *  - Calls `generate_info` to prepare the `info` input.
 *  - Passes the PRK, generated `info`, and length to `edhoc_expand`.
 * 
 * Example usage:
 *  - OKM = EDHOC_Expand(PRK, info, length)
 */
int16_t edhoc_kdf(const uint8_t *prk, uint8_t info_label, const uint8_t *context, uint8_t context_sz, uint16_t length, uint8_t *result);

/**
 * \brief HMAC-based Key Expansion Function for EDHOC context using HKDF (RFC 5869)
 * \param result OKM (Output Keying Material) - the buffer where the derived key will be stored.
 * \param key PRK (Pseudorandom Key) - a pseudorandom key used as input for the HMAC-based key derivation.
 * \param info Additional context information used in the key derivation, which is generated from the info_label and context.
 * \param info_sz The size of the info parameter in bytes.
 * \param length The desired length of the output key material (OKM) in bits.
 * \return 1 if key derivation is successful, or a negative error code on failure.
 *
 * This function implements the HKDF-Expand function as described in RFC 5869. 
 * It takes the PRK, context info, and the desired length to produce the final key material.
 * It calls hkdf_expand internally to perform the HMAC-based key expansion using SHA-256.
 *
 * The steps include:
 *  - Verifying the size of the info and output key material (OKM).
 *  - Using HMAC-Expand to expand the PRK and info into OKM.
 *  - Returning the length of the derived key or an error code in case of failure.
 *
 * Example usage:
 *  - OKM = HKDF-Expand(PRK, info, length)
 */
int16_t edhoc_expand(const uint8_t *prk, const uint8_t *info, uint16_t info_sz, uint16_t length, uint8_t *result);

int edhoc_authenticate_msg(edhoc_context_t *ctx, uint8_t **ptr, uint8_t cipher_len, uint8_t *ad, cose_key_t *key);
void set_rx_gx(edhoc_context_t *ctx, const uint8_t *gx);
uint8_t edhoc_initialize_context(edhoc_context_t *ctx);
uint8_t edhoc_get_authentication_key(edhoc_context_t *ctx, cose_key_t **key);
uint8_t get_edhoc_curve(uint8_t ciphersuite_id);

// static int16_t gen_ks_2e(edhoc_context_t *ctx, uint16_t length);
// static int16_t get_rx_suite_I(const edhoc_context_t *ctx, uint8_t *suite_rx);
// static int8_t check_rx_suite_I(edhoc_context_t *ctx, uint8_t *suiterx);
// static int8_t gen_th2(edhoc_context_t *ctx, uint8_t *data, uint8_t *msg, uint16_t msg_sz);
// static int8_t set_rx_cid(edhoc_context_t *ctx, uint8_t *cidrx, uint8_t cidrx_sz);
// static int8_t set_rx_method(edhoc_context_t *ctx, uint8_t method);
// static size_t generate_cred_x(cose_key_t *cose, uint8_t *cred);
// static size_t generate_id_cred_x(cose_key_t *cose, uint8_t *cred);
// static size_t generate_info(uint8_t *info, uint8_t *th, uint8_t th_sz, uint8_t length, uint8_t value);
// static size_t reconstruct_id_cred_x(uint8_t *cred_in, size_t cred_in_sz);
// static uint16_t check_mac_dh(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *cipher, uint16_t cipher_sz, uint8_t *mac);
// static uint16_t decrypt_ciphertext_3(edhoc_context_t *ctx, uint8_t *ciphertext, uint16_t ciphertext_sz, uint8_t *plaintext);
// static uint16_t gen_ciphertext_3(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *mac, uint16_t mac_sz, uint8_t *ciphertext);
// static uint16_t gen_plaintext(uint8_t *buffer, edhoc_context_t *ctx, uint8_t *ad, size_t ad_sz, bool msg2);
// static uint8_t gen_gxy(edhoc_context_t *ctx);
// static uint8_t gen_mac_dh(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t *mac);
// static uint8_t gen_prk_2e(edhoc_context_t *ctx);
// static uint8_t gen_prk_3e2m(edhoc_context_t *ctx, ecc_key *key_authenticate, uint8_t gen);
// static uint8_t gen_prk_4e3m(edhoc_context_t *ctx, ecc_key *key_authenticate, uint8_t gen);
// static uint8_t gen_th3(edhoc_context_t *ctx, uint8_t *data, uint16_t data_sz, uint8_t *ciphertext, uint16_t ciphertext_sz);
// static uint8_t gen_th4(edhoc_context_t *ctx, uint8_t *data, uint16_t data_sz, uint8_t *ciphertext, uint16_t ciphertext_sz);
// static uint8_t int_sz(int num);
// static void context_free(edhoc_context_t *ctx);
// static void gen_ciphertext_2(edhoc_context_t *ctx, uint8_t *plaintext, uint16_t plaintext_sz);
// static void print_connection(edhoc_session *con);
// static void set_rx_msg(edhoc_context_t *ctx, uint8_t *msg, uint8_t msg_sz);
// static retrieve_cred_i(edhoc_context_t *ctx, uint8_t *inf, uint8_t *cred_i);
// static uint8_t set_mac(edhoc_context_t *ctx, uint8_t *ad, uint16_t ad_sz, uint8_t mac_num, uint8_t *mac);

#endif /* _EDHOC_H_ */
/** @} */
