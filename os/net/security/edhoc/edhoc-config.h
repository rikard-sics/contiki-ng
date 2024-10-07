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
 *      EDHOC configuration file
 * \author
 *      Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */

/**
 * \addtogroup edhoc
 * @{
 */

#ifndef _EDHOC_CONFIG_H_
#define _EDHOC_CONFIG_H_

/* SHA256 types*/
#define DECC_SH2 0       /* Macro to declare the use of SH2 Software library from Oriol Pinol */
#define DCC2538_SH2 1    /* Macro to declare the use of SH2 Hardware of the CC2538 module */

/**
 * \brief Set the SH2 library
 */
#ifdef EDHOC_CONF_SH256
  #define SH256 EDHOC_CONF_SH256
#else
  #define SH256 DECC_SH2
#endif

/* Correlation types */
#define NON_EXTERNAL_CORR 0
#define EXTERNAL_CORR_U 1
#define EXTERNAL_CORR_V 2
#define EXTERNAL_CORR_UV 3

/**
 * \brief Set the Correlation type
 * TODO: This is never used (remove?)
 */
#ifdef EDHOC_CONF_CORR
  #define CORR EDHOC_CONF_CORR
#else
  #define CORR EXTERNAL_CORR_UV
#endif

/* EDHOC Role definitions */
#define RESPONDER 0   /* The Responder of the EDHOC protocol */
#define INITIATOR 1   /* The Initiator of the EDHOC protocol */

/**
 * \brief Set the EDHOC Protocol role
 */
#ifdef EDHOC_CONF_ROLE
  #define ROLE EDHOC_CONF_ROLE
#else
  #define ROLE INITIATOR
#endif

/* COSE_key parameters */
#define OKP 1  /* not implemented yet */
#define EC2 2
#define SYMMETRIC 3  /* not implemented yet */

/* EDHOC Authentication Method Types: Initiator (I) | Responder (R) */
#define METH0 0                  /* Signature Key  | Signature Key  */
#define METH1 1                  /* Signature Key  | Static DH Key  */
#define METH2 2                  /* Static DH Key  | Signature Key  */
#define METH3 3                  /* Static DH Key  | Static DH Key  */

/**
 * \brief Set the Authentication method
 */
#ifdef EDHOC_CONF_METHOD
 #define METHOD EDHOC_CONF_METHOD
#else
 #define METHOD METH3
#endif

/**
 * \brief Helper defines for method handling on msg. reception
 */
#define INITIATOR_METH2 (METHOD == METH2 && ROLE == INITIATOR)
#define RESPONDER_METH1 (METHOD == METH1 && ROLE == RESPONDER)
#define INITIATOR_METH1 (METHOD == METH1 && ROLE == INITIATOR)
#define RESPONDER_METH2 (METHOD == METH2 && ROLE == RESPONDER)

/* Credential Types */
#define CRED_KID 2
#define CRED_INCLUDE 3

/**
 * \brief Set the authentication credential type
 */
#ifdef EDHOC_CONF_AUTHENT_TYPE
  #define AUTHENT_TYPE EDHOC_CONF_AUTHENT_TYPE
#else
  #define AUTHENT_TYPE CRED_KID
#endif

/* #define AUTHENTICATION_KEY_LEN 32 // For Signature key, not yet implemented */

/* cipher suits */
#define EDHOC_CIPHERSUITE_0 0   /* AES-CCM-16-64-128,  (HMAC 256/256) SHA-256,  MAC LEN 8,  X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256 */
#define EDHOC_CIPHERSUITE_1 1   /* AES-CCM-16-128-128, (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, SHA-256 */
#define EDHOC_CIPHERSUITE_2 2   /* AES-CCM-16-64-128,  (HMAC 256/256) SHA-256,  MAC LEN 8,  P-256,  ES256, P-256,   AES-CCM-16-64-128, SHA-256 */ // Supported
#define EDHOC_CIPHERSUITE_3 3   /* AES-CCM-16-128-128, (HMAC 256/256) SHA-256,  MAC LEN 16, P-256,  ES256, P-256,   AES-CCM-16-64-128, SHA-256 */
#define EDHOC_CIPHERSUITE_4 4   /* ChaCha20/Poly1305,  (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, EdDSA, Ed25519, ChaCha20/Poly1305, SHA-256 */
#define EDHOC_CIPHERSUITE_5 5   /* ChaCha20/Poly1305,  (HMAC 256/256) SHA-256,  MAC LEN 16, P-256,  ES256, P-256,   ChaCha20/Poly1305, SHA-256 */
#define EDHOC_CIPHERSUITE_6 6   /* A128GCM,            (HMAC 256/256) SHA-256,  MAC LEN 16, X25519, ES256, P-256,   A128GCM, SHA-256 */
#define EDHOC_CIPHERSUITE_24 24 /* A256GCM,            (HMAC 384/384) SHA-384,  MAC LEN 16, P-384,  ES384, P-384,   A256GCM, SHA-384 */
#define EDHOC_CIPHERSUITE_25 25 /* ChaCha20/Poly1305,  (HMAC 256/256) SHAKE256, MAC LEN 16, X448,   EdDSA, Ed448,   ChaCha20/Poly1305, SHAKE256 */

/* Algorithms for signing */
#define ES256 -7
#define EDDSA -8
#define ES384 -35

/**
 * \brief Length of signatures
 */
#define P256_SIGNATURE_LEN 64
#define ED25519_SIGNATURE_LEN 64
#define ED448_SIGNATURE_LEN 114
#define P384_SIGNATURE_LEN 96

/**
 * \brief Set EDHOC cipher suit config
 */
#ifdef EDHOC_CONF_SUPPORTED_SUIT_1
  #define SUPPORTED_SUIT_1 EDHOC_CONF_SUPPORTED_SUIT_1
#else
  #define SUPPORTED_SUIT_1 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUIT_2
  #define SUPPORTED_SUIT_2 EDHOC_CONF_SUPPORTED_SUIT_2
#else
  #define SUPPORTED_SUIT_2 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUIT_3
  #define SUPPORTED_SUIT_3 EDHOC_CONF_SUPPORTED_SUIT_3
#else
  #define SUPPORTED_SUIT_3 -1
#endif

#ifdef EDHOC_CONF_SUPPORTED_SUIT_4
  #define SUPPORTED_SUIT_4 EDHOC_CONF_SUPPORTED_SUIT_4
#else
  #define SUPPORTED_SUIT_4 -1
#endif

/* Set COSE_Key parameter */
//#if (SUIT == P256)
#define KEY_CRV 1
#define KEY_TYPE EC2 /* EC2 key */
//#endif

/**
 * \brief COSE algorithm selection
 */
#ifdef EDHOC_CONF_ALGORITHM_ID
  #define ALGORITHM_ID EDHOC_CONF_ALGORITHM_ID
  #define COSE_CONF_ALGORITHM_ID EDHOC_CONF_ALGORITHM_ID
#else
  #define ALGORITHM_ID COSE_Algorithm_AES_CCM_16_64_128
  #define COSE_CONF_ALGORITHM_ID COSE_Algorithm_AES_CCM_16_64_128
#endif

/* Selected Algorithm Parameters */
#if ALGORITHM_ID == COSE_Algorithm_AES_CCM_16_64_128
  #define ECC_KEY_BYTE_LENGTH 32
  #define HASH_LENGTH 32
  #define KEY_DATA_LENGTH COSE_algorithm_AES_CCM_16_64_128_KEY_LEN
  #define IV_LENGTH COSE_algorithm_AES_CCM_16_64_128_IV_LEN
#endif

/**
 * \brief Set the EDHOC peer as RPL node. By default deselected
 */
#ifdef EDHOC_CONF_RPL_NODE
  #define RPL_NODE EDHOC_CONF_RPL_NODE
#else
  #define RPL_NODE 0
#endif

/**
 * \brief The number of attempts to try to connect with the EDHOC server successfully
 */
#ifndef EDHOC_CONF_ATTEMPTS
  #define EDHOC_CONF_ATTEMPTS 3
#endif

/**
 * \brief The max length of the EDHOC message, as CoAP payload
 */
#ifdef EDHOC_CONF_MAX_PAYLOAD
  #define MAX_DATA_LEN EDHOC_CONF_MAX_PAYLOAD
#else
  #define MAX_DATA_LEN 254
#endif

/**
 * \brief The max length of the Application Data
 */
#ifdef EDHOC_CONF_MAX_AD_SZ
  #define MAX_AD_SZ EDHOC_CONF_MAX_AD_SZ
#else
  #define MAX_AD_SZ 16
#endif

/**
 * \brief EDHOC resource Uri-Path
 */
#define EDHOC_WELL_KNOWN ".well-known/edhoc"

#endif /* _EDHOC_CONFIG_H_ */

/** @} */
