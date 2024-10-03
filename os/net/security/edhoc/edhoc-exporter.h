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
 *         edhoc-exporter This is an interface to derive application security context
 *         from the EDHOC shared secret
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 *         Christos Koulamas <cklm@isi.gr>
 */

/**
 * \addtogroup edhoc
 * @{
 */
#ifndef _EDHOC_EXPORTER_H_
#define _EDHOC_EXPORTER_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "edhoc.h"

/* OSCORE KEY and SALT size */
#define OSCORE_SALT_SZ 8
#define OSCORE_KEY_SZ 16 /*Key length of the APP AEAD in bytes */

/* PSK KEY and SALT sizes */
#define PSK_KEY_SZ 16
#define PSK_KEY_ID_SZ 4

/**
 * \brief OSCORE context struct
 */
typedef struct oscore_ctx_t {
  uint8_t master_secret[OSCORE_KEY_SZ];
  uint8_t master_salt[OSCORE_SALT_SZ];
  int client_ID;   /* coap client is the Initiator */
  int server_ID;   /* coap server is the Responder */
}oscore_ctx_t;

/**
 * \brief PSK context struct
 */
typedef struct psk_ctx_t {
  uint8_t PSK[PSK_KEY_SZ];
  uint8_t kid_PSK[PSK_KEY_ID_SZ];
}psk_ctx_t;

/**
 * \brief Derive an OSCORE Context from EDHOC
 * \param osc output OSCORE Context struct
 * \param ctx input EDHOC Context struct
 * \return negative number HKDF ERROR code when an ERROR happens in the key derivation
 *
 *  This function is used to derive an OSCORE Security Context [RFC8613] from the EDHOC shared secret.
 *  This can be run from both EDHOC Initiator and Responder once the EDHOC protocol has finished
 *  successfully.
 */
int8_t edhoc_exporter_oscore(oscore_ctx_t *osc, edhoc_context_t *ctx);

/**
 * \brief Print an OSCORE Context for debugging
 * \param osc input OSCORE Context struct
 *
 */
void edhoc_exporter_print_oscore_ctx(oscore_ctx_t *osc);

/**
 * \brief Derive an application-specific key from EDHOC
 * \param result Output buffer where the derived key will be stored
 * \param ctx Input EDHOC context containing the necessary state and keys
 * \param info_label Label used to differentiate different key derivation outputs
 * \param length Length of the key to be derived
 * \return Negative number indicating an error code if key derivation fails, 0 on success
 *
 * This function derives a key for application-specific use from the EDHOC shared secret using the EDHOC KDF.
 * The key derivation is based on the provided label and length. This can be used for exporting keys
 * after the successful completion of the EDHOC protocol.
 */
int8_t edhoc_exporter(uint8_t *result, edhoc_context_t *ctx, uint8_t length, uint8_t info_label);

#endif /* _EDHOC_EXPORTER_H_ */
/** @} */
