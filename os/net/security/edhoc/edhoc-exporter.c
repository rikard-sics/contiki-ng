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
 *         edhoc-export an implementation to export keys from the EDHOC shared secret
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>
 *         Peter Jonsson
 *         Rikard Höglund
 *         Marco Tiloca
 */

#include "edhoc-exporter.h"
#include "contiki-lib.h"

void
edhoc_exporter_print_oscore_ctx(oscore_ctx_t *osc)
{
  LOG_PRINT("Initiator client CID: 0x%02x\n", osc->client_ID);
  LOG_PRINT("Responder server CID: 0x%02x\n", osc->server_ID);
  LOG_PRINT("OSCORE Master Secret (%d bytes):", OSCORE_KEY_SZ);
  print_buff_8_print(osc->master_secret, OSCORE_KEY_SZ);
  LOG_PRINT("OSCORE Master Salt (%d bytes):", OSCORE_SALT_SZ);
  print_buff_8_print(osc->master_salt, OSCORE_SALT_SZ);
}
int8_t
edhoc_exporter(uint8_t *result, edhoc_context_t *ctx, uint8_t info_label, uint8_t length)
{
  int8_t er = edhoc_kdf(result, ctx->eph_key.prk_4e3m, info_label, ctx->session.th, length);
  return er;
}
// RH: Actually store PRK_out and PRK_exporter. Then use them in edhoc_exporter above.
int8_t
edhoc_exporter_oscore(oscore_ctx_t *osc, edhoc_context_t *ctx)
{
  /*if(gen_th4_old(ctx) < 0) {
    LOG_ERR("error code at exporter(%d) \n ", ERR_CODE);
    return ERR_CODE;
  }*/
  
  /* RH: WIP Derive prk_out */
  int prk_out_sz = ECC_KEY_BYTE_LENGTH;
  uint8_t prk_out[prk_out_sz];
  int8_t er = edhoc_kdf(prk_out, ctx->eph_key.prk_4e3m, PRK_OUT_LABEL, ctx->session.th, prk_out_sz);
  if(er < 0) {
    return er;
  }
  LOG_DBG("PRK_out (%d bytes): ", prk_out_sz);
  print_buff_8_dbg(prk_out, prk_out_sz);
  
  /* RH: WIP Derive prk_exporter */
  int prk_exporter_sz = ECC_KEY_BYTE_LENGTH;
  uint8_t prk_exporter[prk_exporter_sz];
  bstr empty; // Empty CBOR bstr
  empty.len = 0;
  empty.buf = NULL;
  er = edhoc_kdf(prk_exporter, prk_out, PRK_EXPORTER_LABEL, empty, prk_exporter_sz);
  if(er < 0) {
    return er;
  }
  LOG_DBG("PRK_exporter (%d bytes): ", prk_exporter_sz);
  print_buff_8_dbg(prk_exporter, prk_exporter_sz);

  /* RH: WIP Derive OSCORE Master Secret */

  /*The oscore client is the initiator */
  /*if(PART == PART_I) {
    osc->client_ID = ctx->session.cid;
    osc->server_ID = ctx->session.cid_rx;
  }
  if(PART == PART_R) {
    osc->client_ID = ctx->session.cid_rx;
    osc->server_ID = ctx->session.cid;
  }
  LOG_DBG("Info for OSCORE master secret:\n");
  er = edhoc_exporter(osc->master_secret, ctx, "OSCORE Master Secret", strlen("OSCORE Master Secret"), OSCORE_KEY_SZ);
  if(er < 0) {
    return er;
  }
  LOG_DBG("Info for OSCORE master salt:\n");
  er = edhoc_exporter(osc->master_salt, ctx, "OSCORE Master Salt", strlen("OSCORE Master Salt"), OSCORE_SALT_SZ);*/
  return er;
}

