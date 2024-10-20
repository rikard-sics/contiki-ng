/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB (RISE), Stockholm, Sweden
 * Copyright (c) 2020, Industrial System Institute (ISI), Patras, Greece
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
 *      EDHOC server example [RFC9528] with CoAP Block-Wise Transfer [RFC7959]
 * \author
 *      Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-lib.h"
#include "edhoc-exporter.h"
#include "edhoc-server-API.h"
#include "sys/rtimer.h"
#include "rpl.h"

rtimer_clock_t t;

oscore_ctx_t osc;

ecc_curve_t test;

#if TEST == TEST_VECTOR_TRACE_DH
  uint8_t eph_pub_x_r[ECC_KEY_LEN] = { 0x41, 0x97, 0x01, 0xd7, 0xf0, 0x0a, 0x26, 0xc2, 0xdc, 0x58, 0x7a, 0x36, 0xdd, 0x75, 0x25, 0x49, 0xf3, 0x37, 0x63, 0xc8, 0x93, 0x42, 0x2c,
    0x8e, 0xa0, 0xf9, 0x55, 0xa1, 0x3a, 0x4f, 0xf5, 0xd5 };

  uint8_t eph_pub_y_r[ECC_KEY_LEN] = { 0x5e, 0x4f, 0x0d, 0xd8, 0xa3, 0xda, 0x0b, 0xaa, 0x16, 0xb9, 0xd3, 0xad, 0x56, 0xa0, 0xc1, 0x86, 0x0a, 0x94, 0x0a, 0xf8, 0x59, 0x14, 0x91,
    0x5e, 0x25, 0x01, 0x9b, 0x40, 0x24, 0x17, 0xe9, 0x9d };

  uint8_t eph_private_r[ECC_KEY_LEN] = { 0xe2, 0xf4, 0x12, 0x67, 0x77, 0x20, 0x5e, 0x85, 0x3b, 0x43, 0x7d, 0x6e, 0xac, 0xa1, 0xe1, 0xf7, 0x53, 0xcd, 0xcc, 0x3e, 0x2c, 0x69, 0xfa,
    0x88, 0x4b, 0x0a, 0x1a, 0x64, 0x09, 0x77, 0xe4, 0x18 };
#endif

void generate_ephemeral_key(uint8_t *pub_x, uint8_t *pub_y, uint8_t *priv) {
  rtimer_clock_t drv_time = RTIMER_NOW();

#if ECC == UECC_ECC
  LOG_DBG("Generate key with uEcc\n");
  uECC_Curve curve = uECC_secp256r1();
  uECC_make_key(pub_x, priv, curve);
#elif ECC == CC2538_ECC
  LOG_DBG("Generate key with CC2538 HW modules\n");
  static key_gen_t key = {
    .process = &edhoc_example_server,
    .curve_info = &nist_p_256,
  };
  PT_SPAWN(&edhoc_example_server.pt, &key.pt, generate_key_hw(&key));
  memcpy(pub_x, key.x, ECC_KEY_LEN);
  memcpy(pub_y, key.y, ECC_KEY_LEN);
  memcpy(priv, key.private, ECC_KEY_LEN);
#endif

#if TEST == TEST_VECTOR_TRACE_DH
  memcpy(edhoc_ctx->creds.ephemeral_key.pub.x, eph_pub_x_r, ECC_KEY_LEN);
  memcpy(edhoc_ctx->creds.ephemeral_key.pub.y, eph_pub_y_r, ECC_KEY_LEN);
  memcpy(edhoc_ctx->creds.ephemeral_key.priv, eph_private_r, ECC_KEY_LEN);
#endif

  drv_time = RTIMER_NOW() - drv_time;
  LOG_INFO("Server time to generate new key: %" PRIu32 " ms (%" PRIu32 " CPU cycles ).\n", (uint32_t)((uint64_t)drv_time * 1000 / RTIMER_SECOND), (uint32_t)drv_time);
  LOG_DBG("Gy (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(edhoc_ctx->creds.ephemeral_key.pub.x, ECC_KEY_LEN);
  LOG_DBG("Y (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(edhoc_ctx->creds.ephemeral_key.priv, ECC_KEY_LEN);
}

PROCESS(edhoc_example_server, "EDHOC Example Server");
AUTOSTART_PROCESSES(&edhoc_example_server);

PROCESS_THREAD(edhoc_example_server, ev, data)
{
/* static struct etimer wait_timer; */
#if RPL_NODE == 1
  static struct etimer timer;
#endif
  PROCESS_BEGIN();
#if RPL_NODE == 1
  etimer_set(&timer, CLOCK_SECOND * 10);
  while(1) {
    watchdog_periodic();
    LOG_INFO("Waiting to reach the RPL\n");
    if(rpl_is_reachable()) {
      LOG_INFO("RPL reached\n");
      watchdog_periodic();
      break;
    }
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }
#endif
#if BORDER_ROUTER_CONF_WEBSERVER
  PROCESS_NAME(webserver_nogui_process);
  process_start(&webserver_nogui_process, NULL);
#endif /* BORDER_ROUTER_CONF_WEBSERVER */

  /* Set the client authentication credentials and add in the storage */
cose_key_t auth_client = {
    NULL,                                            // next
    { 0x2b },                                        // kid[4]
    1,                                               // kid_sz
    { "42-50-31-FF-EF-37-32-39" },                   // identity[IDENTITY_MAX_LEN]
    strlen("42-50-31-FF-EF-37-32-39"),               // identity_sz
    2,                                               // kty
    1,                                               // crv
    {                                                // ecc_key_t ecc
        { 0 },                                       // ecc.priv[ECC_KEY_LEN]
        {                                            // ecc_point_a pub
            { 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5,
              0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99,
              0x88, 0x95, 0x22, 0x40, 0x5c, 0x47,
              0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a,
              0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f,
              0x7e, 0xb6 },                          // ecc.pub.x[ECC_KEY_LEN]
            { 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a,
              0x4b, 0x8a, 0x82, 0x11, 0x33, 0x4a,
              0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3,
              0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c,
              0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a,
              0xff, 0xc8 }                           // ecc.pub.y[ECC_KEY_LEN]
        }
    }
};

  /* Set the server authentication credentials and add in the storage */
cose_key_t auth_server = {
    NULL,                                          // next
    { 0x32 },                                      // kid[4]
    1,                                             // kid_sz
    { "example.edu" },                             // identity[IDENTITY_MAX_LEN]
    strlen("example.edu"),                         // identity_sz
    2,                                             // kty
    1,                                             // crv
    {                                              // ecc_key_t ecc
        {                                          // ecc.priv[ECC_KEY_LEN]
            0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f,
            0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d,
            0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2,
            0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac
        },
        {                                          // ecc_point_a pub
            {                                      // ecc.pub.x[ECC_KEY_LEN]
                0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3,
                0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48,
                0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb,
                0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0
            },
            {                                      // ecc.pub.y[ECC_KEY_LEN]
                0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c,
                0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86,
                0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0, 0x10,
                0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72
            }
        }
    }
};

  edhoc_add_key(&auth_client);
  edhoc_add_key(&auth_server);

  /* edhoc_server_set_ad_2("MSG2!",strlen("MSG2!")); */

  edhoc_server_init();
  if(!edhoc_server_start()) {
    PROCESS_EXIT();
  }

  /* Generate ephemeral keys */
  // TODO: Do this elsewhere as the curve is not known yet
  generate_ephemeral_key(edhoc_ctx->creds.ephemeral_key.pub.x, edhoc_ctx->creds.ephemeral_key.pub.y, edhoc_ctx->creds.ephemeral_key.priv);

  while(1) {
    PROCESS_WAIT_EVENT();
    uint8_t res = edhoc_server_callback(ev, &data);
    if(res == SERV_FINISHED) {
      LOG_DBG("New EDHOC server finished, export the security context here\n");
      t = RTIMER_NOW();
      if(edhoc_exporter_oscore(&osc, edhoc_ctx) < 0) {
        LOG_ERR("ERROR IN EXPORT CTX\n");
      } else {
        t = RTIMER_NOW() - t;
        LOG_INFO("Server time to generate OSCORE ctx: %" PRIu32 " ms (%" PRIu32 " CPU cycles ).\n", (uint32_t)((uint64_t)t * 1000 / RTIMER_SECOND), (uint32_t)t);

        print_oscore_ctx(&osc);
      }
      res = SERV_RESTART;
    }
    if(res == SERV_RESTART) {
      edhoc_server_restart();
      LOG_INFO("Server restarting\n");
      generate_ephemeral_key(edhoc_ctx->creds.ephemeral_key.pub.x, edhoc_ctx->creds.ephemeral_key.pub.y, edhoc_ctx->creds.ephemeral_key.priv);
      LOG_INFO("Compile time: %s %s\n", __DATE__, __TIME__);
    }
  }
  PROCESS_END();
}
