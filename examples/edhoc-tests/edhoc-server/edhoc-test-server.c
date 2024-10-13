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

#if TEST == TEST_VECTOR_TRACE_2
#if 0
  uint8_t eph_pub_x_r[ECC_KEY_LEN] = { 0x81, 0xdf, 0x54, 0xb3, 0x75, 0x6a, 0xcf, 0xc8, 0xa1, 0xe9, 0xb0, 0x8b, 0xa1, 0x0d, 0xe4, 0xe7, 0xe7, 0xdd, 0x93, 0x45, 0x87, 0xa1, 0xec, 0xdb,
                                               0x21, 0xb9, 0x2f, 0x8f, 0x22, 0xc3, 0xa3, 0x8d };
#else
  uint8_t eph_pub_x_r[ECC_KEY_LEN] = { 0x41, 0x97, 0x01, 0xd7, 0xf0, 0x0a, 0x26, 0xc2, 0xdc, 0x58, 0x7a, 0x36, 0xdd, 0x75, 0x25, 0x49, 0xf3, 0x37, 0x63, 0xc8, 0x93, 0x42, 0x2c,
  0x8e, 0xa0, 0xf9, 0x55, 0xa1, 0x3a, 0x4f, 0xf5, 0xd5 };
#endif
#if 0
  uint8_t eph_pub_y_r[ECC_KEY_LEN] = { 0xd6, 0xd5, 0xb9, 0xf3, 0x10, 0x8a, 0x90, 0xec, 0x5a, 0x13, 0x19, 0x6f, 0x2b, 0x64, 0x9b, 0x95, 0xe6, 0x53, 0x6f, 0x9a, 0x89, 0x8f, 0x6a, 0xeb,
                                               0xb8, 0xd3, 0xca, 0xdd, 0x85, 0x3c, 0xe5, 0x24 };
#else
  uint8_t eph_pub_y_r[ECC_KEY_LEN] = { 0x5e, 0x4f, 0x0d, 0xd8, 0xa3, 0xda, 0x0b, 0xaa, 0x16, 0xb9, 0xd3, 0xad, 0x56, 0xa0, 0xc1, 0x86, 0x0a, 0x94, 0x0a, 0xf8, 0x59, 0x14, 0x91,
  0x5e, 0x25, 0x01, 0x9b, 0x40, 0x24, 0x17, 0xe9, 0x9d };
#endif
#if 0
  uint8_t eph_private_r[ECC_KEY_LEN] = { 0x73, 0x97, 0xba, 0x34, 0xa7, 0xb6, 0x0a, 0x4d, 0x98, 0xef, 0x5e, 0x91, 0x56, 0x3f, 0xc8, 0x54, 0x9f, 0x35, 0x54, 0x49, 0x4f, 0x1f, 0xeb, 0xd4,
                                                 0x65, 0x36, 0x0c, 0x4b, 0x90, 0xe7, 0x41, 0x71 };
#else
  uint8_t eph_private_r[ECC_KEY_LEN] = { 0xe2, 0xf4, 0x12, 0x67, 0x77, 0x20, 0x5e, 0x85, 0x3b, 0x43, 0x7d, 0x6e, 0xac, 0xa1, 0xe1, 0xf7, 0x53, 0xcd, 0xcc, 0x3e, 0x2c, 0x69, 0xfa,
  0x88, 0x4b, 0x0a, 0x1a, 0x64, 0x09, 0x77, 0xe4, 0x18 };
#endif
#endif

  /* Set the client authentication credentials and add in the storage */
  cose_key_t auth_client = { NULL, { 0x2b }, 1,
                             { "42-50-31-FF-EF-37-32-39" }, strlen("42-50-31-FF-EF-37-32-39"),
                             KEY_TYPE, KEY_CRV,
                             { 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6, },
                             { 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8 },
                             };

#if 0
  cose_key_t auth_client = { NULL, { 0x2b }, 1,
                             { "42-50-31-FF-EF-37-32-39" }, strlen("42-50-31-FF-EF-37-32-39"),
                             KEY_TYPE, KEY_CRV,
                             { 0xcd, 0x41, 0x77, 0xba, 0x62, 0x43, 0x33, 0x75, 0xed, 0xe2, 0x79, 0xb5, 0xe1, 0x8e, 0x8b, 0x91, 0xbc, 0x3e, 0xd8, 0xf1, 0xe1, 0x74, 0x47, 0x4a, 0x26, 0xfc, 0x0e, 0xdb, 0x44, 0xea, 0x53, 0x73 },
                             { 0xa0, 0x39, 0x1d, 0xe2, 0x9c, 0x5c, 0x5b, 0xad, 0xda, 0x61, 0x0d, 0x4e, 0x30, 0x1e, 0xaa, 0xa1, 0x84, 0x22, 0x36, 0x77, 0x22, 0x28, 0x9c, 0xd1, 0x8c, 0xbe, 0x66, 0x24, 0xe8, 0x9b, 0x9c, 0xfd },
                             };
#endif


  /* Set the server authentication credentials and add in the storage */
  cose_key_t auth_server = { NULL, { 0x32 }, 1,
                             { "example.edu" }, strlen("example.edu"),
                             KEY_TYPE, KEY_CRV,
                             { 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0 },
                             { 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd, 0xe0,0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72 },
                             { 0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed,
                             0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac },
                             };

#if 0
  cose_key_t auth_server = { NULL, { 0x32 }, 1,
                             { "example.edu" }, strlen("example.edu"),
                             KEY_TYPE, KEY_CRV,
                             { 0x6f, 0x97, 0x02, 0xa6, 0x66, 0x02, 0xd7, 0x8f, 0x5e, 0x81, 0xba, 0xc1, 0xe0, 0xaf, 0x01, 0xf8, 0xb5, 0x28, 0x10, 0xc5, 0x02, 0xe8, 0x7e, 0xbb, 0x7c, 0x92, 0x6c, 0x07, 0x42, 0x6f, 0xd0, 0x2f },
                             { 0xc8, 0xd3, 0x32, 0x74, 0xc7, 0x1c, 0x9b, 0x3e, 0xe5, 0x7d, 0x84, 0x2b, 0xbf, 0x22, 0x38, 0xb8, 0x28, 0x3c, 0xb4, 0x10, 0xec, 0xa2, 0x16, 0xfb, 0x72, 0xa7, 0x8e, 0xa7, 0xa8, 0x70, 0xf8, 0x00 },
                             { 0xec, 0x93, 0xc2, 0xf8, 0xa5, 0x8f, 0x12, 0x3d, 0xaa, 0x98, 0x26, 0x88, 0xe3, 0x84, 0xf5, 0x4c, 0x10, 0xc5, 0x0a, 0x1d, 0x2c, 0x90, 0xc0, 0x03, 0x04, 0xf6, 0x48, 0xe5, 0x8f, 0x14, 0x35, 0x4c },
                             };
#endif


  edhoc_add_key(&auth_client);
  edhoc_add_key(&auth_server);

  /* edhoc_server_set_ad_2("MSG2!",strlen("MSG2!")); */

  edhoc_server_init();
  if(!edhoc_server_start()) {
    PROCESS_EXIT();
  }

  t = RTIMER_NOW();
#if TEST == TEST_VECTOR_TRACE_2
  LOG_INFO("Using test vector\n");
  memcpy(edhoc_ctx->ephemeral_key.public.x, eph_pub_x_r, ECC_KEY_LEN);
  memcpy(edhoc_ctx->ephemeral_key.public.y, eph_pub_y_r, ECC_KEY_LEN);
  memcpy(edhoc_ctx->ephemeral_key.private_key, eph_private_r, ECC_KEY_LEN);
#if ECC == UECC_ECC
  LOG_INFO("set curve of uEcc\n");
  edhoc_ctx->curve.curve = uECC_secp256r1();
#endif
#elif ECC == UECC_ECC
  LOG_INFO("generate key with uEcc\n");
  edhoc_ctx->curve.curve = uECC_secp256r1();
  uecc_generate_key(&edhoc_ctx->ephemeral_key, edhoc_ctx->curve);
#elif ECC == CC2538_ECC
  LOG_INFO("generate key with CC2538 HW modules\n");
  static key_gen_t key = {
    .process = &edhoc_example_server,
    .curve_info = &nist_p_256,
  };
  PT_SPAWN(&edhoc_example_server.pt, &key.pt, generate_key_hw(&key));
  memcpy(edhoc_ctx->ephemeral_key.public.x, key.x, ECC_KEY_LEN);
  memcpy(edhoc_ctx->ephemeral_key.public.y, key.y, ECC_KEY_LEN);
  memcpy(edhoc_ctx->ephemeral_key.private_key, key.private, ECC_KEY_LEN);

#endif
  t = RTIMER_NOW() - t;
  LOG_INFO("Server time to generate new key: %" PRIu32 " ms (%" PRIu32 " CPU cycles ).\n", (uint32_t)((uint64_t)t * 1000 / RTIMER_SECOND), (uint32_t)t);

  LOG_DBG("Gy (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(edhoc_ctx->ephemeral_key.public.x, ECC_KEY_LEN);
  LOG_DBG("Y (%d bytes): ", ECC_KEY_LEN);
  print_buff_8_dbg(edhoc_ctx->ephemeral_key.private_key, ECC_KEY_LEN);
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
      t = RTIMER_NOW();
#if TEST == TEST_VECTOR_TRACE_2
      LOG_INFO("Using test vector\n");

#elif ECC == UECC_ECC
      LOG_INFO("generate key with uEcc\n");
      edhoc_ctx->curve.curve = uECC_secp256r1();
      uecc_generate_key(&edhoc_ctx->ephemeral_key, edhoc_ctx->curve);
#elif ECC == CC2538_ECC
      LOG_INFO("generate key with CC2538 HW modules\n");
      static key_gen_t key = {
        .process = &edhoc_example_server,
        .curve_info = &nist_p_256,
      };
      PT_SPAWN(&edhoc_example_server.pt, &key.pt, generate_key_hw(&key));

      memcpy(edhoc_ctx->ephemeral_key.public.x, key.x, ECC_KEY_LEN);
      memcpy(edhoc_ctx->ephemeral_key.public.y, key.y, ECC_KEY_LEN);
      memcpy(edhoc_ctx->ephemeral_key.private_key, key.private, ECC_KEY_LEN);

#endif
      t = RTIMER_NOW() - t;
      LOG_INFO("Server time to generate new key: %" PRIu32 " ms (%" PRIu32 " CPU cycles ).\n", (uint32_t)((uint64_t)t * 1000 / RTIMER_SECOND), (uint32_t)t);
      LOG_INFO("Compile time: %s %s\n", __DATE__, __TIME__);
      LOG_INFO("\n");
      LOG_INFO("G_y (%d bytes): ", ECC_KEY_LEN);
      print_buff_8_info(edhoc_ctx->ephemeral_key.public.x, ECC_KEY_LEN);
      LOG_INFO("Y (%d bytes): ", ECC_KEY_LEN);
      print_buff_8_info(edhoc_ctx->ephemeral_key.private_key, ECC_KEY_LEN);
    }
  }
  PROCESS_END();
}
