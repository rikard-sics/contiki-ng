/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"
#include "oscore.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP
/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern coap_resource_t
  //res_hello,
  res_mcast;//,
  //res_mcastq;

#if SERVER == 1
uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
uint8_t sender_id[1] = { 0x52 };
uint8_t receiver_id[1] = { 0x25 };
uint8_t group_id[3] = { 0x44, 0x61, 0x6c };
uint8_t snd_public_key[64] = {0x4C,0x04,0x3D,0xCB,0xA7,0xDC,0x9B,0x21,0x39,0xF7,0x49,0x7C,0x03,0x0F,0x4B,0xE1,0x3B,0xB6,0x62,0xD3,0x62,0x4C,0xA5,0x5D,0x8D,0x96,0xEB,0x40,0xD9,0xB0,0x33,0x6F,0x67,0xEB,0x2F,0xB7,0x26,0x92,0x71,0xEB,0x04,0x9E,0xC6,0x8A,0xA9,0x9B,0xB1,0x11,0x08,0x45,0xA0,0x20,0xC6,0x27,0x94,0x1B,0x37,0x6F,0x03,0xD9,0xB0,0x49,0x81,0x89 };
uint8_t snd_private_key[32] = {0x16,0xD9,0x89,0x42,0x23,0x7C,0xE1,0x03,0x23,0x5D,0x0E,0xDF,0x3A,0xE4,0x5B,0x0B,0xB3,0xB3,0x6F,0x79,0x5E,0x05,0xDA,0xEC,0x99,0x44,0x30,0x2A,0x7B,0x26,0x0A,0x3C};
uint8_t rcv_public_key[64] = { 0xCA,0x37,0x63,0x38,0x99,0x87,0x8F,0xD0,0x32,0xA6,0xCA,0x20,0xBF,0xE3,0x45,0x09,0x88,0x02,0x91,0x6D,0xB3,0xD2,0xAA,0xF5,0xC7,0xAA,0x4F,0x06,0x52,0xF7,0x17,0x74,0xEB,0x7D,0xAB,0x8B,0x46,0x49,0x03,0xF5,0xE2,0x67,0x75,0x4E,0x76,0x04,0x79,0x93,0x25,0x97,0x92,0x06,0x48,0x48,0x3C,0xE0,0xD3,0x50,0xE6,0xE4,0x96,0x4E,0x93,0xDD};
uint8_t rcv_private_key[32] = {0xE8,0x98,0x69,0xAF,0xA7,0x69,0x87,0xBC,0xBC,0xBF,0xE3,0x10,0xB6,0xFA,0xE8,0x6E,0x31,0x50,0x64,0xC0,0x76,0x93,0x32,0x28,0x48,0xF2,0x24,0x15,0x43,0x07,0xAE,0xF9};
#elif SERVER == 2
#endif /* SERVER */

PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);
PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  LOG_INFO("Starting Group OSCORE Server\n");

  oscore_init_server();

  /*Derive an OSCORE-Security-Context. */
  static oscore_ctx_t *context;
  context = oscore_derive_ctx(master_secret, 16, salt, 8, 10, sender_id, 1, receiver_id, 1, group_id, 3, OSCORE_DEFAULT_REPLAY_WINDOW, group_id);
  if(!context){
        printf("Could not create OSCORE Security Context!\n");
  }

  uint8_t key_id[1] = { 0x25 };
  oscore_ctx_t *ctx;
  ctx = oscore_find_ctx_by_rid(key_id, 1);
  if(ctx == NULL){
    printf("CONTEXT NOT FOUND\n");
  }
  oscore_add_group_keys(ctx, snd_public_key, snd_private_key, rcv_public_key, rcv_private_key, COSE_Algorithm_ES256, COSE_Elliptic_Curve_P256);  
  //coap_activate_resource(&res_hello, "test/hello");
  coap_activate_resource(&res_mcast, "test/mcast");
  //coap_activate_resource(&res_mcastq, "test/mcastq");
  
  //multicast initialisation stuff here
  //uip_ip6addr(addr, addr0, addr1, addr2, addr3, addr4, addr5, addr6, addr7)
  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}
