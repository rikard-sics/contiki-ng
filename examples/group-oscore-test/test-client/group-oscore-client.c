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
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "oscore.h"
#include "../client-keys.h"
#include "../client-conf.h"
#include "dev/leds.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

#define MULTICAST_EP "coap://[ff1E::89:ABCD]"

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_IPV6_RPL"
#endif

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
char *url = "mc/post";

static uint8_t payload_lengths[PAYLOAD_NUM] = {1, 32, 64, 128};
static unsigned long send_time_s;
static unsigned long first_response_time_s;
static unsigned long last_response_time_s;
static uint8_t num_msg;

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  if(response == NULL) {
    printf("f:%lu,l:%lu,m:%d\n", (first_response_time_s - send_time_s), (last_response_time_s - send_time_s), num_msg);
    return;
  } else {
    num_msg++;
  }

  if (first_response_time_s == 0){
    first_response_time_s = RTIMER_NOW();
  }

  last_response_time_s = RTIMER_NOW();
}


PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();
  NETSTACK_ROUTING.root_start();
  oscore_init_client();  
 
  static coap_endpoint_t server_ep;
  static coap_message_t request[1]; /* This way the packet can be treated as pointer as usual. */
  static oscore_ctx_t *contexts[SERVER_NUM];
  static uint8_t token[2] = {0xAA, 0x00};
  static int j = 0;
  static int p = 0;
  static int iter = 0;
  
  /* Context 1 */
  contexts[0] = oscore_derive_ctx(master_secret, 16, salt, 8, 10, client_id, 1, server_id_1, 1, group_id, 3, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!contexts[0]){
        LOG_ERR("Could not create OSCORE Security Context!\n");
  }
  oscore_add_group_keys(contexts[0], client_public_key, client_private_key, server_public_key_1, COSE_Algorithm_ECC, COSE_Elliptic_Curve);
  
  /* Context 2 */
  contexts[1] = oscore_derive_ctx(master_secret, 16, salt, 8, 10, client_id, 1, server_id_2, 1, group_id, 3, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!contexts[1]){
        LOG_ERR("Could not create OSCORE Security Context!\n");
  }
  oscore_add_group_keys(contexts[1], client_public_key, client_private_key, server_public_key_2, COSE_Algorithm_ECC, COSE_Elliptic_Curve);
  
  /* Context 3 */
  contexts[2] = oscore_derive_ctx(master_secret, 16, salt, 8, 10, client_id, 1, server_id_3, 1, group_id, 3, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!contexts[1]){
        LOG_ERR("Could not create OSCORE Security Context!\n");
  }
  oscore_add_group_keys(contexts[2], client_public_key, client_private_key, server_public_key_3, COSE_Algorithm_ECC, COSE_Elliptic_Curve);
  
  oscore_ep_ctx_set_association(&server_ep, url, contexts[0]);
  coap_endpoint_parse(MULTICAST_EP, strlen(MULTICAST_EP), &server_ep);

  etimer_set(&et, CLOCK_SECOND * 60);

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      send_time_s = RTIMER_NOW();
      num_msg = 0;
      first_response_time_s = 0;
      last_response_time_s = 0;

      uint8_t payload_len = payload_lengths[p];
      coap_init_message(request, COAP_TYPE_NON, COAP_POST, 0);
      char dummy_payload[128];
      memset(dummy_payload, 'a', payload_len);
      coap_set_header_uri_path(request, url);
      coap_set_token(request, token, 2);
      coap_set_payload(request, dummy_payload, payload_len);

      COAP_MULTICAST_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);
      token[1]++;
      printf("--Done--\n");

      iter++;
      if( iter >= ITERATIONS){ /* If we have done the desired number of iterations we increase the payload length. */
        p++;
        iter = 0;
      }

      etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
    } else if(etimer_expired(&et) && p >= PAYLOAD_NUM) {
        printf("Tests over!\n");
        leds_on(LEDS_GREEN);
        etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
    }
  }

  PROCESS_END();
}
