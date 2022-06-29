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
#include "../client-conf.h"
#include "dev/leds.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

/* Zoul servers */
//char* server_uris[SERVER_NUM] = {"coap://[fd00::212:4b00:14b5:de16]", "coap://[fd00::212:4b00:14b5:ee10]","coap://[fd00::212:4b00:14b5:d8fb]" }; 
/* Simplelink servers */
char* server_uris[SERVER_NUM] = {"coap://[fd00::212:4b00:1ca7:6356]", "coap://[fd00::212:4b00:1ca1:99ff]","coap://[fd00::212:4b00:1ca7:7713]" }; 

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
char *url = "uc/post";

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
  
  static uint8_t token[2] = {0xAA, 0x00};
  static coap_endpoint_t server_eps[SERVER_NUM];
  static coap_message_t request[SERVER_NUM]; /* This way the packet can be treated as pointer as usual. */
  static int j = 0;
  static int p = 0;
  static int iter = 0;
  
  for (int i = 0; i < SERVER_NUM; i++){
    coap_endpoint_parse(server_uris[i], strlen(server_uris[i]), &server_eps[i]);
  }
  
  etimer_set(&et, CLOCK_SECOND * 60);
  printf("S\n");
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et) && p < PAYLOAD_NUM) {
      send_time_s = RTIMER_NOW();
      num_msg = 0;
      first_response_time_s = 0;
      last_response_time_s = 0;
   
      for( j = 0; j < SERVER_NUM; j++){
        coap_init_message(&request[j], COAP_TYPE_CON, COAP_POST, 0); 
        
        char dummy_payload[128];
        uint8_t payload_len = payload_lengths[p]; 
        memset(dummy_payload, 'a', payload_len);
        
        coap_set_header_uri_path(&request[j], url);
        coap_set_token(&request[j], token, 2);
        coap_set_payload(&request[j], dummy_payload, payload_len);
        COAP_BLOCKING_REQUEST(&server_eps[j], &request[j], client_chunk_handler);
        token[1]++;
      }
      printf("f:%lu,l:%lu,m:%d\n", (first_response_time_s - send_time_s), (last_response_time_s - send_time_s), num_msg);

      iter++;
      if( iter >= ITERATIONS){ /* If we have done the desired number of iterations we increase the payload length. */
        p++;
        printf("%d\n",p);
        iter = 0;
      }

      etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
    } else if(etimer_expired(&et) && p >= PAYLOAD_NUM) {
        printf("E\n");
        leds_on(LEDS_GREEN);
        etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
    }
  } 
  
  PROCESS_END();
}
