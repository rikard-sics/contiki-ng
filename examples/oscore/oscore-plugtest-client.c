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
#include "dev/button-sensor.h"
#include "plugtest_resources.h"

#ifdef WITH_OSCORE
#include "oscore.h"

void response_handler(void* response);

uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 
uint8_t *sender_id = NULL;
uint8_t receiver_id[] = { 0x01};
#endif /* WITH_OSCORE */

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fe80::202:0002:0002:0002]"
char* server_ip =  "coap://[fe80::202:0002:0002:0002]";

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;

extern uint8_t failed_tests;
//uint8_t token[2] = { 0x05, 0x05};
extern uint8_t test;

#define NUMBER_OF_URLS 8
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "oscore/hello/coap", "oscore/hello/1", "oscore/hello/2", "oscore/hello/3", "oscore/hello/6", "oscore/hello/7" };


PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static coap_endpoint_t server_ep;

  coap_endpoint_parse(server_ip, strlen(server_ip), &server_ep);

  /* receives all CoAP messages */
  coap_engine_init();

  #ifdef WITH_OSCORE
  oscore_init_client();

  static oscore_ctx_t *context;
  context = oscore_derive_ctx(master_secret, 16, NULL, 0, 10, sender_id, 0, receiver_id, 1, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!context){
	printf("Could not create OSCORE Security Context!\n");
  }
  
  oscore_ep_ctx_set_association(&server_ep, service_urls[2], context);
  oscore_ep_ctx_set_association(&server_ep, service_urls[3], context);
  oscore_ep_ctx_set_association(&server_ep, service_urls[4], context);
  oscore_ep_ctx_set_association(&server_ep, service_urls[5], context);
  oscore_ep_ctx_set_association(&server_ep, service_urls[6], context);

  #endif /* WITH_OSCORE */
  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  
  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      switch ( test ) {
        case 0:
          test0_a(request);
          break;
        case 1:
          test1_a(request);
          break;
        case 2:
          test2_a(request);
          break;
        case 3:
          test3_a(request);
          break;
        case 4:
          //test4_a( &server_ipaddr, REMOTE_PORT);
          printf("Skipping test 4a\n");
          break;
        case 5:
          printf("Skipping test 5a\n");
          break;
        case 6:
          test6_a(request);
          break;
        case 7:
          test7_a(request);
          break;
        case 8:
          test8_a(request);
          break;
        case 9:
          test9_a(request);
          break;
        case 10:
          test10_a(request);
          break;
        case 11:
          test11_a(request);
          break;
        case 12:
          test12_a(request);
          break;
        case 13:
          test13_a(request);
          break;
        case 14:
          test14_a(request);
          break;
        case 15:
          test15_a(request);
          break;
        default:
          if(failed_tests == 0){
          printf("ALL tests PASSED! Drinks all around!\n");
          } else {
            printf("%d tests failed! Go back and fix those :(\n", failed_tests);
          }
      }
      if(test != 4 && test != 5){
        //coap_set_token(request, token, 2);
        //COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request, response_handler);
      }
      test++;

      etimer_reset(&et);


    }
  }

  PROCESS_END();
}

void response_handler(void* response){
  printf("Response handler test: %d\n", test);
  switch (test) {
    case 0:
      test0_a_handler(response);
      break;
    case 1:
      test1_a_handler(response);
      break;
    case 2:
      test2_a_handler(response);
      break;
    case 3:
      test3_a_handler(response);
      break;
    case 4:
      printf("Skipping Test 4a Handler\n");
      break;
    case 5:
      printf("Skipping Test 5a Handler\n");
      break;
    case 6:
      test6_a_handler(response);
      break;
    case 7:
     test7_a_handler(response);
      break;
    case 8:
      test8_a_handler(response);
      break;
    case 9:
      test9_a_handler(response);
      break;
    case 10:
      test10_a_handler(response);
      break;
    case 11:
      test11_a_handler(response);
      break;
    case 12:
      printf("TEST 12 Handler\n");
      test12_a_handler(response);
      break;
    case 13:
      test13_a_handler(response);
      break;
    case 14:
      test14_a_handler(response);
      break;
    case 15:
      test15_a_handler(response);
      break;
    default:
      printf("Default handler\n");
  }
}

