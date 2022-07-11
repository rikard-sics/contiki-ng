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
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"
#include "stdio.h"
#include "contiki-net.h"
#include "coap-callback-api.h"
/* Log configuration */
#include "sys/log.h"
#include "coap-log.h"
#define LOG_MODULE "Main"
#define LOG_LEVEL LOG_LEVEL_DBG

/* Last two bytes of ip address in host endianness */
#define e_addr_suffix  0xF682
#define d1_addr_suffix 0xec46
#define d2_addr_suffix 0x7149
#define d3_addr_suffix 0x4D45

#define E_ADDR "coap://[fd00::212:4b00:1ca7:82f6]"
#define D1_ADDR "coap://[fd00::212:4b00:26ad:46ec]"
#define D2_ADDR "coap://[fd00::212:4b00:26ad:4971]"
#define D3_ADDR "coap://[fd00::212:4b00:26ad:454d]"

static coap_endpoint_t endpoints[4];
static coap_callback_request_state_t callback_state[4];

static void res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
void client_chunk_handler(coap_message_t *response);
void callback_func();

RESOURCE(res_1,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_2,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_3,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_e,"", NULL, res_post_handler, NULL, NULL);

char* urls[4] = {"mke", "mk1", "mk2", "mk3"};

/* Return 0 for evaluator, number for device number */
uint8_t determine_role(){

  uip_ds6_addr_t *lladdr;
  memcpy(&uip_lladdr.addr, &linkaddr_node_addr, sizeof(uip_lladdr.addr));
  lladdr = uip_ds6_get_link_local(-1);
  LOG_INFO("My IPv6 address: ");
  LOG_INFO_6ADDR(lladdr != NULL ? &lladdr->ipaddr : NULL);
  LOG_INFO_("\n");

  uint8_t ret = 255;
  // Beware of endianess here
  switch (lladdr->ipaddr.u16[7]) {
    case e_addr_suffix:
      ret = 0;
      break;
    case d1_addr_suffix:
      ret = 1;
      break;
    case d2_addr_suffix:
      ret = 2;
      break;
    case d3_addr_suffix:
      ret = 3;
      break;
    default:
      ret = 99;

  }

  return ret;

}


void start_device(uint8_t role){
//set up resources
  switch (role){
  case 1:
    coap_activate_resource(&res_2, "mk2");
    coap_activate_resource(&res_3, "mk3");
    coap_endpoint_parse(E_ADDR, strlen(E_ADDR), &endpoints[0]);
    coap_endpoint_parse(D2_ADDR, strlen(D2_ADDR), &endpoints[2]);
    coap_endpoint_parse(D3_ADDR, strlen(D3_ADDR), &endpoints[3]);
    break;
  case 2:
    coap_activate_resource(&res_1, "mk1");
    coap_activate_resource(&res_3, "mk3");
    coap_endpoint_parse(E_ADDR, strlen(E_ADDR), &endpoints[0]);
    coap_endpoint_parse(D1_ADDR, strlen(D1_ADDR), &endpoints[1]);
    coap_endpoint_parse(D3_ADDR, strlen(D3_ADDR), &endpoints[3]);
    break;
  case 3:
    coap_activate_resource(&res_1, "mk1");
    coap_activate_resource(&res_2, "mk2");
    coap_endpoint_parse(E_ADDR, strlen(E_ADDR), &endpoints[0]);
    coap_endpoint_parse(D1_ADDR, strlen(D1_ADDR), &endpoints[1]);
    coap_endpoint_parse(D2_ADDR, strlen(D2_ADDR), &endpoints[2]);
    break;
  }
  
  
//secure resources
//TODO
}

void start_evaluator(){
  coap_activate_resource(&res_e, "mke");
}


void send_masking_key_shares(uint8_t role){
  printf("Start sending shares\n");
  for (int i = 0; i < 4; i++){
  if(i == role){
    continue;
  }

  coap_message_t request[1];
  char msg[10];
  coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
  coap_set_header_uri_path(request, urls[role]);
  uint8_t m = role*10 + i;
  sprintf(msg, "%d", m);
  coap_set_payload(request, msg, strlen(msg));
  printf("Sending %s \n", msg);
  LOG_DBG_COAP_EP(&endpoints[i]);
  LOG_DBG_("\n");
  coap_send_request(&callback_state[i], &endpoints[i], request, callback_func);

  }
}

static void res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  
  const uint8_t *payload = NULL;
  int payload_len = coap_get_payload(request, &payload);
  printf("Got %d bytes: %s\n", payload_len, (char*)payload);
  coap_set_status_code(response, CHANGED_2_04);
}

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
   const uint8_t *chunk;
  
  int len = coap_get_payload(response, &chunk);
  LOG_DBG("Response: ");
  printf("%.*s\n", len, (char *)chunk);
}

void callback_func(){
  printf("CALLBACK!\n");
}
