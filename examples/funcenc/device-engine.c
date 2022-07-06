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

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Main"
#define LOG_LEVEL LOG_LEVEL_MAIN

/* Last two bytes of ip address in host endianness */
#define e_addr  0xF682
#define d1_addr 0xec46
#define d2_addr 0x7149
#define d3_addr 0x4D45

static void res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_1,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_2,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_3,"", NULL, res_post_handler, NULL, NULL);
RESOURCE(res_e,"", NULL, res_post_handler, NULL, NULL);

/* Return 0 for evaluator, number for device number */
uint8_t determine_role(){

  uip_ds6_addr_t *lladdr;
  memcpy(&uip_lladdr.addr, &linkaddr_node_addr, sizeof(uip_lladdr.addr));
  lladdr = uip_ds6_get_link_local(-1);
  LOG_INFO("My IPv6 address: ");
  LOG_INFO_6ADDR(lladdr != NULL ? &lladdr->ipaddr : NULL);

  uint8_t ret = 255;
  // Beware of endianess here
  switch (lladdr->ipaddr.u16[7]) {
    case e_addr:
      ret = 0;
      break;
    case d1_addr:
      ret = 1;
      break;
    case d2_addr:
      ret = 2;
      break;
    case d3_addr:
      ret = 3;
      break;
    default:
      ret = 99;

  }

  return ret;

}


void start_device(){
//set up resources
  coap_activate_resource(&res_1, "mk1");
  coap_activate_resource(&res_2, "mk2");
  coap_activate_resource(&res_3, "mk3");
//secure resources
//TODO
}

void start_evaluator(){
  coap_activate_resource(&res_e, "mke");
}




static void res_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset){
  
  const uint8_t *payload = NULL;
  int payload_len = coap_get_payload(request, &payload);
  printf("Got : ");
  for (int i = 0; i < payload_len; i++){
    printf("%02X", payload[i]);
  }
  printf("\n");
  coap_set_status_code(response, CHANGED_2_04);
}

