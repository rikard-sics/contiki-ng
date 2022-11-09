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
#include "psa-crypto.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP


/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fd00::1]"

/* Declaired in psa-crypto.c */
extern uint8_t psa_key_material[PSA_KEY_LEN]; //Allocate 2096 128 bit values
extern uint8_t psa_scratchpad[PSA_KEY_LEN]; //Allocate 2096 128 bit values
extern uint8_t myPrivateKeyingMaterial[32];
extern uint8_t myPublicKeyingMaterial[64];
extern uint8_t theirPublicKeyingMaterial[64];
extern uint8_t sharedSecretKeyingMaterial[64]; //TODO try reading from this when ECDH is done
extern uint8_t symmetricKeyingMaterial[64];
extern uint16_t my_id;

#define TOGGLE_INTERVAL 10

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
static const char* key_url = "other/block";


/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  if(response == NULL) {
    puts("Request timed out");
    return;
  }

  //int len = coap_get_payload(response, &chunk);
  coap_get_payload(response, &chunk);
  
  
  //printf("|%.*s", len, (char *)chunk);
  memcpy(&theirPublicKeyingMaterial, &chunk[1], 64);
  printf("Before inversion\n");
  for(int i = 0; i < 64; i++){
    printf("%02X", theirPublicKeyingMaterial[i]);
  }
  printf("\n");

  reverse_endianness(theirPublicKeyingMaterial, 32);
  reverse_endianness(&theirPublicKeyingMaterial[32], 32);
  printf("After inversion\n");
  for(int i = 0; i < 64; i++){
    printf("%02X", theirPublicKeyingMaterial[i]);
  }
  printf("\n");

  uint16_t their_id =  55555;
  //call NIKE
  NIKE(my_id, their_id, myPrivateKeyingMaterial, theirPublicKeyingMaterial);
  //get symmetric key
  //generate 33kb of symmetric data
  //
  generate_keystream(symmetricKeyingMaterial, 100);

}



PROCESS_THREAD(er_example_client, ev, data)
{
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();

  init_psa_crypto();
  //generate_psa_key(); 
  
  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */

  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();


    if(etimer_expired(&et)) {
      printf("--Toggle timer--\n");


      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, key_url);
      COAP_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);
      

      printf("--Done--\n");
      etimer_reset(&et);

    }
  }

  PROCESS_END();
}
