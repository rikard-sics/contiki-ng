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
#include "lass-crypto.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP


/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fd00::1]"

/* Declaired in psa-crypto.c */
extern uint8_t lass_keys[LASS_KEY_LEN_BYTES]; //Allocate 2096 128 bit values
extern uint8_t myPrivateKeyingMaterial[32];
extern uint8_t myPublicKeyingMaterial[64];
extern uint8_t theirPublicKeyingMaterial[64];
extern uint8_t symmetricKeyingMaterial[64];
extern uint16_t my_id;

#define TOGGLE_INTERVAL 10
static int pk_i = 2;

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
static const char* pk_url = "pubkey";
static const char* data_url = "data";

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */

void get_pk_handler(coap_message_t *response);
void lass_msg_handler(coap_message_t *response);

//TODO create nike handler, Blockwise handler and 


static int iteration = 0;
static uint16_t num_keys = 1000;
static int block_index = 0;

static unsigned long long start;
static unsigned long long end;

PROCESS_THREAD(er_example_client, ev, data)
{
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  
  init_lass_crypto();
  
  etimer_set(&et, 60 * CLOCK_SECOND); // Long delay to let network start
  while(1) {
    PROCESS_YIELD();


    if(etimer_expired(&et)) {
    //Get Public keys
    //compute nike and throw away the key
    //send aks_i
    //encrypt values
      printf("--Get pk_i and encrypt ek_i --\n");
      start = RTIMER_NOW();
      //while(pk_i <= num_keys+1){
      while(pk_i <= 10+1){
          char str_buf[8];
          sprintf(str_buf, "%d", pk_i);
          coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
          coap_set_header_uri_path(request, pk_url);
          coap_set_header_uri_query(request, str_buf);
          COAP_BLOCKING_REQUEST(&server_ep, request, get_pk_handler);
      }
      end = RTIMER_NOW();
      printf("s %llu\n", (end - start));
      printf("-- Sending PSA msg--\n");
     
      start = RTIMER_NOW(); 
      uint8_t ciphertext_buf[16] = {0}; 
      //lass_encrypt(iteration, iteration+num_keys, num_keys, ciphertext_buf);
      lass_encrypt(1, 0, 10, ciphertext_buf);
       
      coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
      coap_set_header_uri_path(request, data_url);
      coap_set_payload(request, ciphertext_buf, 16);
      COAP_BLOCKING_REQUEST(&server_ep, request, lass_msg_handler);
      end = RTIMER_NOW();
      printf("e %llu\n", (end - start));
     
      //increment iteration and prepare for next round 
      iteration++;
      pk_i = 2;
      block_index = 0;
      //we run 10 iterations per number of keys
      if(iteration >= 10) {
        iteration = 0;
        num_keys += 1000;
        if( num_keys > 10000){
          printf("End of tests!\n");
          etimer_set(&et, 200 * CLOCK_SECOND);
        }
      }
      
      etimer_set(&et, 5 * CLOCK_SECOND);
          
    }
  }

  PROCESS_END();
}

void get_pk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  if(response == NULL) {
    puts("Request timed out");
    return;
  }

  int len = coap_get_payload(response, &chunk);
  if ( len == 0){
    return; //Exit this function
  } 
  //Get ID that arrive MSB-first
  uint16_t their_id =  (chunk[0]<<8) | (chunk[1]);
  //printf("Their ID %d\n", their_id); 

  //Get public key offset 3, 2 bytes ID + 1 byte public key header
  memcpy(&theirPublicKeyingMaterial, &chunk[3], 64);
  reverse_endianness(theirPublicKeyingMaterial, 32);
  reverse_endianness(&theirPublicKeyingMaterial[32], 32);
/*  printf("their pubkey\n");
  for (int k=0; k < 64; k++){
    printf("%02X", theirPublicKeyingMaterial[k]);
  }
  printf("\n");
  */
  //call NIKE TODO add errors and error handling
  NIKE(my_id, their_id, myPrivateKeyingMaterial, theirPublicKeyingMaterial);
  
  //Store symmetric key in array
  //memcpy(&lass_keys[pk_i-2], symmetricKeyingMaterial, 16);
  printf("nike key %d\n", their_id);
  for( int k = 0; k < 16; k++){
    printf("%02X", symmetricKeyingMaterial[k]);
  }
  printf("\n");


  pk_i++;
}

void lass_msg_handler(coap_message_t *response)
{

  if(response == NULL) {
    puts("Request timed out");
    return;
  }

}
