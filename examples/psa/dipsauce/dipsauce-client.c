#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "dipsauce-crypto.h"
#include "tprpg.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

//For GPIO
#include <Board.h>
#include "dev/gpio-hal.h"

#define SERVER_EP "coap://[fd00::1]"

/* Declaired in psa-crypto.c */
extern uint8_t dipsauce_keys[DIPSAUCE_KEY_LEN_BYTES]; //Allocate 2096 128 bit values
extern uint8_t myPrivateKeyingMaterial[32];
extern uint8_t myPublicKeyingMaterial[64];
extern uint8_t theirPublicKeyingMaterial[64];
extern uint8_t symmetricKeyingMaterial[64];
extern uint16_t my_id;
extern uint8_t dipsauce_randomness[32];
extern uint16_t neighbors[200];

#define TOGGLE_INTERVAL 10
static int pk_i = 0;

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;
static const char* random_url = "random";
static const char* pk_url = "pubkey";
static const char* data_url = "data";

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void randomness_handler(coap_message_t *response);
void get_pk_handler(coap_message_t *response);
void dipsauce_msg_handler(coap_message_t *response);

static int iteration = 0;
static uint16_t sizes[11] = {1024, 2025, 3025, 4096, 5041, 6084, 7056, 8100, 9025, 10000, 11000};
static uint8_t size_ctr = 0;
static uint16_t num_keys = 1024;
static int block_index = 0;
static uint16_t retransmissions = 0;
static uint16_t num_neighbors = 0;

static unsigned long long start;
static unsigned long long end;

PROCESS_THREAD(er_example_client, ev, data)
{
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();
  gpio_hal_arch_init();
  gpio_hal_arch_pin_set_output(GPIO_PORT, GPIO_TOGGLE_PIN);
  gpio_hal_arch_write_pin(GPIO_PORT, GPIO_TOGGLE_PIN, 0); 

  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  
  init_dipsauce_crypto();

  etimer_set(&et, 60 * CLOCK_SECOND); // Long delay to let network start
  while(1) {
    PROCESS_YIELD();


    if(etimer_expired(&et)) {
    //Get Public keys
    //compute nike and throw away the key
    //send aks_i
    //encrypt values
      start = RTIMER_NOW();
      gpio_hal_arch_write_pin(GPIO_PORT, GPIO_TOGGLE_PIN, 1);
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, random_url);
      COAP_BLOCKING_REQUEST(&server_ep, request, randomness_handler);
      num_neighbors = dipsauce_get_neighbors(dipsauce_randomness, num_keys);
      
      while(pk_i < num_neighbors){
          char str_buf[8];
          sprintf(str_buf, "%d", neighbors[pk_i]);
          coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
          coap_set_header_uri_path(request, pk_url);
          coap_set_header_uri_query(request, str_buf);
          COAP_BLOCKING_REQUEST(&server_ep, request, get_pk_handler);
      }
      end = RTIMER_NOW();
      gpio_hal_arch_write_pin(GPIO_PORT, GPIO_TOGGLE_PIN, 0);
      if(end < start) { //If end < start, the RTIMER counter (32bit) has overflowed. IIt will do this each 24 hours (approx).
        end += UINT32_MAX;
      }
      //type iter, size, time, retransmissions
      printf("s,%d,%d, %llu, %d\n", iteration, num_keys, (end - start), retransmissions);
      retransmissions = 0;

      start = RTIMER_NOW(); 
      gpio_hal_arch_write_pin(GPIO_PORT, GPIO_TOGGLE_PIN, 1);
      uint8_t ciphertext_buf[16] = {0}; 
      dipsauce_encrypt(iteration, iteration+num_keys, num_neighbors, ciphertext_buf);
      gpio_hal_arch_write_pin(GPIO_PORT, GPIO_TOGGLE_PIN, 0);
      end = RTIMER_NOW();
      if(end < start) { //If end < start, the RTIMER counter (32bit) has overflowed. IIt will do this each 24 hours (approx).
        end += UINT32_MAX;
      }
      printf("e,%d,%d, %llu, %d\n", iteration, num_keys, (end - start), retransmissions);
 
      coap_init_message(request, COAP_TYPE_CON, COAP_PUT, 0);
      coap_set_header_uri_path(request, data_url);
      coap_set_payload(request, ciphertext_buf, 16);
      COAP_BLOCKING_REQUEST(&server_ep, request, dipsauce_msg_handler);
     
      //increment iteration and prepare for next round 
      retransmissions = 0;
      iteration++;
      pk_i = 0;
      block_index = 0;

      //we run 10 iterations per number of keys
      if(iteration >= 10) {
        iteration = 0;
        size_ctr++;
        num_keys = sizes[size_ctr];
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
    retransmissions++;
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
  
  //call NIKE TODO add errors and error handling
  NIKE(my_id, their_id, myPrivateKeyingMaterial, theirPublicKeyingMaterial);

  pk_i++;
}

void dipsauce_msg_handler(coap_message_t *response)
{

  if(response == NULL) {
    retransmissions++;
    return;
  }

}

void randomness_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  if(response == NULL) {
    retransmissions++;
    return;
  }

  coap_get_payload(response, &chunk);
  memcpy(dipsauce_randomness, chunk, 32);
}

