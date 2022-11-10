#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP


#define PSA_KEY_LEN 16*2096

void reverse_endianness(uint8_t *a, unsigned int len);

void NIKE(uint16_t my_id, uint16_t remote_id, uint8_t* my_sk, uint8_t* remote_pk);

void generate_keystream(uint8_t* symmetric_key, uint16_t keystream_len);

void init_psa_crypto();

void generate_psa_key();

void psa_encrypt(uint8_t* psa_key, uint64_t label, uint64_t message);
