#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP


#define DIPSAUCE_KEY_LEN      16
#define DIPSAUCE_KEY_NUM   10000
#define DIPSAUCE_KEY_LEN_BYTES DIPSAUCE_KEY_LEN*DIPSAUCE_KEY_NUM

uint16_t dipsauce_get_neighbors(uint8_t* key, uint16_t num_users);

void reverse_endianness(uint8_t *a, unsigned int len);

void NIKE(uint16_t my_id, uint16_t remote_id, uint8_t* my_sk, uint8_t* remote_pk);

void init_dipsauce_crypto();

void dipsauce_encrypt(uint64_t label, uint64_t message, uint16_t num_users, uint8_t* ciphertext_buffer);
#endif /* PSA_CRYPTO_H */
