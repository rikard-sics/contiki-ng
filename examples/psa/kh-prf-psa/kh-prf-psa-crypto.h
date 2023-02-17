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


#define PSA_KEY_LEN          2096 //2096
#define PSA_KEY_LEN_BYTES 16*PSA_KEY_LEN //2096

void reverse_endianness(uint8_t *a, unsigned int len);

void NIKE(uint16_t my_id, uint16_t remote_id, uint8_t* my_sk, uint8_t* remote_pk);


void init_psa_crypto();

void generate_psa_key();

void encrypt_psa_key_init();
void encrypt_psa_key_update();
void encrypt_psa_key_finalize();

void psa_encrypt(uint64_t label, uint64_t message, uint16_t num_users, uint8_t* ciphertext_buffer);
#endif /* PSA_CRYPTO_H */
