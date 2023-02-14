#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "ti/drivers/ECDH.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#include "ti/drivers/cryptoutils/ecc/ECCParams.h"
#include "ti/drivers/TRNG.h"
#include "ti/drivers/SHA2.h"
#include "ti/drivers/AESECB.h"
#include "dipsauce-crypto.h"
#include "biguint128.h"
#include "tprpg.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

uint8_t myPrivateKeyingMaterial[32] = {0x54,0x16,0x19,0x15,0x20,0x33,0x07,0x90,0x94,0xc5,
                                      0xa5,0xce,0xad,0x2f,0x1b,0x43,0xa6,0xac,0xf5,0x15,
                                      0x24,0x91,0x55,0xd0,0x19,0x5d,0xb7,0x0d,0x17,0x16,0x00,0x7e};

extern const uint8_t dipsauce_keys[DIPSAUCE_KEY_LEN_BYTES];

uint8_t myPublicKeyingMaterial[64] = {0};
uint8_t theirPublicKeyingMaterial[64] = {0};
uint8_t sharedSecretKeyingMaterial[64] = {0}; //TODO try reading from this when ECDH is done
uint8_t symmetricKeyingMaterial[32] = {0};
uint16_t my_id = 1;
uint16_t neighbors[200];
uint8_t  dipsauce_randomness[32];

CryptoKey myPrivateKey;
CryptoKey myPublicKey;
CryptoKey psa_key; //Used to interface the TRNG

ECDH_Handle ecdhHandle;
ECDH_OperationGeneratePublicKey operationGeneratePublicKey;
ECDH_OperationComputeSharedSecret operationComputeSharedSecret;

void
reverse_endianness(uint8_t *a, unsigned int len) {
	uint8_t i, tmp[len];
	memcpy(tmp, a, len);
	for(i = 0; i < len; i++) {
		 a[len - 1 - i] = tmp[i];
	}
}

// Square root of integer - from wikipedia
unsigned int int_sqrt ( unsigned int s )
{
  // Zero yields zero
  // One yields one
  if (s <= 1) {
    return s;
  }
  // Initial estimate (must be too high)
  unsigned int x0 = s / 2;

  // Update
  unsigned int x1 = ( x0 + s / x0 ) / 2;

  while ( x1 < x0 ) {   // Bound check
    x0 = x1;
    x1 = ( x0 + s / x0 ) / 2;
  }

  return x0;
}

uint16_t dipsauce_get_neighbors(uint8_t* key, uint16_t num_users){
  uint16_t sqrt_num_users = int_sqrt(num_users);
  //printf("num users %u, sqrt %u \n", num_users, sqrt_num_users);
  tprpg_ctx ctx;
  tprpg_setkey(&ctx, key, 256);

  uint32_t my_id_perm = tprpg(&ctx, my_id, num_users);

  int j = 0;
  for (int i = 0; i < num_users; i++) {
    uint32_t id_perm = tprpg(&ctx, i, num_users);
    //printf("permute %u\n", id_perm); 
    if(((id_perm/sqrt_num_users) == (my_id_perm/sqrt_num_users)) ||
      ((id_perm%sqrt_num_users) == (my_id_perm%sqrt_num_users))){
      if(i != my_id){
        neighbors[j] = i;
        j++;
      }
    }
  }

  return j;
}

static void prepare_nike_data(uint16_t my_id, uint16_t remote_id, uint8_t* shared_secret, uint8_t* data) {
  //Set my_id and reverse order to big endian
  uint16_t* int_ptr = (uint16_t*)&data[0];
  *int_ptr = my_id;
  reverse_endianness(&data[0], 2);
  //Set remote_id and reverse order to big endian
  int_ptr = (uint16_t*)&data[2];
  *int_ptr = remote_id;
  reverse_endianness(&data[2], 2);
  
  memcpy(&data[4], sharedSecretKeyingMaterial, 64);
  //Reverse endianness of x & y in shared secret
  reverse_endianness(&data[4], 32);
  reverse_endianness(&data[4+32], 32);

}

void NIKE(uint16_t my_id, uint16_t remote_id, uint8_t* my_sk, uint8_t* remote_pk) {

  CryptoKey theirPublicKey;
  CryptoKey sharedSecret;
  SHA2_Handle handle;
  uint16_t result;
  CryptoKeyPlaintext_initKey(&theirPublicKey, theirPublicKeyingMaterial, sizeof(theirPublicKeyingMaterial));
  CryptoKeyPlaintext_initBlankKey(&sharedSecret, sharedSecretKeyingMaterial, sizeof(sharedSecretKeyingMaterial));

  ECDH_OperationComputeSharedSecret_init(&operationComputeSharedSecret);
  operationComputeSharedSecret.curve              = &ECCParams_NISTP256;
  operationComputeSharedSecret.myPrivateKey       = &myPrivateKey;
  operationComputeSharedSecret.theirPublicKey     = &theirPublicKey;
  operationComputeSharedSecret.sharedSecret       = &sharedSecret;

  result = ECDH_computeSharedSecret(ecdhHandle, &operationComputeSharedSecret);
  if (result != ECDH_STATUS_SUCCESS) {
    printf("Could not generate shared secret\n");
  }

  //Hash the shared secret accoding to NIKE
  handle = SHA2_open(0, NULL);
  if (!handle) {
    printf("SHA2 driver could not be opened\n");
  }
   
  //data is our_id||their_id||shared_secret
  //We do this with the mysterious magic of C pointers
  uint8_t data[2+2+64];

  prepare_nike_data(my_id, remote_id, sharedSecretKeyingMaterial, data);
  result = SHA2_hashData(handle, data, 2+2+64, symmetricKeyingMaterial);
  if (result != SHA2_STATUS_SUCCESS) {
    printf("SHA2 driver could not produce value\n");
  }
  SHA2_close(handle);
  
}

BigUInt128 b16_to_u128(const uint8_t* bytes) {
    //Reverse byteorder. Take 128 bits and interpret as number
    uint8_t buf[16];
    memcpy(buf, bytes, 16);
    reverse_endianness(buf, 16);
    BigUInt128 num;
    biguint128_import(&num, (const char*)buf); 
    
    return num;
}

void u128_to_b16(BigUInt128* num, uint8_t* byte_array){
  biguint128_export(num, (char*)byte_array);
  reverse_endianness(byte_array, 16);
} 

BigUInt128 b64_to_u128(const uint8_t* hash) {
    //Reverse byteorder. Take 128 least-significant bits and interpret as number
    uint8_t buf[64];
    memcpy(buf, hash, 64);
    BigUInt128 num;
    reverse_endianness(&buf[48], 16);
    biguint128_import(&num, (const char*)&buf[48]); 
    
    return num;
}

BigUInt128 b32_to_u128(const uint8_t* hash) {
    //Reverse byteorder. Take 128 least-significant bits and interpret as number
    uint8_t buf[32];
    memcpy(buf, hash, 32);
    BigUInt128 num;
    reverse_endianness(&buf[16], 16);
    biguint128_import(&num, (const char*)&buf[16]); 
    
    return num;
}



void init_dipsauce_crypto() {

  uint16_t result;

  TRNG_init();
  ECDH_init();
  SHA2_init();
  AESECB_init();

  ecdhHandle = ECDH_open(0, NULL);
  if (!ecdhHandle) {
    printf("ECDH driver could not be opened!\n");
  }

  CryptoKeyPlaintext_initKey(&myPrivateKey, myPrivateKeyingMaterial, sizeof(myPrivateKeyingMaterial));
  CryptoKeyPlaintext_initBlankKey(&myPublicKey, myPublicKeyingMaterial, sizeof(myPublicKeyingMaterial));

  ECDH_OperationGeneratePublicKey_init(&operationGeneratePublicKey);
  operationGeneratePublicKey.curve            = &ECCParams_NISTP256;
  operationGeneratePublicKey.myPrivateKey     = &myPrivateKey;
  operationGeneratePublicKey.myPublicKey      = &myPublicKey;

  result = ECDH_generatePublicKey(ecdhHandle, &operationGeneratePublicKey);
  if (result != ECDH_STATUS_SUCCESS) {
    printf("Could not generate public key!\n");
  }
  
  printf("Private Key:\n");
  for( int i = 0; i < 32; i++){
    printf("%02X", myPrivateKeyingMaterial[i]);
  }
  printf("\n");
  printf("Public Key:\n");
  for( int i = 0; i < 64; i++){
    printf("%02X", myPublicKeyingMaterial[i]);
  }
  printf("\n");

}

#define BUFLEN 42

void dipsauce_encrypt(uint64_t label, uint64_t message, uint16_t num_users, uint8_t* ciphertext_buffer) {
  //Run AES-ECB with counter to make AES-CTR that generate one block at the time.
  uint8_t counter[16] = {0}; 
  counter[12] = ((0xFF000000&label)>>32);  
  counter[13] = ((0xFF0000&label)>>16);  
  counter[14] = ((0xFF00&label)>>8);  
  counter[15] = 0x00FF&label;  
  
  AESECB_Handle handle;
  CryptoKey cryptoKey;
  int_fast16_t encryptionResult;
  BigUInt128 ciphertext_sum = biguint128_value_of_uint(message);

  handle = AESECB_open(0, NULL);
  if (!handle) {
    printf("Could not open AES handle\n");
  }
  
  for(int i = 0; i < num_users; i++) {
    //Get new key from key array
    uint8_t* symm_key = (uint8_t*)&dipsauce_keys[i*16];
    CryptoKeyPlaintext_initKey(&cryptoKey, symm_key, 16);
    AESECB_Operation operation;
    AESECB_Operation_init(&operation);
    
    uint8_t byte_buffer[16] = {0};
    operation.key               = &cryptoKey;
    operation.input             = counter;
    operation.output            = byte_buffer;
    operation.inputLength       = 16;

    // run aes-ctr get 16 bytes
    encryptionResult = AESECB_oneStepEncrypt(handle, &operation);
    if (encryptionResult != AESECB_STATUS_SUCCESS) {
        printf("AESECB failed!\n");
    }
    
    // convert bytes to 128-bit integer
    BigUInt128 new_number = b16_to_u128(byte_buffer);

    // add number to ciphertext_sum
    ciphertext_sum = biguint128_add(&new_number, &ciphertext_sum);
    
  }
  AESECB_close(handle);
  
  //export number back
  u128_to_b16(&ciphertext_sum, ciphertext_buffer);

}
