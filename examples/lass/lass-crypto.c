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
#include "lass-crypto.h"
#include "biguint128.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

uint8_t myPrivateKeyingMaterial[32] = {0x54,0x16,0x19,0x15,0x20,0x33,0x07,0x90,0x94,0xc5,
                                      0xa5,0xce,0xad,0x2f,0x1b,0x43,0xa6,0xac,0xf5,0x15,
                                      0x24,0x91,0x55,0xd0,0x19,0x5d,0xb7,0x0d,0x17,0x16,0x00,0x7e};

uint8_t lass_keys[LASS_KEY_LEN_BYTES];

uint8_t myPublicKeyingMaterial[64] = {0};
uint8_t theirPublicKeyingMaterial[64] = {0};
uint8_t sharedSecretKeyingMaterial[64] = {0}; //TODO try reading from this when ECDH is done
uint8_t symmetricKeyingMaterial[32] = {0};
uint16_t my_id = 1;

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
  //CryptoKey symmetricKey;
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
  /*
  printf("ECDH secret\n");
  for (int i = 0; i < 64; i++) {
    printf("%02X", sharedSecretKeyingMaterial[i]);
  }
  printf("\n");
  */
   
  //data is our_id||their_id||shared_secret
  //We do this with the mysterious magic of C pointers
  uint8_t data[2+2+64];

  prepare_nike_data(my_id, remote_id, sharedSecretKeyingMaterial, data);
  /*
  printf("nike data\n");
  for (int i = 0; i < 68; i++) {
    printf("%02X", data[i]);
  }
  printf("\n");
  */
  result = SHA2_hashData(handle, data, 2+2+64, symmetricKeyingMaterial);
  if (result != SHA2_STATUS_SUCCESS) {
    printf("SHA2 driver could not produce value\n");
  }
  SHA2_close(handle);
  /*
  printf("Derrived Nike Key ID1 %d ID2 %d:\n", my_id, remote_id);
  for (int i = 0; i < 32; i++) {
    printf("%02X", symmetricKeyingMaterial[i]);
  }
  printf("\n");
  */
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



void init_lass_crypto() {

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

void lass_encrypt(uint64_t label, uint64_t message, uint16_t num_users, uint8_t* ciphertext_buffer) {
  printf("LASS encrypt\n");
  

  //Run AES-ECB with counter to make AES-CTR that generate one block at the time.
  uint8_t counter[16] = {0}; 
  counter[12] = ((0xFF000000&label)>>32);  
  counter[13] = ((0xFF0000&label)>>16);  
  counter[14] = ((0xFF00&label)>>8);  
  counter[15] = 0x00FF&label;  
  
  AESECB_Handle handle;
  CryptoKey cryptoKey;
  int_fast16_t encryptionResult;
  BigUInt128 ciphertext_sum = biguint128_ctor_default();

  handle = AESECB_open(0, NULL);
  if (!handle) {
    printf("Could not open AES handle\n");
  }
  
  for(int i = 0; i < num_users; i++) {
    //Get new key from key array
    CryptoKeyPlaintext_initKey(&cryptoKey, &lass_keys[i], 16);
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
    /*
    res_str[biguint128_print_dec(&sum, res_str, 42)]=0;
    printf("Sum\n %s\n", res_str);
    */
    

    /*char res_str[42];
    if( (i == 0) || (i == PSA_KEY_LEN-1)){ //just print a few values
        res_str[biguint128_print_dec(&sum, res_str, 42)]=0;
        printf("[%d]: %s \n",i, res_str);
        res_str[biguint128_print_dec(&new_number, res_str, 42)]=0;
        printf("%s = ", res_str);
        res_str[biguint128_print_dec(&sum, res_str, 42)]=0;
        printf("%s\n", res_str);
        
    } */
  }
  AESECB_close(handle);
  
  //export number back
  biguint128_export(&ciphertext_sum, (char*)ciphertext_buffer);


}
