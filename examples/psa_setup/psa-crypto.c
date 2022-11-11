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
#include "psa-crypto.h"
#include "sha3.h"
#include "biguint128.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

uint8_t myPrivateKeyingMaterial[32] = {0x54,0x16,0x19,0x15,0x20,0x33,0x07,0x90,0x94,0xc5,
                                      0xa5,0xce,0xad,0x2f,0x1b,0x43,0xa6,0xac,0xf5,0x15,
                                      0x24,0x91,0x55,0xd0,0x19,0x5d,0xb7,0x0d,0x17,0x16,0x00,0x7e};

extern const uint8_t psa_key_material[PSA_KEY_LEN]; //Allocate 2096 128 bit values
uint8_t psa_scratchpad[PSA_KEY_LEN]; //Allocate 2096 128 bit values
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
  printf("hash:\n");
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
    
    /*
    size_t read = biguint128_import(&num, (const char*)buf); 
    printf("read %zu bytes\n", read);
    char res_str[42];
    res_str[biguint128_print_dec(&num, res_str, 42)]=0;
    printf("Bytes interpreted as int\n %s\n", res_str);
    */
    return num;
}

//Encrypt psa_key add it to psa_scratchpad
void encrypt_psa_key(){
    printf("Encrypting PSA key\n");

    //TODO add psa_key_num that is PSA_KEY_LEN/16
    for ( int i = 0; i < PSA_KEY_LEN/16; i++) {
      //get number from psa_key 
      BigUInt128 key_number = b16_to_u128(&psa_key_material[16*i]);

      // add number to psa_scratchpad
      //first take number from scratchpad
      uint8_t* sp_ptr = &psa_scratchpad[16*i];
      BigUInt128 sp_number; 
      //Use import and keep byte order
      biguint128_import(&sp_number, (const char*)sp_ptr);
      //add current number to scratchpad number
      BigUInt128 sum = biguint128_add(&key_number, &sp_number);
      char res_str[42];
      res_str[biguint128_print_dec(&key_number, res_str, 42)]=0;
      printf("Adding: %s ", res_str);
      res_str[biguint128_print_dec(&sp_number, res_str, 42)]=0;
      printf(" + %s ", res_str);
      res_str[biguint128_print_dec(&sum, res_str, 42)]=0;
      printf(" =  %s\n", res_str);
      //export number back
      biguint128_export(&sum, (char*)sp_ptr);

    } 

}

//32 byte input key
//Generate one round of keystream, interpet it as an u128 and add to the scratchpad.
void generate_keystream(uint8_t* symmetric_key, uint16_t keystream_len){
  //Run AES-ECB with counter to make AES-CTR that generate one block at the time.
  //IV = '0'
  uint8_t counter[16] = {0}; 
  
  AESECB_Handle handle;
  CryptoKey cryptoKey;
  int_fast16_t encryptionResult;

  handle = AESECB_open(0, NULL);
  if (!handle) {
    printf("Could not open AES handle\n");
  }
 
  CryptoKeyPlaintext_initKey(&cryptoKey, symmetric_key, 32);
  AESECB_Operation operation;
  AESECB_Operation_init(&operation);
  
  uint8_t byte_buffer[16] = {0};
  operation.key               = &cryptoKey;
  operation.input             = counter;
  operation.output            = byte_buffer;
  operation.inputLength       = 16;

  // iterate over psa_key_len
  for( uint16_t i = 0; i < PSA_KEY_LEN/16; i++) {
    //Set up counter
    counter[14] = ((0xFF00&i)>>8);  
    counter[15] = 0x00FF&i;  
   /* printf("IV\n");
    for (int i = 0; i < 16; i++) {
      printf("%02X", counter[i]);
    }
    printf("\n");
*/
   // run aes-ctr get 16 bytes
    encryptionResult = AESECB_oneStepEncrypt(handle, &operation);
    if (encryptionResult != AESECB_STATUS_SUCCESS) {
      printf("AESECB failed!\n");
    }
    /*
    printf("step %d, generated bytes:\n", i);
    for (int i = 0; i < 16; i++) {
      printf("%02X", byte_buffer[i]);
    }
    printf("\n");
    */
    // convert bytes to 128-bit integer
    BigUInt128 new_number = b16_to_u128(byte_buffer);

    // add number to psa_scratchpad
    //first take number from scratchpad
    uint8_t* sp_ptr = &psa_scratchpad[16*i];
    BigUInt128 sp_number; // = b16_to_u128(sp_ptr);
    //Use import and keep byte order
    biguint128_import(&sp_number, (const char*)sp_ptr);
    //add current number to scratchpad number
    BigUInt128 sum = biguint128_add(&new_number, &sp_number);
    /*
    char res_str[42];
    res_str[biguint128_print_dec(&sum, res_str, 42)]=0;
    printf("Sum\n %s\n", res_str);
    */
    //export number back
    biguint128_export(&sum, (char*)sp_ptr);

  }

  AESECB_close(handle);
}

void init_psa_crypto() {
  printf("PSA key\n");
  for( int i = 0; i < PSA_KEY_LEN; i++){
    printf("%02X", psa_key_material[i]);
    if ( (i + 1) % 16 == 0 ){
      printf("\n");
    }
  }
  printf("\n");


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

/*
void generate_psa_key() {
  TRNG_Handle trngHandle;
  uint16_t result;

  result = CryptoKeyPlaintext_initBlankKey(&psa_key, psa_key_material, PSA_KEY_LEN);
  if( result != CryptoKey_STATUS_SUCCESS) {
    printf("Error! Could not create crypto key!\n");
  }

  trngHandle = TRNG_open(0, NULL);
  if (!trngHandle) {
    printf("Error! Cannot open TRNG handle!\n");
  }

  result = TRNG_generateEntropy(trngHandle, &psa_key);

  if (result != TRNG_STATUS_SUCCESS) {
    printf("Error! TRNG did not work!\n");
  } else {
    printf("Sucess! Key created!\n");
  }
 
  TRNG_close(trngHandle);
}
*/
#define BUFLEN 42

BigUInt128 b64_to_u128(const uint8_t* hash) {
    //Reverse byteorder. Take 128 least-significant bits and interpret as number
    uint8_t buf[64];
    memcpy(buf, hash, 64);
    BigUInt128 num;
    reverse_endianness(&buf[48], 16);
    size_t read = biguint128_import(&num, (const char*)&buf[48]); 
    printf("read %zu bytes\n", read);
    char res_str[BUFLEN];
    res_str[biguint128_print_dec(&num, res_str, BUFLEN)]=0;
    printf("Hash interpreted as int\n %s\n", res_str);
 
    //UINT128 TEST!!
    return num;
}

void psa_encrypt(uint8_t* psa_key, uint64_t label, uint64_t message) {
  printf("PSA encrypt\n");
  sha3_context c;
  const uint8_t* hash;
//just a hash test
//input is 8 bytes of label||0x00||two bytes of lambda
//label and lambda is big-endian

  for ( uint16_t lambda = 0; lambda < 1; lambda++) {
//      hash label||i
    uint8_t data[11];
    memset(data, 0, 11);
    uint64_t* u64_ptr = (uint64_t*)&data[0];
    *u64_ptr = label;
    reverse_endianness(&data[0], 8);
  
    uint16_t* u16_ptr = (uint16_t*)&data[9];
    *u16_ptr = lambda;
    reverse_endianness(&data[9], 2);
 

    printf("data\n");
    for ( int i = 0; i < 11; i++) {
      printf("%02X", data[i]);
    }
    printf("\n"); 
    sha3_Init512(&c);
    sha3_Update(&c, data, 11);
    hash = sha3_Finalize(&c);
    printf("hash\n");
    for ( int i = 0; i < 64; i++) {
      printf("%02X", hash[i]);
    }
    printf("\n"); 
    BigUInt128 num;
    num = b64_to_u128(hash); 
    char res_str[BUFLEN];
    res_str[biguint128_print_dec(&num, res_str, BUFLEN)]=0;
    printf("returned uint\n %s\n", res_str);

//      convert to integer
//      mod 2^128
//      add
}


}
