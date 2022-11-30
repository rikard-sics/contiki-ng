/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h"
#include "ti/drivers/cryptoutils/ecc/ECCParams.h"
#include "ti/drivers/SHA2.h"
#include "ti/drivers/AESECB.h"

#include <stdio.h> /* For printf() */
/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Hello world process");
AUTOSTART_PROCESSES(&hello_world_process);
/*---------------------------------------------------------------------------*/


PROCESS_THREAD(hello_world_process, ev, data)
{
  static struct etimer timer;
static SHA2_Handle sha_handle;
static AESECB_Handle aes_handle;
static CryptoKey cryptoKey;
static AESECB_Operation operation;
static uint8_t aes_key[16] = {0x74, 0xdf, 0xc7, 0x8e, 0x53, 0xd9, 0x4b, 0xf1, 0xfa, 0xd7, 0xb2, 0xb2, 0x51, 0x91, 0x12, 0x91};
static const uint8_t in_data[32]    = {0x40, 0x8c, 0x7d, 0x1f, 0x80, 0x2c, 0x1e, 0xe7, 0x58, 0xb5, 0xc7, 0x4a, 0x42, 0xdf, 0x50, 0xdc,
                                      0xf0, 0x69, 0xb9, 0x07, 0x8f, 0xec, 0xe8, 0x7d, 0x70, 0x6f, 0xdc, 0x17, 0x64, 0x39, 0x2d, 0x6d};
static uint8_t counter[16] = {0};
static uint8_t out[32] = {0};

  PROCESS_BEGIN();
  
  SHA2_init();
  AESECB_init();
  /* Setup a periodic timer that expires after 10 seconds. */
  etimer_set(&timer, CLOCK_SECOND * 10);
  sha_handle = SHA2_open(0, NULL);
  if (!sha_handle) {
    printf("SHA2 driver could not be opened\n");
  }
  
  aes_handle = AESECB_open(0, NULL);
  if (!aes_handle) {
    printf("Could not open AES handle\n");
  }
  
  CryptoKeyPlaintext_initKey(&cryptoKey, aes_key, 16);
  AESECB_Operation_init(&operation);

  operation.key               = &cryptoKey;
  operation.input             = counter;
  operation.output            = out;
  operation.inputLength       = 16;

  while(1) {
    printf("Hello, Crypto\n");
    unsigned long long start = RTIMER_NOW();
    for (int i = 0; i < 10000; i++){
      int_fast16_t result;
      result = SHA2_hashData(sha_handle, in_data, 32, out);
      if (result != SHA2_STATUS_SUCCESS) {
        printf("SHA2 driver could not produce value\n");
      }
    }
    unsigned long long end = RTIMER_NOW();
    printf("Hashing took %llu ticks\n", end-start);    
    start = RTIMER_NOW();
    for (int i = 0; i < 10000; i++){
      int_fast16_t result;
      result = AESECB_oneStepEncrypt(aes_handle, &operation);
      if (result != AESECB_STATUS_SUCCESS) {
        printf("AESECB failed!\n");
      }
    }
    end = RTIMER_NOW();
    printf("AES took %llu ticks\n", end-start);    

    /* Wait for the periodic timer to expire and then restart the timer. */
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
