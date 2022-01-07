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
 *      Example resource
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include "contiki.h"
#include "coap-engine.h"

#include <string.h>

#ifdef PROCESSING_TIME
#include "rtimer.h"
unsigned long parsing_time_s = 0;
unsigned long parsing_time_e = 0;
unsigned long serializing_time_s = 0;
unsigned long serializing_time_e = 0;
#ifdef WITH_OSCORE
unsigned long decryption_time_s = 0;
unsigned long decryption_time_e = 0;
unsigned long encryption_time_s = 0;
unsigned long encryption_time_e = 0;
#ifdef WITH_GROUPCOM
unsigned long verify_time_s = 0;
unsigned long verify_time_e = 0;
unsigned long sign_time_s = 0;
unsigned long sign_time_e = 0;
#endif /* WITH_GROUPCOM */
#endif /* WITH_OSCORE */
#endif /* PROCESSING_TIME */

/* For energy mesurements */
#if OTII_ENERGY && CONTIKI_TARGET_SIMPLELINK
#include <ti/drivers/GPIO.h>
#include <Board.h>
#endif /* OTII_ENERGY && CONTIKI_TARGET_SIMPLELINK */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

static void res_post_put_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/* A simple actuator example, depending on the color query parameter and post variable mode, corresponding led is activated or deactivated */
RESOURCE(res_post,
         "",
         NULL,
         res_post_put_handler,
         res_post_put_handler,
         NULL);

static uint8_t response_payload[200]; 
static void

res_post_put_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  #ifdef PROCESSING_TIME
  unsigned long parsing_time_e = RTIMER_NOW();

  printf("p:%lu; ", (parsing_time_e - parsing_time_s));

  #ifdef WITH_OSCORE
  printf("d:%lu; ", (decryption_time_e - decryption_time_s));
 
  #ifdef WITH_GROUPCOM
  printf("v:%lu;l:%d ", (verify_time_e - verify_time_s), request->payload_len);
  #endif /* WITH_GROUPCOM */
  #endif /* WITH_OSCORE */
  printf("\n");
  #endif /* PROCESSING_TIME */
  #ifdef OTII_ENERGY
  #if CONTIKI_TARGET_ZOUL
  GPIO_CLR_PIN(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN);
  #elif CONTIKI_TARGET_SIMPLELINK
  GPIO_write(TEST_GPIO_PARSE_PIN, 0);
  #endif /* TARGET */
  #endif /* OTII_ENERGY */
  const uint8_t *payload = NULL;
  int payload_len = coap_get_payload(request, &payload);
  if( payload_len != 0 && payload != NULL) {

  	for (int i = 0; i < payload_len; i++){
		response_payload[i] = (payload[i] - 32); 
	}
  	coap_set_payload(response, response_payload, payload_len); 
    	coap_set_header_content_format(response, TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  	coap_set_status_code(response, CHANGED_2_04);

  } else {
  	coap_set_status_code(response, BAD_REQUEST_4_00);
  }
  #ifdef PROCESSING_TIME
  serializing_time_s = RTIMER_NOW();
  #endif
  #ifdef OTII_ENERGY
  #if CONTIKI_TARGET_ZOUL
  GPIO_SET_PIN(TEST_GPIO_PORT, TEST_GPIO_SERIALIZE_PIN);
  #elif CONTIKI_TARGET_SIMPLELINK
  GPIO_write(TEST_GPIO_SERIALIZE_PIN, 1);
  #endif /* TARGET */
  #endif /* OTII_ENERGY */

}
