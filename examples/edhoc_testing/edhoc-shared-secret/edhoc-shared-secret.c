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
 *      ECDSA 256 shared secret calculation example in software.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 *      Rikard Höglund
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"

#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

//Rikard: Include the uECC header
#include "uECC.h"
#include "tinydtls.h"

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern coap_resource_t
  res_hello,
  res_mirror,
  res_chunks,
  res_separate,
  res_push,
  res_event,
  res_sub,
  res_b1_sep_b2;
#if PLATFORM_HAS_LEDS
extern coap_resource_t res_leds, res_toggle;
#endif
#if PLATFORM_HAS_LIGHT
#include "dev/light-sensor.h"
extern coap_resource_t res_light;
#endif
#if PLATFORM_HAS_BATTERY
#include "dev/battery-sensor.h"
extern coap_resource_t res_battery;
#endif
#if PLATFORM_HAS_TEMPERATURE
#include "dev/temperature-sensor.h"
extern coap_resource_t res_temperature;
#endif

PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  LOG_INFO("Starting Erbium Example Server\n");


  //Rikard: Testing shared secret calculation
  //Note that the curve is set in the Makefile

  printf("===\r\n");
  printf("===\r\n");
  printf("Shared secret calculation starting\r\n");

/*
  uint8_t rcv_public_key[64] = { 0xCA, 0x37, 0x63, 0x38, 0x99, 0x87, 0x8F, 0xD0, 0x32, 0xA6, 0xCA, 0x20, 0xBF, 0xE3, 0x45, 0x09,
   0x88, 0x02, 0x91, 0x6D, 0xB3, 0xD2, 0xAA, 0xF5, 0xC7, 0xAA, 0x4F, 0x06, 0x52, 0xF7, 0x17, 0x74, 0xEB, 0x7D, 0xAB, 0x8B, 0x46,
   0x49, 0x03, 0xF5, 0xE2, 0x67, 0x75, 0x4E, 0x76, 0x04, 0x79, 0x93, 0x25, 0x97, 0x92, 0x06, 0x48, 0x48, 0x3C, 0xE0, 0xD3, 0x50,
   0xE6, 0xE4, 0x96, 0x4E, 0x93, 0xDD};

  uint8_t snd_public_key[64] = { 0x4C, 0x04, 0x3D, 0xCB, 0xA7, 0xDC, 0x9B, 0x21, 0x39, 0xF7, 0x49, 0x7C, 0x03, 0x0F, 0x4B, 0xE1,
   0x3B, 0xB6, 0x62, 0xD3, 0x62, 0x4C, 0xA5, 0x5D, 0x8D, 0x96, 0xEB, 0x40, 0xD9, 0xB0, 0x33, 0x6F, 0x67, 0xEB, 0x2F, 0xB7, 0x26,
   0x92, 0x71, 0xEB, 0x04, 0x9E, 0xC6, 0x8A, 0xA9, 0x9B, 0xB1, 0x11, 0x08, 0x45, 0xA0, 0x20, 0xC6, 0x27, 0x94, 0x1B, 0x37, 0x6F,
   0x03, 0xD9, 0xB0, 0x49, 0x81, 0x89 };

  uint8_t snd_private_key[32] = { 0x16, 0xD9, 0x89, 0x42, 0x23, 0x7C, 0xE1, 0x03, 0x23, 0x5D, 0x0E, 0xDF, 0x3A, 0xE4, 0x5B, 0x0B,
   0xB3, 0xB3, 0x6F, 0x79, 0x5E, 0x05, 0xDA, 0xEC,0x99, 0x44, 0x30, 0x2A, 0x7B, 0x26, 0x0A, 0x3C };

  uint8_t rcv_private_key[32] = { 0xE8, 0x98, 0x69, 0xAF, 0xA7, 0x69, 0x87, 0xBC, 0xBC, 0xBF, 0xE3, 0x10, 0xB6, 0xFA, 0xE8, 0x6E,
   0x31, 0x50, 0x64, 0xC0, 0x76, 0x93, 0x32, 0x28, 0x48, 0xF2, 0x24, 0x15, 0x43, 0x07, 0xAE, 0xF9 };
*/

  uint8_t private1[32] = {0};
  uint8_t private2[32] = {0};
  uint8_t public1[64] = {0};
  uint8_t public2[64] = {0};
  uint8_t secret1[32] = {0};
  uint8_t secret2[32] = {0};

  // Generate 2 keys
  uECC_make_key(public1, private1);
  uECC_make_key(public2, private2);

  // Calculate shared secret 1
  uECC_shared_secret(public2, private1, secret1);

  // Calculate shared secret 2
  uECC_shared_secret(public1, private2, secret2);

  // Make sure they are the same
  if (memcmp(secret1, secret2, sizeof(secret1)) != 0) {
    printf("Shared secrets are NOT identical\n");
  } else {
    printf("Shared secrets are identical\n");
  }

  printf("Shared secret calculation over\r\n");
  printf("===\r\n");
  printf("===\r\n");

  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  coap_activate_resource(&res_hello, "test/hello");
  coap_activate_resource(&res_mirror, "debug/mirror");
  coap_activate_resource(&res_chunks, "test/chunks");
  coap_activate_resource(&res_separate, "test/separate");
  coap_activate_resource(&res_push, "test/push");
#if PLATFORM_HAS_BUTTON
  coap_activate_resource(&res_event, "sensors/button");
#endif /* PLATFORM_HAS_BUTTON */
  coap_activate_resource(&res_sub, "test/sub");
  coap_activate_resource(&res_b1_sep_b2, "test/b1sepb2");
#if PLATFORM_HAS_LEDS
/*  coap_activate_resource(&res_leds, "actuators/leds"); */
  coap_activate_resource(&res_toggle, "actuators/toggle");
#endif
#if PLATFORM_HAS_LIGHT
  coap_activate_resource(&res_light, "sensors/light");
  SENSORS_ACTIVATE(light_sensor);
#endif
#if PLATFORM_HAS_BATTERY
  coap_activate_resource(&res_battery, "sensors/battery");
  SENSORS_ACTIVATE(battery_sensor);
#endif
#if PLATFORM_HAS_TEMPERATURE
  coap_activate_resource(&res_temperature, "sensors/temperature");
  SENSORS_ACTIVATE(temperature_sensor);
#endif

  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
#if PLATFORM_HAS_BUTTON
#if PLATFORM_SUPPORTS_BUTTON_HAL
    if(ev == button_hal_release_event) {
#else
    if(ev == sensors_event && data == &button_sensor) {
#endif
      LOG_DBG("*******BUTTON*******\n");

      /* Call the event_handler for this application-specific event. */
      res_event.trigger();

      /* Also call the separate response example handler. */
      res_separate.resume();
    }
#endif /* PLATFORM_HAS_BUTTON */
  }                             /* while (1) */

  PROCESS_END();
}
