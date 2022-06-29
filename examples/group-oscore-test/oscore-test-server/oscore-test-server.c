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
 *      Erbium (Er) CoAP Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"
#include "oscore.h"

/* Keys included from file */
#include "../server-keys.h"

/* For energy mesurements */
#if OTII_ENERGY == 1 && CONTIKI_TARGET_SIMPLELINK == 1
#include <Board.h>
#include "dev/gpio-hal.h"
#endif /* OTII_ENERGY && CONTIKI_TARGET_SIMPLELINK */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP
/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern coap_resource_t
  res_post;

static struct etimer et;
PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);
PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();
  PROCESS_PAUSE();

  LOG_INFO("Starting OSCORE Server\n");

  oscore_init_server();

  /*Derive an OSCORE-Security-Context. */
  static oscore_ctx_t *context;
  context = oscore_derive_ctx(master_secret, 16, salt, 8, 10, server_id, 1, client_id, 1, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!context){
        LOG_ERR("Could not create OSCORE Security Context!\n");
  }

  coap_activate_resource(&res_post, "uc/post");
  oscore_protect_resource(&res_post);

#ifdef OTII_ENERGY
  #if CONTIKI_TARGET_ZOUL
    GPIO_SOFTWARE_CONTROL(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN);
    GPIO_SET_OUTPUT(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN);
    GPIO_SOFTWARE_CONTROL(TEST_GPIO_PORT, TEST_GPIO_SERIALIZE_PIN);
    GPIO_SET_OUTPUT(TEST_GPIO_PORT, TEST_GPIO_SERIALIZE_PIN);
    
    GPIO_CLR_PIN(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN);
    GPIO_CLR_PIN(TEST_GPIO_PORT, TEST_GPIO_SERIALIZE_PIN);
    
  #elif CONTIKI_TARGET_SIMPLELINK
    gpio_hal_arch_init();
    gpio_hal_arch_pin_set_output(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN);
    gpio_hal_arch_write_pin(TEST_GPIO_PORT, TEST_GPIO_PARSE_PIN, 0);

#endif /* TARGET */
#endif /* OTII_ENERGY */

  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}
