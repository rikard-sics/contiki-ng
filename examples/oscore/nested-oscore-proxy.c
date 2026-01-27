#include "coap-blocking-api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"
#ifdef WITH_OSCORE
#include "oscore.h"
#include "oscore-context.h"
#endif /* WITH_OSCORE */

#if PLATFORM_SUPPORTS_BUTTON_HAL
#include "dev/button-hal.h"
#else
#include "dev/button-sensor.h"
#endif

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP


#ifdef WITH_OSCORE
/* Key material, sender-ID and receiver-ID used for deriving an OSCORE-Security-Context. Note that Sender-ID and Receiver-ID is
 * mirrored in the Client and Server. */
uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 
// 0 : proxy -> server 1 : client -> proxy
uint8_t sender_id[2][1] = { {0x02},{0x09} };
uint8_t receiver_id[2][1] = { {0x01},{0x08} };
uint8_t id_contexts[2][1] = { {0x01}, {0x09} };
#endif /* WITH_OSCORE */

#define SERVER_EP "coap://[fe80::203:0003:0003:0003]"
#define CLIENT_EP "coap://[fe80::201:0001:0001:0001]"


PROCESS(er_example_proxy, "Nested OSCORE Example Proxy");
AUTOSTART_PROCESSES(&er_example_proxy);


PROCESS_THREAD(er_example_proxy, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  printf("Starting Nested OSCORE Example Proxy\n");

  #ifdef WITH_OSCORE
  /*Derive an OSCORE-Security-Context. */
  static oscore_ctx_t client_context;
  oscore_derive_ctx(&client_context, master_secret, 16, salt, 8, 10, sender_id[1], 1, receiver_id[1], 1, id_contexts[1], 1);


  
  #endif /* WITH_OSCORE */

    /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}

