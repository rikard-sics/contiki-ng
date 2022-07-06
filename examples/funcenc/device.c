#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "device-engine.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "server"
#define LOG_LEVEL LOG_LEVEL_DBG

static struct etimer et;

#define TOGGLE_INTERVAL 10

static uint8_t role = 255;

PROCESS(er_example_server, "Device");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();
  printf("FuncEnc Device\n");
  
  role = determine_role();
  printf("My role is %d\n", role);
  if (role == 0) {
    start_evaluator();
  } else {
    start_device(role);
  }
 
  etimer_set(&et, 20 * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if ( role != 0) {
        LOG_DBG("--Toggle timer--\n");
        send_masking_key_shares(role);
        etimer_reset(&et);
        LOG_DBG("--Done--\n");
      }   
    }
  }

  PROCESS_END();
}

