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

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern coap_resource_t
  res_hello;


static struct etimer et;

#define SERVER_EP "coap://[fd00::212:4b00:14b5:d8fb]"
char *url = "test/hello";
#define TOGGLE_INTERVAL 10

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
   const uint8_t *chunk;
  
  int len = coap_get_payload(response, &chunk);
  LOG_DBG("Response: ");
  printf("%.*s\n", len, (char *)chunk);
}



PROCESS(er_example_server, "Device");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();
  printf("FuncEnc Device\n");
  
 // static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static coap_endpoint_t server_ep;
  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  
  uint8_t role = determine_role();
  printf("My role is %d\n", role);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et)) {
      LOG_DBG("--Toggle timer--\n");
/*
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0); 
      coap_set_header_uri_path(request, url);

      const char msg[] = "Toggle!";

      coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1); 

      LOG_DBG_COAP_EP(&server_ep);
      LOG_DBG_("\n");

      COAP_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);

      LOG_DBG("--Done--\n");

      etimer_reset(&et);
*/
    }   
  }

  PROCESS_END();
}

