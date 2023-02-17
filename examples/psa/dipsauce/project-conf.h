#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#include "net/ipv6/multicast/uip-mcast6-engines.h"

#define RF_CONF_MODE RF_MODE_2_4_GHZ
#define REST_MAX_CHUNK_SIZE 256

#define WATCHDOG_CONF_DISABLE 1

#define LOG_LEVEL_APP LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_NONE

#define GPIO_PORT       GPIO_HAL_NULL_PORT 
#define GPIO_TOGGLE_PIN Board_DIO25_ANALOG

#endif /* PROJECT_CONF_H_ */
