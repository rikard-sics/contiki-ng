#ifndef GROUP_OSCORE_TEST_COMMON_CONF_H_
#define GROUP_OSCORE_TEST_COMMON_CONF_H_

#if TEST == 1 //Memory Tests
#define STACK_CHECK_CONF_ENABLED 1 
#define STACK_CHECK_CONF_PERIOD 10*CLOCK_SECOND

#elif TEST == 2 //CPU Test
#define STACK_CHECK_CONF_ENABLED 0 
#define PROCESSING_TIME 1

#elif TEST == 3 //Energest Test
#define STACK_CHECK_CONF_ENABLED 0 
#define ENERGEST_CONF_ON 1

#elif TEST == 4 //Round Trip Time Test
#define STACK_CHECK_CONF_ENABLED 0 

#elif TEST == 5 //Otii Energy mesurements
#define OTII_ENERGY 1 
#define STACK_CHECK_CONF_ENABLED 0 
//Toggle GPIO pins when serialize and parse functions are executing to enable
//precise enery mesurements.

//For ZOUL
#if CONTIKI_TARGET_ZOUL
#define TEST_GPIO_PORT GPIO_PORT_TO_BASE(GPIO_C_NUM)
#define TEST_GPIO_PARSE_PIN     GPIO_PIN_MASK(0)
#define TEST_GPIO_SERIALIZE_PIN     GPIO_PIN_MASK(0)
//#define TEST_GPIO_SERIALIZE_PIN GPIO_PIN_MASK(1)

#elif CONTIKI_TARGET_SIMPLELINK
#define TEST_GPIO_PORT GPIO_HAL_NULL_PORT 

#define TEST_GPIO_PARSE_PIN Board_DIO25_ANALOG

#endif /* TARGET */
#else
#endif /* TEST */

/*For testing*/
#define LOG_LEVEL_APP           LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_COAP     LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_MAIN     LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_TCPIP    LOG_LEVEL_NONE
#define LOG_CONF_LEVEL_IPV6     LOG_LEVEL_NONE
/* For debug */
/*
#define LOG_LEVEL_APP           LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAIN     LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_TCPIP    LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_IPV6     LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL    	LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_6LOWPAN  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC      LOG_LEVEL_DBG
*/


#define CSMA_CONF_ACK_WAIT_TIME RTIMER_SECOND * 20
#define COAP_CONF_MULTICAST_RESPONSE_DELAY 8
#define COAP_CONF_MULTICAST_REQUEST_TIMEOUT_INTERVAL 10000

/* For Imin: Use 16 over CSMA, 64 over Contiki MAC */
#define RF_CONF_MODE RF_MODE_2_4_GHZ
#define ROLL_TM_CONF_IMIN_1         64

#define REST_MAX_CHUNK_SIZE 250

/* Enable more RAM on CC2538 and increase Stack size. */
#define LPM_CONF_MAX_PM 1
#define CC2538_CONF_STACK_SIZE 1000

#ifdef PROCESSING_TIME
extern unsigned long parsing_time_s;
extern unsigned long parsing_time_e;
extern unsigned long serializing_time_s;
extern unsigned long serializing_time_e;
#ifdef WITH_OSCORE
extern unsigned long decryption_time_s;
extern unsigned long decryption_time_e;
extern unsigned long encryption_time_s;
extern unsigned long encryption_time_e;
#ifdef WITH_GROUPCOM
extern unsigned long verify_time_s;
extern unsigned long verify_time_e;
extern unsigned long sign_time_s;
extern unsigned long sign_time_e;
#endif /* WITH_GROUPCOM */
#endif /* WITH_OSCORE */
#endif /* PROCESSING_TIME */

#endif /* GROUP_OSCORE_TEST_COMMON_CONF_H_ */
