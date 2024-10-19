
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LPM_CONF_MAX_PM 1

#define EDHOC_CONF_TIMEOUT 100000
/* Mandatory EDHOC definitions on Server */
/* Define one kind of the following kind of identification for the authentication key */
//#define AUTH_SUBJECT_NAME "Serv_A"
#define AUTH_KID 0x32

/* Define a value for the Connection Identifier */
// #define EDHOC_CID 0x20
// #define EDHOC_CID -8
#define EDHOC_CID 0x27

/* Define the party role on the EDHOC protocol as responder and the correlation method */
#define EDHOC_CONF_ROLE RESPONDER /* Server */

/* To run with the test vector DH ephemeral keys used on the interoperability session */
#define EDHOC_CONF_TEST TEST_VECTOR_TRACE_DH

/* Define the authentication method */
#define EDHOC_CONF_AUTHENT_TYPE CRED_KID

/* Define the library for SHA operations */
//#define EDHOC_CONF_SH256 DECC_SH2
//#define EDHOC_CONF_SH256 CC2538_SH2

/* Define the library for ECDH operations */
//#define EDHOC_CONF_ECC CC2538_ECC
#define EDHOC_CONF_ECC UECC_ECC

/* To run EDHOC server as RPL node */
//#define EDHOC_CONF_RPL_NODE 1

/* Set the supported cipher suites */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Set up the node as Border Router (if enabled in Makefile) */
#if BORDER_ROUTER_CONF_WEBSERVER
  #ifndef WEBSERVER_CONF_CFS_CONNS
  #define WEBSERVER_CONF_CFS_CONNS 2
  #endif
  #define UIP_CONF_TCP 1
#endif

/* May be necesary to define one of the following macros when the UECC_ECC library is
used and the target is an embedded device */
//#define WATCHDOG_CONF_ENABLE 0x00000000
//#define SYS_CTRL_CONF_SYS_DIV SYS_CTRL_CLOCK_CTRL_SYS_DIV_32MHZ

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_COAP LOG_LEVEL_DBG
/*#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_DBG */
//#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_DBG

#endif /* PROJECT_CONF_H_ */
