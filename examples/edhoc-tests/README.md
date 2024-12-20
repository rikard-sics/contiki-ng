An EDHOC Client and Server that demonstrate the EDHOC module based on IETF[RFC9528], running as RPL node and RPL router respectively on the Cooja Simulator.

# EDHOC Cooja demo

Run the demo from within the Cooja gui. This executes a demo with one client and one server, using the Method zero. For actual tests which can be run without gui, please see the Contiki test folder.

#EDHOC Client Example
An EDHOC Client Example is provided at `examples/edhoc-tests/edhoc-client/edhoc-test-client.c `.
For the specific example the EDHOC Server IP must be selected in the project-conf file, the Node Key Identity and, the EDHOC role as Initiator:

```c
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]" /* Server IP for Cooja simulator */

#define EDHOC_CONF_ROLE EDHOC_INITIATOR
```

#EDHOC Server Example
An EDHOC Server Example is provided at `examples/edhoc-tests/edhoc-server/edhoc-test-server.c `.

The Server Identity must be selected at:

```c
#define AUTH_SUBJECT_NAME "Server_key_identity"
```
