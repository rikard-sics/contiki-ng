CONTIKI_PROJECT = group-oscore-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

MAKE_WITH_OSCORE = 1
MAKE_WITH_GROUPCOM = 1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

# Include the Multicast implementation
MODULES += os/net/ipv6/multicast

#Determine what test to build, 4 (RTT) by default
ifeq ($(strip $(TEST)),)
CFLAGS += -DTEST=4
else
CFLAGS += -DTEST=$(TEST)
endif

#Determine what server to build, 1 by default
ifeq ($(strip $(SERVER)),)
CFLAGS += -DSERVER=1
else
CFLAGS += -DSERVER=$(SERVER)
endif

#Determine what ECDSA algorithm to use, ECDSA P-256 by default
ifeq ($(strip $(ED25519)),1)
MAKE_WITH_ES256 = 0
else
MAKE_WITH_ES256 = 1
endif

#Determine usage of HW/SW cryptography, SW by default 
ifeq ($(strip $(HW)),1)
MAKE_WITH_HW_CRYPTO = 1
else
MAKE_WITH_HW_CRYPTO = 0
endif

# Include CoAP resources
MODULES_REL += ../resources

#dissable Werror for now
WERROR=0

CONTIKI=../../..
include $(CONTIKI)/Makefile.identify-target
include $(CONTIKI)/Makefile.include
