CONTIKI_PROJECT = oscore-test-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

MAKE_WITH_OSCORE = 1

#Determine what tetst to build, 4 (RTT) by default
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
