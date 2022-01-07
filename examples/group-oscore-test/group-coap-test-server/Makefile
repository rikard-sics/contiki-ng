CONTIKI_PROJECT = group-coap-test-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..

include $(CONTIKI)/Makefile.identify-target

MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

MAKE_WITH_GROUPCOM = 1

# Include the CoAP implementation
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast

#Determine what tetst to build, 4 (RTT) by default
ifeq ($(strip $(TEST)),)
CFLAGS += -DTEST=4
else
CFLAGS += -DTEST=$(TEST)
endif

# Include CoAP resources
MODULES_REL += ../resources

include $(CONTIKI)/Makefile.include
