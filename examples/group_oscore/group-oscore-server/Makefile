CONTIKI_PROJECT = group-oscore-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

MAKE_WITH_OSCORE = 1
MAKE_WITH_GROUPCOM = 1

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
