CONTIKI_PROJECT = group-oscore-server
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

# Include the Multicast implementation
MODULES += os/net/ipv6/multicast


MAKE_WITH_OSCORE = 1
MAKE_WITH_GROUPCOM = 1
MAKE_WITH_HW_CRYPTO = 1

# Include CoAP resources
MODULES_REL += ./resources

#dissable Werror for now
WERROR=0

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
