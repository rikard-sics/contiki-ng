CONTIKI_PROJECT = oscore-example-server oscore-example-client
# use target "oscore-plugtest-server" explicitly when required

MAKE_WITH_OSCORE = 1
WERROR = 1
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=4096
CFLAGS += -DOSCORE_EP_CTX_ASSOCIATION

all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include CoAP resources
MODULES_REL += ./resources

CONTIKI=../..

# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

include $(CONTIKI)/Makefile.include

