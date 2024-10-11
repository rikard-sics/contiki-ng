CONTIKI_PROJECT = edhoc-test-server

all: $(CONTIKI_PROJECT)

# Include CoAP resources
MODULES_REL += ./resources

#uECC fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1
CFLAGS += -Wno-unused-function

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

ifeq ($(TARGET),cooja)
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
# Include webserver module
# FIXME: should not include across examples
MODULES_REL += ../../rpl-border-router/webserver
CFLAGS += -DBORDER_ROUTER_CONF_WEBSERVER=1
endif

MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc
MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc/server

# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)


include $(CONTIKI)/Makefile.include
