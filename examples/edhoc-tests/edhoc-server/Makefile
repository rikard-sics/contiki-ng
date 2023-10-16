CONTIKI_PROJECT = edhoc-test-server

all: $(CONTIKI_PROJECT)

# Include CoAP resources
MODULES_REL += ./resources

#uecc fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1 

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
# Include webserver module
# FIXME: should not include cross-examples.
MODULES_REL += ../../rpl-border-router/webserver

MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc
MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc/server

# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)



include $(CONTIKI)/Makefile.include
