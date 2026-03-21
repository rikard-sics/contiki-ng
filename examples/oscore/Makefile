all: oscore-example-server oscore-example-client oscore-plugtest-server oscore-plugtest-client nested-oscore-proxy nested-oscore-client nested-oscore-server
# use target "oscore-plugtest-server" explicitly when required

CONTIKI=../..

MAKE_WITH_OSCORE = 1
WERROR = 1
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=4096
CFLAGS += -DOSCORE_EP_CTX_ASSOCIATION

# build RESTful resources
include $(CONTIKI)/Makefile.identify-target
ifeq ($(TARGET),native)
	MODULES_REL += ./resources-plugtest
endif
MODULES_REL += ./resources
MODULES_REL += ../coap/coap-example-server/resources
MODULES_REL += $(TARGET)

CONTIKI_TARGET_SOURCEFILES += plugtest_resources.c

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

nested-oscore-client.$(TARGET): CFLAGS += -DOSCORE_CLIENT_MODE
nested-oscore-proxy.$(TARGET): CFLAGS += -DOSCORE_PROXY_MODE
nested-oscore-server.$(TARGET): CFLAGS += -DOSCORE_SERVER_MODE

ifeq ($(MAKE_TARGET_MODE),proxy)
    CFLAGS += -DOSCORE_PROXY_MODE
else ifeq ($(MAKE_TARGET_MODE),client)
    CFLAGS += -DOSCORE_CLIENT_MODE
endif

include $(CONTIKI)/Makefile.include

# border router rules
$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 fd00::1/64

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 -p 60001 fd00::1/64

connect-router-native:	$(CONTIKI)/examples/rpl-border-router/border-router.native
	sudo $(CONTIKI)/examples/rpl-border-router/border-router.native -a 127.0.0.1 -p 60001 fd00::1/64

connect-native:
	sudo ip address add fdfd::1/64 dev tun0
