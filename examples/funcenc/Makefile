all: device
# use target "oscore-plugtest-server" explicitly when required

CONTIKI=../..

# build RESTful resources
include $(CONTIKI)/Makefile.identify-target

MODULES_REL += ./resources
MODULES_REL += $(TARGET)
PROJECT_SOURCEFILES += device-engine.c

# Include the CoAP implementation
MODULES += os/net/app-layer/coap

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
