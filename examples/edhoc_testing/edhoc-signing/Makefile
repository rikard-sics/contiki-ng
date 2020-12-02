CONTIKI_PROJECT = edhoc-signing
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky z1

# Include CoAP resources
MODULES_REL += ./resources

#Rikard: See Makefile.coap
#HW/SW Crypto configurations for Zoul
ifeq ($(TARGET), zoul)
ifeq ($(MAKE_WITH_HW_CRYPTO),1)
  CFLAGS += -DOSCORE_WITH_HW_CRYPTO=1
  #Force Zoul to use HW crypto
  CFLAGS += -DCCM_STAR_CONF=cc2538_ccm_star_driver
else  #With SW Crypto
  #Force Zoul to use SW crypto
  CFLAGS += -DCCM_STAR_CONF=ccm_star_driver
    
  #uECC software configuration.
  MODULES += os/net/app-layer/coap/oscore-support/uecc 
  CFLAGS += -DWATCHDOG_CONF_ENABLE=0
  CFLAGS += -DuECC_PLATFORM=uECC_arm
  CFLAGS += -DuECC_CURVE=uECC_secp256r1
endif #MAKE_WITH_HW_CRYPTO
endif #Zoul
#SW Crypto configurations for Native 
ifeq ($(TARGET), native)
  MODULES += os/net/app-layer/coap/oscore-support/uecc 
  CFLAGS += -DuECC_PLATFORM=uECC_x86_64
  CFLAGS += -DuECC_CURVE=uECC_secp256r1
endif

CONTIKI=../../..

# Include the CoAP implementation
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

include $(CONTIKI)/Makefile.include
