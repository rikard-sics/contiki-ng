CONTIKI_PROJECT = edhoc-test-client

all: $(CONTIKI_PROJECT)

MODULES += /os/net/security/edhoc

CONTIKI = ../../..

CFLAGS += -Wno-unused-function

#uECC fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1


include $(CONTIKI)/Makefile.include
