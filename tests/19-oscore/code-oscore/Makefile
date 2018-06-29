all:


MAKE_WITH_OSCORE = 1

MODULES += os/services/unit-test
MODULES += os/net/app-layer/oscore

PROJECT_SOURCEFILES += common.c

#ifeq ($(TEST_04),1)
#CFLAGS  += -DSIXP_MSG_API_TEST=1
#endif

CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
