CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -I../include
LDLIBS ?= -lssl -lcrypto

SRC := \
	../src/airportal_types.c \
	../src/client_manager.c \
	../src/config_manager.c \
	../src/log.c \
	../src/session_manager.c \
	../src/token_manager.c

all: test_core

test_core: test_core.c $(SRC)
	$(CC) $(CFLAGS) -o $@ test_core.c $(SRC) $(LDLIBS)

check: test_core
	./test_core

clean:
	rm -f test_core

.PHONY: all check clean
