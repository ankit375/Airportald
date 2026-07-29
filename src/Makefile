TARGET := airportald

SRC := \
	airportal_types.c \
	client_manager.c \
	cloud_client.c \
	coa_server.c \
	config_manager.c \
	enforcement_manager.c \
	hostapd_monitor.c \
	log.c \
	main.c \
	metrics.c \
	netlink_monitor.c \
	nft_manager.c \
	persistence.c \
	portal_http.c \
	radius_accounting.c \
	radius_client.c \
	radius_transport.c \
	session_manager.c \
	tc_manager.c \
	token_manager.c \
	ubus_api.c

OBJ := $(SRC:.c=.o)

CFLAGS ?= -O2
override CFLAGS += -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing -D_DEFAULT_SOURCE -I../include
LDFLAGS ?=
LDLIBS ?= -lev -lssl -lcrypto

ifeq ($(AIRPORTAL_OPENWRT),1)
override CFLAGS += -DAIRPORTAL_OPENWRT
override LDLIBS += -lubus -lubox -luci
endif

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: all clean
