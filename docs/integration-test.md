# AirPortal Phase 1 Integration Test

Build and install:

```sh
make package/feeds/airportald/airportal/{clean,compile} V=s
opkg install /tmp/airportal_0.1.0*.ipk
```

Prepare token key for repeatable signing:

```sh
mkdir -p /etc/airportal/secrets
openssl rand -hex 32 > /etc/airportal/token.key
chmod 0600 /etc/airportal/token.key
```

Start and inspect:

```sh
/etc/init.d/airportal enable
/etc/init.d/airportal start
ubus call airportal status
ubus call airportal portals
logread -f | grep airportal
```

Client flow:

```sh
iw dev wlan1-1 station dump
ubus call airportal clients
ubus call airportal authorize '{"mac":"AA:BB:CC:DD:EE:FF","ifname":"wlan1-1","portal_id":36,"username":"test-user","session_timeout":300}'
ubus call airportal sessions
ubus call airportal disconnect '{"mac":"AA:BB:CC:DD:EE:FF","ifname":"wlan1-1","portal_id":36,"reason":"admin_disconnect"}'
```

nftables and recovery:

```sh
nft list table inet airportal
/etc/init.d/firewall reload
/etc/init.d/airportal reload
/etc/init.d/airportal restart
```

Scenarios to cover:

1. Unauthenticated client gets DHCP and DNS.
2. HTTP request redirects to the configured portal URL.
3. HTTPS is not transparently intercepted.
4. Manual ubus authorization moves the client to authenticated.
5. Short session timeout returns the client to captive.
6. Disconnect marks the client disconnected and removes policy.
7. `wlan0-1` and `wlan1-1` both bind to portal 36.
8. Duplicate binding in UCI is rejected with a clear log.
9. Restart recreates base managed nftables objects.
10. Firewall reload followed by daemon reload restores managed state.
