# AirPortal / airportald

`airportald` is a new captive access-control daemon for OpenWrt access points.
It is designed to replace CoovaChilli without a TUN forwarding path and without
one daemon instance per SSID. Client traffic stays in the normal Linux
bridge/routing path; the daemon owns the control plane and installs kernel
policy through nftables and, in later phases, traffic control.

## Repository Analysis

This package directory was empty when the Phase 1 work started. Nearby packages
under the same feed show conventional OpenWrt package makefiles and procd init
scripts, but no reusable captive daemon framework was present here.

Reusable OpenWrt components selected for this package:

- `libev` for the daemon event loop.
- `libubus`/`libubox` for the `airportal` ubus object.
- `libuci` for `/etc/config/airportal`.
- OpenSSL for HMAC-SHA256 tokens and secure randomness.
- OpenWrt package/procd patterns from adjacent feed packages.

No existing local modules were found in this package for hostapd monitoring,
nftables management, JSON helpers, cloud sockets, or netlink. Phase 1 therefore
adds clean module boundaries and stubs where deeper native integrations belong.

## Architecture

Packet flow:

```text
Wi-Fi client
  -> hostapd wireless interface
  -> normal OpenWrt bridge/VLAN
  -> nftables airportal admission policy
  -> normal OpenWrt forwarding/WAN
```

Client identity is not MAC-only. The key includes MAC, ifindex, VLAN ID and
portal ID so the same MAC can appear in different captive domains without
colliding.

State flow:

```text
NEW
 |
 v
CAPTIVE
 |
 +---- authentication start ----> AUTH_PENDING
 |                                  |
 |                           +------+------+
 |                           |             |
 |                           v             v
 |                      AUTHENTICATED    CAPTIVE
 |                           |
 |          +----------------+----------------+
 |          |                |                |
 |          v                v                v
 |   SESSION_EXPIRED   IDLE_EXPIRED   QUOTA_EXCEEDED
 |          |                |                |
 +----------+----------------+----------------+
                            |
                            v
                         CAPTIVE
```

## Modules

- `airportal_types`: public data structures, MAC parsing, key hashing, clocks.
- `config_manager`: UCI load plus strict validation of portals and bindings.
- `client_manager`: bounded in-memory client table.
- `session_manager`: bounded session table and timeout expiration.
- `enforcement_manager`: coordinates nftables and tc operations.
- `nft_manager`: Phase 1 managed-policy abstraction; native libnftables work lands here.
- `tc_manager`: Phase 1 shaping abstraction stub.
- `hostapd_monitor`: Phase 1 event parser for AP-STA connect/disconnect.
- `portal_http`: small libev HTTP redirect and health service.
- `token_manager`: HMAC-SHA256 token create/validate with nonce replay cache.
- `ubus_api`: `airportal` status, clients, sessions, authorize, disconnect, reload, portals, statistics.
- `radius_*`, `coa_server`, `persistence`, `cloud_client`, `netlink_monitor`: explicit Phase 2+ extension points.

## Build

Host sanity build:

```sh
make -C src clean all
make -C tests clean check
```

OpenWrt package build from the tree root:

```sh
make package/feeds/airportald/clean
make package/feeds/airportald/compile
```

See [docs/working-flow.md](docs/working-flow.md) for the validated AP flow,
runtime packages, RADIUS/UAM/CoA behavior, and test commands. See
[docs/packet-flow.md](docs/packet-flow.md) for the nftables, tc, hostapd, and
RADIUS packet path. See [docs/stress-test-plan.md](docs/stress-test-plan.md)
for the full AP stress test checklist.

Install on target:

```sh
opkg install /tmp/airportal_0.1.0*.ipk
mkdir -p /etc/airportal/secrets
openssl rand -hex 32 > /etc/airportal/token.key
chmod 0600 /etc/airportal/token.key
/etc/init.d/airportal enable
/etc/init.d/airportal start
```

## UCI Example

```uci
config global 'global'
	option enabled '1'
	option log_level 'info'
	option portal_http_port '8088'
	option default_session_timeout '3600'
	option default_idle_timeout '600'
	option token_key_file '/etc/airportal/token.key'

config portal 'guest'
	option enabled '1'
	option portal_id '36'
	option auth_mode 'manual'
	option portal_url 'https://captive-portal.example.com/login'
	option network 'guest'

config binding
	option portal 'guest'
	option vif 'wlan1-1'
```

## ubus API

```sh
ubus call airportal status
ubus call airportal clients
ubus call airportal sessions
ubus call airportal portals
ubus call airportal statistics
ubus call airportal reload
ubus call airportal authorize '{"mac":"AA:BB:CC:DD:EE:FF","ifname":"wlan1-1","portal_id":36,"username":"test-user","session_timeout":300}'
ubus call airportal disconnect '{"mac":"AA:BB:CC:DD:EE:FF","ifname":"wlan1-1","portal_id":36,"reason":"admin_disconnect"}'
```

## nftables Design

The daemon owns only `inet airportal`. The intended native ruleset contains
sets/maps for captive, authenticated and blocked clients, keyed by interface
classification plus MAC/portal where supported. Phase 1 installs through the
`nft_manager` abstraction and logs managed operations; native libnftables
transactions are the next implementation step.

Verification:

```sh
nft list table inet airportal
logread -f | grep airportal
```

## Known Limitations

- Phase 1 manual authorization flow is implemented; RADIUS auth/accounting is stubbed.
- Native nftables/libnftables transactions are not yet implemented.
- hostapd monitor currently exposes the parser and lifecycle hook; control-socket attachment is next.
- Persistence, CoA, traffic shaping and cloud socket protocol are extension stubs.
- HTTP client identification is conservative Phase 1 plumbing and must be replaced by source IP to client lookup.

## Phase 2 Plan

1. Implement native nftables table/set/map transactions.
2. Attach to hostapd control sockets per configured binding.
3. Add RADIUS Access-Request/Accept/Reject and policy normalization.
4. Add RADIUS Accounting Start/Interim/Stop.
5. Replace HTTP fallback client selection with IP/MAC/portal lookup.
6. Add persistence and restart restore after policy install is native.
