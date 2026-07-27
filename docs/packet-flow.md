# AirPortal Packet Flow

This document explains how packets move through AirPortal on the OpenWrt AP.
It focuses on the data path and control path that were validated on the guest
SSID bound to `phy0-ap2` and `phy1-ap2`.

AirPortal does not create a Coova-Chilli tunnel interface. Client packets remain
on the normal OpenWrt bridge/routing path, while AirPortal controls access with
hostapd, nftables, tc, ubus, RADIUS, and a local HTTP listener.

## Main Components

- `hostapd`: owns Wi-Fi association and station state for each VIF.
- `airportald`: tracks clients, sessions, RADIUS policy, accounting, CoA, and
  local captive HTTP.
- `nftables`: redirects captive HTTP, allows DNS/DHCP and walled garden traffic,
  drops captive internet traffic, and provides fallback bandwidth limiting.
- `tc`: primary per-client bandwidth enforcement with `clsact`, `flower`, and
  `police`.
- `ubus`: exposes management APIs and lets AirPortal call hostapd.
- RADIUS server: receives Access-Request and Accounting packets, and sends CoA
  or Disconnect-Request packets back to the AP.
- External UAM portal: the login UI, for example
  `https://poetic-taiyaki-a23b0a.netlify.app/?realm=default`.

Runtime package dependencies are listed in [working-flow.md](working-flow.md).

## nftables Data Plane

AirPortal owns this table:

```text
table inet airportal
```

The important sets are:

```text
set captive_macs {
	type ether_addr
}

set walled_ipv4 {
	type ipv4_addr
}
```

The installed chains have this shape:

```text
chain prerouting {
	type nat hook prerouting priority dstnat; policy accept;
	ether saddr @captive_macs tcp dport 80 redirect to :8088
}

chain forward {
	type filter hook forward priority filter; policy accept;
	jump bandwidth
	ether saddr @captive_macs ip daddr @walled_ipv4 accept
	ether saddr @captive_macs udp dport { 53, 67, 68 } accept
	ether saddr @captive_macs tcp dport 53 accept
	ether saddr @captive_macs drop
}

chain bandwidth {
}
```

AirPortal also enables bridge netfilter so bridged Wi-Fi traffic is visible to
the nftables hooks:

```text
/proc/sys/net/bridge/bridge-nf-call-iptables = 1
/proc/sys/net/bridge/bridge-nf-call-ip6tables = 1
```

## Before Authentication

When a station joins the guest SSID, hostapd reports it through ubus. AirPortal
creates a client record and adds the MAC address to `captive_macs`.

```text
Phone
  |
  | Wi-Fi association
  v
hostapd.<vif>
  |
  | ubus get_clients polling
  v
airportald client manager
  |
  | add MAC to captive set
  v
nft table inet airportal
```

Pre-auth packet decisions:

| Packet | Result |
| --- | --- |
| DHCP from captive MAC | Allowed |
| DNS from captive MAC | Allowed |
| HTTP port `80` from captive MAC | Redirected to local `airportald:8088` |
| Traffic to walled garden IPs | Allowed |
| Other forwarded traffic from captive MAC | Dropped |
| HTTPS to normal internet | Not intercepted; usually fails until login |

This is why captive detection opens the portal, but normal internet stays
blocked before login.

## Captive Redirect Flow

Only plain HTTP can be transparently redirected. Captive detection URLs such as
`/generate_204` hit the prerouting redirect rule.

```text
Phone HTTP request
  |
  | src MAC is in captive_macs, tcp dport 80
  v
nft prerouting redirect to :8088
  |
  v
airportald portal_http
  |
  | find client by source IP
  | generate UAM challenge
  v
HTTP redirect to external portal_url
  |
  v
External UAM portal
```

Expected log:

```text
portal_http_redirect mac=... ip=... ifname=phy1-ap2 portal_id=36 uamip=192.168.1.2 target=/generate_204
```

The external portal domain must be reachable while captive. Add it as a
`walled_garden` domain or IP. Domain entries are resolved to IPv4 addresses and
refreshed on config reload and periodic refresh.

## Login And RADIUS Flow

The external portal sends a Coova-compatible `/logon` request back to the AP.

```text
External portal
  |
  | GET http://<uamip>:8088/logon?username=...&password=...&userurl=...
  v
airportald portal_http
  |
  | locate client by source IP
  | decode UAM password using uam_secret and challenge
  v
RADIUS Access-Request
  |
  v
RADIUS server
  |
  | Access-Accept or Access-Reject
  v
airportald
```

Core Access-Request attributes:

- `User-Name`
- `User-Password`
- `Calling-Station-Id`
- `Called-Station-Id`
- `NAS-Identifier`
- `Service-Type = Login`
- `NAS-Port-Type = Wireless-802.11`
- `Framed-MTU = 1500`

Accepted policy attributes include:

- `Session-Timeout`
- `Idle-Timeout`
- `Filter-Id`
- `Class`
- WISPr bandwidth attributes
- ChilliSpot quota and bandwidth attributes

Expected success logs:

```text
portal_http_uam_password_decode status=success username=...
radius_auth_request username=... server=192.168.1.10 nas_identifier=cp_e48623cc
radius_accounting_start session_id=AP001-...
portal_http_auth_accept username=... portal_id=36 ifname=...
```

Expected reject logs:

```text
radius_auth_reject username=... code=3 reply=...
portal_http_auth_reject reason=radius_reject username=...
```

## After Authentication

On Access-Accept, AirPortal authorizes the client.

```text
airportald
  |
  | remove MAC from captive_macs
  | create session
  | install bandwidth policy if present
  | send Accounting-Start
  v
Phone traffic follows normal OpenWrt forwarding/NAT path
```

Authenticated packet decisions:

| Packet | Result |
| --- | --- |
| Traffic from authenticated MAC | No captive redirect or captive drop |
| Normal internet | Allowed by existing OpenWrt firewall/routing |
| Bandwidth-limited traffic | Policed by tc, or nft fallback if tc failed |
| Quota/session/idle expired client | Session stops and MAC returns captive |

Because the authenticated MAC is removed from `captive_macs`, the captive
forward-chain drop no longer matches that client.

## Bandwidth Packet Flow

AirPortal prefers tc for bandwidth limiting.

```text
Upload from client
  |
  v
tc ingress filter on <vif>
  |
  | flower src_mac <client>
  | police rate <upload_bps>
  v
OpenWrt forwarding
```

```text
Download to client
  |
  v
tc egress filter on <vif>
  |
  | flower dst_mac <client>
  | police rate <download_bps>
  v
Wi-Fi client
```

The tc commands have this form:

```text
tc qdisc replace dev <ifname> clsact
tc filter replace dev <ifname> ingress protocol all pref <pref> flower src_mac <mac> action police rate <rate> burst <burst> conform-exceed drop
tc filter replace dev <ifname> egress protocol all pref <pref> flower dst_mac <mac> action police rate <rate> burst <burst> conform-exceed drop
```

If tc cannot apply the policy, AirPortal falls back to nftables:

```text
chain bandwidth {
	ether saddr <mac> limit rate over <upload bytes/second> drop
	ether daddr <mac> limit rate over <download bytes/second> drop
}
```

Inspect bandwidth state:

```sh
nft -a list chain inet airportal bandwidth
tc qdisc show dev phy1-ap2
tc filter show dev phy1-ap2 ingress
tc filter show dev phy1-ap2 egress
```

## Accounting Packet Flow

Accounting packets are sent out of the AP to the configured accounting server.

```text
Session authorized
  |
  v
Accounting-Start
  |
  | every default_accounting_interval seconds
  v
Accounting-Interim-Update
  |
  | disconnect, timeout, quota, or CoA
  v
Accounting-Stop
```

Stop reasons include:

- `admin_disconnect`
- `coa_disconnect`
- `idle_timeout`
- `session_timeout`
- `quota_exceeded`

Useful checks:

```sh
logread | grep -i "radius_accounting" | tail -80
ubus call airportal sessions
ubus call airportal statistics
```

## CoA And Disconnect Packet Flow

AirPortal listens on UDP `3799` for CoA and Disconnect-Request packets.

```text
RADIUS server
  |
  | UDP CoA or Disconnect-Request to AP:3799
  v
airportald coa_server
  |
  | validate source IP
  | verify RADIUS authenticator with shared secret
  | find client/session by Session-Id or MAC
  v
Policy update or disconnect
```

Source validation:

- If `option coa_source` is set, only that source IP is accepted.
- If `coa_source` is empty, AirPortal accepts CoA from configured auth/acct
  server IPs.

CoA policy update can change the live session policy:

- Bandwidth
- Quota
- Session timeout
- Idle timeout
- `Filter-Id`
- `Class`

Disconnect-Request flow:

```text
Disconnect-Request accepted
  |
  v
Accounting-Stop reason=coa_disconnect
  |
  v
session removed
  |
  v
MAC added back to captive_macs
  |
  v
hostapd.<ifname> del_client deauth=true reason=5
  |
  v
phone disconnects and must reconnect/login again
```

The AP intentionally deauthenticates on CoA disconnect. Without that, the phone
can remain Wi-Fi associated while internet is blocked, which looks confusing to
users.

Useful checks:

```sh
netstat -lnup | grep 3799
logread | grep -i "coa\\|disconnect\\|session_stop\\|hostapd_deauth" | tail -100
ubus call airportal clients
ubus call airportal sessions
```

Expected disconnect logs:

```text
radius_accounting_stop session_id=... reason=coa_disconnect
session_stop session_id=... reason=coa_disconnect
coa_disconnect_ack ifname=... portal_id=36
hostapd_deauth_sent mac=... ifname=... reason=coa_disconnect
```

## Roaming And Stale Client Cleanup

Some phones move between `phy0-ap2` and `phy1-ap2` with the same MAC and IP.
AirPortal keys client records by MAC, interface, and portal ID, so roaming can
temporarily create duplicate rows.

When a client appears on a new VIF, AirPortal prunes stale same-MAC/same-portal
rows that do not have an active session. This prevents old captive rows and old
UAM challenges from being selected during login.

Expected log:

```text
client_pruned_stale mac=... old_ifname=... new_ifname=... old_state=... portal_id=36
```

## End-To-End Packet State Table

| Client state | MAC in `captive_macs` | HTTP port 80 | DNS/DHCP | Walled garden | Normal internet | Session present |
| --- | --- | --- | --- | --- | --- | --- |
| New/captive | Yes | Redirect to `8088` | Allowed | Allowed | Dropped | No |
| Authenticating | Yes | Portal callback handled by `8088` | Allowed | Allowed | Dropped | No |
| Authenticated | No | Normal forwarding | Normal forwarding | Normal forwarding | Allowed | Yes |
| CoA disconnected | Yes | Redirect again | Allowed | Allowed | Dropped | No |
| Session expired | Yes | Redirect again | Allowed | Allowed | Dropped | No |

## Inspection Commands

Client and session state:

```sh
ubus call airportal status
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
```

nftables state:

```sh
nft list table inet airportal
nft -a list chain inet airportal bandwidth
```

hostapd state:

```sh
ubus -v list hostapd.phy1-ap2
ubus call hostapd.phy1-ap2 get_clients
```

RADIUS, portal, and CoA logs:

```sh
logread | grep -i "portal_http_redirect\\|radius_auth\\|radius_accounting\\|coa\\|hostapd_deauth\\|client_pruned_stale" | tail -120
```

CoA listener:

```sh
netstat -lnup | grep 3799
```

## Current Limits

- HTTPS traffic is not transparently redirected. Captive detection should reach
  the portal through HTTP probes or allowed portal domains.
- The walled garden set is IPv4-focused.
- Domain walled garden entries depend on DNS resolution and are refreshed by
  AirPortal, but DNS changes can still take a short time to appear in nftables.
- AirPortal uses the existing OpenWrt bridge/routing path instead of a dedicated
  tunnel interface.
- Bandwidth enforcement is per client MAC on the bound VIF, using tc when
  available and nftables fallback when tc cannot be installed.
