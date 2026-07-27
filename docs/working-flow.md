# AirPortal Working Flow

This document describes the AirPortal captive portal flow that was validated on
the OpenWrt access point at `192.168.1.2`.

AirPortal is intended to replace the Coova-Chilli data path. It keeps client
traffic in the normal OpenWrt bridge/routing path and uses nftables, tc,
hostapd, ubus, RADIUS, and a small local HTTP service for the control plane.

## OpenWrt Packages And Libraries Used

AirPortal package:

- `airportal`: the OpenWrt package built from this repository.
- `/usr/sbin/airportald`: the main daemon.
- `/etc/init.d/airportal`: procd init script.
- `/etc/config/airportal`: UCI configuration.
- `/usr/sbin/airportal-coova-import`: Coova-style config migration helper.

Runtime OpenWrt dependencies:

- `libev`: event loop for HTTP server, timers, signals, CoA socket, and ubus fd.
- `libubus`: exposes `ubus call airportal ...` API and calls hostapd objects.
- `libubox`: blob message helpers used with ubus.
- `libuci`: reads `/etc/config/airportal`.
- `libopenssl`: HMAC/token handling, RADIUS password encryption, authenticators.
- `jansson`: JSON dependency kept for OpenWrt package compatibility.
- `nftables-json`: nftables userspace support.
- `tc`: traffic-control userspace command.
- `kmod-sched-core`: Linux traffic-control scheduler support.
- `kmod-sched-flower`: classifier support for per-client shaping.
- `kmod-sched-act-police`: policing action used by shaping.

OpenWrt services AirPortal integrates with:

- `hostapd`: detects associated clients through `hostapd.<ifname> get_clients`
  and deauthenticates stations through `hostapd.<ifname> del_client`.
- `ubus`: management API and hostapd control channel.
- `nftables`: captive redirect, walled garden, drop, allow, and fallback
  bandwidth enforcement.
- `netifd`/bridge interfaces: client traffic remains on the configured network,
  for example `lan`.
- RADIUS server: Access-Request, Accounting Start/Interim/Stop, CoA, and PoD.

## Validated AP Configuration

The tested guest portal uses portal ID `36` on `phy0-ap2` and `phy1-ap2`.
The RADIUS server and CoA source are `192.168.1.10`.

Important UCI fields:

```uci
config global 'global'
	option enabled '1'
	option cloud_managed '1'
	option portal_http_port '8088'
	option portal_http_host '192.168.1.2'
	option coa_port '3799'
	option device_id 'AP001'
	option default_accounting_interval '300'
	option default_session_timeout '3600'
	option default_idle_timeout '600'
	option default_idle_activity_threshold_bytes '65536'

config portal 'guest'
	option enabled '1'
	option portal_id '36'
	option auth_mode 'radius'
	option portal_url 'https://poetic-taiyaki-a23b0a.netlify.app/?realm=default'
	option network 'lan'
	option radius_profile 'main'
	option uam_secret 'greatsecret'
	option allow_dns '1'
	option allow_dhcp '1'
	option allow_captive_detection '1'
	option default_idle_activity_threshold_bytes '65536'

config binding
	option portal 'guest'
	option vif 'phy0-ap2'

config binding
	option portal 'guest'
	option vif 'phy1-ap2'

config radius 'main'
	option auth_server '192.168.1.10'
	option auth_port '1812'
	option acct_server '192.168.1.10'
	option acct_port '1813'
	option coa_bind '0.0.0.0'
	option coa_port '3799'
	option coa_source '192.168.1.10'
	option secret_file '/etc/airportal/secrets/radius-main'
	option nas_identifier 'cp_e48623cc'
	option retry_count '3'
	option timeout_ms '3000'
```

Walled garden entries must include the RADIUS/UAM server and external portal
domains that unauthenticated clients need before login.

## Client Connection Flow

1. The client associates to a configured guest VIF, for example `phy0-ap2`.
2. `hostapd_monitor` polls `hostapd.<ifname> get_clients`.
3. AirPortal creates or updates an in-memory client record.
4. If no valid restored session exists, AirPortal installs captive policy:
   - Client MAC is added to the nftables captive set.
   - HTTP port `80` is redirected to local portal HTTP port `8088`.
   - DNS and DHCP are allowed.
   - Walled garden destinations are allowed.
   - Other forwarding is dropped.
5. The client remains Wi-Fi associated but captive.

Expected checks:

```sh
ubus call airportal clients
nft list table inet airportal
logread | grep -i "client_connected\|nft_add_captive_client" | tail -50
```

## Captive Redirect Flow

1. Client opens a captive detection URL or HTTP page.
2. nftables redirects HTTP traffic from captive MACs to `airportald:8088`.
3. AirPortal maps the client source IP to the active client record.
4. AirPortal redirects the browser to the external portal URL with UAM-style
   parameters, including client identity and challenge data.
5. HTTPS is not transparently intercepted; normal captive detection should use
   HTTP endpoints.

Expected log:

```text
portal_http_redirect mac=... ip=... ifname=... portal_id=36 uamip=192.168.1.2
```

## UAM Password Flow

The external portal sends a Coova-style `/logon` request back to the AP:

```text
/logon?username=<user>&password=<encrypted-uam-password>&userurl=<url>
```

AirPortal:

1. Finds the active client by source IP.
2. Decodes the encrypted UAM password using the client challenge and
   `option uam_secret`.
3. Uses the decoded password in the RADIUS `User-Password` attribute.

Expected logs:

```text
portal_http_auth_request path=/logon?... username=<user>
portal_http_uam_password_decode status=success username=<user>
radius_auth_request username=<user> server=192.168.1.10 nas_identifier=cp_e48623cc
```

If the browser submits an SSO username when Enterprise Account was expected, the
AP will send that SSO username to RADIUS. For Enterprise Account testing, the
log must show:

```text
radius_auth_request username=employee1 server=192.168.1.10 nas_identifier=cp_e48623cc
```

## RADIUS Authentication Flow

AirPortal sends RADIUS Access-Request to the configured `auth_server`.

Core attributes currently sent:

- `User-Name`
- `User-Password`
- `Calling-Station-Id`
- `Called-Station-Id`
- `NAS-Identifier`
- `Service-Type = Login`
- `NAS-Port-Type = Wireless-802.11`
- `Framed-MTU = 1500`

Access-Accept can return policy attributes:

- `Session-Timeout`
- `Idle-Timeout`
- `Filter-Id`
- `Class`
- WISPr bandwidth up/down vendor attributes
- ChilliSpot quota and bandwidth vendor attributes

On Access-Accept:

1. AirPortal authorizes the client.
2. Captive nftables rule no longer applies to that MAC.
3. Bandwidth policy is applied using tc, with nftables fallback.
4. Session state is created.
5. RADIUS Accounting-Start is sent.
6. Periodic Accounting-Interim-Update is sent.

Expected logs:

```text
radius_accounting_start session_id=AP001-...
portal_http_auth_accept username=... portal_id=36 ifname=...
```

If RADIUS rejects:

```text
radius_auth_reject username=... code=3 reply=...
portal_http_auth_reject reason=radius_reject username=...
```

`reply=-` means the RADIUS server did not include `Reply-Message`; check the
RADIUS server logs for the real policy reason.

## Accounting Flow

Accounting is sent to `acct_server:acct_port`.

Supported accounting events:

- Start on successful authorization.
- Interim update every `default_accounting_interval` seconds.
- Stop on manual disconnect, CoA disconnect, idle timeout, session timeout, and
  quota exceeded.

Accounting includes improved stop reasons and counters, including gigaword
handling for large byte counters.

Useful checks:

```sh
logread | grep -i "radius_accounting" | tail -80
ubus call airportal sessions
```

## Session Restore Flow

AirPortal persists active sessions to:

```text
/etc/airportal/sessions.db
```

On daemon restart:

1. Session DB is loaded.
2. Active sessions are restored.
3. Policies are reinstalled.
4. Associated clients are marked restored.

Expected logs:

```text
persistence_restore_loaded path=/etc/airportal/sessions.db sessions=...
persistence_restore_success session_id=...
client_restored mac=... ifname=... portal_id=36
```

## Timeout And Quota Flow

Session timeout:

- Uses `Session-Timeout` from RADIUS if provided.
- Otherwise uses portal/global default.
- When expired, session stops with `reason=session_timeout`.

Idle timeout:

- Uses `Idle-Timeout` from RADIUS if provided.
- Otherwise uses portal/global default.
- Uses `idle_activity_threshold_bytes` to avoid treating tiny background traffic
  as meaningful activity.
- When expired, session stops with `reason=idle_timeout`.

Quota:

- Supports max input, max output, and max total octets.
- When exceeded, session stops with `reason=quota_exceeded`.

Useful checks:

```sh
ubus call airportal sessions
ubus call airportal statistics
logread | grep -i "idle_timeout\|session_timeout\|quota_exceeded\|session_stop" | tail -80
```

## Bandwidth Limit Flow

AirPortal supports live bandwidth limits from RADIUS and CoA.

Policy fields:

- `max_upload_bps`
- `max_download_bps`

When tc is available, AirPortal applies shaping through tc. If tc policy cannot
be applied, AirPortal falls back to nftables rate limiting.

Useful checks:

```sh
ubus call airportal sessions
nft -a list chain inet airportal bandwidth
logread | grep -i "session_policy_update\|tc_policy\|bandwidth" | tail -80
```

Validated result:

- A 1 Mbps policy produced about 1 Mbps downlink and uplink in speed tests.

## CoA And Disconnect Flow

AirPortal listens for CoA/PoD on UDP `3799`.

Configuration:

```uci
option coa_bind '0.0.0.0'
option coa_port '3799'
option coa_source '192.168.1.10'
```

Source validation:

- If `coa_source` is set, only that source is accepted.
- If `coa_source` is empty, CoA falls back to accepting packets from configured
  auth/acct server IPs.

CoA policy update supports:

- Bandwidth changes
- Quota changes
- Session timeout changes
- Idle timeout changes
- `Filter-Id`
- `Class`
- Supported WISPr and ChilliSpot vendor attributes

Disconnect-Request flow:

1. CoA packet is source-validated.
2. Request authenticator is verified using the shared secret.
3. Matching session/client is found by session ID or MAC.
4. RADIUS Accounting-Stop is sent with `reason=coa_disconnect`.
5. Session is stopped.
6. Client is returned to captive policy.
7. AirPortal calls `hostapd.<ifname> del_client` to deauthenticate the station.
8. Client reconnects and must authenticate again.

Expected logs:

```text
radius_accounting_stop session_id=... reason=coa_disconnect
session_stop session_id=... reason=coa_disconnect
coa_disconnect_ack ifname=... portal_id=36
hostapd_deauth_sent mac=... ifname=... reason=coa_disconnect
```

Troubleshooting:

```sh
netstat -lnup | grep 3799
logread | grep -i "coa_source_rejected\|coa_request_rejected\|coa_disconnect\|coa_update" | tail -100
```

Important reject logs:

- `coa_source_rejected`: packet came from an IP not allowed by config.
- `coa_request_rejected reason=parse_failed`: malformed CoA packet.
- `coa_request_rejected reason=bad_authenticator`: shared secret or request
  authenticator mismatch.

## Roaming And Duplicate Client Cleanup

Phones can move between `phy0-ap2` and `phy1-ap2` while keeping the same MAC and
IP. AirPortal keys clients by MAC, ifindex, and portal ID, so a roam can create
more than one row for the same MAC.

The daemon now prunes stale same-MAC/same-portal records when a client appears
on a new VIF, as long as the old row has no active session. This prevents stale
UAM challenges from being selected by source IP.

Expected log:

```text
client_pruned_stale mac=... old_ifname=... new_ifname=... old_state=... portal_id=36
```

## Useful ubus Commands

```sh
ubus call airportal status
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
ubus call airportal portals
ubus call airportal reload
```

Manual authorization:

```sh
ubus call airportal authorize '{"mac":"7C:2A:31:09:62:62","ifname":"phy0-ap2","portal_id":36,"username":"manual-test","session_timeout":300,"idle_timeout":60}'
```

Manual disconnect:

```sh
ubus call airportal disconnect '{"mac":"7C:2A:31:09:62:62","ifname":"phy0-ap2","portal_id":36,"reason":"admin_disconnect"}'
```

## Build And Deploy

Host sanity build:

```sh
make -C src clean all
make -C tests clean check
make -C src clean
make -C tests clean
```

OpenWrt package build from the OpenWrt tree root:

```sh
make package/feeds/airportald/clean
make package/feeds/airportald/compile
```

The IPK is produced under:

```text
bin/packages/mipsel_24kc/airportald/airportal_0.1.0-r<release>_mipsel_24kc.ipk
```

Install on AP:

```sh
scp -O -P 3041 bin/packages/mipsel_24kc/airportald/airportal_0.1.0-r<release>_mipsel_24kc.ipk root@192.168.1.2:/tmp/
ssh -p 3041 root@192.168.1.2
opkg install /tmp/airportal_0.1.0-r<release>_mipsel_24kc.ipk
/etc/init.d/airportal restart
```

## Current Validated Test

The clean working login flow is:

1. Forget the Wi-Fi network on the phone.
2. Reconnect to guest SSID.
3. Use the external portal page.
4. Select Enterprise Account.
5. Login with a valid RADIUS user.
6. Confirm AP logs show `portal_http_auth_accept`.
7. Confirm `ubus call airportal clients` shows `state=authenticated`.
8. Confirm internet access works.

Known validated enterprise account:

```text
employee1 / 12345678
```

Do not use stale browser tabs or old SSO sessions when testing Enterprise
Account. The AP log must show the intended username in `radius_auth_request`.

