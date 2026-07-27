# Coova-Chilli Vs AirPortal Feature Comparison

This document compares a typical Coova-Chilli captive portal deployment with
the current AirPortal implementation in this repository.

AirPortal is not a line-by-line clone of Coova-Chilli. It keeps the parts that
matter for the current product flow, especially UAM login, RADIUS auth,
accounting, quotas, bandwidth, and CoA, but uses a more OpenWrt-native packet
path based on hostapd, ubus, nftables, and tc.

## Summary

| Area | Coova-Chilli | AirPortal Current State |
| --- | --- | --- |
| Packet architecture | TUN/NAT captive gateway model | Native OpenWrt bridge/routing path with nftables policy |
| Per-SSID operation | Commonly one Chilli instance per captive network | One daemon can manage multiple portal bindings/VIFs |
| UAM portal flow | Mature Coova UAM flow | Coova-compatible UAM-style redirect and `/logon` flow |
| RADIUS authentication | Mature | Working and validated |
| RADIUS accounting | Mature | Working: Start, Interim, Stop |
| CoA/PoD | Mature | Working: disconnect and live policy update support |
| Bandwidth policy | Supported through Chilli policy path | Working through tc, with nftables fallback |
| Quota policy | Supported | Working for input, output, and total octets |
| Session restore | Deployment-dependent | Built in with persistent session DB |
| OpenWrt integration | Widely used, but older architecture | Native hostapd/ubus/nft/tc integration |
| Config migration | Existing Coova config format | Coova-style import helper included |
| Production maturity | Battle-tested legacy project | Feature-rich current prototype, needs wider stress/soak testing |

## Architecture Difference

Coova-Chilli normally places clients behind a Chilli-controlled gateway path.
Traffic is captured and controlled through Chilli's own forwarding model, often
using a TUN interface and a dedicated captive network.

AirPortal keeps packets in the normal OpenWrt data path:

```text
Wi-Fi client
  -> hostapd VIF
  -> OpenWrt bridge/routing/firewall
  -> nftables AirPortal admission policy
  -> tc bandwidth policy when configured
  -> normal WAN/LAN forwarding
```

This gives AirPortal a smaller packet-path footprint. The daemon manages
control state and installs kernel policies, but it does not become the main data
forwarder.

## Feature Matrix

Status legend:

- `Done`: implemented and validated in current AirPortal testing.
- `Partial`: implemented for the current target flow, but not a complete
  replacement for every Coova-Chilli option.
- `Planned`: sensible next feature, not fully implemented yet.
- `Not targeted`: not currently part of AirPortal's intended design.

| Feature | Coova-Chilli | AirPortal | Status |
| --- | --- | --- | --- |
| Captive client detection | Yes | hostapd polling through `hostapd.<ifname> get_clients` | Done |
| Captive HTTP redirect | Yes | nftables redirect from captive MACs to local HTTP port | Done |
| HTTPS interception | No clean transparent interception without browser warnings | Not intercepted; blocked or allowed by policy | Done |
| External UAM portal | Yes, `uamserver` | `portal_url` | Done |
| Coova-style `/logon` | Yes | Supported | Done |
| UAM challenge | Yes | Generated per client | Done |
| UAM shared secret | `uamsecret` | `option uam_secret` | Done |
| UAM password decode | Yes | Supported for Coova-compatible encrypted password | Done |
| Walled garden IP allow | `uamallowed` | `config walled_garden`, `type ip` | Done |
| Walled garden domain allow | Commonly supported by DNS/IP handling | `config walled_garden`, `type domain`, resolved to IPv4 | Done |
| Walled garden refresh | Deployment-dependent | Periodic refresh and config reload refresh | Done |
| DNS allow before login | Yes | `allow_dns` plus nft DNS allow rules | Done |
| DHCP allow before login | Yes | `allow_dhcp` plus nft DHCP allow rules | Done |
| Captive detection allow | Commonly configurable | `allow_captive_detection` option present | Partial |
| RADIUS Access-Request | Yes | Supported | Done |
| RADIUS Access-Reject | Yes | Supported with reject logs | Done |
| RADIUS timeout handling | Yes | Supported with retry/timeout config | Done |
| RADIUS shared secret file | Config option/string | Secret stored in protected file | Done |
| NAS-Identifier | `radiusnasid` | `nas_identifier` | Done |
| Calling-Station-Id | Yes | Supported | Done |
| Called-Station-Id | Yes | Supported | Done |
| NAS-Port-Type | Yes | Sends `Wireless-802.11` | Done |
| Service-Type | Yes | Sends `Login` | Done |
| Framed-MTU | Common | Sends `1500` | Done |
| Session-Timeout | Yes | Parsed and enforced | Done |
| Idle-Timeout | Yes | Parsed and enforced | Done |
| Idle activity threshold | Not a common Coova-style control | `idle_activity_threshold_bytes` avoids tiny background traffic | Done |
| Input quota | Yes | `max_input_octets` | Done |
| Output quota | Yes | `max_output_octets` | Done |
| Total quota | Yes | `max_total_octets` | Done |
| WISPr bandwidth attributes | Commonly supported | Parsed and applied | Done |
| ChilliSpot bandwidth attributes | Yes | Parsed and applied | Done |
| ChilliSpot quota attributes | Yes | Parsed and applied | Done |
| Filter-Id | Yes | Stored in session policy, updateable by CoA | Done |
| Class | Yes | Stored and used for accounting/policy state | Done |
| Vendor-specific attributes | Broad ecosystem support | Supports currently needed WISPr/ChilliSpot vendor attributes | Partial |
| RADIUS Accounting-Start | Yes | Supported | Done |
| RADIUS Accounting-Interim | Yes | Supported | Done |
| RADIUS Accounting-Stop | Yes | Supported | Done |
| Accounting stop reasons | Yes | Improved reasons for admin, CoA, idle, timeout, quota | Done |
| Large byte counters | Mature | Gigaword handling included | Done |
| CoA listener | Yes | UDP listener on configured CoA port | Done |
| CoA source validation | Commonly restricted by deployment/firewall | `coa_source` or auth/acct server validation | Done |
| CoA authenticator validation | Yes | Verifies with shared secret | Done |
| Disconnect-Request / PoD | Yes | Supported | Done |
| CoA bandwidth update | Yes | Supported | Done |
| CoA quota update | Yes | Supported | Done |
| CoA session timeout update | Yes | Supported | Done |
| CoA idle timeout update | Yes | Supported | Done |
| Deauth on disconnect | Chilli usually cuts network access; Wi-Fi behavior depends on integration | Calls `hostapd del_client` on CoA disconnect | Done |
| Session persistence | Deployment-dependent | `/etc/airportal/sessions.db` restore | Done |
| Multi-radio same portal | Usually separate interface/config handling | Multiple VIF bindings under one daemon | Done |
| Duplicate stale client cleanup | Not directly comparable | Prunes stale same-MAC/same-portal rows | Done |
| ubus management API | No native ubus API in classic Chilli | `status`, `clients`, `sessions`, `authorize`, `disconnect`, `reload`, etc. | Done |
| Token-based local auth endpoints | Not primary Coova feature | HMAC token support exists | Done |
| Cloud-managed mode | External controller dependent | `cloud_managed` config path exists | Partial |
| Config import | Native Coova config | `airportal-coova-import` helper | Done |
| IPv6 captive enforcement | Deployment/build dependent | Data structs exist, enforcement is IPv4-focused today | Partial |
| VLAN assignment | Supported in many RADIUS access systems | Policy field exists, full enforcement not validated | Partial |
| Per-client firewall ACLs by `Filter-Id` | Common deployment pattern | `Filter-Id` stored, detailed ACL enforcement not complete | Planned |
| Secondary RADIUS server | `radiusserver2` commonly configured | Import reserves it, full failover not complete | Planned |
| Mature production soak | Yes, due age/deployment history | Needs wider multi-client and long soak validation | Planned |

## Configuration Mapping

This is the practical mapping from the working Coova-style config to AirPortal
UCI.

| Coova-Chilli option | AirPortal option |
| --- | --- |
| `radiusserver1` | `config radius`, `option auth_server`, `option acct_server` |
| `radiusserver2` | Planned secondary server/failover |
| `radiusauthport` | `option auth_port` |
| `radiusacctport` | `option acct_port` |
| `radiussecret` | `option secret_file`, content stored in `/etc/airportal/secrets/...` |
| `coaport` | `option coa_port` in global/radius config |
| CoA allowed source | `option coa_source` |
| `uamserver` | `config portal`, `option portal_url` |
| `radiusnasid` | `option nas_identifier` |
| `dhcpif` | AirPortal uses OpenWrt `network` plus bound VIFs |
| `uamallowed` | `config walled_garden`, `type ip` or `type domain` |
| `uamsecret` | `config portal`, `option uam_secret` |
| `dns1`, `dns2` | Normal OpenWrt DHCP/DNS configuration |
| `ssid` | hostapd/wireless config; AirPortal binds by VIF |
| `cmdsocket`, `unixipc`, `pidfile` | Not used; AirPortal uses procd and ubus |

Example Coova-style input:

```text
radiusserver1 '192.168.1.10'
radiusauthport 1812
radiusacctport 1813
radiussecret 'testing123'
coaport 3799
uamserver 'https://poetic-taiyaki-a23b0a.netlify.app/?realm=default'
radiusnasid 'cp_e48623cc'
uamallowed '192.168.1.10'
uamallowed 'poetic-taiyaki-a23b0a.netlify.app'
uamsecret 'greatsecret'
```

Equivalent AirPortal shape:

```uci
config portal 'guest'
	option enabled '1'
	option portal_id '36'
	option auth_mode 'radius'
	option portal_url 'https://poetic-taiyaki-a23b0a.netlify.app/?realm=default'
	option network 'lan'
	option radius_profile 'main'
	option uam_secret 'greatsecret'

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

config walled_garden
	option portal 'guest'
	option type 'ip'
	option value '192.168.1.10'

config walled_garden
	option portal 'guest'
	option type 'domain'
	option value 'poetic-taiyaki-a23b0a.netlify.app'
```

The migration helper can import many Coova-style options:

```sh
airportal-coova-import /path/to/coova.conf guest
/etc/init.d/airportal restart
```

## Where AirPortal Is Already Better For This Project

Native OpenWrt path:

- No TUN interface dependency.
- Client packets stay in the normal bridge/routing path.
- nftables and tc are visible with normal OpenWrt tools.

Single daemon model:

- One `airportald` process can manage multiple portal bindings.
- Current tested config binds the same portal to both `phy0-ap2` and `phy1-ap2`.

Operational visibility:

- `ubus call airportal clients`
- `ubus call airportal sessions`
- `ubus call airportal statistics`
- Clear logs for auth request, auth reject, accounting, CoA, stale pruning, and
  deauth.

Restart behavior:

- Active sessions persist in `/etc/airportal/sessions.db`.
- Sessions and policies are restored after daemon restart.

CoA disconnect user experience:

- AirPortal does not only cut internet.
- It also calls hostapd deauth so the phone reconnects and sees the captive
  flow again.

Idle behavior:

- `idle_activity_threshold_bytes` prevents tiny background traffic from always
  resetting idle timeout.

## Where Coova-Chilli Is Still Ahead

Production history:

- Coova-Chilli has many years of real deployments.
- AirPortal needs the full stress plan and more field testing.

Compatibility breadth:

- Coova-Chilli has broad compatibility with legacy portal integrations and
  deployment-specific options.
- AirPortal supports the current required UAM/RADIUS/CoA flow, not every legacy
  option.

Secondary/failover RADIUS:

- Coova deployments often use `radiusserver2`.
- AirPortal currently reserves this in import logic, but full failover behavior
  should be added.

Advanced policy:

- Coova ecosystems often use many vendor-specific attributes and custom policy
  scripts.
- AirPortal supports the WISPr/ChilliSpot attributes currently needed, but
  should expand VSA coverage as server requirements grow.

IPv6:

- AirPortal has IPv6 fields in the client model, but current captive/walled
  garden enforcement is IPv4-focused.

## Current AirPortal Release Confidence

Validated:

- Captive portal redirect.
- Pre-login internet blocking.
- External portal UAM login.
- RADIUS Access-Accept and Access-Reject.
- Accounting Start/Interim/Stop.
- Session restore.
- Session timeout.
- Idle timeout with activity threshold.
- Quota disconnect.
- Bandwidth limiting.
- CoA disconnect.
- CoA source validation.
- hostapd deauth after CoA disconnect.
- Stale duplicate client pruning.

Needs wider testing:

- 25 to 50 simultaneous clients.
- 24 to 72 hour soak test.
- Repeated roaming between `phy0-ap2` and `phy1-ap2`.
- Repeated CoA live policy updates.
- RADIUS server failure and recovery.
- DNS changes for domain walled garden entries.

## Recommended Next Features

Highest priority:

1. Full secondary RADIUS failover.
2. More vendor-specific RADIUS attributes as required by the controller.
3. `Filter-Id` based ACL enforcement.
4. IPv6 captive and walled garden enforcement.
5. Automated AP-side stress test runner.
6. Better diagnostics command, for example `ubus call airportal diagnose`.

Useful polish:

1. Export current UCI back to Coova-style summary for support teams.
2. Add a compact troubleshooting bundle command.
3. Add per-portal counters.
4. Add clearer logs for every policy value received from RADIUS or CoA.

## Bottom Line

For the current tested guest portal use case, AirPortal now covers the important
Coova-Chilli replacement features:

- Captive redirect
- External UAM portal
- RADIUS authentication
- RADIUS accounting
- Session timeout
- Idle timeout
- Quota
- Bandwidth limits
- CoA disconnect
- CoA policy updates
- Walled garden
- Config migration path

The main gap is not the core feature set anymore. The main gap is production
confidence: more clients, longer runtime, more failure cases, and broader
RADIUS compatibility.
