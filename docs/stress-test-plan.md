# AirPortal Stress Test Plan

This document is the full validation plan for stress testing the AirPortal
OpenWrt package on a real AP.

Use it together with:

- [working-flow.md](working-flow.md)
- [packet-flow.md](packet-flow.md)
- [integration-test.md](integration-test.md)

The goal is to prove that AirPortal is stable under repeated login, multiple
clients, RADIUS policy, bandwidth limits, quotas, CoA, roaming, service
restarts, and long-running sessions.

## Test Environment

Validated AP:

- AP IP: `192.168.1.2`
- SSH port: `3041`
- Portal HTTP port: `8088`
- CoA port: `3799`
- Portal ID: `36`
- Guest VIFs: `phy0-ap2`, `phy1-ap2`
- RADIUS server: `192.168.1.10`
- Auth port: `1812`
- Accounting port: `1813`
- NAS identifier: `cp_e48623cc`
- External portal:
  `https://poetic-taiyaki-a23b0a.netlify.app/?realm=default`

Expected package components:

- `/usr/sbin/airportald`
- `/etc/init.d/airportal`
- `/etc/config/airportal`
- `/etc/airportal/secrets/radius-main`
- `/etc/airportal/token.key`
- `/etc/airportal/sessions.db`

Expected OpenWrt/runtime packages:

- `libev`
- `libubus`
- `libubox`
- `libuci`
- `libopenssl`
- `jansson`
- `nftables-json`
- `tc`
- `kmod-sched-core`
- `kmod-sched-flower`
- `kmod-sched-act-police`

## Baseline AP Checks

Run these before every stress test round.

```sh
/etc/init.d/airportal restart
sleep 3
ubus call airportal status
ubus call airportal portals
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
nft list table inet airportal
netstat -lnup | grep 3799
logread | grep -i airportal | tail -120
```

Pass criteria:

- `airportald` is running.
- `ubus call airportal status` succeeds.
- Portal `36` is enabled.
- `nft list table inet airportal` shows `captive_macs`, `walled_ipv4`,
  `prerouting`, `forward`, and `bandwidth`.
- CoA listener is open on UDP `3799`.
- No crash, parse failure, or repeated config reload failure appears in logs.

## Test Result Template

Use one row for each test run.

```text
Date:
AP build/package:
Git commit:
Tester:
Client device/MAC:
SSID/VIF:
RADIUS user:
Test case:
Expected result:
Actual result:
Pass/Fail:
Logs captured:
Notes:
```

Useful version markers:

```sh
opkg list-installed | grep -i airportal
/usr/sbin/airportald -h 2>&1 | head
ubus call airportal status
```

## Phase 1: Single-Client Login Stability

Purpose: prove the basic captive portal loop survives repeated use.

Repeat this 50 times with one phone or laptop:

1. Forget the guest Wi-Fi network.
2. Connect to the guest SSID.
3. Confirm captive portal opens automatically.
4. Login with a valid RADIUS user.
5. Browse an HTTP site and an HTTPS site.
6. Disconnect Wi-Fi.
7. Reconnect and repeat.

Commands after every 10 cycles:

```sh
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
logread | grep -i "client_connected\|portal_http_auth_accept\|portal_http_auth_reject\|session_stop" | tail -120
```

Pass criteria:

- Login succeeds consistently with valid credentials.
- Invalid credentials do not authorize internet.
- There is only one active session for the test MAC.
- No stale captive row blocks a valid login.
- No daemon crash or restart occurs.
- Accounting Start and Stop events appear correctly.

Failure signs:

- Client remains captive after Access-Accept.
- Client has internet before login.
- Multiple active sessions exist for the same MAC.
- Browser loops on the same login URL after valid credentials.

## Phase 2: Multi-Client Authentication Load

Purpose: prove AirPortal handles many clients joining and logging in.

Recommended client counts:

- Round 1: 5 clients
- Round 2: 10 clients
- Round 3: 25 clients
- Round 4: 50 clients, if hardware allows

Steps:

1. Restart AirPortal.
2. Connect all clients to the guest SSID.
3. Login clients using valid RADIUS accounts.
4. Keep each client browsing or running light traffic.
5. Disconnect half the clients.
6. Reconnect them and login again.

Commands:

```sh
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
logread | grep -i "client_connected\|client_disconnected\|portal_http_auth_accept\|portal_http_auth_reject\|radius" | tail -250
```

Pass criteria:

- All clients move from `captive` to `authenticated` after valid login.
- Session count matches authenticated client count.
- Rejected users remain captive.
- No active session is assigned to the wrong MAC.
- Accounting events match the number of accepted sessions.

## Phase 3: Pre-Auth Isolation And Walled Garden

Purpose: prove captive users can reach only allowed pre-login destinations.

Before login, from a connected captive client:

```sh
nslookup poetic-taiyaki-a23b0a.netlify.app
wget -O- http://neverssl.com
wget -O- https://google.com
```

On AP:

```sh
nft list table inet airportal
ubus call airportal clients
logread | grep -i "portal_http_redirect\|walled\|nft" | tail -120
```

Pass criteria:

- DNS works if `allow_dns=1`.
- DHCP works and client receives an IP.
- External portal domain is reachable because it is in the walled garden.
- HTTP internet redirects to the portal.
- HTTPS internet is not transparently redirected and should not bypass login.
- Normal internet is unavailable before login.

Also test reload:

```sh
ubus call airportal reload
sleep 3
nft list table inet airportal
```

Pass criteria for reload:

- Walled garden entries return after reload.
- Domain entries resolve to IPv4 addresses.
- Existing captive/authenticated behavior remains correct.

## Phase 4: Session Restore Stress

Purpose: prove daemon restart does not break active authenticated users.

With 5 to 20 authenticated clients:

```sh
ubus call airportal sessions
/etc/init.d/airportal restart
sleep 5
ubus call airportal clients
ubus call airportal sessions
logread | grep -i "persistence\|client_restored\|session_restore\|policy" | tail -160
```

Pass criteria:

- Active sessions are loaded from `/etc/airportal/sessions.db`.
- Logs show `persistence_restore_loaded`.
- Logs show `persistence_restore_success` for valid sessions.
- Associated clients are restored as authenticated.
- nft and tc policies are reinstalled.
- Internet continues without forcing valid users to login again.

Repeat:

- 10 daemon restarts with one client.
- 5 daemon restarts with 10 or more clients.
- One restart while clients are actively downloading.

Failure signs:

- Valid users return to captive after daemon restart.
- Session DB loads but policies are missing.
- Duplicate client rows appear after restore.

## Phase 5: Session Timeout

Purpose: prove absolute session timeout works.

Manual authorization:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"session-timeout-test","session_timeout":60,"idle_timeout":600}'
```

Monitor:

```sh
watch -n 5 'ubus call airportal sessions'
logread | grep -i "session_timeout\|session_stop\|radius_accounting_stop" | tail -80
```

Pass criteria:

- Session exists immediately after authorization.
- Client has internet during the timeout window.
- Session stops at about 60 seconds.
- Stop reason is `session_timeout`.
- Client returns to captive state.
- Accounting Stop is sent.

## Phase 6: Idle Timeout With Activity Threshold

Purpose: prove idle timeout ignores tiny background traffic and expires only
when meaningful activity stays below threshold.

Manual authorization:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"idle-test","session_timeout":300,"idle_timeout":30,"idle_activity_threshold_bytes":65536}'
```

Monitor:

```sh
ubus call airportal sessions
logread | grep -i "idle_timeout\|session_stop" | tail -80
```

Test A, idle client:

1. Stop active browsing/downloads on the client.
2. Leave the phone connected.
3. Wait for more than `idle_timeout`.

Expected:

- Small background packets do not refresh `last_activity_ms` unless traffic
  crosses `idle_activity_threshold_bytes`.
- Session stops with `reason=idle_timeout`.

Test B, active client:

1. Reauthorize the same client.
2. Run browsing or download traffic above the threshold.
3. Watch `last_activity_ms` and `idle_expires_at_ms`.

Expected:

- `last_activity_ms` moves forward.
- `idle_expires_at_ms` extends.
- Session does not stop while meaningful traffic continues.

## Phase 7: Quota Enforcement

Purpose: prove input, output, and total quotas disconnect correctly.

Total quota:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"quota-total-test","session_timeout":600,"max_total_octets":10485760}'
```

Upload quota:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"quota-upload-test","session_timeout":600,"max_input_octets":5242880}'
```

Download quota:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"quota-download-test","session_timeout":600,"max_output_octets":5242880}'
```

Monitor:

```sh
watch -n 3 'ubus call airportal sessions'
logread | grep -i "quota_exceeded\|session_stop\|radius_accounting_stop" | tail -120
```

Pass criteria:

- Remaining quota decreases while traffic flows.
- Session stops after quota is exceeded.
- Stop reason is `quota_exceeded`.
- Client returns to captive.
- Accounting Stop is sent with final counters.

## Phase 8: Bandwidth Limit Stress

Purpose: prove upload/download limits work per client and survive policy
changes.

1 Mbps symmetric limit:

```sh
ubus call airportal authorize '{"mac":"CLIENT_MAC","ifname":"phy1-ap2","portal_id":36,"username":"bw-1m-test","session_timeout":600,"max_upload_bps":1000000,"max_download_bps":1000000}'
```

Inspect:

```sh
ubus call airportal sessions
nft -a list chain inet airportal bandwidth
tc qdisc show dev phy1-ap2
tc filter show dev phy1-ap2 ingress
tc filter show dev phy1-ap2 egress
logread | grep -i "tc_policy\|bandwidth\|session_policy_update" | tail -120
```

Traffic tests:

- Run a speed test.
- Download a large file.
- Upload a file.
- Run two clients with different limits.
- Change one client's limit while the other keeps traffic running.

Pass criteria:

- Speed test result is close to configured policy.
- Upload and download are limited independently.
- One client's policy does not affect another client's policy.
- Policy cleanup happens when the session stops.
- tc is used when available; nft fallback is visible if tc cannot apply policy.

Validated example:

```text
max_upload_bps=1000000
max_download_bps=1000000
speed test result: about 1 Mbps down and 0.97 Mbps up
```

## Phase 9: CoA Disconnect Stress

Purpose: prove server-driven disconnect works reliably.

Preconditions:

- AP config has `option coa_port '3799'`.
- Radius profile has `option coa_source '192.168.1.10'`.
- AP shows listener on UDP `3799`.

AP checks:

```sh
netstat -lnup | grep 3799
ubus call airportal clients
ubus call airportal sessions
```

From the RADIUS/control server, send Disconnect-Request for an active session or
MAC.

AP monitor:

```sh
logread | grep -i "coa\|disconnect\|session_stop\|radius_accounting_stop\|hostapd_deauth" | tail -150
ubus call airportal clients
ubus call airportal sessions
```

Pass criteria:

- AP sends CoA ACK.
- Logs show `session_stop ... reason=coa_disconnect`.
- Logs show `radius_accounting_stop ... reason=coa_disconnect`.
- Logs show hostapd deauth for the client.
- Client Wi-Fi disconnects or reconnects and returns to captive.
- Internet is blocked until the client logs in again.

Repeat:

- 20 Disconnect-Requests for the same client over repeated logins.
- 10 Disconnect-Requests while the client is running traffic.
- 10 Disconnect-Requests for different clients.

Failure signs:

- Server reports no reply from AP.
- `coa_source_rejected` appears for the valid server.
- `bad_authenticator` appears with the expected shared secret.
- Client remains authenticated after disconnect.
- Client stays Wi-Fi connected but internet silently stops without deauth.

## Phase 10: CoA Live Policy Update Stress

Purpose: prove live policy updates do not require reconnect or re-login.

Test updates from RADIUS/control server:

- Change download bandwidth.
- Change upload bandwidth.
- Change session timeout.
- Change idle timeout.
- Change quota.
- Update `Filter-Id`.
- Update `Class`.

AP monitor:

```sh
ubus call airportal sessions
nft -a list chain inet airportal bandwidth
tc filter show dev phy1-ap2 ingress
tc filter show dev phy1-ap2 egress
logread | grep -i "coa\|session_policy_update\|bandwidth\|quota\|timeout" | tail -160
```

Pass criteria:

- CoA update receives ACK.
- Session remains authenticated.
- `ubus call airportal sessions` shows updated policy.
- New bandwidth is visible in speed tests.
- New timeout/quota behavior takes effect without re-login.
- Invalid CoA source or secret is rejected and does not change policy.

## Phase 11: Roaming Stress

Purpose: prove clients moving between guest VIFs do not create stale active
state.

Steps:

1. Connect client near one radio.
2. Authenticate.
3. Move client until it roams to the other VIF.
4. Toggle Wi-Fi quickly.
5. Repeat 20 times.

Commands:

```sh
ubus call airportal clients
ubus call airportal sessions
logread | grep -i "client_connected\|client_disconnected\|client_pruned_stale\|portal_http_auth" | tail -220
```

Pass criteria:

- At most one active authenticated session exists per MAC.
- Stale same-MAC/same-portal rows without sessions are pruned.
- Login uses the current client challenge.
- The client does not loop on stale `/logon` credentials.
- Internet remains available if the session is restored on the new VIF, or the
  client cleanly returns to captive and logs in again.

## Phase 12: Service Failure And Recovery

Purpose: prove failures are clear and recovery is clean.

Test cases:

- Stop RADIUS server.
- Use wrong RADIUS shared secret.
- Use wrong CoA shared secret.
- Send CoA from wrong source IP.
- Restart `firewall`.
- Restart `network`.
- Restart `hostapd`.
- Restart `airportal`.
- Disconnect AP uplink.
- Change external portal domain DNS.

Commands:

```sh
logread | grep -i "radius_timeout\|radius_auth_reject\|coa_source_rejected\|bad_authenticator\|config_reload\|daemon" | tail -200
ubus call airportal status
ubus call airportal clients
ubus call airportal sessions
nft list table inet airportal
```

Pass criteria:

- With `fail_open=0`, unauthenticated clients remain blocked if RADIUS fails.
- Wrong RADIUS credentials do not authorize internet.
- Wrong CoA source or secret does not affect sessions.
- AirPortal does not crash.
- After dependency recovery, valid login works again.
- nft and tc state are rebuilt after daemon restart.

## Phase 13: Long Soak Test

Purpose: catch leaks, counter drift, stale sessions, and accounting problems.

Recommended duration:

- Minimum: 12 hours
- Preferred: 24 hours
- Enterprise confidence: 72 hours

Recommended client mix:

- 2 idle clients
- 2 browsing clients
- 1 streaming client
- 1 client with bandwidth limit
- 1 client with quota
- 1 client that reconnects every 30 minutes

Collect every 5 minutes:

```sh
date
ubus call airportal clients
ubus call airportal sessions
ubus call airportal statistics
ps w | grep airportal
free
logread | grep -i "airportal" | tail -120
```

Pass criteria:

- `airportald` remains alive.
- Memory remains stable.
- Accounting interim updates continue.
- Idle clients expire when expected.
- Active clients do not expire by idle timeout.
- Session timeout and quota events occur at correct thresholds.
- No duplicate active session appears for the same MAC.
- No pre-auth internet leakage appears.

## Phase 14: Scale And Abuse

Purpose: find edge cases before customer deployment.

Run these only after the previous phases pass.

Tests:

- 100 rapid login/logout cycles on one client.
- 50 clients connecting within 5 minutes.
- 10 clients starting speed tests at the same time.
- 100 invalid login attempts.
- Repeated `/logon` submissions with stale UAM password.
- CoA updates every 5 seconds for one active client for 5 minutes.
- Restart AirPortal while CoA requests are being sent.
- Reconnect same phone repeatedly between `phy0-ap2` and `phy1-ap2`.

Pass criteria:

- No crash.
- No stuck client that requires AP reboot.
- Invalid logins remain rejected.
- Stale UAM submissions do not authorize a client.
- CoA replies are deterministic.
- Logs clearly explain failures.

## Final Release Gate

The package is ready for a wider pilot when all of these are true:

- 24-hour soak passes.
- 25 clients authenticate and browse at the same time.
- 100 login/logout cycles pass.
- CoA disconnect works every time.
- CoA live bandwidth update works.
- CoA live timeout/quota update works.
- Session restore survives daemon restart.
- No duplicate active session exists for the same MAC.
- No pre-login internet leakage is observed.
- Accounting Start, Interim, and Stop are visible on RADIUS.
- Bad RADIUS auth rejects cleanly.
- Bad CoA source and bad CoA secret are rejected.
- Walled garden domains work before login and refresh after reload.

## Quick Triage Guide

Client has internet before login:

```sh
nft list table inet airportal
ubus call airportal clients
```

Check that the client MAC is in `captive_macs` and that the forward-chain drop
rule exists.

Login accepts but internet does not work:

```sh
ubus call airportal clients
ubus call airportal sessions
nft list table inet airportal
```

Check that the MAC was removed from `captive_macs` and that the session exists.

Browser loops to login page:

```sh
logread | grep -i "portal_http_uam\|radius_auth\|client_pruned_stale" | tail -120
ubus call airportal clients
```

Check for stale duplicate rows, stale UAM challenge, or RADIUS reject.

CoA gets no reply:

```sh
netstat -lnup | grep 3799
logread | grep -i "coa_source_rejected\|bad_authenticator\|coa_request_rejected\|coa_disconnect" | tail -120
```

Check AP listener, source IP, shared secret, and firewall reachability.

Bandwidth limit not applying:

```sh
ubus call airportal sessions
tc qdisc show dev phy1-ap2
tc filter show dev phy1-ap2 ingress
tc filter show dev phy1-ap2 egress
nft -a list chain inet airportal bandwidth
```

Check whether tc policy exists, or whether nft fallback rules were installed.

## Suggested Test Order

Run the phases in this order:

1. Baseline AP checks
2. Single-client login stability
3. Pre-auth isolation and walled garden
4. Session timeout
5. Idle timeout
6. Quota
7. Bandwidth
8. Session restore
9. CoA disconnect
10. CoA live policy update
11. Roaming
12. Multi-client load
13. Service failure and recovery
14. Long soak
15. Scale and abuse

This order finds simple packet-path problems before spending time on long or
multi-client tests.
