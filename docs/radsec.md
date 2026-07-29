# AirPortal RadSec

AirPortal supports native RadSec for RADIUS authentication and accounting.
RadSec is RADIUS over TLS/TCP, normally on port `2083`.

UDP RADIUS remains the default. Enable RadSec per radius profile:

```uci
config radius 'main'
	option transport 'radsec'
	option auth_server '192.168.1.10'
	option auth_port '2083'
	option acct_server '192.168.1.10'
	option acct_port '2083'
	option secret_file '/etc/airportal/secrets/radius-main'
	option nas_identifier 'cp_e48623cc'
	option radsec_ca_cert '/etc/airportal/certs/radsec/ca.pem'
	option radsec_crl_file '/etc/airportal/certs/radsec/crl.pem'
	option radsec_client_cert '/etc/airportal/certs/radsec/client.pem'
	option radsec_client_key '/etc/airportal/certs/radsec/client.key'
	option radsec_server_name 'ideapad'
	option radsec_verify_host '0'
```

Certificate paths:

- `radsec_ca_cert`: CA used to verify the RadSec server certificate.
- `radsec_crl_file`: optional CRL file.
- `radsec_client_cert`: optional client certificate for mutual TLS.
- `radsec_client_key`: optional private key for mutual TLS.
- `radsec_server_name`: SNI name sent to the RadSec server.
- `radsec_verify_host`: set to `1` only if the server certificate name matches
  `radsec_server_name` or the configured server hostname/IP.

For the current AP, CA/CRL files were staged here:

```text
/etc/airportal/certs/radsec/ca.pem
/etc/airportal/certs/radsec/crl.pem
```

If FreeRADIUS requires client certificates, also copy:

```text
/etc/airportal/certs/radsec/client.pem
/etc/airportal/certs/radsec/client.key
```

Recommended permissions:

```sh
mkdir -p /etc/airportal/certs/radsec
chmod 755 /etc/airportal /etc/airportal/certs /etc/airportal/certs/radsec
chmod 644 /etc/airportal/certs/radsec/ca.pem
chmod 644 /etc/airportal/certs/radsec/crl.pem
chmod 644 /etc/airportal/certs/radsec/client.pem
chmod 600 /etc/airportal/certs/radsec/client.key
chown root:root /etc/airportal/certs/radsec/*
```

Restart after config changes:

```sh
uci commit airportal
/etc/init.d/airportal restart
```

Expected auth log:

```text
radius_auth_request username=... server=192.168.1.10 port=2083 transport=radsec nas_identifier=cp_e48623cc
```

If RadSec fails, check:

```sh
logread | grep -i "radsec\|radius_auth" | tail -100
```

Notes:

- CoA/PoD still listens on UDP `3799`; this change affects auth and
  accounting transport.
- The RADIUS shared secret is still used inside the RADIUS packet, even though
  transport security is provided by TLS.
