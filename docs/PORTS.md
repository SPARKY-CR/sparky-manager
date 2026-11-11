# Port plan

Defaults from DESIGN.md §3. All ports are changeable in the panel UI;
this is the plan the installer ships with.

| Service | Port | Notes |
|---|---|---|
| Panel UI / API | TCP <random 10000–60000> | Randomised on fresh install; see the login box or `sudo sparky-manager info`. TLS if a domain is given, else self-signed (§7 of DESIGN.md) |
| VLESS + Reality | TCP 443 | No certificate needed; `sni` is a real site, e.g. `www.microsoft.com` |
| VLESS / Trojan + TLS (WS / XHTTP) | TCP 8443 | Needs a domain + certificate, or use Reality instead |
| VMess + WS + TLS | TCP 8443 (shared path) | Distinct `path` per inbound |
| Shadowsocks 2022 | TCP 8388 | `2022-blake3-aes-128-gcm` |
| Hysteria2 | UDP 443 | Shares 443 with VLESS-Reality (TCP vs UDP — no clash) |
| TUIC v5 | UDP 8443 | sing-box; shares the TLS certificate with Hysteria2 |
| AnyTLS | TCP 8444 | sing-box ≥ 1.12 |
| Naive | TCP 8445 | sing-box; TLS mandatory |
| ShadowTLS v3 + SS2022 | TCP 8446 | Inner Shadowsocks on 127.0.0.1 only, `strict_mode` |
| WireGuard | UDP 51820 | Native `wg0` |
| OpenVPN | UDP 1194 | Username/password auth (`auth-user-pass-verify` against the panel DB); `.ovpn` file export, CA embedded |
| OpenConnect (ocserv) | TCP + UDP 4433 | Password auth (`ocpasswd`); 443 is taken by the default VLESS/Hysteria2 pair, so 4433. AnyConnect profile XML export |
| AmneziaWG | UDP 51821 | WireGuard fork with obfuscation (`awg0`); needs the AmneziaWG kernel module or `amneziawg-go` — the installer tries the Amnezia PPA (pinned to `noble` on Ubuntu 26.04) and the panel says plainly when it is missing |
| IKEv2 (strongSwan) | UDP 500 + 4500 | EAP-MSCHAPv2 + server certificate; `.mobileconfig` export. Both ports are reserved by design — the inbound form rejects them for other protocols |
| Subscription endpoint | Same panel port, `/sub/<token>` | Separate port only if the admin wants it unlisted |

## Forwarding and NAT (v12 protocols)

The installer enables IPv4 forwarding (`net.ipv4.ip_forward = 1`,
persisted in `/etc/sysctl.d/99-sparky-manager.conf`) — without it
the VPN servers cannot route client traffic. **NAT is not added
automatically**: for clients to reach the internet, the server needs
a MASQUERADE rule for each client subnet, e.g. with nftables:

```
table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    ip saddr { 10.8.0.0/24, 10.8.1.0/24, 10.9.0.0/24, 10.10.10.0/24, 10.20.0.0/24 } masquerade
  }
}
```

(The WireGuard subnets 10.8.0.0/24 and 10.8.1.0/24, OpenVPN
10.9.0.0/24, OpenConnect 10.10.10.0/24, IKEv2 10.20.0.0/24.) The
panel does not write firewall rules itself — a wrong NAT rule can
break the server's own networking, so it stays a documented manual
step.

## No domain? What is omitted

Reality (TCP 443) + Hysteria2 (UDP 443) sharing port 443 is the
recommended first pair: no domain, no certificate, maximum
compatibility.

The TLS inbounds — VLESS/Trojan/VMess over WS/XHTTP + TLS (8443),
TUIC (8443), AnyTLS (8444), Naive (8445), ShadowTLS (8446) — all need
a hostname and a certificate, so **they are not created when no domain
is given**. Hysteria2 is the exception in the installer: it can run on
the self-signed panel certificate, with clients accepting/pinning that
certificate. Once a domain is entered in the panel settings, the TLS
inbounds become available as an option.

## Ports the panel does NOT use

Xray's stats API listens only on loopback (`127.0.0.1:10085`) and is
never public. UDP 500/4500 are reserved for IKEv2 by design — the
inbound form rejects them for every other protocol (an IKEv2 inbound
itself uses port 500).
