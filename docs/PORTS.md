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
| Subscription endpoint | Same panel port, `/sub/<token>` | Separate port only if the admin wants it unlisted |

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

IKEv2 uses UDP 500/4500 — those belong to strongSwan/IKEv2 when it runs
on the same server, and the panel reserves them by simply never using
them (the inbound form rejects them). Xray's stats API listens only on loopback (`127.0.0.1:10085`)
and is never public.
