# ZedSecure import checklist

ZedSecure is a **client only** — it provides no servers. It imports
share links, subscriptions in **v2rayNG and sing-box formats**, Xray
and sing-box JSON, `.ovpn` files, Amnezia `vpn://` links, and QR codes.
The panel emits both subscription formats from the same per-user data,
so a user never has to care which engine a protocol belongs to.

## Which feed carries which protocol

| Protocol | v2rayNG feed (base64 links) | sing-box JSON feed | Notes |
|---|---|---|---|
| VLESS + Reality | ✅ `vless://…security=reality…` | ✅ `type: vless` + `tls.reality` | First pair; works with no domain |
| VLESS + WS / XHTTP + TLS | ✅ | ⚠️ XHTTP omitted | sing-box does not support XHTTP; those inbounds are v2rayNG-only |
| VMess + WS + TLS | ✅ `vmess://` (base64 JSON) | ✅ `type: vmess` | Needs a domain + certificate |
| Trojan + TLS | ✅ `trojan://` | ✅ `type: trojan` | Needs a domain + certificate |
| Shadowsocks 2022 | ✅ `ss://` (SIP002) | ✅ `type: shadowsocks` | No domain needed |
| Hysteria2 | ✅ `hysteria2://` (alias `hy2://`) | ✅ `type: hysteria2` | UDP 443; no domain needed (self-signed cert — accept/pin it in the client) |
| TUIC v5 | ✅ `tuic://` | ✅ `type: tuic` | Needs a domain + certificate |
| AnyTLS | ✅ `anytls://` | ✅ `type: anytls` | Needs a domain + certificate; sing-box ≥ 1.12 |
| Naive | ✅ `naive+https://` | ✅ `type: naive` | Needs a domain + certificate. **Note the `naive+https` scheme** — a common gotcha; verify against the real ZedSecure importer |
| ShadowTLS v3 + SS | ⚠️ link form only | ✅ sing-box JSON | The bare share-link form is unreliable; ShadowTLS is offered via the sing-box JSON subscription. Verify against ZedSecure before relying on the link form |
| WireGuard | ❌ no share-link standard | ✅ `type: wireguard` | Also exported as a standard `.conf` file + QR code of the file content |
| IKEv2 | ❌ | ❌ | Phase 2 (native support, `.mobileconfig` export) |
| OpenVPN / OpenConnect | ❌ | ❌ | Phase 2 (`.ovpn` file export) |

## How to import (per user)

1. In the panel, open the user and copy their **subscription link**
   (`/sub/<token>`) or scan the **QR code** on their page
   (`/u/<token>`).
2. In ZedSecure: add a subscription (paste the link or scan the QR).
   ZedSecure picks the format by User-Agent: a sing-box-based client
   gets sing-box JSON, a v2rayNG-style client gets the base64 link list.
   Force a format with `?format=v2rayng` or `?format=singbox`.
3. Single links and QR codes also work: paste/scan one protocol link
   at a time from the user's page.
4. WireGuard: download the `.conf` file from the user's page, or scan
   its QR code; ZedSecure imports WireGuard configs directly.

## Subscription behaviour to know about

- The `Subscription-Userinfo` header (`upload / download / total /
  expire`) lets clients show quota and expiry.
- A disabled, expired, or over-quota user gets **HTTP 403 with an
  empty body** on `/sub/` — never a stale list.
- Rotating a user's subscription token (one button in the panel)
  invalidates the old subscription instantly.
- Base64 in the v2rayNG feed is **encoding, not encryption** — anyone
  with the link can decode the credentials.

## What the panel does NOT provide

These are ZedSecure engines that need no server of yours — the panel
has nothing to run for them, and ZedSecure already bundles them:

- **Psiphon** — its own network; the user just taps it in the app when
  nothing else connects.
- **Tor** (obfs4, Snowflake, Conjure) — a third-party anonymity
  network; running a bridge is a separate project.
- **DNS tunnels** (DNSTT, VayDNS, MasterDNS) — niche fallback needing a
  DNS server plus a tunnel endpoint and NS records.
- **SSH as a VPN** — a manual fallback (dynamic SOCKS); the server
  already has SSH and the panel does not manage it.
- **OpenConnect** — Cisco AnyConnect gateways; Phase 2 at most.

## Before calling the feeds "done"

Import **both** feeds into the real ZedSecure app on a phone and
connect with each protocol — especially Naive (`naive+https://`) and
ShadowTLS, whose link forms vary between clients. The spec alone is
not a test.
