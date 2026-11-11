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
| ShadowTLS v3 + SS | ⚠️ link form only | ✅ sing-box JSON | Carried as TWO outbounds: `shadowtls` (outer handshake) + a `shadowsocks` outbound that detours through it. The bare share-link form is unreliable; prefer the sing-box JSON or the ZedSecure bundle. Verify against ZedSecure before relying on the link form |
| WireGuard | ❌ no share-link standard | ✅ endpoint (`type: wireguard` under `endpoints`) | sing-box 1.13+ removed the WireGuard *outbound*; the feed carries it as an endpoint (`address` + `peers[]`), plus a standard `.conf` file + QR code of the file content |
| AmneziaWG | ✅ `vpn://` (base64url of the whole `.conf`) | ❌ upstream sing-box has no AmneziaWG | Only sing-box forks support it (Hiddify's `"type": "awg"` endpoint, sing-box-lx's root-promoted AWG fields) — the stock sing-box feed must not carry a plain WireGuard endpoint for it (the obfuscation parameters would be lost). Export is the `vpn://` link + the `.conf` file |
| IKEv2 | ❌ | ❌ | Native strongSwan (EAP-MSCHAPv2 + server cert). Export is the `.mobileconfig` file (VPN payload + the panel CA as a trusted root). iOS 13+ needs the user to enable full trust for the CA in Settings after installing |
| OpenVPN | ❌ | ❌ | Username/password auth; export is the `.ovpn` file (CA embedded, password prompt) + its QR code |
| OpenConnect | ❌ | ❌ | Password auth; export is the AnyConnect profile XML + host / port / username / password in the bundle |

## The ZedSecure bundle (`/sub/<token>/zedsecure.json`)

One JSON document with **everything** the app needs for one user, so
ZedSecure can import all of the user's configs in a single action
instead of choosing between the two generic feeds. The panel also
shows it on the user's page as a "ZedSecure export" card with its own
QR code.

**Endpoint:** `GET /sub/<token>/zedsecure.json` (the token is the
same subscription token; rotating it invalidates the old bundle URL).
Same access rules as the other feeds: unknown, disabled, expired, or
over-quota user → HTTP 403 with an empty body. The
`Subscription-Userinfo` header is sent as well.

**Schema** (`format: "zedsecure-bundle"`, `version: 1`):

```json
{
  "format": "zedsecure-bundle",
  "version": 1,
  "generated_at": "2026-11-11T08:00:00+00:00",
  "user": {
    "name": "alice",
    "expires_at": "2026-12-01T00:00:00+00:00",
    "traffic_used_bytes": 0,
    "traffic_limit_bytes": null,
    "traffic_unlimited": true
  },
  "server": {"host": "203.0.113.10"},
  "configs": [
    {
      "tag": "vless-reality",
      "protocol": "vless",
      "core": "xray",
      "port": 443,
      "remark": "VLESS + Reality",
      "share_link": "vless://...",
      "singbox_outbound": {"type": "vless", "...": "..."}
    },
    {
      "tag": "wireguard",
      "protocol": "wireguard",
      "core": "wireguard",
      "port": 51820,
      "remark": "WireGuard (native)",
      "singbox_endpoint": {"type": "wireguard", "...": "..."},
      "wireguard_conf": "[Interface]\nPrivateKey = ...\n..."
    },
    {
      "tag": "openvpn",
      "protocol": "openvpn",
      "core": "openvpn",
      "port": 1194,
      "remark": "OpenVPN",
      "openvpn_config": "client\ndev tun\nproto udp\nremote 203.0.113.10 1194\n...\n<ca>\n-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "tag": "openconnect",
      "protocol": "openconnect",
      "core": "openconnect",
      "port": 4433,
      "remark": "OpenConnect",
      "openconnect": {
        "host": "203.0.113.10",
        "port": 4433,
        "username": "alice",
        "password": "…",
        "profile_xml": "<?xml version=\"1.0\" …?><AnyConnectProfile …>…"
      }
    },
    {
      "tag": "amneziawg",
      "protocol": "amneziawg",
      "core": "amneziawg",
      "port": 51821,
      "remark": "AmneziaWG",
      "share_link": "vpn://…",
      "amneziawg_conf": "[Interface]\nPrivateKey = …\nJc = 4\n…"
    },
    {
      "tag": "ikev2",
      "protocol": "ikev2",
      "core": "ikev2",
      "port": 500,
      "remark": "IKEv2",
      "ikev2_mobileconfig": "<?xml version=\"1.0\" …?><!DOCTYPE plist …>…"
    }
  ],
  "links": ["vless://...", "trojan://..."],
  "singbox": {"outbounds": [{"type": "vless", "...": "..."}],
              "endpoints": [{"type": "wireguard", "...": "..."}]}
}
```

- `configs` has one entry per usable (client, inbound) pair:
  `share_link` when the protocol has one (WireGuard has none —
  there is no share-link standard for it), `singbox_outbound`
  when a sing-box outbound could be built (`singbox_endpoint`
  instead for WireGuard, which is an endpoint since sing-box
  1.13), and `wireguard_conf` (the full `.conf` text) for
  WireGuard inbounds. A ShadowTLS entry's companion
  Shadowsocks detour outbound (tag `<tag>-ss`) lives in the
  feed's `outbounds`, not on the entry — the pair is only usable
  together. The file-export protocols add their file contents:
  `openvpn_config` (the `.ovpn` text), `openconnect` (host /
  port / username / password / `profile_xml`), `amneziawg_conf`
  (the `.conf` text — the `vpn://` link is the `share_link`),
  `ikev2_mobileconfig` (the `.mobileconfig` plist text). The same
  files are also downloadable per user (token-gated):
  `/sub/<token>/openvpn.ovpn`, `/sub/<token>/openconnect.xml`,
  `/sub/<token>/amneziawg.conf`, `/sub/<token>/ikev2.mobileconfig`
  (403 for an unknown / disabled / expired user, 404 when the user
  has no usable inbound of that protocol).
- `links` is the same flat list the v2rayNG feed carries.
- `singbox` is the whole sing-box feed object, so the app can take
  it wholesale.

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
5. File exports: on the user's page, under "File exports", the
   OpenVPN `.ovpn`, OpenConnect profile XML, AmneziaWG `.conf`
   (+ its `vpn://` link), and IKEv2 `.mobileconfig` are all
   downloadable — one file per protocol the user actually has.

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

## Before calling the feeds "done"

Import **both** feeds into the real ZedSecure app on a phone and
connect with each protocol — especially Naive (`naive+https://`) and
ShadowTLS, whose link forms vary between clients. The spec alone is
not a test. The same applies to the v12 file exports: import the
`.ovpn` into ZedSecure's OpenVPN engine, the `vpn://` link / `.conf`
into its AmneziaWG engine, the AnyConnect profile into its
OpenConnect engine, and install the `.mobileconfig` on iOS — no
public documentation exists for ZedSecure's import parser, so the
real app is the only verification that matters.
