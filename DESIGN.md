# sparky-manager — Design Document

> **Status:** DESIGN ONLY — no code, no GitHub push, no server install yet.
> **Date:** 2026-11-11 · **Working name:** `sparky-manager`

> **Decisions confirmed by James, 2026-11-11 (override any conflicting
> suggestion below):**
> 1. **PUBLIC project** — prepared as a public repo (README FA+EN, MIT
>    LICENSE, CI). James can change the license later.
> 2. **DOMAIN-AGNOSTIC** — installer and panel work with a bare server IP
>    and no domain. Default first pair: VLESS+Reality on TCP 443 +
>    Hysteria2 on UDP 443 + WireGuard, none needing a domain or cert.
>    A domain entered later in settings only *unlocks* TLS inbounds and
>    Let's Encrypt as an option — never a requirement.
> 3. **FROM SCRATCH, NO REFERENCE PROJECT** — all panel code, templates,
>    install script and tests are written originally for this project.
>    No code is copied, forked or adapted from any other panel project
>    (3X-UI, vpn-ui, Marzban, Marzneshin, Remnawave, Hiddify, …) or from
>    James's Ikev2-manager. Stock upstream Xray-core and sing-box
>    binaries are used as protocol engines only. The comparison table
>    in §2 is context, not a template.
> **For:** James (Persian-speaking, works from phone in Termux, Ubuntu/Debian server)
> **Client target:** ZedSecure (multi-core client, Android/Linux/Windows/macOS)
> **Replaces / beats:** Sir-MmD/vpn-ui (3X-UI fork, v2.9.3-based) and MHSanaei/3x-ui

## 0. What changed in this version

The first draft was Xray-only (VLESS / VMess / Trojan / Shadowsocks).
James then clarified: **ALL methods and ALL cores, suitable for the ZedSecure app.**
This document is the revised, multi-core design. The Xray-only scope is superseded.

ZedSecure (GitHub `EbiDevSharp/ZedSecure`, also `CluvexStudio/ZedSecure`,
AGPL-3.0) is a **client only — it provides no servers**. The user supplies their
own configs via share link / subscription / QR / config-file import. Its engines
(verified against its README, 2026-11-11):

| Engine | Carries |
|---|---|
| Xray | VLESS with Reality, Vision, XHTTP · VMess · Trojan · Shadowsocks · Hysteria2 · WireGuard · AmneziaWG |
| sing-box | TUIC · Naive · AnyTLS · ShadowTLS · OpenVPN `.ovpn` files · plain sing-box JSON |
| Psiphon | Its own network; no server of yours needed |
| Tor | obfs4, Snowflake, Conjure bridges |
| DNS tunnels | DNSTT, VayDNS, MasterDNS over UDP / TCP / DoT / DoH |
| Others (Android) | OpenConnect (Cisco AnyConnect gateways) · IKEv2 (Android built-in IPsec client) · SSH |

It imports share links, subscriptions in **v2rayNG and sing-box formats**,
Xray and sing-box JSON, `.ovpn`, Amnezia `vpn://`, and QR codes.
UI in English, Persian, Russian, Chinese. Desktop (Linux/Windows/macOS)
carries Xray, sing-box, DNS tunnels and SSH — not the full Android set.

**Consequence for the panel:** the panel is a *server* panel. It must serve
everything ZedSecure can connect to *that needs a server*, in the two
subscription formats ZedSecure understands. It must NOT try to run
Psiphon / Tor / DNS-tunnel servers — those are client-side or third-party
networks (see §9).

---

## 1. Goals — and what was wrong with vpn-ui

James installed vpn-ui, got in, then deleted it as "not good".
Exact pain points were never spelled out, so this design fixes the
**known, verifiable** vpn-ui / 3X-UI weaknesses:

| Pain point (vpn-ui / 3X-UI) | Fix in sparky-manager |
|---|---|
| Fresh install **randomises port, username, password and web path**; login info is hidden behind `/opt/vpn-ui/vpn-ui-amd64 info` (menu option 8) | **Like other panels** (see §7): fresh install randomises the panel port (10000–60000), the admin password and the secret web path; username `admin`. Installer prints one big, unmissable login box at the end (full URL + user + password), saves it to `/root/sparky-manager-login.txt`, and `sparky-manager info` reprints it. Port and password are re-used on re-install, never re-randomised. |
| Cluttered English UI; 3X-UI has 14 languages but no Persian-first design, and vpn-ui adds ~15 protocols, resellers, multi-admin, bulk ops — a huge surface for one person | **Persian-first RTL UI**, English as secondary toggle. One screen per job: Dashboard → Inbounds → Users → Subscriptions. No reseller/multi-admin in MVP. |
| Heavy setup: vpn-ui is a Go monolith bundling patched Xray-core, RADIUS, procmgr, a dozen daemons (xl2tpd, strongSwan, pptpd, OpenVPN, ocserv, accel-ppp, telemt…), kernel-module builds (AmneziaWG DKMS fails on kernel ≥ 7.1 and on RHEL kernels) | **Two stock cores + Python backend, no patched core, no kernel builds in Phase 1.** Xray-core and sing-box are downloaded as official upstream binaries. AmneziaWG (needs a kernel module) is Phase 2, explicitly gated. |
| Go + Vue build: editing the UI means a Node build step | **No Node/Vue build step.** Server-rendered pages (Jinja2) + one hand-written CSS file + a little vanilla JS. James can edit a template with copy-paste in Termux. |
| One-line install exists (`curl …/deploy.sh \| sudo bash`) but the *result* is hard to find | Same one-line install shape, but the installer **ends by printing the URL + login** and verifying the panel answers HTTP 200 before exiting. |

### Non-goals (MVP)
- No reseller / multi-admin / billing. One admin account (Phase 2: optional second admin).
- No multi-node / multi-server management (3X-UI has it; out of scope).
- No WARP / outbound routing / load balancers / Clash-rule editor.
- No Telegram bot in Phase 1 (could be Phase 3).

---

## 2. Comparison: 3X-UI vs vpn-ui vs sparky-manager (planned)

| Feature | 3X-UI (MHSanaei) | vpn-ui (Sir-MmD) | sparky-manager (this design) |
|---|---|---|---|
| Core(s) | Xray-core (stock) | Patched Xray-core + many daemons, single Go binary | **Xray-core (stock) + sing-box (stock), side by side** |
| Xray protocols | VLESS, VMess, Trojan, SS, WG, AmneziaWG, TUIC v5, Hysteria2, MTProto, HTTP/SOCKS, TUN | All of 3X-UI + AnyTLS, NaiveProxy (in patched core) + PPTP/L2TP/OpenVPN/OpenConnect/SSTP/IKEv2/SSH/GRE/MTProto | Phase 1: VLESS, VMess, Trojan, SS, Hysteria2 (Xray) + TUIC, AnyTLS, Naive, ShadowTLS (sing-box) + WireGuard (native); v1.2.0 adds OpenVPN, OpenConnect, AmneziaWG, IKEv2 |
| sing-box protocols | — (Xray only) | — (patched Xray only) | **TUIC, AnyTLS, Naive, ShadowTLS via real sing-box** |
| IKEv2 | — | Bundled strongSwan | **Native strongSwan since v1.2.0** (§5.4) |
| OpenVPN / OpenConnect | — | Bundled daemons | v1.2.0 (§8) |
| Subscription formats | v2rayNG-style links, JSON, Clash | Same + TXT/PDF export | **Dual: v2rayNG base64 links AND sing-box JSON** (§6), QR, per-user link |
| Per-user quota / expiry / enable-disable | Yes | Yes + Freeze + bulk ops | Yes (MVP core); Freeze = enable/disable; bulk ops Phase 2 |
| Traffic stats / online users | Xray gRPC stats | Xray gRPC + RADIUS/nftables for daemons | Xray gRPC + `wg show` + nftables-per-port for sing-box (§6.4) |
| UI language | 14 languages, English-first | Same + FA/AR/ZH/ES/RU/TR READMEs | **Persian RTL first**, English toggle |
| Install | `bash <(curl …/install.sh)` | `curl …/deploy.sh \| sudo bash`, randomised login | One-liner, **fixed port/login, printed login box** |
| Stack | Go + Vue (Node build) | Go + Vue (Node build) | **Python FastAPI + Jinja2, no build step** (§3) |
| Storage | SQLite | SQLite (changed path) | SQLite (WAL) |

---

## 3. Tech stack — recommendation: FastAPI

**Recommendation: Python 3.11+ · FastAPI + SQLAlchemy 2.0 (sync) + SQLite (WAL)
+ Jinja2 server-rendered UI + vanilla JS + Uvicorn + systemd.**

| Choice | Why | Rejected alternative |
|---|---|---|
| **FastAPI** (not Flask) | Async-native (ASGI): the traffic-sync loop, Xray gRPC polling and expiry sweeper run as background tasks without blocking requests. Pydantic v2 validates every API payload (inbound/user forms) for free. Auto-generated OpenAPI docs (`/docs`) — useful when James later adds a Telegram bot. Type hints catch config-shape bugs before runtime. Now ahead of Flask in PyPI downloads; well documented. | Flask: sync WSGI, no built-in validation, needs extensions for everything FastAPI ships. Fine for a prototype, worse for background jobs + validation. |
| **SQLAlchemy 2.0 sync + SQLite** | One file (`/opt/sparky-manager/data/panel.db`), zero DB server, trivial backup (`cp` the file). WAL mode so reads don't block the sweeper's writes. Sync engine (not async) keeps the code simple: FastAPI runs sync endpoints in a threadpool; the DB is small and local, so async adds complexity for no gain. | PostgreSQL: overkill for one server / one admin. aiosqlite/async SQLAlchemy: async-everywhere tax for a single-file DB. Raw `sqlite3`: no migrations. |
| **Jinja2 + hand-written CSS, no Node/Vue** | James edits in Termux by copy-paste. A template change is a file edit + `systemctl reload`, not `npm run build`. RTL + Vazirmatn font (system fallback if offline; CDN optional). | Vue/React SPA: needs a build step, exactly the friction vpn-ui has. Django: batteries-included but heavy; its admin is English-first and its ORM/migration ceremony is overkill here. |
| **Uvicorn, single process, systemd unit** | One service `sparky-manager.service`. No Gunicorn workers (SQLite + multiple writers = lock contention). | Gunicorn multi-worker: wrong for SQLite. |
| **Xray-core + sing-box, official binaries** | No patched core. Upgrades = replace binary + restart. Each core owns its own `config.json`, generated by the panel. | Patched Xray-core (vpn-ui approach): carries AnyTLS/TUIC/Naive inside Xray but forks the project from upstream security fixes. |
| **Deps (pinned in `requirements.txt`)** | `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `jinja2`, `qrcode[pil]`, `passlib[argon2]` (or `argon2-cffi`), `python-multipart`, `httpx` (for version checks), `cryptography` (key gen). Nothing else in MVP. | — |

### Architecture (text diagram)

```
                    ┌─────────────────────────────────────────────┐
                    │  Browser / ZedSecure (phone, desktop)     │
                    │  fa-RTL UI · /sub/<token> · QR · links     │
                    └──────────────┬──────────────────────────────┘
                                   │ HTTPS :<random> (panel) / :2054 (sub, optional)
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  sparky-manager  (FastAPI + Uvicorn, systemd: sparky-manager.service)          │
│                                                                      │
│  routes:  / (Jinja2 UI) · /api/* (JSON) · /sub/<token> (dual fmt)    │
│  services: users/inbounds · config renderers (xray/sing-box/wg)     │
│            link builders (v2rayNG + sing-box JSON) · QR              │
│            traffic syncer (60 s tick) · expiry sweeper (5 min tick) │
│  storage:  SQLite WAL  /opt/sparky-manager/data/panel.db                  │
└──────┬───────────────┬───────────────────┬───────────────────────────┘
       │               │                   │
       ▼               ▼                   ▼
  Xray-core       sing-box           WireGuard (native)
  :10085 API      config.json        wg0 · wg show
  (127.0.0.1)     no stats API (*)   per-peer counters
  gRPC stats      nftables/port      AmneziaWG: v1.2.0 (gated — see §5.3)
  config.json     accounting (*)     IKEv2: v1.2.0 (strongSwan, §5.4)
                                     OpenVPN/ocserv: v1.2.0
       │               │                   │
       └───────────────┴───────────────────┘
                       ▼
              Internet (freedom outbound)
```

(*) sing-box has **no per-user stats API** like Xray's gRPC stats.
Design decision (§6.4): for sing-box-only protocols, give each user a
**dedicated port** and count bytes with an **nftables counter per port**
(polled by the syncer). Coarse but honest; documented as a limitation.
Where a protocol exists in *both* cores, prefer the Xray inbound
(Hysteria2: Xray 26.1+ has a native `hysteria` inbound/outbound — verify
at build time against the pinned Xray version; otherwise serve it from
sing-box on UDP/443).

**Port plan (defaults, all changeable in UI):**

| Service | Port | Notes |
|---|---|---|
| Panel UI/API | TCP <random 10000–60000> | Randomised on fresh install, re-used on re-install; TLS if domain given, else self-signed (§7) |
| VLESS + Reality | TCP 443 | No cert needed; `sni` = real site, e.g. `www.microsoft.com` |
| VLESS/Trojan + TLS (WS/XHTTP) | TCP 8443 | Needs domain + cert, or Reality instead |
| VMess + WS + TLS | TCP 8443 (shared path) | Distinct `path` per inbound |
| Shadowsocks 2022 | TCP 8388 | `2022-blake3-aes-128-gcm` |
| Hysteria2 | UDP 443 | Shares 443 with VLESS-Reality (TCP vs UDP — no clash) |
| TUIC v5 | UDP 8443 | sing-box, shares TLS cert with Hysteria2 |
| AnyTLS | TCP 8444 | sing-box ≥ 1.12 |
| Naive | TCP 8445 | sing-box, TLS mandatory |
| ShadowTLS v3 + SS2022 | TCP 8446 | Inner SS on 127.0.0.1 only, `strict_mode` |
| WireGuard | UDP 51820 | Native `wg0` |
| Subscription endpoint | Same panel port, `/sub/<token>` | Separate port only if James wants it unlisted |

Reality (TCP 443) + Hysteria2 (UDP 443) sharing port 443 is the
recommended first pair: no domain, no certificate, maximum compatibility.

---

## 4. Data model (SQLite)

```sql
-- admins: exactly one row in MVP (username 'admin'); Phase 2 may add more.
admins(id PK, username UNIQUE, password_hash TEXT /* argon2id */,
       created_at, last_login_at)

-- settings: single-row key/value (panel port, domain, subscription host,
-- reality keys, TLS mode, traffic-sync interval). No .env sprawl.
settings(key PK, value TEXT)

-- inbounds: one row per listening inbound, across BOTH cores.
-- core: 'xray' | 'singbox' | 'wireguard' | 'ikev2' | 'openvpn' | 'openconnect'
-- protocol: vless | vmess | trojan | shadowsocks | hysteria2 | tuic |
--           anytls | naive | shadowtls | wireguard | amneziawg | ikev2 | ...
-- stream/security are JSON blobs so a new transport doesn't need a migration.
inbounds(id PK, tag UNIQUE, core TEXT, protocol TEXT, port INT UNIQUE,
         enabled BOOL DEFAULT 1,
         stream_json TEXT,   -- {network: tcp/ws/xhttp/grpc, security: reality/tls/none,
                             --  reality: {sni, private_key, public_key, short_id},
                             --  tls: {sni, alpn, cert_path}, path, service_name, ...}
         remark TEXT, created_at)

-- users: one row per person. Credentials live per (user, inbound) in clients,
-- because one user may have a VLESS UUID *and* a TUIC password.
users(id PK, name UNIQUE, enabled BOOL DEFAULT 1,
      traffic_limit_bytes INT NULL,   -- NULL = unlimited
      traffic_used_bytes INT DEFAULT 0,
      expires_at DATETIME NULL,      -- NULL = never
      sub_token TEXT UNIQUE,         -- random 32-char, per-user subscription
      note TEXT, created_at)

-- clients: one credential per (user, inbound). This is the key table:
-- it is what the config renderers and the link builders both read.
clients(id PK, user_id FK, inbound_id FK,
        uuid TEXT NULL,              -- VLESS / VMess / TUIC
        password TEXT NULL,          -- Trojan / SS / Hysteria2 / TUIC / AnyTLS / Naive
        method TEXT NULL,            -- SS cipher, e.g. 2022-blake3-aes-128-gcm
        flow TEXT NULL,              -- xtls-rprx-vision (VLESS)
        extra_json TEXT NULL,        -- {congestion_control: bbr, alpn: h3, ...}
        enabled BOOL DEFAULT 1,
        UNIQUE(user_id, inbound_id))

-- traffic_daily: append-only rollup so the dashboard can graph history
-- without scanning a counter table. Syncer upserts today's row per user.
traffic_daily(id PK, user_id FK, date DATE,
              up_bytes INT DEFAULT 0, down_bytes INT DEFAULT 0,
              UNIQUE(user_id, date))

-- audit_log: who did what (admin actions only in MVP).
audit_log(id PK, admin_id FK NULL, action TEXT, detail TEXT, created_at)
```

Rules enforced by the backend (not just the UI):
- A user is **usable** iff `users.enabled AND clients.enabled AND
  inbound.enabled AND (expires_at IS NULL OR expires_at > now) AND
  (traffic_limit IS NULL OR traffic_used < traffic_limit)`.
- The renderers **omit** unusable clients from generated configs, so an
  expired/over-quota user stops working even if a core is restarted by hand.
- `traffic_used_bytes` is the running total; `traffic_daily` is the history.
  The syncer adds *deltas* only, never overwrites, so a panel restart
  cannot double-count or lose usage.
- Deleting a user deletes its clients (FK cascade) and regenerates configs.

---

## 5. Config generation — one source of truth (the DB)

**Principle:** the DB is the source of truth; `config.json` files are
*rendered artifacts*, never hand-edited. Every mutation (add user, add
inbound, disable, expiry) follows the same pipeline:

```
DB change (transaction)
  → render core config(s) to *.tmp
  → validate:  `xray run -test -c config.json` / `sing-box check -c config.json`
  → atomic rename into place (0640, root:xray / root:sing-box)
  → reload: systemctl restart xray / sing-box   (MVP; see below)
  → on failure: keep old config, keep old service running, show the error
```

MVP restarts the affected core on every change (simple, reliable,
a ~1 s blip). **Phase 2:** use Xray's gRPC `HandlerService.AddUser /
RemoveUser` for zero-downtime user add/remove, and keep full regen only
for inbound changes. sing-box has no equivalent live API, so sing-box
inbound changes always restart sing-box.

### 5.1 Xray-core (`/usr/local/etc/xray/config.json`)

Always present: `log`, `api` inbound on `127.0.0.1:10085` (stats only,
never public), `stats: {}`, `outbounds: [freedom, blackhole]`,
`routing` (block private IPs). One inbound object per enabled `inbounds`
row with `core='xray'`.

**VLESS + Reality (recommended default, TCP 443):**
```json
{"tag": "vless-reality", "port": 443, "protocol": "vless",
 "settings": {"clients": [{"id": "<uuid>", "flow": "xtls-rprx-vision"}],
              "decryption": "none"},
 "streamSettings": {"network": "tcp",
   "security": "reality",
   "realitySettings": {"show": false, "dest": "www.microsoft.com:443",
     "xver": 0, "serverNames": ["www.microsoft.com"],
     "privateKey": "<x25519 private>", "shortIds": ["<8-hex>"]}}}
```
Keys from `xray x25519`. Share link:
`vless://<uuid>@<host>:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=<public>&sid=<shortid>&type=tcp#<name>`

**VLESS/VMess + WebSocket + TLS** — same shape, `security: "tls"`,
`tlsSettings: {alpn: ["h2","http/1.1"], certificates: [...]}`, plus
`wsSettings: {path: "/<inbound-tag>"}`. VMess clients carry
`alterId: 0` and `security: "auto"`.

**Trojan + TLS:** `protocol: "trojan"`, `settings.clients[].password`,
`streamSettings.security: "tls"`. Link:
`trojan://<password>@<host>:443?security=tls&type=tcp&sni=<host>#<name>`

**Shadowsocks 2022:** `protocol: "shadowsocks"`,
`settings: {method: "2022-blake3-aes-128-gcm", password: "<base64>",
"network": "tcp,udp"}`. Link (SIP002):
`ss://<base64url(method:password)>@<host>:8388#<name>`
The password must be a real key — base64 of exactly 16 bytes for
`2022-blake3-aes-128-gcm` (32 for the `-256-` variants). A random
token string is rejected by Xray at load (`bad key`, verified
2026-11-11 against Xray 26.11.9); the panel generates real keys.
⚠️ **Known risk:** Xray 26.x prints a deprecation warning that the
`shadowsocks` protocol "might be removed" and advises migrating to
VLESS Encryption. Keep SS in MVP (ZedSecure users expect it), but
default new users to VLESS-Reality and note SS may be dropped in a
future Xray release — the sing-box SS inbound is the fallback.

**Hysteria2 (Xray):** verified against real Xray 26.11.9 at build time
(2026-11-11, `xray run -test`): the native inbound is protocol
`"hysteria"` — **not** `"hysteria2"` — with
`settings: {"version": 2, "clients": [{"password": …}]}` and
`streamSettings: {"network": "hysteria", "security": "tls", …}`.
The shapes `protocol="hysteria2"` and `network="udp"` are both
rejected by this Xray, and `network="quic"` is rejected as removed.
The client-facing scheme stays `hysteria2://`. If a future Xray
changes this again, serve Hysteria2 from sing-box (§5.2) instead.
Link: `hysteria2://<password>@<host>:443?sni=<host>#<name>`

### 5.2 sing-box (`/etc/sing-box/config.json`)

One `config.json`, `inbounds[]` rendered from `core='singbox'` rows.
Requires **sing-box ≥ 1.12** (AnyTLS). Validate with
`sing-box check -c config.json` (+ `sing-box format` on write).

```json
{"log": {"level": "info"},
 "inbounds": [
  {"type": "hysteria2", "tag": "hy2", "listen": "::", "listen_port": 443,
   "users": [{"password": "<pw>"}],
   "tls": {"enabled": true, "server_name": "<domain>",
           "certificate_path": "/opt/sparky-manager/certs/fullchain.pem",
           "key_path": "/opt/sparky-manager/certs/privkey.pem"}},
  {"type": "tuic", "tag": "tuic", "listen": "::", "listen_port": 8443,
   "users": [{"uuid": "<uuid>", "password": "<pw>"}],
   "congestion_control": "bbr",
   "tls": {"enabled": true, "server_name": "<domain>", "alpn": ["h3"], ...}},
  {"type": "anytls", "tag": "anytls", "listen": "::", "listen_port": 8444,
   "users": [{"password": "<pw>"}],
   "tls": {"enabled": true, "server_name": "<domain>", ...}},
  {"type": "naive", "tag": "naive", "listen": "::", "listen_port": 8445,
   "users": [{"username": "<user>", "password": "<pw>"}],
   "tls": {"enabled": true, "server_name": "<domain>", ...}},
  {"type": "shadowtls", "tag": "shadowtls", "listen": "::",
   "listen_port": 8446, "version": 3, "strict_mode": true,
   "password": "<pw>",
   "tls": {"enabled": true, "server_name": "<domain>", ...},
   "detour": "ss-inner"},
  {"type": "shadowsocks", "tag": "ss-inner", "listen": "127.0.0.1",
   "listen_port": 28388, "method": "2022-blake3-aes-128-gcm",
   "password": "<pw>"}
 ],
 "outbounds": [{"type": "direct", "tag": "direct"}]}
```

Share links (sing-box schemes, all understood by ZedSecure):
- TUIC: `tuic://<uuid>:<password>@<host>:8443?congestion_control=bbr&alpn=h3&sni=<domain>#<name>`
- AnyTLS: `anytls://<password>@<host>:8444?sni=<domain>#<name>`
- Naive: `naive+https://<user>:<password>@<host>:8445#<name>` (note the
  `naive+https` scheme — a common gotcha; test against ZedSecure at build time)
- ShadowTLS: served as `ss://…` with ShadowTLS as detour in sing-box JSON;
  as a bare share link it is `ss://` + ShadowTLS params — **verify against
  ZedSecure's importer at build time**; if the link form is unreliable,
  ShadowTLS is offered only via the sing-box JSON subscription.
- Hysteria2 (if served by sing-box): `hysteria2://<password>@<host>:443?sni=<domain>#<name>`

**Certificate sharing:** Hysteria2 / TUIC / AnyTLS / Naive / ShadowTLS all
use the *same* TLS certificate (one domain, one cert pair in
`/opt/sparky-manager/certs/`). Reality needs none. If no domain is given,
these TLS inbounds are **not created** in Phase 1 — Reality + WireGuard
carry the install instead (see open question Q2).

### 5.3 WireGuard / AmneziaWG (native, not Xray/sing-box)

- **WireGuard:** kernel `wg0`, managed with `wg` / `wg-quick`.
  Panel renders `/etc/wireguard/wg0.conf` from the DB (one `[Peer]` per
  client: `PublicKey`, `AllowedIPs = 10.8.0.X/32`, `PresharedKey`
  optional). Per-peer traffic from `wg show wg0 transfer`.
  Client config export = standard `[Interface]/[Peer]` `.conf` file
  + QR code (ZedSecure imports WireGuard configs; also `wireguard://` links).
  This is the *same* model commercial providers use and the same one
  vpn-ui uses for "WireGuard (C)".
- **AmneziaWG:** **v1.2.0, gated.** Needs a DKMS kernel module that
  fails to build on kernel ≥ 7.1 and on RHEL-family kernels (vpn-ui's own
  README says so). The installer *tries* the Amnezia PPA (suite pinned
  to `noble` on Ubuntu 26.04, which the PPA does not publish) and falls
  back cleanly — it never breaks the rest of the install. If the module
  is missing, the panel renders the config but reports honestly
  ("amneziawg is not installed") instead of pretending the inbound
  works. ZedSecure imports it via `vpn://` links and `.conf` files;
  upstream sing-box has no AmneziaWG support, so the sing-box feed
  carries none of it.

### 5.4 IKEv2 — native strongSwan since v1.2.0

The panel is built from scratch and does not detect, show, link to, or
depend on any other project. `ikev2` is a native protocol in the data
model since v1.2.0: the panel renders `/etc/swanctl/swanctl.conf`
(`remote-access` connection, EAP-MSCHAPv2 + server certificate) and a
`.mobileconfig` per user, and applies it with `swanctl --load-all`.
The strongSwan code is written from scratch for this panel — it does
not reuse, read, or depend on any other project's IKEv2 code.

Port plan note: strongSwan/IKEv2 uses UDP 500/4500 — the panel never
assigns those ports to its own inbounds (the inbound form rejects
them, except an IKEv2 inbound itself, which uses 500).

### 5.5 What the panel does NOT run (by design)

| ZedSecure engine | Panel provides? | Why not |
|---|---|---|
| **Psiphon** | ❌ No | Psiphon's own network; no server of yours exists to run. ZedSecure ships it built-in — the user just taps it in the app when nothing else connects. Nothing for a panel to do. |
| **Tor** (obfs4 / Snowflake / Conjure) | ❌ No (Phase 3 at most) | Tor is a third-party anonymity network. Running a bridge is a separate project (obfs4 bridge + Tor daemon + bridge-line distribution) with its own abuse/ops profile. ZedSecure already bundles Tor; the panel gains nothing by owning it in MVP. |
| **DNS tunnels** (DNSTT / VayDNS / MasterDNS) | ❌ No | These tunnel through DNS on networks that allow little else. They need a DNS server + a tunnel endpoint (iodine-style) and a domain with NS records — a niche fallback, not a general VPN server. ZedSecure bundles the clients; the panel does not need a DNS-tunnel server for its core job. Revisit only if James explicitly asks. |
| **SSH** (as a VPN) | ❌ No server in MVP | ZedSecure lists SSH as an engine, but SSH-as-VPN (dynamic SOCKS) is a manual fallback, not a managed multi-user service. The server already has SSH; the panel doesn't need to manage it. |
| OpenVPN / OpenConnect | ✅ v1.2.0 | Real servers (OpenVPN daemon, ocserv) with `.ovpn` / AnyConnect-profile export; one shared CA under `data/ca/` with the IKEv2 server cert. |

---

## 6. Subscriptions, links, QR — dual format (mandatory)

ZedSecure imports **both** v2rayNG-style subscriptions and sing-box JSON.
The panel must emit both from the same per-user data, so a user never
has to care which engine a protocol belongs to.

### 6.1 Endpoints (per user, tokenised)

```
GET /sub/<sub_token>              → format by User-Agent (default: v2rayNG)
GET /sub/<sub_token>?format=v2rayng   → base64 list of share links
GET /sub/<sub_token>?format=singbox  → sing-box JSON {"outbounds": [...]}
GET /sub/<sub_token>?format=clash    → Phase 2 (Clash/Mihomo YAML)
GET /u/<sub_token>                → human page (Persian): links + QR codes
```

- `sub_token`: random 32-char URL-safe token per user, stored in `users`.
  Rotating it (one button) invalidates the old subscription instantly.
- **User-Agent sniffing** (like Marzban/Marzneshin/Remnawave do): if the
  UA contains `sing-box`, `SFA`, `Hiddify` → sing-box JSON; if it contains
  `v2rayNG`, `v2rayN`, `NekoBox`, `Clash` → v2rayNG links; unknown UA →
  v2rayNG (the safer default). The explicit `?format=` always wins.
- Response headers: `Content-Type: text/plain` for v2rayNG,
  `application/json` for sing-box, plus
  `Subscription-Userinfo: upload=0; download=<used>; total=<limit>; expire=<unix>`
  so clients can show quota/expiry.
- Disabled / expired / over-quota users get **HTTP 403 with an empty
  body** on `/sub/` (never a stale list).

### 6.2 v2rayNG format (base64)

Body = base64 (standard, with padding) of one share link per line,
`\n`-separated, in this order: VLESS-Reality, VLESS-WS-TLS, VMess,
Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, Naive, ShadowTLS/SS.
Only the user's *enabled* inbounds are included.

| Protocol | Share-link shape |
|---|---|
| VLESS | `vless://<uuid>@<host>:<port>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<sni>&fp=chrome&pbk=<pub>&sid=<sid>&type=tcp#<name>` (Reality) — or `security=tls&type=ws&path=…&host=…&sni=…` (WS+TLS) |
| VMess | `vmess://<base64(JSON {v:"2", ps, add, port, id, aid:0, scy:"auto", net:"ws", type:"none", host, path, tls:"tls", sni, fp})>` |
| Trojan | `trojan://<password>@<host>:<port>?security=tls&type=tcp&sni=<host>#<name>` |
| Shadowsocks | `ss://<base64url(method:password)>@<host>:<port>#<name>` (SIP002) |
| Hysteria2 | `hysteria2://<password>@<host>:443?sni=<host>#<name>` (alias `hy2://` also accepted by clients) |
| TUIC | `tuic://<uuid>:<password>@<host>:8443?congestion_control=bbr&alpn=h3&sni=<host>#<name>` |
| AnyTLS | `anytls://<password>@<host>:8444?sni=<host>#<name>` |
| Naive | `naive+https://<user>:<password>@<host>:8445#<name>` |
| WireGuard | No share-link standard — export `.conf` file + QR of the file content (§6.3) |
| AmneziaWG | `vpn://` + base64url of the whole `.conf` text (v1.2.0); no sing-box outbound (upstream has no AmneziaWG support) |
| IKEv2 / OpenVPN | No share link — `.mobileconfig` / `.ovpn` file export (both in v1.2.0) |
| OpenConnect | No share link — AnyConnect profile XML + host / port / credentials (v1.2.0) |

URL-encode the `#name` fragment and any password containing `@`, `#`,
`?`, `/`. Base64 is **encoding, not encryption** — anyone with the link
can decode the credentials; say so in the UI.

### 6.3 sing-box format (JSON)

Body = a JSON object the client can import directly:

```json
{"outbounds": [
  {"type": "vless", "tag": "🇮🇷 VLESS-Reality",
   "server": "<host>", "server_port": 443, "uuid": "<uuid>",
   "flow": "xtls-rprx-vision",
   "tls": {"enabled": true, "server_name": "www.microsoft.com",
           "utls": {"enabled": true, "fingerprint": "chrome"},
           "reality": {"enabled": true, "public_key": "<pub>",
                       "short_id": "<sid>"}}},
  {"type": "hysteria2", "tag": "Hysteria2",
   "server": "<host>", "server_port": 443, "password": "<pw>",
   "tls": {"enabled": true, "server_name": "<domain>"}},
  {"type": "tuic", "tag": "TUIC",
   "server": "<host>", "server_port": 8443, "uuid": "<uuid>",
   "password": "<pw>", "congestion_control": "bbr",
   "tls": {"enabled": true, "server_name": "<domain>", "alpn": ["h3"]}},
  {"type": "anytls", "tag": "AnyTLS",
   "server": "<host>", "server_port": 8444, "password": "<pw>",
   "tls": {"enabled": true, "server_name": "<domain>"}},
  {"type": "wireguard", "tag": "WireGuard",
   "server": "<host>", "server_port": 51820,
   "local_address": ["10.8.0.2/32"], "private_key": "<key>",
   "peer_public_key": "<server pub>", "mtu": 1280}
]}
```

Notes: sing-box JSON uses `type` + `server`/`server_port` (not Xray's
`protocol`/`address`/`port`). XHTTP is **not** supported by sing-box —
VLESS-XHTTP inbounds are emitted in the v2rayNG feed only, and the
sing-box feed omits them (with a note on the `/u/<token>` page).
Test both feeds against the real ZedSecure app before calling the
feature done (see §10, Q5).

### 6.4 Traffic stats & online users

| Source | How | Granularity |
|---|---|---|
| Xray inbounds | gRPC Stats API on `127.0.0.1:10085` (`QueryStats` per `user>>>…>>>traffic>>>uplink/downlink` + `inbound>>>…`). Poll every 60 s. | Per user, per inbound. Accurate. |
| WireGuard | `wg show wg0 transfer` (bytes per peer public key → map to client). Poll every 60 s. | Per peer. Accurate. |
| sing-box inbounds | **No stats API.** Per-user dedicated port + nftables counter per port (`nft add rule … counter`), polled every 60 s. | Per user *only if* the user has a dedicated port for that protocol. Shared-port sing-box inbounds cannot be attributed per user — the UI must say "traffic: n/a (shared port)" rather than invent a number. |
| IKEv2 | Native since v1.2.0; no per-user traffic API yet (same gap as OpenVPN/ocserv — `swanctl --list-sas` / occtl exist but are not wired into the panel yet). | — |
| Online status | Xray: a user with non-zero traffic delta in the last 60–120 s, or present in `QueryStats` with recent activity → "online". WireGuard: `latest handshake < 3 min ago`. sing-box: no live sessions API — show "last seen" from traffic deltas only, never fake "online". | Best-effort, labelled as such. |

Enforcement runs in the sweeper (every 5 min): expired or over-quota
users are removed from the rendered configs (so the core drops them)
and their subscription returns 403. No live-connection killing in MVP
(Xray `RemoveUser` / `wg set peer remove` are the Phase 2 mechanism).

---

## 7. Security

- **Admin auth:** one admin, Argon2id hash (never plaintext, never in
  a file). Session = signed, HttpOnly, `Secure` (when TLS), `SameSite=Lax`
  cookie, 12 h expiry, server-side session record so logout invalidates
  it. Login rate-limit: 5 failed attempts → 15 min lockout for that IP.
  No "remember me" in MVP.
- **Panel port:** TCP, randomised on a fresh install (free port in
  10000–60000, like other panels), plus a random secret web path (like
  3X-UI's webBasePath): the panel only answers under `/<random-path>`
  and the root returns 404. Printed in the login box,
  saved to `/root/sparky-manager-login.txt`, reprintable with `sparky-manager info`.
  Re-used on re-install; `--port` fixes it. The firewall opens only the
  panel port + the inbound ports in use.
- **Panel TLS:** installer asks for a domain (optional).
  - *Domain given:* `certbot` / `acme.sh` (Let's Encrypt) obtains a cert
    for the panel + the TLS inbounds; auto-renew via systemd timer;
    renewal is picked up without dropping connections (reload, not restart).
  - *No domain:* panel serves a **self-signed cert** (generated at
    install, fingerprint printed in the login box) and Reality +
    WireGuard carry the VPN side, since neither needs a domain or cert.
    The browser will warn — the login box says so plainly, with the
    fingerprint to check. Since v8 the installer instead obtains a
    free Let's Encrypt IP certificate automatically (shortlived,
    ~6 days, via acme.sh — the same trick 3X-UI uses), so a bare-IP
    install is trusted with no browser warning.
- **Core APIs are loopback-only:** Xray API `127.0.0.1:10085`, sing-box
  has no API port at all, panel DB `0600`, rendered configs `0640`.
- **Secrets:** Reality keys, SS passwords, WireGuard keys generated with
  `secrets` / the cores' own generators (`xray x25519`,
  `sing-box generate reality-keypair`, `wg genkey`). Never logged.
  Subscription tokens are random 32-char strings, rotatable.
- **Input validation:** Pydantic models on every API route; ports
  validated 1–65535 and checked for clashes before render; usernames
  `[a-zA-Z0-9_-]` only (they appear in share-link fragments and file names).
- **Updates:** installer pins Xray + sing-box versions in
  `/opt/sparky-manager/versions.env`; `sparky-manager update-cores` downloads the
  new binaries, validates configs, restarts. No auto-update (a bad core
  must never take the server down unattended).

---

## 8. Install script (Ubuntu / Debian)

One-liner install:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash
# or pinned:  curl -Ls …/install.sh | sudo bash -s -- --version 1.2.0
```

`install.sh` outline (idempotent — safe to re-run):
1. Refuse non-root; detect OS (`Ubuntu 22.04/24.04/26.04`, `Debian 12/13` only;
   anything else → clear error, not a half-install).
2. `apt-get update`; install `curl, ca-certificates, qrencode?, python3.11+,
   python3-venv, wireguard, nftables, iproute2, ufw?` (no — use nftables
   directly; don't fight UFW).
3. Create `/opt/sparky-manager/{app,data,certs}`, `sparky-manager` system user,
   `xray`/`sing-box` config dirs; download pinned Xray-core + sing-box
   release tarballs (verify SHA256 from the release page), place binaries
   in `/usr/local/bin/`.
4. Python venv at `/opt/sparky-manager/venv`, `pip install -r requirements.txt`.
5. Interactive prompts (with sane defaults, all skippable with flags
   for unattended install): panel port `[random]`, web path
   `[random]`, domain `[none]`, Reality SNI `[www.microsoft.com]`,
   admin password `[generated]`. The random panel port and web path
   are printed before proceeding (prompt, summary and login box), and
   `--yes` accepts them.
6. Generate Reality keypair, WireGuard server keypair, admin password
   (if not supplied), per-user subscription salt. Write
   `/opt/sparky-manager/data/panel.db` (initialised by the app on first run).
7. Render the **default inbounds** (VLESS-Reality :443 TCP,
   Hysteria2 :443 UDP via whichever core owns it, Shadowsocks :8388,
   WireGuard :51820) + `xray`/`sing-box`/`wg0` configs; validate both
   cores; `systemctl enable --now xray sing-box sparky-manager`.
8. If a domain was given: obtain the Let's Encrypt cert, then restart
   the panel once with TLS enabled.
9. **Verify before finishing:** `curl -k https://127.0.0.1:<panel-port>/<web-path>/health`
   must return 200; `xray` and `sing-box` must be `active`. If any check
   fails, print the failing service's last 20 log lines and exit non-zero.
10. **Print the login box** (and save it to `/root/sparky-manager-login.txt`):
```
============================================================
  sparky-manager installed ✓
  Panel:    https://<IP>:<random-port>/<web-path>   (or https://<domain>:<same-port>/<web-path>)
  Username: admin
  Password: <generated-or-supplied>
  Subscriptions, QR codes and users are inside the panel.
  Reprint this anytime:  sudo sparky-manager info
  Docs: /opt/sparky-manager/README.md
============================================================
```

`sparky-manager` CLI (a small wrapper, like `vpn-ui`'s menu but non-interactive
first): `sparky-manager info | status | restart | update-cores | backup | restore`.
`backup` = tarball of `/opt/sparky-manager/data/` + both `config.json` files
(DB is the source of truth, so restoring the DB + re-rendering is enough).

---

## 9. Phases — what ships when

### Phase 1 — MVP (build this first)
- FastAPI + SQLite + Persian RTL UI; fixed-port install, printed login box.
- **Xray:** VLESS (Reality + WS/TLS + XHTTP), VMess, Trojan, Shadowsocks 2022,
  Hysteria2 (if the pinned Xray ships it, else sing-box).
- **sing-box:** TUIC, AnyTLS, Naive, ShadowTLS (+ inner SS).
- **WireGuard** native (keys, `wg0.conf`, `wg show` accounting, `.conf` + QR export).
- Users: quota, expiry, enable/disable, per-user subscription token.
- **Dual subscription:** v2rayNG base64 + sing-box JSON, UA sniffing,
  `?format=` override, `Subscription-Userinfo` header; per-user page with
  QR codes + single links; token rotation.
- Traffic: Xray gRPC + `wg show` + nftables-per-port for sing-box;
  dashboard totals + per-user used/remaining + expiry countdown.
- IKEv2: native strongSwan since v1.2.0 (EAP-MSCHAPv2 + server cert,
  `.mobileconfig` export); OpenVPN + OpenConnect since v1.2.0;
  AmneziaWG since v1.2.0 (gated on the kernel module).
- Tests: config-render golden tests (render → `xray -test` /
  `sing-box check` on known inputs), link-builder tests (round-trip:
  build a link → parse it back), subscription tests (both formats parse
  in a reference parser), install dry-run on Ubuntu 24.04 + Debian 12.

### Phase 2 (v1.2.0: OpenVPN, OpenConnect, AmneziaWG, native IKEv2 — done)
- ~~OpenVPN (daemon + `.ovpn` export) and OpenConnect/ocserv.~~ Done in v1.2.0.
- ~~AmneziaWG — **only** when the installer can verify the kernel module
  builds on that host; otherwise it stays unavailable with a clear reason.~~ Done in v1.2.0 (gated: the panel reports honestly when the tools are missing).
- Zero-downtime user add/remove (Xray gRPC `AddUser`/`RemoveUser`).
- Bulk operations (traffic/days/enable/delete) + Freeze.
- Clash/Mihomo YAML subscription format.
- Optional second admin (read-only role).
- ~~Native IKEv2 (strongSwan) support.~~ Done in v1.2.0.
- Telegram-bot hook — only if James asks.

### Phase 3 (only if asked)
- Tor obfs4 bridge (separate daemon + bridge-line distribution).
- Multi-node support.
- Reseller / billing.

### Will NOT provide (and why) — §5.5 in short
Psiphon, Tor, DNS tunnels, SSH-as-VPN: client-side or third-party
networks, not things a server panel runs. ZedSecure already bundles
them; the panel's job is to give ZedSecure clean server-side configs.

---

## 10. MVP file tree

```
sparky-manager/
├── DESIGN.md                  # this file
├── README.md                  # install + login + FAQ (FA + EN)
├── README_FA.md
├── install.sh                 # one-line installer (§8)
├── requirements.txt           # pinned Python deps
├── .github/workflows/ci.yml   # pytest + shellcheck + config golden tests
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI app, routes, startup (sweeper, syncer)
│   ├── config.py              # settings, paths, versions.env
│   ├── db.py                  # SQLAlchemy engine/session, init
│   ├── models.py              # admins, settings, inbounds, users, clients,
│   │                          #   traffic_daily, audit_log (§4)
│   ├── auth.py                # argon2id, sessions, rate limit
│   ├── i18n.py                # fa (default) / en strings
│   ├── xray.py                # render /usr/local/etc/xray/config.json + validate
│   ├── singbox.py             # render /etc/sing-box/config.json + validate
│   ├── wireguard.py           # render wg0.conf, wg show parsing
│   ├── ikev2.py               # Phase 1: status/deep-link only (§5.4)
│   ├── links.py               # share-link builders (§6.2) + QR (qrcode)
│   ├── subscription.py        # /sub/ dual format + UA sniffing (§6.1/6.3)
│   ├── traffic.py             # Xray gRPC client, wg/nftables pollers, sweeper
│   ├── panel_cli.py           # `sparky-manager info/status/restart/update-cores/backup`
│   ├── templates/             # Jinja2, RTL, Persian-first
│   │   ├── base.html  dashboard.html  inbounds.html
│   │   ├── users.html  user_detail.html  settings.html  login.html
│   └── static/
│       ├── style.css          # one hand-written stylesheet, no build step
│       └── app.js             # small vanilla JS (copy link, show QR, confirm dialogs)
├── scripts/
│   ├── render_configs.py      # render both cores from DB (used by installer + CLI)
│   └── backup.sh
├── systemd/
│   ├── sparky-manager.service
│   ├── xray.service           # or use the cores' shipped units
│   └── sing-box.service
├── tests/
│   ├── test_links.py          # link round-trips for all 9 schemes
│   ├── test_render.py         # golden configs → xray -test / sing-box check
│   ├── test_subscription.py   # v2rayNG + sing-box feeds parse cleanly
│   └── test_users.py          # quota/expiry/enable rules (§4)
└── docs/
    ├── PORTS.md               # §3 port plan
    └── ZEDSECURE.md           # per-protocol import checklist for ZedSecure
```

---

## 11. Open questions (answers that would change the design)

1. **Domain?** Do you have a domain for this server? It decides whether
   the TLS inbounds (WS/TLS, TUIC, AnyTLS, Naive, ShadowTLS, Hysteria2)
   and the panel itself get real Let's Encrypt certs, or whether Phase 1
   ships Reality + WireGuard only (no domain needed) and TLS inbounds wait.
2. **Server IP / host?** Needed for the default subscription host and the
   Reality `dest`. Also: is strongSwan/IKEv2 running on the *same* server?
   (If yes, Phase 1 must reserve UDP 500/4500 and avoid port clashes.)
3. **Hysteria2 core:** prefer Xray (if pinned Xray ≥ 26.1 ships a native
   hysteria inbound) or sing-box? Affects which core owns UDP/443 and
   whether Hysteria2 gets accurate per-user stats (Xray gRPC) or
   nftables-port accounting (sing-box).
4. **AmneziaWG now or later?** It needs a kernel-module build that fails
   on some hosts. Phase 2 (recommended) or attempt in Phase 1 with a
   build check that disables it cleanly?
5. **ZedSecure test device?** Can you install ZedSecure on your phone and
   import the two subscription feeds (v2rayNG + sing-box) to verify them
   against the real app? This is the single most valuable test; link
   formats (especially Naive `naive+https://` and ShadowTLS) vary between
   clients and must be checked against the real importer, not the spec.
6. **OpenVPN / OpenConnect in Phase 1?** The brief says "ALL methods".
   They are real daemons with their own PKI; putting them in Phase 1
   roughly doubles the installer's scope. Confirm Phase 2 is acceptable,
   or say which of the two matters more.
7. **Public repo?** Should sparky-manager be public from day one, or
   private until Phase 1 works?
   (Affects whether the install URL can be the public raw GitHub URL.)

---

## Sources (checked 2026-11-11)

- ZedSecure README — `github.com/EbiDevSharp/ZedSecure` (also
  `CluvexStudio/ZedSecure`): engine table, import formats, "provides no
  servers" statement; AGPL-3.0.
- vpn-ui README — `github.com/Sir-MmD/vpn-ui` (main, read 2026-11-11):
  protocol list, patched Xray-core, single-binary bundling, randomised
  login via `vpn-ui-amd64 info`, AmneziaWG kernel-module limits,
  install `curl …/deploy.sh | sudo bash`.
- 3X-UI README — `github.com/MHSanaei/3x-ui`: multi-protocol inbounds,
  per-client quota/expiry/IP limits, subscription server (raw/JSON/Clash,
  UA-based), REALITY + XTLS-Vision, multi-node, 14 UI languages.
- Xray docs — `xtls.github.io/en/config/…`: VLESS inbound object
  (`decryption: "none"`, `flow: xtls-rprx-vision`), `streamSettings`
  (Reality/TLS/XHTTP), VLESS-must-have-transport-security warning;
  Xray 26.x Shadowsocks deprecation warning; Xray 26.1+ native Hysteria.
- sing-box server guide — `dementor.cn/en/sing-box-server/` (2026-08-17):
  Reality + Hysteria2 + TUIC + AnyTLS in one `config.json`,
  AnyTLS needs sing-box ≥ 1.12, ShadowTLS v3 `strict_mode`, shared cert,
  `sing-box check` validation; VortexUI protocol matrix (sing-box
  inbounds: vless/vmess/trojan/shadowsocks/hysteria2/tuic/wireguard/
  shadowtls/anytls/socks/http/naive).
- Share-link / subscription formats — oxidom docs + Shadowrocket link
  guides: `vless://uuid@host:port?…`, `vmess://` base64 JSON,
  `trojan://password@host:port?…`, `ss://` SIP002, `hysteria2://` /
  `hy2://`, `tuic://`, `anytls://`; subscription = base64 link list
  *or* JSON `{outbounds:[…]}`, format selected by User-Agent
  (Marzban/Marzneshin/Remnawave/Hiddify precedents).
- FastAPI vs Flask — 2025/2026 comparisons: FastAPI async + Pydantic
  validation + auto OpenAPI docs; Flask sync WSGI, minimal core.
