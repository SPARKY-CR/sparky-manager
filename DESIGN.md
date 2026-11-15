# sparky-manager — Design Document

> **Status:** IMPLEMENTED. The design below shipped as v1.2.0 (2026-11-14,
> on `main`), was expanded with a full inbound editor, per-client
> management, panel settings and a Telegram bot (2026-11-15), and then
> went through a 7-phase professional upgrade on branch
> `upgrade/professional` (2026-11-15, §§12–14). The panel is installed
> and running on a real server. Historical sections (§§0–11) describe
> the original design and are annotated where the shipped code differs.
> **Date:** 2026-11-11 · **Working name:** `sparky-manager`

> **Decisions confirmed by Morteza, 2026-11-11 (override any conflicting
> suggestion below):**
> 1. **PUBLIC project** — prepared as a public repo (README FA+EN, MIT
>    LICENSE, CI). Morteza can change the license later.
> 2. **DOMAIN-AGNOSTIC** — installer and panel work with a bare server IP
>    and no domain. Default first pair: VLESS+Reality on TCP 443 +
>    Hysteria2 on UDP 443 + WireGuard, none needing a domain or cert.
>    A domain entered later in settings only *unlocks* TLS inbounds and
>    Let's Encrypt as an option — never a requirement.
> 3. **FROM SCRATCH, NO REFERENCE PROJECT** — all panel code, templates,
>    install script and tests are written originally for this project.
>    No code is copied, forked or adapted from any other panel project
>    (3X-UI, vpn-ui, Marzban, Marzneshin, Remnawave, Hiddify, …) or from
>    Morteza's Ikev2-manager. Stock upstream Xray-core and sing-box
>    binaries are used as protocol engines only. The comparison table
>    in §2 is context, not a template.
> **For:** Morteza (Persian-speaking, works from phone in Termux, Ubuntu/Debian server)
> **Client target:** ZedSecure (multi-core client, Android/Linux/Windows/macOS)
> **Replaces / beats:** Sir-MmD/vpn-ui (3X-UI fork, v2.9.3-based) and MHSanaei/3x-ui

## 0. What changed in this version

The first draft was Xray-only (VLESS / VMess / Trojan / Shadowsocks).
Morteza then clarified: **ALL methods and ALL cores, suitable for the ZedSecure app.**
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

Morteza installed vpn-ui, got in, then deleted it as "not good".
Exact pain points were never spelled out, so this design fixes the
**known, verifiable** vpn-ui / 3X-UI weaknesses:

| Pain point (vpn-ui / 3X-UI) | Fix in sparky-manager |
|---|---|
| Fresh install **randomises port, username, password and web path**; login info is hidden behind `/opt/vpn-ui/vpn-ui-amd64 info` (menu option 8) | **Like other panels** (see §7): fresh install randomises the panel port (10000–60000), the admin password and the secret web path; username `admin`. Installer prints one big, unmissable login box at the end (full URL + user + password), saves it to `/root/sparky-manager-login.txt`, and `sparky-manager info` reprints it. Port and password are re-used on re-install, never re-randomised. |
| Cluttered English UI; 3X-UI has 14 languages but no Persian-first design, and vpn-ui adds ~15 protocols, resellers, multi-admin, bulk ops — a huge surface for one person | **Persian-first RTL UI**, English as secondary toggle. One screen per job: Dashboard → Inbounds → Users → Subscriptions. No reseller/multi-admin in MVP. |
| Heavy setup: vpn-ui is a Go monolith bundling patched Xray-core, RADIUS, procmgr, a dozen daemons (xl2tpd, strongSwan, pptpd, OpenVPN, ocserv, accel-ppp, telemt…), kernel-module builds (AmneziaWG DKMS fails on kernel ≥ 7.1 and on RHEL kernels) | **Two stock cores + Python backend, no patched core, no kernel builds in Phase 1.** Xray-core and sing-box are downloaded as official upstream binaries. AmneziaWG (needs a kernel module) is Phase 2, explicitly gated. |
| Go + Vue build: editing the UI means a Node build step | **No Node/Vue build step.** Server-rendered pages (Jinja2) + one hand-written CSS file + a little vanilla JS. Morteza can edit a template with copy-paste in Termux. |
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
| Traffic stats / online users | Xray gRPC stats | Xray gRPC + RADIUS/nftables for daemons | Xray gRPC + `wg show`; sing-box traffic uncollected (no stats API) (§6.4) |
| UI language | 14 languages, English-first | Same + FA/AR/ZH/ES/RU/TR READMEs | **Persian RTL first**, English toggle |
| Install | `bash <(curl …/install.sh)` | `curl …/deploy.sh \| sudo bash`, randomised login | One-liner, **randomised port/password/web path, printed login box** |
| Stack | Go + Vue (Node build) | Go + Vue (Node build) | **Python FastAPI + Jinja2, no build step** (§3) |
| Storage | SQLite | SQLite (changed path) | SQLite (WAL) |

---

## 3. Tech stack — recommendation: FastAPI

**Recommendation: Python 3.11+ · FastAPI + SQLAlchemy 2.0 (sync) + SQLite (WAL)
+ Jinja2 server-rendered UI + vanilla JS + Uvicorn + systemd.**

| Choice | Why | Rejected alternative |
|---|---|---|
| **FastAPI** (not Flask) | Async-native (ASGI): the traffic-sync loop, Xray gRPC polling and expiry sweeper run as background tasks without blocking requests. Pydantic v2 validates every API payload (inbound/user forms) for free. Type hints catch config-shape bugs before runtime. Now ahead of Flask in PyPI downloads; well documented. (The auto-generated OpenAPI docs pages `/docs`, `/redoc`, `/openapi.json` were disabled in the professional upgrade, Phase 7 — a private admin panel has no use for an unauthenticated schema dump; see §14.) | Flask: sync WSGI, no built-in validation, needs extensions for everything FastAPI ships. Fine for a prototype, worse for background jobs + validation. |
| **SQLAlchemy 2.0 sync + SQLite** | One file (`/opt/sparky-manager/data/panel.db`), zero DB server, trivial backup (`cp` the file). WAL mode so reads don't block the sweeper's writes. Sync engine (not async) keeps the code simple: FastAPI runs sync endpoints in a threadpool; the DB is small and local, so async adds complexity for no gain. | PostgreSQL: overkill for one server / one admin. aiosqlite/async SQLAlchemy: async-everywhere tax for a single-file DB. Raw `sqlite3`: no migrations. |
| **Jinja2 + hand-written CSS, no Node/Vue** | Morteza edits in Termux by copy-paste. A template change is a file edit + `systemctl reload`, not `npm run build`. RTL + Vazirmatn font (system fallback if offline; CDN optional). | Vue/React SPA: needs a build step, exactly the friction vpn-ui has. Django: batteries-included but heavy; its admin is English-first and its ORM/migration ceremony is overkill here. |
| **Uvicorn, single process, systemd unit** | One service `sparky-manager.service`. No Gunicorn workers (SQLite + multiple writers = lock contention). | Gunicorn multi-worker: wrong for SQLite. |
| **Xray-core + sing-box, official binaries** | No patched core. Upgrades = replace binary + restart. Each core owns its own `config.json`, generated by the panel. | Patched Xray-core (vpn-ui approach): carries AnyTLS/TUIC/Naive inside Xray but forks the project from upstream security fixes. |
| **Deps (pinned in `requirements.txt`)** | `fastapi`, `uvicorn[standard]`, `sqlalchemy`, `jinja2`, `qrcode[pil]`, `python-multipart`, `httpx` (Telegram Bot API), `cryptography` (key gen), `grpcio` (Xray Stats client). Auth uses stdlib PBKDF2 — no `argon2-cffi` (removed in the professional upgrade, Phase 5). Nothing else. | — |

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
| Subscription endpoint | Same panel port, `/sub/<token>` | Separate port only if Morteza wants it unlisted |

Reality (TCP 443) + Hysteria2 (UDP 443) sharing port 443 is the
recommended first pair: no domain, no certificate, maximum compatibility.

---

## 4. Data model (SQLite)

```sql
-- admins: exactly one row in MVP (username 'admin'); Phase 2 may add more.
admins(id PK, username UNIQUE, password_hash TEXT /* PBKDF2-HMAC-SHA256, 600k iters */,
       created_at, last_login_at)

-- settings: single-row key/value (panel port, domain, subscription host,
-- reality keys, TLS mode, traffic-sync interval). No .env sprawl.
settings(key PK, value TEXT)

-- inbounds: one row per listening inbound, across BOTH cores.
-- core: 'xray' | 'singbox' | 'wireguard' | 'ikev2' | 'openvpn' | 'openconnect'
-- protocol: vless | vmess | trojan | shadowsocks | hysteria2 | tuic |
--           anytls | naive | shadowtls | wireguard | amneziawg | ikev2 | ...
-- stream/security are JSON blobs so a new transport doesn't need a migration.
inbounds(id PK, tag UNIQUE, core TEXT, protocol TEXT, port INT,
         UNIQUE(port, protocol),  -- same port may serve TCP + UDP protocols
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
                                     -- Phase 2 keys: frozen (bool), ip_limit (int),
                                     -- allowed_ips (WireGuard/AmneziaWG peer address)
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
- A client with `extra.frozen` set is unusable (Phase 2, §5.7): it is
  omitted from configs, links and feeds, but keeps its credentials and
  traffic history; unfreezing restores it exactly. Distinct from
  `enabled=False` (admin off-switch) and from delete.
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

The panel restarts the affected core on every change (simple, reliable,
a ~1 s blip). Zero-downtime user add/remove via Xray's gRPC
`HandlerService.AddUser / RemoveUser` was considered and NOT
implemented — full re-render on every change is what ships, and
sing-box has no equivalent live API anyway, so sing-box inbound
changes always restart sing-box.

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

### 5.5 Inbound editor — `stream_json` keys (Phase 1, 2026-11-15)

Every per-inbound option lives in the inbound's `stream_json` blob —
no DB migration. The edit page (`GET/POST /inbounds/{id}/edit`, plus
`POST /inbounds/{id}/regenerate-reality|regenerate-awg-params|regenerate-server-key`)
validates, saves, and re-renders through the same pipeline as §5.
Validation errors re-render the form (200) with the submitted values;
a re-render failure redirects to `/inbounds` with the error.

| Family | Keys (all optional unless noted) |
|---|---|
| Xray vless/vmess/trojan | `network` (tcp/ws/grpc/xhttp/httpupgrade), `security` (none/tls/reality), `path`, `host`, `service_name`, `mode` (xhttp: auto/packet/stream), `fp`, `sniffing` (bool), `sniffing_dest_override`, `fallbacks` ([{dest, xver}] — rendered in `streamSettings`, TCP only), `reality` {dest, sni, server_names, private_key, public_key, short_id}, `tls` {sni, alpn, cert_path, key_path} |
| Hysteria2 (both cores) | `up_mbps`, `down_mbps` (Xray emits `upMbps`/`downMbps`) |
| TUIC | `congestion_control` (bbr/cubic/new_reno), `zero_rtt_handshake` |
| ShadowTLS | `method`, `password`, `strict_mode`, `inner_port` |
| WireGuard / AmneziaWG | `subnet` (server Address = first host; existing peers keep their addresses — changing the subnet does NOT re-allocate), `mtu`, `dns` (list, ≤ 2); AmneziaWG adds `awg_params` (Jc/Jmin/Jmax, S1–S4, H1–H4, I1–I5 tags, `HeaderProtectionKey`) |
| OpenVPN / OpenConnect / IKEv2 | `subnet`, `dns` (list, ≤ 2); OpenVPN adds `transport` (udp/tcp); OpenConnect adds `max_clients` |

Notes: Reality only works over TCP (the editor rejects Reality+WS/gRPC).
The WG/AWG server keypair is shared per protocol (settings keys
`wireguard_private_key`/`amneziawg_private_key`); regenerating it forces
every client of that protocol to re-fetch. The Shadowsocks method is
NOT editable per inbound — it lives per client (`clients.method` is
authoritative). XTLS is not offered (no renderer support).

### 5.6 What the panel does NOT run (by design)

| ZedSecure engine | Panel provides? | Why not |
|---|---|---|
| **Psiphon** | ❌ No | Psiphon's own network; no server of yours exists to run. ZedSecure ships it built-in — the user just taps it in the app when nothing else connects. Nothing for a panel to do. |
| **Tor** (obfs4 / Snowflake / Conjure) | ❌ No (Phase 3 at most) | Tor is a third-party anonymity network. Running a bridge is a separate project (obfs4 bridge + Tor daemon + bridge-line distribution) with its own abuse/ops profile. ZedSecure already bundles Tor; the panel gains nothing by owning it in MVP. |
| **DNS tunnels** (DNSTT / VayDNS / MasterDNS) | ❌ No | These tunnel through DNS on networks that allow little else. They need a DNS server + a tunnel endpoint (iodine-style) and a domain with NS records — a niche fallback, not a general VPN server. ZedSecure bundles the clients; the panel does not need a DNS-tunnel server for its core job. Revisit only if Morteza explicitly asks. |
| **SSH** (as a VPN) | ❌ No server in MVP | ZedSecure lists SSH as an engine, but SSH-as-VPN (dynamic SOCKS) is a manual fallback, not a managed multi-user service. The server already has SSH; the panel doesn't need to manage it. |
| OpenVPN / OpenConnect | ✅ v1.2.0 | Real servers (OpenVPN daemon, ocserv) with `.ovpn` / AnyConnect-profile export; one shared CA under `data/ca/` with the IKEv2 server cert. |

### 5.7 Per-client management (Phase 2, 2026-11-15)

The user editor (`GET/POST /users/{id}/edit`) edits the user fields
(name, note, traffic limit, expiry as a **date** — stored as
`expires_at`, end of day 23:59:59 UTC; empty = never) plus one row
per client:

| Field | Storage | Effect |
|---|---|---|
| `flow` (VLESS only) | `clients.flow` | Rendered into the Xray client entry and carried in the share link / sing-box feed. Reality inbounds accept only the Vision variants (the renderer defaults an empty flow to Vision for Reality, so "none" there would build a client that can never connect); TLS accepts none / Vision / Vision-UDP443; security=none accepts only none — saving clears any stale Vision value. |
| IP limit | `clients.extra.ip_limit` | Stored and shown only — **not enforced** (see §6.4). Empty/0 = unlimited, 1–1000 otherwise. |
| Frozen | `clients.extra.frozen` | The client is unusable (`client_is_usable` returns False), so it drops out of every rendered config, share link and subscription feed — but keeps credentials, config and traffic history. `POST /users/{id}/freeze` / `unfreeze` set/clear it on all of a user's clients. Distinct from `enabled=False` (admin off-switch) and from delete. |
| Move | `clients.inbound_id` | To another enabled inbound of the same protocol that has no client for this user yet. Credentials stay; WireGuard/AmneziaWG get a fresh address from the target subnet (the old address is freed). Traffic history is per-user, so it is untouched. The move re-renders configs; links are derived, so they follow automatically. |

Bulk ops (`POST /users/bulk`, checkboxes on the users list):
enable, disable, delete, traffic reset (only the running counter —
`traffic_daily` history is kept), and expiry extension (+N days from
the current expiry when it is still in the future, else from now;
never-expiring users get now + N days). Every bulk action re-renders
configs once at the end. No DB schema change: all new per-client
state lives in the existing `extra` JSON.

### 5.8 Panel & server settings (Phase 3, 2026-11-15)

The settings page (`/settings`) now covers the panel itself:

| Feature | How it works |
|---|---|
| Password change (`POST /settings/password`) | Current + new + confirm; the admin's stored PBKDF2 hash is replaced (`app.auth.hash_password`), so the new password survives restarts (`ensure_defaults` only seeds a password when no admin exists). All OTHER sessions are invalidated (`auth.invalidate_other_sessions`); the session that made the change stays alive. Audited as `admin.password_change`. The installer's login file (`/root/sparky-manager-login.txt`, root-only) still holds the OLD password — the panel cannot rewrite it. |
| Telegram notifications | Bot token + admin chat ID in settings (`telegram_bot_token`, `telegram_chat_id`); the token is never rendered back into the page (a blank field keeps the current value; clearing the chat ID disables notifications) and never logged. `app/telegram.py` is a reusable sender (`send_message`, httpx, 10 s timeout, failure → `False`, never raises) built for the Phase 4 management bot to reuse. Hooks: user created, user expiring within 24 h (checked by the expiry sweeper, once per user per day — dedup in the `telegram_expiry_notified` setting), re-render failure in the sweeper (throttled to once per hour via `telegram_rerender_notified_at`), plus a "send test message" button. Background messages are Persian (no request to take a language from). |
| Backup / restore | `GET /settings/backup` downloads a ZIP (`panel.db` snapshot via the SQLite backup API + `meta.json` with schema version + counts). `POST /settings/restore` accepts the ZIP or a bare `.db` file; validation is integrity check + required tables + schema-version guard (a backup from a NEWER schema version is refused — the schema is versioned through the `schema_version` setting row, written by `ensure_defaults`; a backup without one is v1). A bare `.db` must come from a checkpointed database (a stopped panel): a raw copy of the live WAL file can be missing tables. Restore needs a confirmation checkbox, backs the current DB up first (`data/backups/panel.db.<timestamp>.bak`, last 5 kept), then disposes the engine, swaps the file atomically (temp file + `os.replace`), rebinds (`app.db.reset_engine`), audits, and re-renders configs. The admin may need to log in again afterwards (the restored DB has its own sessions). The ZIP is a full credential bundle (DB holds every password, private key, bot token) — treat it like a private key. Old-format ZIPs that still carry `settings.json` restore fine (restore never read that member; it was dropped in Phase 2). |
| Server status | On the settings page: load averages, RAM, disk (data dir), uptime, and per-service state for xray, sing-box, WireGuard, AmneziaWG, OpenVPN, OpenConnect, IKEv2. All unprivileged: `/proc` + `shutil.disk_usage` + ONE unprivileged `systemctl is-active` call for all units (querying unit state needs no privilege; no new sudoers rule). Fallback when systemd is unavailable: a `/proc` process scan, or `/sys/class/net/<iface>` for wg/awg. A service whose state cannot be determined shows "unknown", never "stopped". |
| Traffic charts | Dashboard: total traffic, last 14 days; user detail: that user's last 14 days — both from `traffic_daily`, zero-filled. Inline SVG generated server-side (`app/charts.py`); no CDN, no JS library. Days with no recorded traffic are zero bars, never invented values. |

No DB schema change: new state (Telegram config, notification dedup,
schema version) lives in the existing `settings` table.

### 5.9 Telegram management bot (Phase 4, 2026-11-15; reworked in the professional upgrade, Phase 3)

The whole panel from Telegram — users, inbounds, links, server status,
services, backups — through a bot that lives inside the FastAPI app
(no second service). Two transports, picked on the settings page
(`telegram_transport` setting, default `"polling"` since the upgrade:
polling works on any panel port, while webhooks only work on
443/80/88/8443 and the installer picks a random port — an install
that explicitly chose `"webhook"` keeps it): webhook (Telegram pushes
updates to the panel) or polling (the panel long-polls `getUpdates`).

| Piece | How it works |
|---|---|
| Transport (webhook) | Telegram POSTs updates to `POST /telegram/webhook/<secret>` on the panel itself (served under the secret WEB_PATH like every other route). The URL carries a random secret stored in the `telegram_webhook_secret` setting — NOT the bot token, which would land in uvicorn's access log on every delivery. The endpoint is inert (404) when the bot is unconfigured or the secret mismatches, so nothing about the bot is revealed to a wrong guess. A malformed body still gets 200 (Telegram retries non-2xx, and retrying garbage helps nobody). |
| Transport (polling) | A background asyncio task in the panel's lifespan (`_telegram_polling_loop`, same pattern as the sweeper/traffic loops) long-polls `getUpdates` (30 s wait) and dispatches each update through the SAME `bot.handle_update` + `TelegramSender` the webhook uses, one DB session per update — so the two transports behave identically. The task is always started, but it only ever calls `getUpdates` while the transport is `"polling"` and the bot is configured; otherwise it is a 10 s sleeper making zero network calls, and the transport setting is re-read every round, so switching transports takes effect live with no panel restart. The offset is persisted in the settings table (`telegram_polling_offset`) after every dispatched update, so a restart resumes where the loop left off instead of re-fetching; duplicates are still ignored by `bot.py`'s `_seen_updates` for the in-flight batch. A module-level guard (`_polling_loop_active`) makes a second worker impossible, and the flag clears on shutdown so a later start is allowed. Each round records its diagnostics (last poll, last update, last error) for the settings page. The long-poll runs in a thread (`asyncio.to_thread` — it is a blocking call) so the event loop never freezes; a fast empty return (the helper returns `[]` on failure) backs off exponentially (5 s → 60 s cap); every failure is caught and logged, never the token. |
| Setup | Settings page: bot token + admin chat ID (the same fields as notifications), then pick the transport. Saving a new token registers the bot's command menu on Telegram (`setMyCommands`, from `app.bot.BOT_COMMANDS` — start / help / menu / status / users / inbounds / cancel); the same registration is available as a "Register commands" button, and a failure is reported, not fatal. Webhook: "register webhook" (`setWebhook` with the panel's public URL — domain setting + panel port + WEB_PATH + secret) and "check webhook status" (stores `getWebhookInfo`'s pending count / last error in `telegram_webhook_info`; fetched on demand, never on page render, so a dead Telegram never slows the page). Saving settings with transport=webhook also registers the webhook (set-on-save — the manual button used to be the only path, so switching to webhook left the bot silently dead; fixed in the bot polish, 2026-11-15). The settings page warns when the panel port cannot receive webhooks (no domain + a port outside 443/80/88/8443 names polling as the fix). Polling: just save — the panel calls `deleteWebhook` first (a webhook set on Telegram's side suppresses `getUpdates` delivery), and a failed removal is shown as an error instead of pretending polling is live. **Port limitation (honest): Telegram only delivers webhooks on ports 443, 80, 88 and 8443, while the installer picks a random panel port (10000–60000). Registration on any other port fails with Telegram's own error plus a warning; the fix is switching to polling — or re-running the installer with `--port 8443` (when no inbound uses TCP 8443) or a reverse proxy on 443.** |
| Diagnostics | The settings page's Telegram section shows the connection mode, the bot identity (`getMe`, fetched on demand by the "Check bot identity" button and cached in `telegram_bot_identity` — id, username, first name, never the token), the authorized chat ID, when the commands were last registered, and — for polling — the last successful poll, the last update received, the last error, and the persisted offset. |
| Auth | Only the configured admin chat ID may use the bot; updates from any other chat are ignored silently — no reply, no error, nothing that confirms the bot exists. The check runs on every command AND every callback (the dispatcher verifies the chat id before any handler runs); callback data is never trusted as authorization — it only identifies the entity to look up. |
| Dispatcher | `app/bot.py:handle_update` — never raises (a bad update is logged and dropped). Duplicate `update_id`s are ignored (Telegram redelivers). Commands: `/start` / `/menu` (main menu), `/help`, `/status`, `/users`, `/inbounds`, `/cancel`. Inline keyboards everywhere; views edit the menu message in place and fall back to sending a new message when the edit fails. An expired/invalid button tap is answered with a friendly message + the main menu, never silence and never a stack trace. Messages use HTML parse_mode (`<b>` only) with all user-controlled text escaped via `h()`; long messages are truncated HTML-safely (a cut never splits a tag or an entity — Telegram rejects malformed HTML wholesale). A persistent reply keyboard (Users / Inbounds / Status / Menu) sits below the chat; tapping a key abandons any in-progress guided flow. `/start` sends two messages by design (one message carries one markup: welcome + inline menu, then a hint + the persistent keyboard). |
| What the bot does | Users: paginated list, search (name/note substring), view (traffic/expiry/frozen/inbounds), create (guided flow: name → pick inbounds → traffic limit → expiry), edit (guided: name / traffic limit / expiry, same validation as the web edit route), freeze/unfreeze, extend expiry (+7/+30/+90 days), reset traffic, delete (with confirmation). Inbounds: paginated list (8 per page) with client counts from one grouped query, view, toggle, guided create (all fourteen protocols the panel supports, with sensible defaults: auto port, auto tag, panel-default SNI, fresh Reality keypair for VLESS, the native cores' default subnets — same stream shape and validation as the web create route via the shared `_check_new_inbound` helper), delete (with confirmation; deletes its clients too). Links: a user's share links + subscription link (the same links the panel generates; a subscription host or domain is required for share links, and a domain for the subscription URL — without one the bot says so instead of sending a broken link). Status: server status (`app.system_status`) + traffic summary (today + 14 days from `traffic_daily`) + user counts. Services: status per service + restart with confirmation for all seven cores (the installer's sudoers block, v15, grants `systemctl restart` for every unit, including `awg-quick@awg0`); the panel itself is not offered (restarting the panel from inside the bot would kill the process before it could report the result). Success is only claimed when the service is actually running afterwards; an unobservable state is reported as unverified, not as success. Backup: creates the backup ZIP (same builder as the settings-page download) and sends it as a document to the admin chat only; a ZIP over Telegram's 50 MB bot-API cap is refused honestly (the web download still works). |
| Semantics | Every state change reuses the web route's exact behavior: same validation (name format/uniqueness, limit/expiry parsing, port/tag/clash checks), same audit action names (detail marked `[telegram]`), same `rerender_configs` call — a re-render failure is reported in the reply, not hidden: the error goes in a copyable `<pre>` block, or the full log is sent as a `.log` file when it is too long for one message (systemd's \"See systemctl status ...\" hint is stripped — it is not actionable from a chat). The create flow's inbound picker defaults to all enabled inbounds (the web form's behavior) and lets the admin narrow the set; `_create_clients_for_user` takes an optional inbound filter for that. |
| Conversation state | In-memory only (`_conversations`, per chat id, 10-minute timeout) — no DB schema change. `/cancel` aborts; any other command or menu tap abandons the flow (except paging through search results, which keeps the query — it lives in the conversation state because a Persian query would not fit Telegram's 64-byte callback-data limit). |
| Language | The bot speaks Persian (no per-admin language setting exists to follow); every bot string still has an EN key (`BOT_STRING_KEYS` in `app/bot.py`; the test suite asserts fa/en parity). The setMyCommands descriptions are Persian too. |

No DB schema change: webhook state (secret, registered URL + time,
status snapshot), the transport choice (`telegram_transport`), the
polling offset + diagnostics, the cached bot identity, and the
commands-registered time all live in the existing `settings` table.

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
| Xray inbounds | gRPC Stats API on `127.0.0.1:10085` — `app/xray_stats.py` calls `QueryStats` with pattern `user>>>traffic>>>` every 60 s and diffs the cumulative counters into per-user deltas. Every rendered Xray client carries an `email` (`user-<id>@sparky.local`, see `app/xray.client_email`) so the API attributes traffic per user. | Per user. Accurate. |
| WireGuard | `wg show wg0 transfer` (bytes per peer public key → map to client). Poll every 60 s. | Per peer. Accurate. |
| sing-box inbounds | **Uncollected — no stats API.** sing-box exposes no per-user traffic API, and the panel does not run `nft list` (the `nft_text` parameter of `sync_traffic` exists for a future nftables-counter implementation, but nothing feeds it today). Shared-port sing-box inbounds cannot be attributed per user at all — the UI must say "traffic: n/a (shared port)" rather than invent a number. | None today. |
| IKEv2 | Native since v1.2.0; no per-user traffic API yet (same gap as OpenVPN/ocserv — `swanctl --list-sas` / occtl exist but are not wired into the panel yet). | — |
| Online status | Not measured as presence — the dashboard shows "Active today": users with any traffic recorded today (Xray deltas, WireGuard transfers). WireGuard's latest handshake is also available (`< 3 min ago`). sing-box has no live sessions API. The label says what the number actually is; nothing claims "online now". | Best-effort, labelled as such. |

Xray collection details (`app/xray_stats.py`, Phase 5 F1 fix): the
renderer enables the Stats API (`api` + `stats` + `policy.levels`
blocks, loopback-only `api` inbound on port 10085, and a routing
rule sending the `api` inbound to the `api` handler — the rule must
precede the geoip:private rule, which would otherwise blackhole the
loopback API traffic). The client is fail-soft: a dead API, a
timeout (5 s), or a malformed response means "no Xray update this
tick", never a crash or an invented number. Known gaps, stated
honestly: a **single-client Shadowsocks inbound** has no
`clients` list in its Xray shape, so its one user gets no
per-user stats (the whole inbound *is* that user, so nothing is
misattributed — the traffic is simply uncollected); **inbound-level**
stats (`inbound>>>…>>>traffic>>>…`) are not collected either, so
traffic cannot be broken down per inbound.

Enforcement runs in the sweeper (every 5 min): expired or over-quota
users are removed from the rendered configs (so the core drops them)
and their subscription returns 403. No live-connection killing:
existing connections are not killed mid-session (Xray `RemoveUser` /
`wg set peer remove` were considered and not implemented).

The per-client IP limit (§5.7) is stored in the client's `extra`
JSON and shown in the UI, but it is **not enforced**: none of the
sources above reports per-connection source IPs (Xray's Stats API
is per-user traffic, `wg show` has no endpoint tracking in the
panel, sing-box has no session API), so enforcing it would require
inventing data. It is recorded for a future enforcement mechanism,
not faked.

---

## 7. Security

- **Admin auth:** one admin, PBKDF2-HMAC-SHA256 hash (600,000
  iterations, per-user salt, versioned format — never plaintext,
  never in a file). Session = signed, HttpOnly, `Secure` (when TLS),
  `SameSite=Lax` cookie, 12 h expiry, server-side session record so
  logout invalidates it. Login rate-limit: 5 failed attempts →
  15 min lockout for that IP; a successful login clears the counter.
  No "remember me" in MVP.
- **CSRF:** every state-changing POST requires a per-session token
  (HMAC-SHA256 of the session token, rendered as a hidden field in
  every form and checked with a constant-time compare; the JSON API
  takes it as an `X-CSRF-Token` header). Missing/wrong token → 403,
  no state change. Excluded, deliberately: `POST /login` (no session
  exists yet) and the Telegram webhook (authenticated by its random
  path secret instead). Logout is POST-only. The token is *derived*
  from the session token rather than stored in a new column: the
  panel has no migration system, so a stored-token column would break
  login on existing installs; the security properties are identical
  (the session token is a 256-bit secret, the HMAC reveals nothing
  about it, and the token dies with the session).
- **Security headers:** every response carries
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
  (nothing embeds the panel), `Referrer-Policy: no-referrer`,
  `Strict-Transport-Security: max-age=31536000`, and a CSP
  (`default-src 'self'`, strict `script-src 'self'`; `style-src`
  keeps `'unsafe-inline'` because the dashboard chart renders widths
  inline — no inline scripts exist anywhere).
- **Session cookie behind a proxy:** the `Secure` flag follows the
  request scheme; behind a TLS-terminating reverse proxy set
  `SPARKY_TRUST_FORWARDED_PROTO=1` and the panel also honors
  `X-Forwarded-Proto: https`. Default off — an untrusted client
  could spoof the header.
- **Backups are credential bundles:** a backup ZIP contains the whole
  panel DB (admin password hash, every VPN password and private key,
  the bot token, the webhook secret). Treat backup files like
  private keys — never share them, never store them unencrypted in
  shared places. (Since Phase 2 the ZIP holds only `panel.db` +
  `meta.json`; the old plaintext `settings.json` member was dropped
  — restore never read it — but old-format backups still restore.)
  Restore swaps the DB atomically (temp file + `os.replace`) after
  backing the current DB up first.
- **Panel port:** TCP, randomised on a fresh install (free port in
  10000–60000, like other panels), plus a random secret web path (like
  3X-UI's webBasePath): the panel only answers under `/<random-path>`
  and the root returns 404. Printed in the login box,
  saved to `/root/sparky-manager-login.txt`, reprintable with `sparky-manager info`.
  Re-used on re-install; `--port` fixes it. The firewall opens only the
  panel port + the inbound ports in use.
- **Panel TLS:** installer asks for a domain (optional).
  - *Domain given:* `acme.sh` (Let's Encrypt) obtains a cert
    for the panel + the TLS inbounds; auto-renew via acme.sh's cron
    job; renewal is picked up without dropping connections (reload, not restart).
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
- **Updates:** the installer records the installed Xray + sing-box
  versions in `/opt/sparky-manager/versions.env`. `sparky-manager
  update-cores` is deliberately unimplemented (exit 2) — downloading
  and swapping core binaries is install.sh's job, with its SHA256
  verification and config validation; re-run the installer to update
  the cores. No auto-update (a bad core must never take the server
  down unattended).

---

## 8. Install script (Ubuntu / Debian)

One-liner install:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash
```

`install.sh` outline (idempotent — safe to re-run):
1. Refuse non-root; detect OS (`Ubuntu 22.04/24.04/26.04`, `Debian 12/13` only;
   anything else → clear error, not a half-install).
2. `apt-get update`; install `curl, ca-certificates, git, unzip,
   python3, python3-venv, python3-pip, wireguard, wireguard-tools,
   nftables, iproute2, openssl, cron, socat, openvpn, ocserv,
   strongswan (+ swanctl/pki/plugins)`; AmneziaWG best-effort from its
   PPA (never breaks the install).
3. Create `/opt/sparky-manager/{app,data,certs}`, `sparky-manager` system user,
   `xray`/`sing-box` config dirs; download the latest stable Xray-core +
   sing-box release tarballs (verify SHA256 from the release API when
   published), place binaries in `/usr/local/bin/`, record versions in
   `/opt/sparky-manager/versions.env`.
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
7. Write the minimal `xray`/`sing-box`/`wg0` configs (fallbacks until
   the admin creates inbounds — a fresh install seeds no inbounds);
   validate both cores; `systemctl enable --now xray sing-box
   sparky-manager`.
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
  Reprint this anytime:  sudo sparky-manager info
============================================================
```

`sparky-manager` CLI (a small wrapper, like `vpn-ui`'s menu but non-interactive
first): `sparky-manager info | status | restart | backup` (`update-cores`
exists but exits 2, deliberately unimplemented — re-run install.sh to
update the cores). There is no CLI `restore` — restore is done from the
panel's settings page. `backup` = tarball of `/opt/sparky-manager/data/`
+ both `config.json` files (DB is the source of truth, so restoring the
DB + re-rendering is enough).

---

## 9. Phases — what ships when

### Phase 1 — MVP (build this first)
- FastAPI + SQLite + Persian RTL UI; randomised-port install, printed login box.
- **Xray:** VLESS (Reality + WS/TLS + XHTTP), VMess, Trojan, Shadowsocks 2022,
  Hysteria2 (both cores ship it — the inbound's `core` field decides).
- **sing-box:** TUIC, AnyTLS, Naive, ShadowTLS (+ inner SS), Hysteria2.
- **WireGuard** native (keys, `wg0.conf`, `wg show` accounting, `.conf` + QR export).
- Users: quota, expiry, enable/disable, per-user subscription token.
- **Dual subscription:** v2rayNG base64 + sing-box JSON, UA sniffing,
  `?format=` override, `Subscription-Userinfo` header; per-user page with
  QR codes + single links; token rotation.
- Traffic: Xray gRPC + `wg show` (sing-box traffic uncollected — no stats API);
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
- Zero-downtime user add/remove (Xray gRPC `AddUser`/`RemoveUser`) — NOT done; re-render still restarts the affected core.
- Bulk operations (traffic/days/enable/delete) + Freeze. Done (expansion Phase 2).
- Clash/Mihomo YAML subscription format — NOT done.
- Optional second admin (read-only role) — NOT done.
- ~~Native IKEv2 (strongSwan) support.~~ Done in v1.2.0.
- Telegram-bot hook — only if Morteza asks.

### Phase 3 (only if asked)
- Tor obfs4 bridge (separate daemon + bridge-line distribution).
- Multi-node support.
- Reseller / billing.

### Will NOT provide (and why) — §5.6 in short
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
│   ├── __init__.py            # __version__ = "1.2.0"
│   ├── main.py                # FastAPI app, routes, startup (sweeper, syncer)
│   ├── webcommon.py           # shared web plumbing: session/auth/CSRF,
│   │                          #   settings/audit, templates/redirects (§13)
│   ├── routes/
│   │   ├── __init__.py
│   │   └── users.py           # /users* routes (APIRouter, §13)
│   ├── config.py              # settings, paths, versions.env
│   ├── db.py                  # SQLAlchemy engine/session, init
│   ├── models.py              # admins, settings, inbounds, users, clients,
│   │                          #   traffic_daily, audit_log (§4)
│   ├── auth.py                # PBKDF2, sessions, rate limit
│   ├── i18n.py                # fa (default) / en strings
│   ├── xray.py                # render /usr/local/etc/xray/config.json + validate
│   ├── xray_stats.py          # Xray gRPC Stats client (§6.4)
│   ├── singbox.py             # render /etc/sing-box/config.json + validate
│   ├── config_io.py           # shared validated-atomic config writer (§13)
│   ├── wireguard.py           # render wg0.conf, wg show parsing
│   ├── wgapply.py             # validate + apply wg/awg configs (syncconf)
│   ├── openvpn.py             # render server/client OpenVPN configs
│   ├── openconnect.py         # render ocserv config + ocpasswd
│   ├── amneziawg.py           # render awg0.conf, AWG params
│   ├── ikev2.py               # render swanctl.conf + mobileconfig (§5.4)
│   ├── links.py               # share-link builders (§6.2) + QR (qrcode)
│   ├── subscription.py        # /sub/ dual format + UA sniffing (§6.1/6.3)
│   ├── traffic.py             # sync_traffic, wg/nftables pollers (§6.4)
│   ├── telegram.py            # Bot API sender + getUpdates (§5.9)
│   ├── bot.py                 # Telegram management bot (§5.9)
│   ├── charts.py              # traffic chart SVG + daily series
│   ├── backup.py              # backup ZIP / restore (§5.8)
│   ├── system_status.py       # server status collector (§12)
│   ├── panel_log.py           # rotating file log + redaction
│   ├── panel_cli.py           # `sparky-manager info/status/restart/update-cores/backup`
│   ├── templates/             # Jinja2, RTL, Persian-first
│   │   ├── base.html  dashboard.html  inbounds.html  inbound_edit.html
│   │   ├── users.html  user_detail.html  user_edit.html
│   │   ├── settings.html  login.html  logs.html  error.html
│   └── static/
│       ├── style.css          # one hand-written stylesheet, no build step
│       ├── app.js             # small vanilla JS (copy link, show QR, confirm dialogs)
│       └── fonts/             # bundled Vazirmatn woff2 (offline-first)
├── scripts/
│   ├── render_configs.py      # render both cores from DB (used by installer + CLI)
│   ├── ovpn-auth.py           # OpenVPN username/password auth helper
│   └── backup.sh
├── systemd/
│   ├── sparky-manager.service
│   ├── xray.service           # or use the cores' shipped units
│   └── sing-box.service
├── tests/                     # 1152 tests (conftest.py: seeded DB + CSRF client)
│   ├── test_links.py          # link round-trips for all 9 schemes
│   ├── test_render.py         # golden configs → xray -test / sing-box check
│   ├── test_subscription.py   # v2rayNG + sing-box feeds parse cleanly
│   ├── test_users.py          # quota/expiry/enable rules (§4)
│   ├── test_security_phase2.py / test_telegram_phase3.py /
│   │   test_ui_phase4.py      # per-phase upgrade tests
│   ├── test_xray_stats.py / test_rerender_lock.py /
│   │   test_config_io.py      # Phase 5 tests
│   └── test_phase6_*.py / test_links.py
│                              # Phase 6: security sweep, loops, perf, UI
└── docs/
    ├── PORTS.md               # §3 port plan
    ├── ZEDSECURE.md           # per-protocol import checklist for ZedSecure
    ├── MANUAL_UI_CHECKLIST.md # human visual/mobile check (Phase 6, §14)
    └── PROFESSIONAL_UPGRADE_REPORT.md  # the upgrade report (Phase 7)
```

---

## 11. Open questions (answers that would change the design)

Written 2026-11-11; all but Q5 are answered now (noted inline).

1. **Domain?** Do you have a domain for this server? It decides whether
   the TLS inbounds (WS/TLS, TUIC, AnyTLS, Naive, ShadowTLS, Hysteria2)
   and the panel itself get real Let's Encrypt certs, or whether Phase 1
   ships Reality + WireGuard only (no domain needed) and TLS inbounds wait.
   *Answered: no domain required — the panel works on a bare IP and the
   installer obtains a free Let's Encrypt IP certificate when TCP 80 is
   open; a domain entered later unlocks TLS inbounds as an option.*
2. **Server IP / host?** Needed for the default subscription host and the
   Reality `dest`. Also: is strongSwan/IKEv2 running on the *same* server?
   (If yes, Phase 1 must reserve UDP 500/4500 and avoid port clashes.)
   *Answered: same server; IKEv2 shipped in v1.2.0 with UDP 500/4500
   reserved.*
3. **Hysteria2 core:** prefer Xray (if pinned Xray ≥ 26.1 ships a native
   hysteria inbound) or sing-box? Affects which core owns UDP/443 and
   whether Hysteria2 gets accurate per-user stats (Xray gRPC) or
   nftables-port accounting (sing-box).
   *Answered: both cores ship Hysteria2 — the inbound's `core` field
   decides. Xray-served Hysteria2 gets per-user gRPC stats; sing-box
   traffic is uncollected (§6.4).*
4. **AmneziaWG now or later?** It needs a kernel-module build that fails
   on some hosts. Phase 2 (recommended) or attempt in Phase 1 with a
   build check that disables it cleanly?
   *Answered: Phase 2 — shipped in v1.2.0, gated on the kernel module.*
5. **ZedSecure test device?** Can you install ZedSecure on your phone and
   import the two subscription feeds (v2rayNG + sing-box) to verify them
   against the real app? This is the single most valuable test; link
   formats (especially Naive `naive+https://` and ShadowTLS) vary between
   clients and must be checked against the real importer, not the spec.
   *Still open — the feeds are verified by parser tests only, not
   against the real ZedSecure importer.*
6. **OpenVPN / OpenConnect in Phase 1?** The brief says "ALL methods".
   They are real daemons with their own PKI; putting them in Phase 1
   roughly doubles the installer's scope. Confirm Phase 2 is acceptable,
   or say which of the two matters more.
   *Answered: Phase 2 — both shipped in v1.2.0.*
7. **Public repo?** Should sparky-manager be public from day one, or
   private until Phase 1 works?
   (Affects whether the install URL can be the public raw GitHub URL.)
   *Answered: public from day one (MIT).*

---

## 12. Web UI (professional upgrade, Phase 4, 2026-11-15)

The panel is a server-rendered FastAPI/Jinja2 app with one stylesheet
(`app/static/style.css`), one small script (`app/static/app.js`), and a
bundled Vazirmatn font. No CDN, no external fonts, no framework JS —
the UI works offline and with JS disabled (progressive enhancement).

- **Design tokens.** The stylesheet's `:root` block is the token set:
  solid charcoal surfaces (`--surface-solid*`), a restrained violet
  accent + sky secondary, documented spacing/type/border/shadow/radius
  scales. Glassmorphism is gone: no `backdrop-filter` on cards or
  topbars, soft shadows only. The only remaining translucent tints are
  small accents (chips, badges, stat icons). Direction-dependent rules
  use CSS logical properties (`margin-inline-start`, `inset-inline-end`,
  …) so Persian RTL and English LTR both render correctly.
- **Navigation.** `base.html` groups the sidebar: Overview (Dashboard),
  Management (Inbounds, Users), Monitoring (Logs), System (Settings).
  There is no Network & Services or Integrations group — no such pages
  exist, and the nav never links to a page that doesn't. Desktop:
  collapsible sidebar (icons only, persisted in `localStorage`).
  Mobile (≤960 px): the sidebar becomes a slide-in drawer, opened by a
  hamburger via `:target` (works without JS; `app.js` adds overlay /
  Escape closing). The old bottom nav was removed.
- **Dashboard.** The server-status block (`app/system_status`) moved
  onto the dashboard as well as Settings — same collector, no
  duplication. A failed collection renders "unavailable", never zero.
  The "Online (approx.)" stat was relabeled "Active today": it counts
  users with any traffic today, which is not presence, and the old
  label said otherwise. The "LIVE" dots were removed for the same
  reason — nothing on the page is live.
- **Users list.** Server-side search (name/note substring), status
  filter (enabled/disabled/frozen/expired), sort (created/name/expiry/
  traffic), pagination (25/page) as GET query params — bookmarkable.
  Invalid values fall back to defaults, never 500. Filtering/sorting
  runs in Python over the user list: the frozen filter needs per-client
  state with no clean SQL expression, and an admin panel holds hundreds
  of users at most. Bulk actions still act on selected IDs only; the
  page states that selection is page-local.
- **Inbounds list.** Client counts per inbound (one grouped query) and
  card-table markup on narrow screens; the client-side search/filter
  and protocol-specific create/edit forms are unchanged.
- **Settings.** Tabbed into General / Telegram / Security / Backup /
  Services / Advanced. There is deliberately no Network tab: the only
  network-ish settings (domain, subscription host, Reality SNI) live in
  General, and a Network tab would duplicate them. Tabs are real links
  (`?section=…`); `app.js` switches them in place, the server renders
  the active panel without JS. Every settings POST carries its `section`
  and redirects back to it. `POST /settings` now accepts partial
  updates: each tab posts only its own fields, and absent fields are
  left untouched (previously a post cleared any field it didn't send).
  All POST forms keep their CSRF token (§7).
- **Tables.** Wide tables use the `.table-cards` pattern: below 640 px
  they stack into cards, each cell labeled from its `data-label`
  attribute. Tables without that class keep horizontal scroll.
- **Verification limit.** No browser or screenshot tooling exists in
  this environment, so the responsive/drawer behavior is verified by
  rendered-HTML and route tests only (`tests/test_ui_phase4.py`,
  `tests/test_phase6_ui.py`); visual layout still needs a manual
  check — the checklist is `docs/MANUAL_UI_CHECKLIST.md` (§14).

---

## 13. Architecture + reliability (professional upgrade, Phase 5, 2026-11-15)

- **Xray traffic collection (§6.4).** The sync loop now feeds real
  Xray per-user traffic into `sync_traffic` via a hand-rolled gRPC
  Stats client (`app/xray_stats.py`, `grpcio`); the renderer enables
  the Stats API on 127.0.0.1:10085 and tags every client with an
  email (`user-<id>@sparky.local`). sing-box traffic remains
  uncollected (no stats API) — documented, not faked.
- **Dependency pinning.** `requirements.txt` pins every dependency to
  exact versions (the versions proven in the dev venv);
  `grpcio==1.75.1` (first release with Python 3.14 wheels);
  `argon2-cffi` removed (auth is stdlib PBKDF2). CI tests Python
  3.11 / 3.12 / 3.14 (the server runs 3.14);
  `app/openconnect.py` guards the removed `crypt` module (the
  `openssl passwd` fallback is the live path on 3.13+).
- **main.py split (first increment).** `main.py` was 6,262 lines;
  after the split it was ~4,550 (4,546 at the end of Phase 7, with the
  docs-pages flags and dead-import cleanup).
  The i18n dicts moved to `app/i18n.py`, the shared web plumbing
  (session/auth/CSRF, settings/audit, template/redirect helpers,
  link builders, client credential/address helpers, Telegram
  notifications, traffic charts) to `app/webcommon.py`, and the
  `/users*` routes to `app/routes/users.py` (an `APIRouter`, mounted
  in the same position so route precedence is unchanged). `main.py`
  re-exports every moved name, so `main_mod.<name>` references
  (remaining routes, bot, tests) keep working. Two lazy seams remain
  in the router (`rerender_configs`, `_file_export_urls` — both live
  in `main` until their owners split); they read `main`'s attribute
  at call time, so tests patching `main_mod.rerender_configs` still
  take effect.
- **Remaining split plan (not started).** Next increments, in order:
  settings routes (`/settings*`, backup/restore, logs), inbounds
  routes (`/inbounds*`), then `rerender_configs` + the config-apply
  helpers last (most entangled: every route and the sweeper call
  them). Each increment keeps route paths identical and runs the
  full suite after the move.
- **Re-render lock.** `rerender_configs()` serializes on a
  `threading.RLock` (`_RERENDER_LOCK`): the expiry sweeper, admin
  POSTs (FastAPI threadpool) and the Telegram bot polling thread all
  call it. Deliberate deviation from the spec's `asyncio.Lock`:
  `rerender_configs` is a SYNC function called from multiple
  threads — an `asyncio.Lock` cannot be acquired from sync code and
  cannot serialize threads. RLock is re-entrant, so a render that
  itself triggers a re-render cannot deadlock.
- **Defensive-import cleanup.** The try/except sibling-import pattern
  with `None` fallbacks ("not written yet") is gone: every sibling
  module is a plain import, and a failed import fails loudly at
  startup instead of degrading silently into a half-working panel.
  The ~90 `None` checks that guarded the fallbacks are removed; the
  `_user_usable` / `_client_usable` wrappers collapsed to direct
  `app.models` calls (`user_is_usable` / `client_is_usable`).
  Genuinely optional behaviour (a missing binary, an unconfigured
  bot) is still handled at the call site, not at import time.
- **Validated config writes.** The near-identical
  `write_and_validate` copies in `xray.py` / `singbox.py` are one
  shared helper now (`app/config_io.write_and_validate_config`:
  temp file → structural validation → binary check → atomic
  rename); both modules keep thin wrappers with identical
  signatures and error messages.
- **Subprocess timeouts (audit).** Every subprocess call in
  request / re-render paths already carried an explicit timeout
  (verified 2026-11-15: `_run_privileged` 30 s default, `wg show
  transfer` 10 s, `openssl passwd` 15 s, `ocserv -t` 30 s, Xray /
  sing-box validation 10 s, systemctl queries 5–10 s) — no change
  needed.
- **Known limitation: re-render blocks the request.** Re-rendering
  runs synchronously inside the POST that triggered it (the reply
  reports its result), so a slow core restart delays the response.
  It is NOT moved to a background task — that needs a UX decision
  (progress reporting), not a silent behaviour change.

---

## 14. Testing + verification (professional upgrade, Phase 6, 2026-11-15)

Phase 6 verified the whole upgrade with teeth: 852 → **954 tests**,
all passing (0 failed, 0 skipped). New suites:
`tests/test_phase6_security.py` (route-table sweep + unauthenticated
sweep + session expiry + malicious input), `tests/test_phase6_loops.py`
(background-loop end-to-end tests), `tests/test_phase6_perf.py`
(N+1 regression tests with a SQL statement counter),
`tests/test_phase6_ui.py` (every page renders, every link/asset
resolves, every form carries a CSRF token, every i18n key exists in
both languages), plus `tests/test_links.py` (every href/src in every
template resolves).

- **N+1 fixes (audit Q6), measured with a statement counter.**
  Dashboard client counts: one grouped COUNT query
  (`webcommon.clients_count_by_inbound`) instead of one COUNT per
  inbound (11 seeded inbounds used to mean 11 queries); the
  dashboard's total statement count is now identical with 11 and
  with 21 inbounds. Dashboard user loads: one full load instead of
  three (total, active count and traffic sum all derive from it).
  Users page: one full load (the expired-ids set derives from the
  same load instead of re-querying the table). Traffic chart: one
  query with the 14-day window filtered at the DB level
  (`traffic_daily.date >= …`) instead of loading all history and
  discarding it in Python (60 days of history still yields a
  14-day total). Static assets are bounded by test: style.css
  ≤ 100 KB, app.js ≤ 50 KB, bundled fonts ≤ 500 KB total.
- **Installer renderer dropped `user_id` (Phase 6 finding).**
  `scripts/render_configs.py` built the client dicts without
  `user_id`, so the Xray renderer could not build the Stats API
  email (`user-<id>@sparky.local`) for installer-rendered configs —
  Xray could not attribute traffic per user on the installer path.
  Fixed: the client dict now carries `user_id`.
- **Privileged-command argv was logged raw (Phase 6 finding).**
  `_run_privileged`'s docstring promised every invocation is logged
  through the redactor, but only the output tail was redacted — the
  argv itself (which can contain config paths and, in future, secrets)
  was logged verbatim. Fixed: argv goes through `_redact` on both
  the success and failure paths. No current call passes secrets in
  argv; the fix is defense-in-depth.
- **Security sweep (tests, not just review).** Route-table
  introspection asserts every POST route carries `require_csrf`
  (except the two documented exemptions) and every GET route is
  either public-by-design or guarded by `require_admin`; an
  unauthenticated sweep hits every admin page and POST and proves
  the redirect AND that no state changed; expired and forged
  sessions are rejected; SQL-injection strings and XSS payloads in
  text fields are stored safely and rendered escaped; path-traversal
  and command-injection attempts in restore/upload fields are
  rejected; the Telegram stranger tests (Phase 3) cover the new
  service-restart and backup callbacks.
- **Loop tests.** The traffic sync loop end-to-end: mocked Xray
  stats reach `traffic_daily`, limits trigger, a malformed stats
  response is ignored, and a dead API leaves the DB untouched; the
  sweeper survives a render failure.
- **Manual UI checklist.** Automation verifies the HTML, not how it
  looks — there is no browser or screenshot tooling in the build
  environment. `docs/MANUAL_UI_CHECKLIST.md` is the human half:
  work through it on a real deployment (desktop + phone, portrait
  and landscape) before calling the upgrade done.
- **Auto-generated API docs (Phase 6 LOW finding, fixed in Phase 7).**
  `/docs`, `/redoc` and `/openapi.json` returned 200
  unauthenticated — and with a secret web path set, the ROOT app
  served them at the root, outside the web path. The panel is a
  private admin tool: the docs pages are disabled on both FastAPI
  constructors (`docs_url=None, redoc_url=None, openapi_url=None`),
  with tests asserting 404 on the panel app and on a web-path-mounted
  root app. The panel's own `/api` endpoints are unaffected (still
  401 unauthenticated).

## 15. Post-upgrade fixes + debug pass (2026-11-15)

After the professional upgrade landed on the live server, Morteza
found live issues and asked for a complete check of the project.
`main.py` is 4,922 lines at this point (4,546 at the end of Phase 7;
the post-upgrade batches added routes, diagnostics, the webhook
set-on-save path, the Cores page and the bot UX work). The full suite
is 1152 tests; i18n parity is 526 keys each.

- **Fix batch (evening, after the server upgrade).** The language
  toggle reverted on navigation (the `lang` cookie was only set on
  redirects) — a middleware now sets it on every response carrying a
  valid `?lang=`; the installer reuses the saved Reality SNI from
  `panel.env` on re-install (no prompt, like the port/web-path);
  the login box lost its protocol lists, logs line and subscriptions
  line; the add-inbound form hides behind a `<details>` (the page is
  empty until the admin asks to add); the footer dropped "— فاز ۱".
- **Bot polish (evening).** The webhook was kept and fixed properly:
  `set_webhook` runs on every settings save with transport=webhook
  (it used to be reachable only from the manual button, so switching
  to webhook left the bot silently dead), the settings page warns
  when the panel port cannot receive webhooks, and `getWebhookInfo`
  diagnostics are cached (5 min). Menus use HTML parse_mode with
  `h()` escaping, regrouped inline keyboards (2 per row) and a
  persistent reply keyboard (see §8).
- **Debug pass (evening).** Full-suite run + static checks + a
  page-by-page live-behavior review + an installer end-to-end read.
  Fixed: the re-install password trap (see below); the uninstaller
  leaving VPN services running (see §15.3 — live incident, stale
  ocserv held TCP 443 and broke a fresh install); stale deployed
  files (the installer now removes `app/`/`scripts/`/`systemd/`
  before copying — `cp -a` never deletes); the uninstaller stopping
  services before its backup tar (see WAL); `NAME_RE` capped at 64
  chars (web + bot + API agree); HTML-safe truncation of bot
  messages; the bot inbound list paginated (8/page) with one grouped
  client-count query instead of one COUNT per inbound; the logs page
  limit label; language toggles preserving query params (via
  `request.url.include_query_params`) plus a toggle on the login
  page; ~30 dead imports removed. Verified clean: no automatic
  deletion path anywhere (all `db.delete` sites are explicit admin
  actions; the expiry sweeper only re-renders), i18n parity (488
  keys each), CSRF on 26 of 28 POST routes (the 2 documented
  exemptions), no dead module-level functions. Found but NOT fixed:
  the installer re-prompts the domain with an empty default on
  re-install (a domain cert would be regenerated with CN=IP —
  recommend defaulting from the existing cert's DNS SAN); no
  pre-start port-conflict check before the cores start (see §15.3);
  IPv6 literals confuse the webhook port check (`":" in domain`);
  user notes have no length cap.
  Full report: kept in the project notes (not shipped in the repo).
- **Menu + bot UX polish (evening).** The bot's guided inbound
  creation now covers all fourteen protocols the web panel
  supports (`BOT_CREATE_PROTOCOLS` in `app/bot.py`: Xray hysteria2,
  sing-box tuic/anytls/naive/shadowtls, and the native
  amneziawg/openvpn/openconnect/ikev2), each created with the web
  create route's defaults (subnets, fresh AmneziaWG params, TLS
  SNI where meaningful) and the same `_check_new_inbound`
  validation — including the transport rule the bot used to get
  wrong (it forced tcp, so a bot-created Hysteria2 falsely clashed
  with VLESS on TCP 443; the transport is now the protocol
  default, like the web route). Every guided bot flow has
  Skip/Back buttons (`c:skip` / `c:back`, step-driven in
  `_on_create_callback`): Telegram cannot send an empty message,
  so every optional step has a visible Skip button that submits
  the default, and no bot prompt says "leave empty" anymore. The
  users list gains a Clear-search button (the filter used to be
  unescapable from the results). Web: the Users add form collapses
  behind `<details>` like the inbounds form (the debug pass had
  deliberately left it visible; Morteza then asked for it); the
  mobile filter-search layout bug is fixed (the 220px flex-basis
  became a 220px-tall empty area in column direction); the logs
  page filter button says Apply and rotated files are labelled
  Archived (not Disabled); the dashboard empty states link to the
  add forms; the settings page shows the webhook live status once
  (diagnostics), and the Telegram action buttons sit in two
  wrapping rows. The full suite is 1101 tests; i18n parity is 495
  keys each.
- **Cores page + copyable bot logs + OpenVPN 2.6 fix (evening).**
  A dedicated Cores page (`/cores`, System group in the nav): one
  card per core (Xray, sing-box, WireGuard, AmneziaWG, OpenVPN,
  OpenConnect, IKEv2) with its live state (from
  `app.system_status` — unobservable is \"unknown\", never
  \"stopped\"), Start / Stop / Restart buttons matched to the state
  (running → Stop + Restart, stopped → Start, unknown → all three),
  the enabled-inbound count or an \"on demand\" hint when no enabled
  inbound uses the core, and a View-log action showing the journal
  tail on demand (`_journal_tail`, already sudoers-covered for all
  8 units). Every action re-checks the actual state afterwards and
  reports success / mismatch / unverified honestly; a failure
  redirects to the page with that core's log already expanded (the
  flash itself stays short — it travels in the URL). All actions
  are CSRF-protected POSTs, audited as `service.start` /
  `service.stop` / `service.restart`. The sudoers block is now v15:
  `start` + `stop` for every managed unit and `restart
  awg-quick@awg0` (exact unit names, no wildcards in the new rules)
  — so the bot's services view offers AmneziaWG restart too (it
  used to refuse it, and the \"cannot restart\" note is gone). The
  panel itself is deliberately not start/stop-managed from the
  page. Bot failure logs are copyable now: the cleaned error goes
  in a `<pre>` block when it fits (1500 chars), otherwise the full
  log is sent as a `.log` file with a short preview note; systemd's
  \"See systemctl status ...\" hint is stripped from bot-facing
  errors (not actionable from a chat), and no cut ever lands
  mid-line. And the OpenVPN crash-loop is fixed (see §15.4).
- **Add user to any inbound + detach (evening).** The web UI had no
  way to add an EXISTING user to another inbound: new users get one
  client per enabled inbound, so the gap was only inbounds created
  after the user (the live case: user "Me" predated the OpenVPN
  inbound). The user detail page now has an add-to-inbound picker
  (enabled inbounds the user has no client on, any protocol,
  including shared ones) and a per-client Detach button with a
  confirmation step. Adding reuses `_create_clients_for_user`
  restricted to the one inbound — fresh credentials per protocol,
  WireGuard/AmneziaWG address from the inbound's subnet (the pool
  is pre-checked, like the move flow). Both actions are
  CSRF-protected POSTs, audited as `user.add_inbound` /
  `user.detach_inbound`, and re-render configs afterwards. One
  client per (user, inbound) stays — the UniqueConstraint is
  untouched, no migration. Detaching the LAST client is allowed:
  zero-client users are already a normal state (fresh installs
  start with no inbounds; deleting an inbound can leave users at
  zero), both pages render it, and add-to-inbound makes it
  reversible — but the confirm dialog carries a distinct warning
  when it is the last client. Edit-page nits fixed alongside: the
  move dropdown explains itself when no targets exist, and the
  IP-limit / freeze / move hints now sit under their fields in the
  table instead of detached at the bottom of the card. Bot
  add-to-inbound is deliberately out of scope (web only).

### 15.1 The admin password on re-install (installer trap, fixed)

The installer can only SET the admin password on a fresh install
(the panel seeds its admin from `SPARKY_ADMIN_PASSWORD` when no
admin exists). Before this fix, a re-install still prompted for a
password — and a typed password was stored in `install.env` and
printed in the login box while the DB kept the old one, overwriting
the only record of the working password. Now the prompt is skipped
on re-install (`install.env` exists), `--admin-password` on a
re-install is ignored with a loud warning, and the login box prints
the stored password with an "(unchanged by this install…)" note —
or "(unchanged — the installer cannot show it…)" when no stored
password exists. Caveat: a password changed in the panel (Settings
→ Security) is NOT written back to `install.env` (the panel user
cannot write that file), so after an in-panel change the login box
prints the stale password with the note; the panel password is the
current one.

### 15.2 SQLite WAL — what is and is not a backup

`panel.db` runs in WAL mode: the main file can be 4 KB while all
live data sits in a 523 KB `panel.db-wal`. A plain `cp panel.db`
copies only the main file — no tables, useless as a backup (this
happened on the live server: `/root/panel.db.bak-2026-11-15`).
Rules:

- **Valid backups:** the panel's Settings → Backup (SQLite backup
  API — a WAL-safe standalone snapshot), or a copy of the WHOLE
  `data/` dir (main file + `-wal` + `-shm`) taken while the panel
  is stopped.
- **Panel backup** (`create_backup_zip`) uses the SQLite backup API.
  **Restore** (`swap_db_file`) removes the old `-wal`/`-shm`
  sidecars before the atomic `os.replace`, after disposing the
  engine; validation checkpoints bare DB uploads and rejects a
  table-less file (so a lone 4 KB copy fails validation instead of
  corrupting anything).
- **Uninstaller:** stops the services BEFORE the backup tar, so the
  panel checkpoints the WAL on shutdown and the tarball holds a
  clean database.
- **`scripts/backup.sh`** (and `sparky-manager backup`) tar the
  live data dir while the panel runs: crash-consistent (SQLite
  replays the WAL on open), but a torn WAL-frame read can silently
  lose the last seconds of transactions. For a guaranteed-clean
  snapshot, use the panel's Settings → Backup.
- **Checkpointing:** no periodic checkpoint is needed — SQLite
  auto-checkpoints at 1,000 WAL pages and the panel's write volume
  is tiny. An explicit engine dispose on shutdown is a recommended
  small improvement (clean shutdowns checkpoint the WAL), not a
  behavior change made here.

### 15.3 Uninstaller left VPN services running (live incident, fixed)

`uninstall_panel()` stopped and disabled only sparky-manager, xray
and sing-box — never ocserv, openvpn-server@sparky-manager or
strongswan, and it brought down wg0 without disabling its unit
(awg0 was untouched entirely). On 2026-11-15 a wipe + fresh install
failed verification: a stale `ocserv-main` from the early-morning
install still held TCP 443 with an old 443 config (the current
minimal default is 4433), while the fresh minimal Xray config binds
VLESS+Reality on 443. It only broke then because the old xray had no
443 listener (all inbounds deleted). Two compounding details: the
uninstaller removed none of the panel-managed v12 configs
(`ocserv.conf`, `ocpasswd`, `openvpn/server/sparky-manager.conf`,
`swanctl.conf`, `awg0.conf`), and the installer writes minimal
versions only when the file does NOT exist — so the stale 443
config would have been started again by the fresh install's
`enable --now` loop (xray starts first, so it would have won 443
and the install would have passed — but ocserv would stay failed,
and on a reboot it could win 443 before xray).

Fix: the uninstaller now stops + disables all eight units
(sparky-manager, xray, sing-box, ocserv,
openvpn-server@sparky-manager, strongswan, wg-quick@wg0,
awg-quick@awg0), brings down both WireGuard interfaces, and removes
the five panel-managed v12 config files. Safe because the panel
restarts these services on demand with freshly rendered configs —
and only when an enabled inbound of that type exists
(`ocserv_inbounds` is filtered on `i.enabled`, main.py:587) —
and `systemctl restart` starts a stopped unit even when disabled.

**Not implemented: a pre-start port-conflict check.** Before
`systemctl enable --now xray sing-box sparky-manager`, the installer
could check the ports the rendered configs will bind (panel port,
Xray TCP 443/8388, sing-box UDP 443, WireGuard UDP 51820) with
`ss -tlnp`/`ss -ulnp` and fail fast naming the holder. Deliberately
left as a recommendation: on a re-install the panel's own services
already hold those ports, so the check must exempt the panel's own
PIDs (or run after stopping them), and the `ss` parsing + UDP +
IPv6 edge cases make it a feature, not a one-liner. The uninstall
fix above closes the reported failure mode.

### 15.4 OpenVPN 2.6 removed `client-cert-not-required` (live incident, fixed)

On 2026-11-15 the bot created an OpenVPN inbound and the service
restart failed; the journal showed `openvpn: REMOVED OPTION:
--client-cert-not-required, use '--verify-client-cert none'
instead` followed by `Exiting due to fatal error`, and systemd
crash-looped the unit (restart counter 25). The option was removed
in OpenVPN 2.6 — Ubuntu 26.04 ships 2.6.x — and both the panel
renderer (`app/openvpn.py`) and the installer's minimal config
carried it. The docstring even claimed the old option was \"still
accepted\" in 2.6; it is not.

Fix: both configs now use `verify-client-cert none`, which exists
since OpenVPN 2.5 and works on 22.04/24.04/26.04 alike. A grep
confirmed no other 2.6-removed option (`tls-remote`,
`ifconfig-pool-linear`, `ncp-disable`, `key-method`,
`ns-cert-type`) appears anywhere in the tree. Regression test: the
rendered server config must contain `verify-client-cert none` and
none of the removed options, and the installer's minimal config
gets the same assertions. Immediate relief on the live server was
`systemctl stop openvpn-server@sparky-manager` (ends the loop);
the fix reaches the server with the next installer re-run, which
re-renders the config.

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
