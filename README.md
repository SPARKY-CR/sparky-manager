# sparky-manager

A multi-core VPN panel built from scratch: **Xray-core + sing-box + native
WireGuard**, managed through one Persian-first web UI. It is made for the
[ZedSecure](https://github.com/CluvexStudio/ZedSecure) client — the panel
serves everything ZedSecure can connect to that needs a server, in the two
subscription formats ZedSecure understands (v2rayNG links and sing-box
JSON), plus QR codes.

Public project, MIT licensed. **Built from scratch** — no fork, no copied
code from 3X-UI, vpn-ui, Marzban, or any other panel.

> **Status: professional upgrade complete on branch
> `upgrade/professional`** (base: `main` at v1.2.0). 1269 tests pass;
> the rendered Xray config passes `xray run -test` against real
> Xray 26.11.9 and the rendered sing-box config passes `sing-box
> check` against real sing-box 1.14.4. The panel is installed and
> running on a real server. The upgrade adds CSRF protection and
> security headers, a reworked Telegram bot (polling by default),
> a redesigned UI, real Xray traffic collection via gRPC, a first
> split of the 6,262-line `main.py`, pinned dependencies, and CI
> on Python 3.11/3.12/3.14 — see
> [docs/PROFESSIONAL_UPGRADE_REPORT.md](docs/PROFESSIONAL_UPGRADE_REPORT.md)
> for the full report. Visual/mobile layout still needs the manual
> check in [docs/MANUAL_UI_CHECKLIST.md](docs/MANUAL_UI_CHECKLIST.md).

## What it does

- **Login like other panels:** a fresh install picks a **random panel
  port** (10000–60000) and a random admin password. The installer
  prints one big login box with the full URL, username and password,
  and saves it to `/root/sparky-manager-login.txt`;
  `sudo sparky-manager info` reprints it. Fix the port with `--port`.
- **No domain needed.** It works with a bare server IP. The recommended
  first pair — **VLESS + Reality (TCP 443)** and **Hysteria2 (UDP 443)**,
  plus **WireGuard (UDP 51820)** — needs no domain and no certificate.
  With no domain the installer tries for a trusted Let's Encrypt
  certificate for the bare public IP instead (the same trick 3x-ui
  uses — free since 2026, valid ~6 days, auto-renewed; needs TCP 80
  open). If that fails it falls back to a self-signed certificate
  (your browser will warn; the login box prints the fingerprint so
  you can check it). If you later add a domain in the panel settings,
  TLS inbounds and a 90-day Let's Encrypt certificate become
  available as an option — never a requirement.
- **Two cores, side by side:** Xray-core serves VLESS, VMess, Trojan,
  Shadowsocks 2022, and Hysteria2; sing-box serves TUIC, AnyTLS, Naive,
  and ShadowTLS. WireGuard runs natively (`wg0`).
- **Dual subscriptions:** every user gets a tokenised subscription in
  both v2rayNG (base64 links) and sing-box JSON formats, picked by
  User-Agent or `?format=`, plus a human page with QR codes.
- **Users:** quota, expiry, enable/disable, per-user subscription token
  (rotatable). Traffic from Xray gRPC and `wg show`; sing-box traffic
  is not collected (sing-box has no per-user stats API — the UI shows
  "n/a" rather than an invented number).

## Install

Ubuntu 22.04/24.04/26.04 or Debian 12/13 only, as root:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash
```

Unattended install with explicit options:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash -s -- --yes --reality-sni www.microsoft.com
```

The installer is idempotent (safe to re-run) and verifies itself before
finishing: the panel must answer `200` on `/health` and `xray` /
`sing-box` must be active, or it prints the last 20 log lines and exits
non-zero. It downloads the latest stable Xray-core and sing-box from
their official GitHub releases and verifies SHA256 when the release
publishes a digest. A re-run reuses the existing panel port, web path,
admin password and keys, keeps the database
(`/opt/sparky-manager/data/panel.db`) untouched, re-installs the pinned
Python dependencies, and heals certificate file permissions an older
installer may have left unreadable.

## Upgrade (from main / v1.2.0 to this branch)

The one-liner above installs `main`. To deploy this upgrade branch on
a server that already runs the panel:

```bash
git clone -b upgrade/professional --depth 1 https://github.com/SPARKY-CR/sparky-manager.git
cd sparky-manager
sudo bash install.sh
```

The installer copies the new code over `/opt/sparky-manager`, keeps
your database, users, inbounds, port, web path and admin password,
and verifies the panel answers before finishing. No database migration
is needed (the upgrade adds no schema change — new state lives in the
existing `settings` table). After upgrading:

1. Set up the Telegram bot in the panel settings if you use it
   (BotFather token + your chat ID; polling is the default — see
   below).
2. Work through the manual UI checklist
   ([docs/MANUAL_UI_CHECKLIST.md](docs/MANUAL_UI_CHECKLIST.md)) on a
   desktop browser and a phone — visual layout is not covered by the
   automated tests.
3. Take a fresh backup (Settings → Backup) once the upgraded panel is
   running.

> The branch is not merged into `main` yet. Do not deploy it by
> checking out `main` — `main` still holds v1.2.0.

## Login

Open the URL from the login box (`https://<your-server-IP>:<port>`), username `admin`, password from
the login box. If you use a domain, `https://<domain>:<port>`.

```bash
sudo sparky-manager info      # reprint the login box
sudo sparky-manager status    # service status
sudo sparky-manager restart   # restart panel + cores
sudo sparky-manager backup    # backup to /root/sparky-manager-backup-<date>.tar.gz
```

## Protocols (no domain needed)

A fresh install creates no inbounds — add them from the panel
(Inbounds → Add inbound). The table lists the recommended ports:

| Protocol | Port | Core |
|---|---|---|
| VLESS + Reality | TCP 443 | Xray |
| Hysteria2 | UDP 443 | Xray or sing-box (per-inbound core choice) |
| Shadowsocks 2022 | TCP 8388 | Xray |
| WireGuard | UDP 51820 | native |

With a domain + certificate, the panel can also serve TUIC (8443),
AnyTLS (8444), Naive (8445), and ShadowTLS (8446) — see
[docs/PORTS.md](docs/PORTS.md). Since v1.2.0 it also runs four more
protocols (create them as inbounds; no domain needed): OpenVPN
(UDP 1194, `.ovpn` file), OpenConnect (TCP+UDP 4433, AnyConnect
profile), AmneziaWG (UDP 51821, `vpn://` link — needs the kernel
module), and IKEv2 (UDP 500+4500, `.mobileconfig`). The ZedSecure
import checklist is in [docs/ZEDSECURE.md](docs/ZEDSECURE.md).

Every inbound is editable after creation (Inbounds → ✏️ Edit):
transport and security (TLS/Reality, WS/gRPC/XHTTP/HTTPUpgrade,
sniffing, fallbacks), WireGuard/AmneziaWG subnet/MTU/DNS and
obfuscation parameters, OpenVPN/OpenConnect/IKEv2 subnet/DNS —
with regenerate actions for Reality keys, AmneziaWG parameters,
and the WG/AWG server keypair. Share links and subscriptions
follow the edited settings automatically.

Every user is editable too (Users → user → Edit): name, note,
traffic limit, and expiry as a calendar date (UTC, valid through
the end of that day). Per client: the XTLS flow for VLESS clients
(Reality inbounds need a Vision flow; a stale Vision value on a
plain-TCP inbound is cleared on save), a concurrent-IP limit, a
freeze switch, and a move to another inbound of the same protocol
(WireGuard/AmneziaWG get a fresh address from the target subnet;
traffic history is kept). A frozen client cannot connect but keeps
its config and history — unfreezing restores it exactly. The users
list supports bulk enable/disable/delete, traffic reset (the daily
history is kept), and expiry extension. The IP limit is stored and
shown but not enforced: the panel cannot see connected IPs, so it
does not pretend to limit them.

The settings page covers the panel itself: change the admin password
in-panel (other sessions are signed out; the installer's login file
still holds the old password), Telegram notifications (bot token +
chat ID, with a test button — notified on user creation, users
expiring within 24h, and config re-render failures), backup/restore
(download a ZIP holding the database snapshot (`panel.db`) plus a
`meta.json` manifest — no `settings.json` since the upgrade; restore
validates the upload, backs the current database up first, swaps it
atomically, and re-renders configs — treat the ZIP like a private key:
it contains every password, private key, and the bot token; restore is
roundtrip-tested but has not been exercised on a live panel yet, so
keep a copy of the current database before restoring), server status (CPU load, RAM, disk, uptime,
and per-service state for every core), a Cores page to start/stop/restart each core separately
and view its journal, and 14-day traffic charts on
the dashboard and each user page (server-rendered SVG, no external
libraries; days without traffic show as zero).

The panel is also manageable from Telegram: a full-management bot
(`app/bot.py`) with the same capabilities as the web UI — list,
search and edit users, create users (guided: name → inbounds →
traffic limit → expiry), freeze/unfreeze, extend expiry, reset
traffic, delete, create/enable/disable/delete inbounds (guided:
protocol → port → SNI), get any user's share links and subscription
link, check server status and traffic, restart services (with
confirmation), and receive a backup as a document. Commands
(`/start /help /menu /status /users /inbounds /cancel`) are
registered on Telegram automatically when you save the bot token.
Setup: create a bot with @BotFather, paste its token and your numeric
chat ID (from @userinfobot) into the settings page — polling is the
default and works out of the box on any panel port (just save and the
bot starts answering); webhook needs a domain and pressing "Register
webhook". The settings page shows the Telegram connection status
(mode, bot identity, last poll, last update, last error). Only that
chat ID can use the bot; anyone else gets no reply at all. The webhook
URL carries a random secret (not the bot token) and lives under the
panel's secret web path. One limitation: Telegram only delivers
webhooks on ports 443, 80, 88 and 8443, while the installer picks a
random panel port — if webhook registration fails, switch to polling,
or re-run the installer with `--port 8443` (when no inbound uses TCP
8443) or put a reverse proxy on 443 in front of the panel.

## Configuration

Most settings live in the panel itself (Settings page): domain,
subscription host, Reality SNI, Telegram, password, backup. A few
things are installer-level and live in
`/opt/sparky-manager/data/panel.env` (re-used on re-install):

| Setting | Meaning |
|---|---|
| Panel port | Random on a fresh install (10000–60000); `--port` fixes it. The firewall opens only this port + the inbound ports in use. |
| Web path | Random secret path (`/<random>`) the panel answers under; the root returns 404. `--web-path` fixes it. |
| `SPARKY_TRUST_FORWARDED_PROTO=1` | Honor `X-Forwarded-Proto: https` for the session cookie's `Secure` flag — only behind a TLS-terminating reverse proxy you trust. Default off (an untrusted client could spoof the header). |

## Security

- **CSRF:** every state-changing form carries a per-session token
  (HMAC-derived from the session token); missing or wrong token → 403.
  `POST /login` and the Telegram webhook are exempt by design (no
  session exists yet / authenticated by a random path secret).
- **Login:** PBKDF2-HMAC-SHA256 password hash (600,000 iterations),
  12-hour server-side sessions, 5 failed attempts → 15-minute lockout
  per IP (a successful login clears the counter). Logout is POST-only.
- **Headers:** every response carries `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, HSTS, and a strict CSP
  (no inline scripts anywhere; the dashboard chart keeps inline
  styles).
- **Backups are credential bundles:** the ZIP holds the whole panel
  database — every password, private key, and the bot token. Never
  share it, never store it unencrypted in shared places.
- **No auto-generated API docs:** FastAPI's `/docs`, `/redoc` and
  `/openapi.json` pages are disabled — this is a private admin tool,
  and the schema exposure served no purpose. The panel's own `/api`
  endpoints are unaffected.
- The Xray Stats API listens on `127.0.0.1:10085` only; the panel
  database is `0600`, rendered configs `0640`.

## Testing

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install pytest
python -m pytest -q
```

The suite (1269 tests) covers config rendering (golden configs
validated against real Xray/sing-box binaries where available), link
builders, subscriptions, user/inbound management, the Telegram bot,
CSRF/auth boundaries, the gRPC stats client, and the UI (every page
renders, every link resolves, every form carries a CSRF token). CI
runs the same suite on Python 3.11, 3.12 and 3.14.

## Troubleshooting

**The panel won't start after an upgrade.**
`sudo journalctl -u sparky-manager -n 50` shows the error. A failed
import fails loudly at startup by design — check that the installer
re-ran `pip install -r requirements.txt` (the upgrade adds `grpcio`).

**A re-render fails after adding a user/inbound.**
The panel keeps the old config and the old service running and shows
the error — nothing is half-applied. Check the failing core's config
with `xray run -test` / `sing-box check` and the panel log
(`sudo journalctl -u sparky-manager`, or the Logs page).

**The Telegram bot doesn't answer.**
Check Settings → Telegram: the diagnostics show the mode, the last
poll/update/error, and whether the token is set. Polling needs no
port and no domain — just a saved token + chat ID. If you switched
from webhook to polling, the panel calls `deleteWebhook` first; a
failed removal is shown as an error instead of pretending polling
is live. Only the configured chat ID gets replies — anyone else
gets silence by design.

**Webhook registration fails.**
Telegram only delivers webhooks on ports 443, 80, 88 and 8443. The
installer picks a random panel port — switch to polling, or re-run
the installer with `--port 8443` (when no inbound uses TCP 8443),
or put a reverse proxy on 443 in front of the panel.

**Traffic shows zero for a sing-box user.**
Expected: sing-box has no per-user stats API, so its traffic is not
collected. Xray and WireGuard traffic is collected; sing-box shows
"n/a".

**Backing up the database — never `cp panel.db` alone.**
`panel.db` runs in SQLite WAL mode: the main file can be 4 KB while
all live data sits in `panel.db-wal`. A plain `cp` of `panel.db`
copies only the main file — no tables, useless as a backup. Use
Settings → Backup in the panel (SQLite backup API — a clean
standalone snapshot), or stop the panel first and copy the whole
`data/` directory (main file + `-wal` + `-shm`). `sparky-manager
backup` tars the live directory: crash-consistent, but it can lose
the last seconds of transactions; the panel backup is the clean
path.

## FAQ

**Do I need a domain?**
No. A bare server IP is enough for the default setup. A domain only
adds the TLS-based protocols and a real certificate for the panel.

**The browser warns about the certificate — is that normal?**
Only if the trusted-certificate step failed (usually TCP 80 closed in
the firewall/security group). With no domain the installer asks for a
free Let's Encrypt certificate for the bare server IP — valid ~6 days,
renewed automatically — and then the browser trusts the panel with no
warning. If it fell back to the self-signed certificate generated at
install, compare its SHA256 fingerprint with the one in the login box
(`/root/sparky-manager-login.txt`) before proceeding, then open TCP 80 and
re-run the installer to retry the trusted certificate.

**How do I reprint the login details?**
`sudo sparky-manager info`.

**How do I uninstall?**
`sudo bash install.sh --uninstall` — it stops the services, keeps a
backup tarball in `/root/`, and removes `/opt/sparky-manager`.

**Does the panel run Psiphon, Tor, or DNS tunnels?**
No, by design. Those are client-side or third-party networks that
ZedSecure already bundles; a server panel has nothing to run for them.

## Known limitations (honest list)

- **sing-box traffic is uncollected** — sing-box has no per-user
  stats API, and the panel does not run nftables counters. Shared-port
  sing-box inbounds show "traffic: n/a" rather than an invented
  number, and traffic limits do not trigger for sing-box-only users.
- **A single-client Shadowsocks inbound has no per-user Xray stats**
  — its Xray shape has no `clients` list, so its one user gets no
  per-user traffic (nothing is misattributed; the traffic is simply
  uncollected). Inbound-level stats are not collected either.
- **The per-client IP limit is stored and shown but not enforced** —
  the panel cannot observe connected IPs, so it does not pretend to
  limit them.
- **"Active today" is not "online now"** — the dashboard counts users
  with any traffic today. Real presence is not observable, and the
  label says what the number actually is.
- **Restore is roundtrip-tested but has not been exercised on a live
  panel** — keep a copy of the current database before the first real
  restore.
- **Visual/mobile layout needs a manual check** — no browser or
  screenshot tooling exists in the build environment; work through
  [docs/MANUAL_UI_CHECKLIST.md](docs/MANUAL_UI_CHECKLIST.md) after
  upgrading.
- **Re-render blocks the request** — a config re-render runs
  synchronously inside the POST that triggered it (the reply reports
  its result), so a slow core restart delays the response. Moving it
  to a background task needs a UX decision (progress reporting).
- **No live-connection killing** — expired or over-quota users are
  removed from the rendered configs at the next re-render; existing
  connections are not killed mid-session.
- No reseller / multi-admin / billing, no multi-node management, no
  Clash/Mihomo YAML subscription format.
- OpenVPN, OpenConnect, AmneziaWG and native IKEv2 (strongSwan)
  shipped in **v1.2.0** (AmneziaWG gated: it needs the kernel module;
  the panel says plainly when it is missing).
- The installer fetches the *latest* stable cores at install time and
  records them in `/opt/sparky-manager/versions.env`; there is no auto-update.

## License

MIT — see [LICENSE](LICENSE).
