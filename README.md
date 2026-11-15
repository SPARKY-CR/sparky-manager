# sparky-manager

A multi-core VPN panel built from scratch: **Xray-core + sing-box + native
WireGuard**, managed through one Persian-first web UI. It is made for the
[ZedSecure](https://github.com/CluvexStudio/ZedSecure) client — the panel
serves everything ZedSecure can connect to that needs a server, in the two
subscription formats ZedSecure understands (v2rayNG links and sing-box
JSON), plus QR codes.

Public project, MIT licensed. **Built from scratch** — no fork, no copied
code from 3X-UI, vpn-ui, Marzban, or any other panel.

> **Status: Phase 1 (MVP) built.** 189 tests pass; the rendered Xray
> config passes `xray run -test` against real Xray 26.11.9 and the
> rendered sing-box config passes `sing-box check` against real
> sing-box 1.14.4. Not yet installed on a real server — test the
> one-line install on a fresh Ubuntu/Debian VPS before using it
> for real users.

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
  (rotatable). Traffic from Xray gRPC, `wg show`, and nftables counters
  for sing-box.

## Install

Ubuntu 22.04/24.04/26.04 or Debian 12/13 only, as root:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash
```

> The one-liner needs the GitHub repo named `SPARKY-CR/sparky-manager`
> (rename it from `Zed-panel` in repo Settings → General). Until the
> rename, clone the repo and run `sudo bash install.sh` from inside it.

Unattended install with explicit options:

```bash
curl -Ls https://raw.githubusercontent.com/SPARKY-CR/sparky-manager/main/install.sh | sudo bash -s -- --yes --reality-sni www.microsoft.com
```

The installer is idempotent (safe to re-run) and verifies itself before
finishing: the panel must answer `200` on `/health` and `xray` /
`sing-box` must be active, or it prints the last 20 log lines and exits
non-zero. It downloads the latest stable Xray-core and sing-box from
their official GitHub releases and verifies SHA256 when the release
publishes a digest.

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
| Hysteria2 | UDP 443 | sing-box (Xray if it ships a native inbound) |
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
(download a ZIP with the database; restore validates the upload,
backs the current database up first, swaps it atomically, and
re-renders configs — treat the ZIP like a private key: it contains
every password, private key, and the bot token), server status (CPU load, RAM, disk, uptime,
and per-service state for every core), and 14-day traffic charts on
the dashboard and each user page (server-rendered SVG, no external
libraries; days without traffic show as zero).

The panel is also manageable from Telegram: a full-management bot
(`app/bot.py`) with the same capabilities as the web UI — list and
create users (guided: name → inbounds → traffic limit → expiry),
freeze/unfreeze, extend expiry, reset traffic, delete, enable/disable
inbounds, get any user's share links and subscription link, and check
server status and traffic. Setup: create a bot with @BotFather, paste
its token and your numeric chat ID (from @userinfobot) into the
settings page, then pick how the bot receives updates. Polling works
out of the box on any panel port (recommended for a standard install
— just save and the bot starts answering); webhook needs a domain and
pressing "Register webhook". Only that chat ID can use the bot; anyone
else gets no reply at all. The webhook URL carries a random secret
(not the bot token) and lives under the panel's secret web path. One
limitation: Telegram only delivers webhooks on ports 443, 80, 88 and
8443, while the installer picks a random panel port — if webhook
registration fails, switch to polling, or re-run the installer with
`--port 8443` (when no inbound uses TCP 8443) or put a reverse proxy
on 443 in front of the panel.

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

## Phase 1 limits (honest list)

- OpenVPN, OpenConnect, AmneziaWG and native IKEv2 (strongSwan) were
  Phase 2 — all four shipped in **v1.2.0** (AmneziaWG gated: it needs
  the kernel module; the panel says plainly when it is missing).
- sing-box has no per-user stats API: shared-port sing-box inbounds show
  "traffic: n/a" rather than an invented number.
- No reseller / multi-admin / billing, no multi-node management.
- The installer fetches the *latest* stable cores at install time and
  records them in `/opt/sparky-manager/versions.env`; there is no auto-update.

## License

MIT — see [LICENSE](LICENSE).
