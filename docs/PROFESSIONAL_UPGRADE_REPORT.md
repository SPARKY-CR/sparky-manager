# sparky-manager — Professional Upgrade Report

**Branch:** `upgrade/professional` · **Base:** `main` at `f7691df` (v1.2.0 + expansion)
· **Date:** 2026-11-15 · **Status:** complete, all 7 phases done, `main` untouched.

This report covers deliverables A–I of the upgrade spec. Every number
in it was measured, not estimated; anything not verified is labeled as
such. The upgrade never touched `main`, never rewrote history, never
force-pushed, and added no database schema change.

---

## A. Implementation summary

| Phase | What | Commit | Tests after | CI |
|---|---|---|---|---|
| 1 — Audit | Read-only repo audit (security, UI, architecture, dependencies, tests). Baseline verified: 659 passed. No code change. | — (report only) | 659 | — |
| 2 — Security | CSRF on all state-changing POSTs, login-lockout reset, security headers, cookie fix behind a TLS proxy, `settings.json` dropped from backup ZIPs, atomic DB restore. | `a50df6c` | 686 | #34 ✅ |
| 3 — Telegram | Polling default transport, `setMyCommands` + `/menu /status /users /inbounds`, user search/edit, inbound create/delete, service restart, backup via bot, Telegram diagnostics page. | `e62d516` | 773 | #35 ✅ |
| 4 — UI/UX | Design tokens, glassmorphism removed, grouped nav, mobile drawer (no-JS `:target`), dashboard server-status card, "Active today" relabel, users search/filter/sort/pagination, tabbed settings. | `166e0e5` | 818 | #36 ✅ |
| 5 — Architecture | Real Xray traffic via a gRPC Stats client, `main.py` split 6,262 → ~4,550 lines, pinned dependencies, CI on Python 3.14, `crypt` guard, re-render lock, shared config writer. | `0ec1747` | 852 | #37 ✅ |
| — CI matrix | Python 3.14 added to the CI matrix (applied by Morteza from Termux — the GitHub connector cannot push workflow files). | `de1b8ac` | 852 | #38 ✅ |
| 6 — Testing | Security-boundary sweep, gRPC integration tests, N+1 fixes, installer-renderer `user_id` fix, argv redaction fix, link/UI checks, manual UI checklist. | `49d6456` | 954 | #39 ✅ |
| 7 — Docs + delivery | Auto-generated API docs disabled, READMEs + DESIGN.md corrected, final code review, this report. | *(SHA assigned on push)* | 956 | — |

**Deliberate deviations from the spec, all documented in code:**
- CSRF tokens are HMAC-derived from the session token rather than
  stored in a new column — the panel has no migration system, so a
  stored-token column would break login on existing installs. The
  security properties are identical (DESIGN.md §7).
- The re-render lock is a `threading.RLock`, not the spec's
  `asyncio.Lock` — `rerender_configs` is a sync function called from
  multiple threads, and an asyncio lock cannot serialize threads
  (DESIGN.md §13).
- Re-render was NOT moved to a background task — the reply reports
  its result, and changing that needs a UX decision (DESIGN.md §13).

**What the upgrade did not do** (out of scope by design): no migration
system (documented as future work), no IP-limit enforcement (no honest
observation hook exists), no multi-admin/reseller/billing, no
Clash/Mihomo YAML subscription format, no live-connection killing.

---

## B. UI summary

- **Design tokens** in `style.css` (`:root`): solid charcoal surfaces,
  restrained violet accent + sky secondary, documented spacing/type/
  border/shadow/radius scales. **Glassmorphism is gone** — zero
  `backdrop-filter` on cards or topbars; the only translucent tints
  are small accents (chips, badges, stat icons). CSS logical
  properties throughout, so Persian RTL and English LTR both render
  correctly. `:focus-visible` and `prefers-reduced-motion` supported.
- **Navigation** (`base.html`): grouped sidebar — Overview (Dashboard),
  Management (Inbounds, Users), Monitoring (Logs), System (Settings).
  No Network & Services or Integrations group: no such pages exist,
  and the nav never links to a page that doesn't. Desktop: collapsible
  sidebar (persisted in `localStorage`). Mobile (≤960 px): slide-in
  drawer opened by a hamburger via `:target` — works without JS.
  The old bottom nav was removed.
- **Dashboard:** server-status card (same collector as Settings —
  CPU/RAM/disk/uptime/services; a failed collection shows
  "unavailable", never zero), 14-day traffic chart, inbound node
  cards, recent activity. "Online (approx.)" relabeled **"Active
  today"** (users with any traffic today — not presence); the "LIVE"
  dots were removed (nothing on the page is live).
- **Users list:** server-side search (name/note), status filter
  (enabled/disabled/frozen/expired), sort (created/name/expiry/
  traffic), pagination (25/page) as GET query params — bookmarkable;
  invalid values fall back to defaults, never 500.
- **Settings:** 6 tabs (General / Telegram / Security / Backup /
  Services / Advanced) via `?section=`; no Network tab (no
  network-only settings exist). `POST /settings` now does partial
  updates — each tab posts only its own fields.
- **Tables:** card-table pattern below 640 px (cells labeled from
  `data-label`); tables without it keep horizontal scroll.
- **Verification limit:** no browser or screenshot tooling exists in
  the build environment. Responsive/drawer behavior is verified by
  rendered-HTML and route tests only; visual/mobile layout needs the
  manual check in `docs/MANUAL_UI_CHECKLIST.md`.

---

## C. Telegram summary

- **Polling is the default transport** (`telegram_transport`,
  default `"polling"`). It works on any panel port with no domain —
  just save the token + chat ID and the bot starts answering.
  An install that explicitly chose `"webhook"` keeps it.
- **Commands** registered on Telegram via `setMyCommands` (Persian
  descriptions) when the token is saved, plus a "Register commands"
  settings action: `/start /help /menu /status /users /inbounds
  /cancel`.
- **Bot capabilities** (same semantics as the web UI — same
  validation, same audit names, same `rerender_configs`): user list
  (paginated), search (name/note substring), view, create (guided:
  name → inbounds → traffic limit → expiry), edit (guided: name /
  traffic limit / expiry), freeze/unfreeze, extend expiry
  (+7/+30/+90 days), reset traffic, delete (with confirmation);
  inbound list, view, toggle, guided create (VLESS / VMess / Trojan
  / Shadowsocks / WireGuard), delete (with confirmation); any user's
  share links + subscription link; server status + traffic summary;
  service restart with confirmation (only the 6 sudoers-covered
  services — success claimed only when the service is actually
  running afterwards); backup as a document (refused honestly over
  Telegram's 50 MB bot-API cap).
- **Diagnostics** on the settings page: connection mode, bot identity
  (`getMe`, cached — never the token), authorized chat ID,
  commands-registered time, and for polling the last poll, last
  update, last error, and the persisted offset (restarts resume
  where the loop left off).
- **Auth:** only the configured admin chat ID is served — strangers
  get no reply at all, on commands AND callbacks. The webhook URL
  carries a random secret (not the bot token) under the secret web
  path; the endpoint is inert (404) when unconfigured or mismatched.
- **Honest limitations:** webhooks only work on ports 443/80/88/8443
  while the installer picks a random panel port (switch to polling,
  or re-run the installer with `--port 8443`, or a reverse proxy on
  443); AmneziaWG cannot be restarted from the bot (no sudoers entry);
  the panel cannot restart itself from the bot; bot inbound creation
  covers only the 5 main protocols.

---

## D. Security audit report

### Findings from the Phase 1 audit — and what fixed them

| ID | Severity | Finding | Fixed in | How |
|---|---|---|---|---|
| S1 | HIGH | No CSRF protection anywhere (~30 state-changing POSTs, session cookie only; `GET /logout` changed state) | Phase 2 | HMAC-derived per-session tokens on 24 of 26 POST routes; `GET /logout` → POST (GET now 405). Exempt by design: `/login` (no session yet) and the Telegram webhook (random path secret). |
| F1 | HIGH | Xray/sing-box traffic never collected — limits never triggered for Xray users, charts showed WireGuard only | Phase 5 | Real gRPC Stats client (`app/xray_stats.py`); renderer enables the Stats API on 127.0.0.1:10085 and tags every client with an email. sing-box remains uncollected (no stats API) — documented, not faked. |
| S2 | MEDIUM | Login-lockout counter never reset (`record_successful_login` defined + tested but never called) | Phase 2 | `login_submit` now calls it. |
| S5 | MEDIUM | Backup ZIP is a full credential bundle (whole DB + plaintext `settings.json` with bot token and private keys) | Phase 2 | `settings.json` dropped from new ZIPs (restore never read it). The ZIP still holds the DB — bot token included — so it is still a credential bundle by design; documented in the UI, READMEs and DESIGN.md §7. |
| S3 | LOW | No security headers | Phase 2 | Middleware: nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, HSTS, strict CSP (`script-src 'self'`; `style-src` keeps `'unsafe-inline'` for inline chart widths). |
| S4 | LOW | Cookie `Secure` flag breaks behind a TLS proxy | Phase 2 | `SPARKY_TRUST_FORWARDED_PROTO` env setting (default off). |
| S6 | LOW | Restore DB swap not atomic (unlink then copy) | Phase 2 | Temp file + fsync + `os.replace`. |
| S7 | LOW | Expired sessions pruned only on lookup | — | **Not changed.** Expired rows are still pruned when looked up (and the lookup rejects them); no sweeper pruning was added. Harmless at this scale — a stale row is never accepted. |
| S8 | LOW | No rate limiting except login | — | **Not changed.** Only the login lockout (5 failed → 15 min per IP) exists; there is no general API rate limiting. The panel is single-admin behind a secret web path. |
| F2 | MEDIUM | "Online now" cannot be measured as labeled | Phase 4 | Relabeled "Active today" (users with any traffic today); the label says what the number actually is. |
| F3 | LOW | `update-cores` deliberately unimplemented (CLI) | — | **Not changed, by design.** Re-run `install.sh` to update the cores. |
| F4 | LOW | API is minimal and cookie-only | — | **Not changed.** No API tokens; the JSON API uses the session cookie + CSRF header. |
| — | LOW | Auto-generated API docs (`/docs`, `/redoc`, `/openapi.json`) returned 200 unauthenticated — and the root app served them at the root, outside the secret web path | Phase 7 | Disabled on both FastAPI constructors (`docs_url=None, redoc_url=None, openapi_url=None`); tests assert 404 on the panel app and on a web-path-mounted root app. `/api` endpoints unaffected. |
| — | LOW | Privileged-command argv logged raw (the docstring promised redaction, but only the output tail was redacted) | Phase 6 | argv goes through `_redact` on success and failure paths. No current call passes secrets in argv. |

### Verified clean (Phase 1, re-confirmed by Phase 6 tests)

No SQL injection (ORM + parameterized queries), no command injection
(all subprocess calls list-form, no `shell=True` — Phase 6 tested
command-injection strings in the re-render path), no XSS (autoescape
on, no `|safe`/`Markup` — Phase 6 tested XSS payloads in text fields),
no path traversal (Phase 6 tested traversal in restore/upload names),
no open redirect, Telegram auth checked per message AND per callback
(including the new restart/backup callbacks), secrets redacted in
logs, PBKDF2-HMAC-SHA256 with 600,000 iterations and a per-user salt,
session fixation N/A (server-side sessions, logout invalidates).

### Remaining honest gaps

S7 and S8 above; the backup ZIP is still a credential bundle by
design; the panel has no migration system (`create_all` only — a
future schema change needs one); the restore 200 MiB upload cap is
enforced in code but has no dedicated test (a >200 MiB test upload
is impractical in the suite).

---

## E. Test report

**Final: 956 passed, 0 failed, 0 skipped** (2 pre-existing warnings:
the `crypt` DeprecationWarning — `crypt` is removed in Python 3.13
and the `openssl passwd` fallback is the live path — and a test-only
Starlette/httpx deprecation).

| Milestone | Passed | Change |
|---|---|---|
| Base (`main` f7691df) | 659 | — |
| Phase 2 (security) | 686 | +27 |
| Phase 3 (Telegram) | 773 | +87 |
| Phase 4 (UI) | 818 | +45 |
| Phase 5 (architecture) | 852 | +35 new, −1 deleted* |
| Phase 6 (testing) | 954 | +102 |
| Phase 7 (docs + delivery) | 956 | +2 (API docs disabled) |

\* One test deleted in Phase 5, not weakened: it asserted the webhook
returned 404 when the bot module was missing — impossible after the
defensive-import cleanup (a missing module now fails loudly at
startup, which is the intended behavior).

**Commands run** (from the repo root, in a venv with the pinned
`requirements.txt` + `pytest`):

```bash
python -m pytest -q            # full suite (final: 956 passed)
python -m pytest tests/test_phase6_security.py -q   # 36 passed
python -m pytest tests/test_links.py tests/test_phase6_ui.py -q  # 84 passed
```

**CI:** every commit on the branch is green — runs #34–#39
(`a50df6c`, `e62d516`, `166e0e5`, `0ec1747`, `de1b8ac`, `49d6456`),
on Python 3.11/3.12/3.14 since run #38 (the first 3.14 run).

**What was NOT verified here (stated plainly):**
- **Visual/mobile layout** — no browser or screenshot tooling exists
  in the build environment. Rendered-HTML and route tests cover
  structure; how the pages actually look needs
  `docs/MANUAL_UI_CHECKLIST.md` on a real deployment.
- **Live restore** — restore has a full roundtrip test, but it has
  never been exercised on a live systemd panel. Keep a copy of the
  current database before the first real restore.
- **Oversized restore upload** — the 200 MiB cap is enforced in code
  (`app/backup.py`) but has no dedicated test. (The Telegram 50 MB
  backup refusal IS tested.)
- **Feeds against the real ZedSecure importer** — the subscription
  feeds are verified by parser tests only (DESIGN.md §11, Q5).
- **The installer on a fresh server** — the installer is covered by
  8 tests plus the LE-cert regression tests; a fresh-server run was
  not part of this upgrade (the panel itself was already installed).

---

## F. Known limitations

- **sing-box traffic is uncollected** — no per-user stats API, and
  the panel does not run nftables counters. sing-box-only users show
  "n/a" and traffic limits do not trigger for them.
- **A single-client Shadowsocks inbound has no per-user Xray stats**
  — its Xray shape has no `clients` list. Inbound-level stats are
  not collected either.
- **The per-client IP limit is stored and shown but not enforced** —
  the panel cannot observe connected IPs.
- **"Active today" is not "online now"** — real presence is not
  observable; the label says what the number is.
- **Restore is roundtrip-tested but never exercised on a live panel.**
- **Visual/mobile layout needs the manual checklist.**
- **Re-render blocks the request** — synchronous inside the POST that
  triggered it; moving it to a background task needs a UX decision.
- **No live-connection killing** — expired/over-quota users leave the
  rendered configs at the next re-render; existing connections are
  not killed mid-session.
- **No migration system** — `create_all` only; a future schema change
  needs one.
- No reseller / multi-admin / billing, no multi-node management, no
  Clash/Mihomo YAML subscription format, no general API rate
  limiting, no API tokens (cookie-only JSON API).
- AmneziaWG restart is unavailable from the bot (no sudoers entry);
  the bot cannot restart the panel itself; bot inbound creation
  covers only the 5 main protocols.
- The installer fetches the *latest* stable cores at install time;
  there is no auto-update.

---

## G. Git info

- **Repository:** `SPARKY-CR/sparky-manager` (public, MIT)
- **Branch:** `upgrade/professional` (created 2026-11-15 from `main`
  at `f7691df`)
- **Base:** `f7691df` — `main` is untouched at this commit. **No merge
  into `main` has been done and none may happen without Morteza's
  explicit approval.**
- **Commits on the branch** (in order):

| SHA | Subject |
|---|---|
| `f7691df` | (base) polling transport for the Telegram bot |
| `a50df6c` | Phase 2: security (CSRF, headers, lockout reset, backup, atomic restore) |
| `e62d516` | Phase 3: Telegram rework (polling default, commands, services, backup) |
| `166e0e5` | Phase 4: UI/UX redesign (design tokens, grouped nav, dashboard status, users search, tabbed settings) |
| `0ec1747` | Phase 5: Xray traffic via gRPC, main.py split, pinned deps, re-render lock |
| `de1b8ac` | CI: test Python 3.14 (production server version) — by Morteza, Termux |
| `49d6456` | Phase 6: testing and verification (security sweep, gRPC integration, perf fixes, UI checks) |
| *(Phase 7)* | Docs + delivery (this report; SHA assigned on push) |

- No force-push, no history rewrite, no secrets in any commit.

---

## H. Deployment instructions

**From a server running `main`/v1.2.0:**

```bash
git clone -b upgrade/professional --depth 1 https://github.com/SPARKY-CR/sparky-manager.git
cd sparky-manager
sudo bash install.sh
```

The installer re-run copies the new code over `/opt/sparky-manager`,
keeps the database, users, inbounds, panel port, web path and admin
password, re-installs the pinned Python dependencies (including the
new `grpcio`), heals certificate file permissions an older installer
may have left unreadable, and verifies the panel answers `/health`
before finishing. No database migration is needed.

**After upgrading:**

1. **Telegram bot** (if used): Settings → Telegram — paste the
   BotFather token and your numeric chat ID, keep the transport on
   polling (the default), save. The bot starts answering; the
   diagnostics on the same page confirm the mode, last poll, and
   last error.
2. **Manual UI check:** work through
   `docs/MANUAL_UI_CHECKLIST.md` on a desktop browser and a phone
   (portrait + landscape) before calling the upgrade done.
3. **Fresh backup:** Settings → Backup, once the upgraded panel is
   running.
4. **First restore (whenever it happens):** keep a copy of the
   current database first — restore is roundtrip-tested but has not
   been exercised on a live panel.

**Rollback:** the installer re-run is the deployment mechanism in
both directions — re-running it from a `main` checkout restores the
v1.2.0 code (the database is forward-compatible: the upgrade added
no schema change, only new `settings` rows, which the old code
ignores).

---

## I. Deliverable ZIP

The deliverable ZIP is built from the **branch archive** after the
final push — not from a working tree:

```bash
# GitHub archive of the branch (exact committed content, no extras):
https://github.com/SPARKY-CR/sparky-manager/archive/refs/heads/upgrade/professional.zip
```

Because it comes from the git archive, it contains only committed
files: no secrets (none are committed), no runtime data (the panel
database lives in `/opt/sparky-manager/data/`, never in the repo),
no virtualenvs, no caches. The ZIP is the same content the installer
deploys when run from a clone of the branch.
