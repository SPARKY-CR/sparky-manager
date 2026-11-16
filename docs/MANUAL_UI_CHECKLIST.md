# Manual UI verification checklist

> **Read this first.** The automated suite verifies the panel's HTML:
> every page renders 200, every link and static asset resolves, every
> POST form carries a CSRF token, every i18n key exists in both
> languages, and the CSS has no fixed widths wider than a phone
> viewport (see `tests/test_phase6_ui.py`). **What automation cannot
> verify is how the pages actually look.** There is no browser or
> screenshot tooling in the build environment, so visual and mobile
> layout has NOT been verified by automation. This checklist is the
> human half of Phase 6 — work through it on a real deployment after
> upgrading, on a desktop browser and on a phone, before calling the
> upgrade done.

## How to use it

- Open the panel on the upgraded server (any browser; the panel is
  offline-first, so no internet is needed beyond reaching the server).
- Check each box as you go. Anything that looks wrong is a real bug —
  file it against the upgrade branch with a screenshot and the
  viewport size.
- Repeat the mobile section in **both portrait and landscape**.

## Desktop (1280 px and wider)

- [ ] **Login page**: the card is centered, the logo and the Persian
      hint text render, the username/password fields and the sign-in
      button are usable. No horizontal scrollbar.
- [ ] **Dashboard**: the sidebar groups are Overview / Management /
      Monitoring / System; the stat cards, the server-status card
      (CPU / RAM / disk / services), the 14-day traffic chart, the
      inbound node cards and the recent-activity list all render with
      real data (no placeholder numbers). The chart bars and labels
      are readable. The label says "Active today", never "online now".
- [ ] **Users**: the search box, status filter, sort dropdown and
      pagination work; the table columns (name, status, traffic,
      expiry, protocol) are readable; the frozen/expired badges show
      correctly. Bulk-action checkboxes select rows.
- [ ] **User detail**: the user's links, QR codes, traffic chart and
      per-client rows render; Edit / Freeze / Rotate token / Delete
      buttons are present and look clickable (do not delete a real
      user — test on a throwaway one).
- [ ] **User edit**: all fields (name, note, traffic limit, expiry
      date, IP limit, freeze) render and save.
- [ ] **Inbounds**: the table shows protocol chips, port, status and
      client counts; the "add inbound" form renders; editing an
      inbound shows the protocol-specific fields only (no options
      that inbound's protocol does not support).
- [ ] **Inbound edit**: Reality keypair / server-key regenerate
      buttons render next to their fields.
- [ ] **Settings**: the six tabs (General / Telegram / Security /
      Backup / Services / Advanced) switch without a page reload
      glitch; each tab shows only its own fields; the Telegram
      monitoring section shows connection mode, status, last poll and
      last error; the Services tab shows real service states.
- [ ] **Logs**: the log viewer renders, the level filter works, the
      download link downloads `panel.log`, and Clear asks for
      confirmation.
- [ ] **Cores**: seven cards (Xray, sing-box, WireGuard, AmneziaWG,
      OpenVPN, OpenConnect, IKEv2), each with a live status badge;
      a running core offers Stop + Restart, a stopped one Start;
      View log expands the journal tail; a restart shows the real
      state afterwards (not a blind success).
- [ ] **Language switch**: `?lang=en` renders every page in English,
      left-to-right, with no clipped text; switching back to Persian
      restores RTL. Long Persian strings do not overflow their cards.
- [ ] **Navigation**: every sidebar link, the brand link and the
      "add inbound" shortcut land on a real page (no dead ends).

## Phase C (2026-11-16) — live checks automation cannot do

- [ ] **Passkeys**: on the desktop browser, Settings → Security →
      register a passkey (fingerprint / security key) with a name;
      it appears in the list with its host and registration time.
      Log out — the login page now shows the "Sign in with passkey"
      button; signing in with it lands on the dashboard. Password
      login still works afterwards. Delete the passkey — the button
      disappears from the login page. (Automation stubs the WebAuthn
      library, so this first real ceremony is the true check.)
- [ ] **IP-limit ban**: set an IP limit of 1 on a test user's Xray
      client, connect that user from two IPs (phone + desktop), and
      within ~10 s the older IP is banned: the user page shows the
      ban, `sudo fail2ban-client status sparky-ipl` lists the IP,
      and the banned device cannot reconnect (a session already
      open when the ban lands is NOT killed immediately — that is a
      documented limitation). Unban from the user page lifts it.
      Do NOT test with your own admin IP unless it is in the jail's
      `ignoreip` — the ban blocks ALL ports, including SSH.
- [ ] **Metrics**: `curl -s https://<server>:<port>/<web-path>/metrics -H
      "Authorization: Bearer spk_..."` with a `status:read` token
      returns Prometheus text (users/inbounds/traffic/core gauges);
      without a token it returns 401. No user names or tokens appear
      in the output.
- [ ] **CLI**: `sudo sparky-manager users`, `inbounds` and `health`
      print real data and exit 0; `user-add` on a throwaway user
      prints its subscription link (delete the user afterwards).

## Mobile — portrait (360–414 px wide)

- [ ] **No horizontal overflow anywhere**: no page scrolls sideways
      (dashboard, users, inbounds, settings, logs, login). This is
      the most common regression — check every page.
- [ ] **Drawer**: the hamburger opens the sidebar as a drawer; the
      overlay and the close button close it; the drawer does not trap
      the page behind it.
- [ ] **Dashboard**: stat cards stack vertically; the server-status
      card and the chart fit the screen (the chart scales down, it
      does not overflow).
- [ ] **Users / Inbounds tables**: rows render as stacked cards with
      labels (not a squeezed desktop table); search, filter and sort
      controls are tappable and do not overlap.
- [ ] **Forms**: every input is full-width and tappable; labels sit
      above their fields; the keyboard does not hide the submit
      button on the login and user-create forms.
- [ ] **Settings tabs**: the six tabs wrap or scroll horizontally
      without clipping; the active tab is visible.
- [ ] **Buttons**: all buttons are at least finger-sized; no two
      buttons overlap; destructive buttons (Delete, Clear logs) still
      ask for confirmation.
- [ ] **QR codes**: the QR images on the user page render at a
      scannable size.

## Mobile — landscape (640–900 px wide)

- [ ] The sidebar/drawer behaves (drawer on narrow landscape, sidebar
      on wide landscape — the breakpoint is 960 px).
- [ ] Tables and cards use the extra width without leaving a large
      empty gutter or overflowing.

## After the check

- [ ] Note the browser(s) and viewport sizes you tested.
- [ ] If everything above passes, the UI is verified. If anything
      fails, it is a Phase 6 finding — fix it on the upgrade branch
      and re-run this checklist for the affected pages.
