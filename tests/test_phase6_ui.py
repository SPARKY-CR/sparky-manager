"""Phase 6 (professional upgrade) UI verification tests — rendered HTML.

No browser or screenshot verification exists in this environment
(the Phase 1 audit's G3-1 and the Phase 4 report both state it), so
these tests assert on the rendered HTML instead: every page renders
200, EVERY link and static asset on every page resolves, every POST
form carries a CSRF token, and no template references a missing i18n
key. Visual / mobile layout still needs the human checklist in
docs/MANUAL_UI_CHECKLIST.md — these tests say nothing about pixels.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from app.i18n import STRINGS

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent / "app" / "static"

_HREF_RE = re.compile(r'''(?:href|src)="([^"]+)"''')
_FORM_RE = re.compile(r'''<form method="post"''')
_TOKEN_RE = re.compile(r'''name="csrf_token"''')
# i18n keys referenced as t.key, t["key"] or t['key'] in templates.
_KEY_DOT_RE = re.compile(r"""\bt\.([A-Za-z_][A-Za-z0-9_]*)""")
_KEY_BRACKET_RE = re.compile(r"""t\[["']([^"']+)["']\]""")


def _pages(seeded):
    """Every HTML page in the panel (authed), as paths."""
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    pages = [
        "/dashboard",
        "/users",
        "/users?q=alice&status=all&sort=name&page=1",
        "/users?status=frozen",
        f"/users/{alice.id}",
        f"/users/{alice.id}/edit",
        "/inbounds",
        f"/inbounds/{vless.id}/edit",
        "/logs",
        "/cores",
        "/cores?log=xray",
        "/tools",
        "/selfcheck",
    ]
    for section in ("general", "telegram", "security", "backup",
                    "services", "advanced"):
        pages.append(f"/settings?section={section}")
    return pages


# ---------------------------------------------------------------------------
# Every page renders 200
# ---------------------------------------------------------------------------

def test_every_page_renders_200(authed_client, db, seeded):
    for path in _pages(seeded):
        resp = authed_client.get(path)
        assert resp.status_code == 200, path
        assert "</html>" in resp.text, path


def test_login_page_renders_200_unauthenticated(test_client):
    resp = test_client.get("/login")
    assert resp.status_code == 200
    assert "</html>" in resp.text


def test_public_user_page_renders_200(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    assert "</html>" in resp.text


def test_error_page_renders_200(authed_client):
    # The CSRF error page is the only error template reachable
    # without breaking something first.
    resp = authed_client.post_raw("/users", data={"name": "x"},
                                  follow_redirects=False)
    assert resp.status_code == 403
    assert "</html>" in resp.text


# ---------------------------------------------------------------------------
# Every link and static asset on every page resolves
# ---------------------------------------------------------------------------

def _resolve_link(client, href, page_text):
    """GET one extracted href/src; returns (ok, reason).

    Absolute URLs (subscription / file-export links carry the
    subscription host) are normalized to path+query and fetched via
    the test client — the panel is offline-first, so any link that
    does not resolve on the panel itself is a dead link.
    Fragment-only hrefs are checked against the page's element ids.
    """
    if not href or href.startswith(("mailto:", "tel:", "javascript:")):
        return False, f"unexpected link scheme: {href}"
    if href.startswith("#"):
        if href == "#":
            # The mobile drawer close/overlay: "#" clears the
            # :target hash (intentional, JS-free drawer control).
            return True, ""
        target = href[1:]
        if f'id="{target}"' in page_text:
            return True, ""
        return False, f"fragment #{target} has no matching id"
    parsed = urlparse(href)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    resp = client.get(path)
    if resp.status_code != 200:
        return False, f"{href} -> {resp.status_code}"
    return True, ""


def test_every_link_and_asset_on_every_page_resolves(
    authed_client, db, seeded
):
    checked: set[str] = set()
    failures: list[str] = []
    for page in _pages(seeded):
        resp = authed_client.get(page)
        assert resp.status_code == 200, page
        for href in _HREF_RE.findall(resp.text):
            if href in checked:
                continue
            checked.add(href)
            ok, reason = _resolve_link(authed_client, href, resp.text)
            if not ok:
                failures.append(f"{page}: {reason}")
    assert checked, "no links found on any page — the regex broke?"
    assert failures == [], "\n".join(failures)


def test_public_user_page_links_resolve(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    failures = []
    for href in _HREF_RE.findall(resp.text):
        ok, reason = _resolve_link(test_client, href, resp.text)
        if not ok:
            failures.append(reason)
    assert failures == [], "\n".join(failures)


def test_login_page_links_resolve(test_client):
    resp = test_client.get("/login")
    assert resp.status_code == 200
    failures = []
    for href in _HREF_RE.findall(resp.text):
        ok, reason = _resolve_link(test_client, href, resp.text)
        if not ok:
            failures.append(reason)
    assert failures == [], "\n".join(failures)


def test_no_external_links_anywhere(authed_client, db, seeded):
    """The panel is offline-first: no page may link to a host that
    is not the panel itself (testserver) or the configured
    subscription host. A CDN / font / analytics URL would fail here
    — and would also break the offline-first promise."""
    allowed_hosts = {"testserver", "203.0.113.10"}
    bad = []
    for page in _pages(seeded):
        resp = authed_client.get(page)
        for href in _HREF_RE.findall(resp.text):
            host = urlparse(href).netloc
            if host and host.split(":")[0] not in allowed_hosts:
                bad.append(f"{page}: {href}")
    assert bad == [], "\n".join(bad)


# ---------------------------------------------------------------------------
# Every POST form carries a CSRF token (all pages)
# ---------------------------------------------------------------------------

def test_every_post_form_on_every_page_carries_csrf_token(
    authed_client, db, seeded
):
    for path in _pages(seeded):
        resp = authed_client.get(path)
        assert resp.status_code == 200, path
        forms = len(_FORM_RE.findall(resp.text))
        tokens = len(_TOKEN_RE.findall(resp.text))
        assert forms > 0, f"{path} has no POST forms to check"
        assert tokens == forms, (
            f"{path}: {forms} POST forms but {tokens} CSRF fields")


def test_public_user_page_has_no_forms(test_client, db, seeded):
    """The public page renders the admin template in public mode —
    no admin action (freeze/delete/...) may leak into it."""
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    assert len(_FORM_RE.findall(resp.text)) == 0
    assert "csrf_token" not in resp.text


# ---------------------------------------------------------------------------
# i18n — every template key exists, both languages in full parity
# ---------------------------------------------------------------------------

def _template_keys() -> set[str]:
    keys: set[str] = set()
    for path in TEMPLATES_DIR.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        keys |= set(_KEY_DOT_RE.findall(text))
        keys |= set(_KEY_BRACKET_RE.findall(text))
    return keys


def test_every_template_i18n_key_exists_in_both_languages():
    keys = _template_keys()
    assert len(keys) > 200, f"only {len(keys)} keys found — regex broke?"
    missing = [
        (k, lang) for k in sorted(keys) for lang in ("fa", "en")
        if k not in STRINGS[lang]
    ]
    assert missing == [], f"missing i18n keys: {missing}"
    empty = [
        (k, lang) for k in sorted(keys) for lang in ("fa", "en")
        if not STRINGS[lang][k]
    ]
    assert empty == [], f"empty i18n values: {empty}"


def test_i18n_full_parity_between_languages():
    """fa and en must carry exactly the same keys — a key added in
    one language and forgotten in the other used to render as a
    KeyError (500) or an empty string."""
    fa_keys = set(STRINGS["fa"])
    en_keys = set(STRINGS["en"])
    assert fa_keys == en_keys, (
        f"fa-only: {sorted(fa_keys - en_keys)}; "
        f"en-only: {sorted(en_keys - fa_keys)}")
    assert all(STRINGS["fa"].values()), "empty fa value"
    assert all(STRINGS["en"].values()), "empty en value"


def test_pages_render_in_english_too(authed_client, db, seeded):
    """The ?lang=en switch renders every page (catches a template
    that only works in the default language)."""
    for path in _pages(seeded):
        sep = "&" if "?" in path else "?"
        resp = authed_client.get(f"{path}{sep}lang=en")
        assert resp.status_code == 200, path
        assert 'lang="en"' in resp.text, path
        assert 'dir="ltr"' in resp.text, path


# ---------------------------------------------------------------------------
# Viewport + CSS sanity (static checks — no browser here)
# ---------------------------------------------------------------------------

def test_viewport_meta_present_on_every_page(authed_client, db, seeded):
    for path in _pages(seeded) + ["/login"]:
        resp = authed_client.get(path)
        assert resp.status_code == 200, path
        assert (
            '<meta name="viewport" content="width=device-width, '
            'initial-scale=1">' in resp.text
        ), path


def _strip_media_blocks(css: str) -> str:
    """Remove @media blocks (brace-matched) so the width check only
    sees base rules — widths inside a breakpoint are the responsive
    fix, not the problem."""
    out: list[str] = []
    i = 0
    while i < len(css):
        at = css.find("@media", i)
        if at == -1:
            out.append(css[i:])
            break
        out.append(css[i:at])
        depth = 0
        j = css.find("{", at)
        while j < len(css):
            if css[j] == "{":
                depth += 1
            elif css[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1
    return "".join(out)


def test_css_has_no_fixed_widths_wider_than_mobile():
    """No layout container may have a fixed pixel width wider than a
    360 px phone viewport (outside @media blocks) — that is the
    classic horizontal-overflow bug. max-width is fine (fluid)."""
    css = (STATIC_DIR / "style.css").read_text(encoding="utf-8")
    base = _strip_media_blocks(css)
    offenders = []
    for match in re.finditer(
        r"(?<![a-z-])(?:width|min-width)\s*:\s*(\d+)px", base
    ):
        if int(match.group(1)) > 360:
            line = base.count("\n", 0, match.start()) + 1
            offenders.append(f"line {line}: {match.group(0)}")
    assert offenders == [], "\n".join(offenders)


def test_css_breakpoints_exist():
    """The two responsive breakpoints must not be accidentally
    removed in a restyle."""
    css = (STATIC_DIR / "style.css").read_text(encoding="utf-8")
    assert "@media (max-width: 960px)" in css
    assert "@media (max-width: 640px)" in css
    # Tables scroll inside their wrapper instead of overflowing.
    assert ".table-wrap" in css
    assert "overflow-x: auto" in css
