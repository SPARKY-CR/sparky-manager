"""Language-cookie persistence (live-feedback fix).

The language toggle links are plain GETs (``?lang=en|fa``), but the
``lang`` cookie used to be set ONLY in ``_redirect`` — normal page
renders never set it. So a toggle rendered one page in the new
language and any navigation reverted to fa. The HTTP middleware in
``app.main`` now sets the cookie on EVERY response carrying a valid
``?lang=``, and ``_redirect`` no longer sets it itself.
"""

from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME


def test_lang_query_sets_en_cookie(authed_client):
    resp = authed_client.get("/dashboard?lang=en")
    assert resp.status_code == 200
    assert resp.cookies.get("lang") == "en"


def test_lang_cookie_persists_across_navigation(authed_client):
    """Toggle to English, then navigate without ?lang=: still English."""
    first = authed_client.get("/dashboard?lang=en")
    assert first.cookies.get("lang") == "en"
    # The TestClient keeps the cookie in its jar, like a browser.
    second = authed_client.get("/dashboard")
    assert second.status_code == 200
    assert 'lang="en"' in second.text
    assert 'dir="ltr"' in second.text


def test_lang_query_sets_fa_cookie_and_renders_fa(authed_client):
    resp = authed_client.get("/dashboard?lang=fa")
    assert resp.status_code == 200
    assert resp.cookies.get("lang") == "fa"
    second = authed_client.get("/dashboard")
    assert 'lang="fa"' in second.text
    assert 'dir="rtl"' in second.text


def test_invalid_lang_sets_no_cookie(authed_client):
    resp = authed_client.get("/dashboard?lang=xx")
    assert resp.status_code == 200
    assert "lang" not in resp.cookies
    # Falls back to the default language.
    assert 'lang="fa"' in resp.text


def test_redirect_response_sets_lang_cookie(test_client):
    """A 303 (e.g. after login) with ?lang=en also sets the cookie —
    the middleware covers redirects, not just page renders."""
    resp = test_client.post(
        "/login?lang=en",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.cookies.get("lang") == "en"
