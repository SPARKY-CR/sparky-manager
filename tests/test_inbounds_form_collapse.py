"""Collapsed add-inbound form (live-feedback fix).

The full add-inbound form used to render always-visible at the bottom
of the inbounds page — on an empty panel it dominated the page. It now
lives in a JS-free <details>, collapsed until the admin asks to add.
Every add button (filter strip, empty state, sidebar CTA) links to
#add-inbound-form: navigating to a fragment inside a closed <details>
opens it (HTML spec), so each button opens the same form.
"""

from app.models import Client, Inbound

DETAILS_OPEN = '<details class="card add-form" id="add-inbound">'


def _assert_form_inside_collapsed_details(resp_text: str) -> None:
    """The form sits inside a <details> that renders collapsed."""
    assert DETAILS_OPEN in resp_text
    assert "<details" in resp_text and "open" not in resp_text.split(
        "<details", 1
    )[1].split(">", 1)[0], "details must render without the open attribute"
    details_at = resp_text.index(DETAILS_OPEN)
    form_at = resp_text.index('id="add-inbound-form"')
    close_at = resp_text.index("</details>", details_at)
    assert details_at < form_at < close_at, "form must be inside the details"
    # The <summary> is the toggle and carries the add label.
    summary_at = resp_text.index("<summary", details_at)
    assert summary_at < form_at
    assert "افزودن اینباند" in resp_text[summary_at : summary_at + 400]


def test_add_form_collapsed_when_inbounds_exist(authed_client, db, seeded):
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    _assert_form_inside_collapsed_details(resp.text)
    # The filter-strip button opens the form.
    assert 'href="#add-inbound-form"' in resp.text
    # Suggested values are still the form's initial values.
    assert 'name="tag"' in resp.text
    assert 'name="sni"' in resp.text
    assert 'value="www.microsoft.com"' in resp.text


def test_add_form_collapsed_on_empty_page(authed_client, db, seeded):
    db.query(Client).delete()
    db.query(Inbound).delete()
    db.commit()
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    assert "هنوز اینباندی ساخته نشده است." in resp.text
    _assert_form_inside_collapsed_details(resp.text)
    # The empty-state button opens the form.
    assert 'href="#add-inbound-form"' in resp.text


def test_create_inbound_still_works_from_collapsed_form(
    authed_client, db, seeded
):
    """Submitting the moved form still creates the inbound."""
    resp = authed_client.post(
        "/inbounds",
        data={
            "tag": "collapse-test",
            "core": "xray",
            "protocol": "vless",
            "port": 24443,
            "remark": "",
            "sni": "www.microsoft.com",
            "path": "",
            "network": "tcp",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    inbound = db.query(Inbound).filter(Inbound.tag == "collapse-test").first()
    assert inbound is not None and inbound.port == 24443


def test_footer_no_longer_says_phase_1(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert "فاز ۱" not in resp.text
    assert "پنل VPN" in resp.text
    resp_en = authed_client.get("/dashboard?lang=en")
    assert "Phase 1" not in resp_en.text
    assert "VPN Panel" in resp_en.text
