import pytest


@pytest.mark.parametrize("url", ["/", "/auth/login", "/notes/999"])
def test_security_headers_on_every_page(client, url):
    """Headers are added to every response, including errors like 404."""
    headers = client.get(url).headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "script-src" not in csp  # no scripts allowed at all (threat I3)
    assert "frame-ancestors 'none'" in csp  # threat I7
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_private_pages_are_not_cached(make_user):
    browser = make_user("alice")
    assert browser.get("/notes/").headers["Cache-Control"] == "no-store"


def test_stylesheet_can_still_be_cached(client):
    assert client.get("/static/style.css").headers.get("Cache-Control") != "no-store"
