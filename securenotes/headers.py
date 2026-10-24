"""Security headers added to every response. Each one tells the browser to
switch on an extra protection, as a second layer behind the app's own defences."""

from flask import request

# Content-Security-Policy: a list of where the page may load things from.
# SecureNotes uses no JavaScript at all, so scripts are blocked completely.
# Even if an XSS bug slipped past Jinja2's escaping, an injected <script>
# would not run (threat I3).
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'none'",  # block everything not allowed below
        "style-src 'self'",  # our own stylesheet only (no inline styles)
        "img-src 'self'",
        "form-action 'self'",  # forms can only submit to SecureNotes
        "frame-ancestors 'none'",  # no other site can put us in a frame (threat I7)
        "base-uri 'none'",
    ]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    # Older browsers don't understand frame-ancestors, so also block framing here.
    "X-Frame-Options": "DENY",
    # Don't let the browser guess a file's type (e.g. treat text as a script).
    "X-Content-Type-Options": "nosniff",
    # Don't tell other sites which SecureNotes page a user came from
    # (URLs contain note IDs).
    "Referrer-Policy": "no-referrer",
}


def add_security_headers(response):
    response.headers.update(SECURITY_HEADERS)
    # Pages may contain private notes: don't let the browser store copies.
    # Otherwise, on a shared computer, pressing Back after logging out
    # could show the previous user's notes. The stylesheet can still be cached.
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


def init_app(app):
    app.after_request(add_security_headers)
