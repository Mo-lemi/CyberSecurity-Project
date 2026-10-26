"""Security event log (threat R1): a record of who did what, and when.

Each event is one line of JSON in instance/security.log, e.g.
{"time": "2026-10-26T14:03:11+00:00", "event": "login_failed", "ip": "127.0.0.1", ...}

Never logged: passwords or note contents.
"""

import json
import logging
import os
from datetime import datetime, timezone

from flask import g, request

logger = logging.getLogger("securenotes.security")
logger.setLevel(logging.INFO)

# Usernames typed into a failed login can be anything an attacker likes,
# so they are cut short before being logged.
MAX_LOGGED_TEXT = 50


def log_event(event, **details):
    """Write one security event, with the time, IP address and logged-in user."""
    user = g.get("user")
    record = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "ip": request.remote_addr,
        "user_id": user["id"] if user else None,
    }
    for key, value in details.items():
        record[key] = value[:MAX_LOGGED_TEXT] if isinstance(value, str) else value
    # json.dumps turns a newline inside a value into the two characters "\n",
    # so input can never start a fake extra line in the log (log injection).
    logger.info(json.dumps(record))


def init_app(app):
    path = app.config.setdefault(
        "SECURITY_LOG", os.path.join(app.instance_path, "security.log")
    )
    # Replace any handler from a previous app (the tests create many apps).
    for old_handler in list(logger.handlers):
        logger.removeHandler(old_handler)
        old_handler.close()
    # delay=True: the file is only created once there is something to write.
    handler = logging.FileHandler(path, encoding="utf-8", delay=True)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
