# Small base image: less installed software means less to attack.
FROM python:3.13-slim

# Don't write .pyc files; print logs straight away instead of buffering them.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# A normal user to run the app. If the app were ever compromised,
# the attacker would not be root inside the container.
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Install dependencies first, so Docker can reuse this layer when only code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The code stays owned by root, so the app user can run it but not change it.
COPY securenotes/ securenotes/

# Only the instance folder (database and security log) is writable by the app.
RUN mkdir instance && chown appuser:appuser instance
VOLUME /app/instance

USER appuser
EXPOSE 8000

# Create the database only if it doesn't exist yet (init-db deletes all data),
# then start gunicorn, a production server (Flask's own server is for development).
# One worker process with threads: the rate limiter counts attempts in memory,
# so several processes would each keep their own count and multiply the limit.
CMD ["sh", "-c", "[ -f instance/securenotes.sqlite ] || python -m flask --app securenotes init-db; exec gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 4 --access-logfile - 'securenotes:create_app()'"]
