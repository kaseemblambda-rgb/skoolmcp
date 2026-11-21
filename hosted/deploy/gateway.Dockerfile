FROM python:3.13-slim-bookworm@sha256:f3dac913ab53b78c64f26d5518fcd7043d5a1a46522d6a493b598c3ed12f62a6
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY hosted/deploy/requirements-gateway.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt
RUN groupadd --gid 10001 stealth && useradd --uid 10001 --gid stealth --create-home stealth
COPY catknows/__init__.py /app/catknows/__init__.py
COPY catknows/auth.py /app/catknows/auth.py
COPY catknows/client.py /app/catknows/client.py
COPY catknows/http.py /app/catknows/http.py
COPY catknows/audit.py /app/catknows/audit.py
COPY catknows/normalize.py /app/catknows/normalize.py
COPY catknows/hosted_server.py /app/catknows/hosted_server.py
COPY catknows/hosted_database.py /app/catknows/hosted_database.py
COPY catknows/hosted_connect.py /app/catknows/hosted_connect.py
COPY catknows/hosted_oauth.py /app/catknows/hosted_oauth.py
COPY catknows/hosted_popup.py /app/catknows/hosted_popup.py
COPY catknows/hosted_sessions.py /app/catknows/hosted_sessions.py
COPY catknows/hosted_keys.py /app/catknows/hosted_keys.py
COPY catknows/hosted_security.py /app/catknows/hosted_security.py
COPY catknows/hosted_private_tls.py /app/catknows/hosted_private_tls.py
COPY catknows/hosted_analytics.py /app/catknows/hosted_analytics.py
COPY catknows/hosted_activity.py /app/catknows/hosted_activity.py
COPY catknows/hosted_tools.py /app/catknows/hosted_tools.py
COPY catknows/hosted_membership.py /app/catknows/hosted_membership.py
USER 10001:10001
CMD ["python", "-m", "catknows.hosted_server"]
