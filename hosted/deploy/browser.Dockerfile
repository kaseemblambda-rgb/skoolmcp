FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY hosted/deploy/requirements-browser.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && python -m playwright install --with-deps chromium && chmod -R a+rX /opt/playwright && rm /tmp/requirements.txt
# Pinned upstream Linux/amd64 Tini. Verify before installing or enabling execution.
RUN python - <<'TINI_INSTALL'
import hashlib
from pathlib import Path
from urllib.request import urlopen
url = "https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64"
expected = "93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c"
with urlopen(url, timeout=30) as response:
    data = response.read(1048577)
if len(data) > 1048576 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit("E_TINI_CHECKSUM")
destination = Path("/usr/local/bin/tini")
destination.write_bytes(data)
destination.chmod(0o555)
TINI_INSTALL
RUN groupadd --gid 10001 stealth && useradd --uid 10001 --gid stealth --create-home stealth
COPY catknows/__init__.py /app/catknows/__init__.py
COPY catknows/auth.py /app/catknows/auth.py
COPY catknows/hosted_browser_service.py /app/catknows/hosted_browser_service.py
COPY catknows/hosted_security.py /app/catknows/hosted_security.py
COPY catknows/hosted_private_tls.py /app/catknows/hosted_private_tls.py
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/tini", "--"]
CMD ["python", "-m", "catknows.hosted_browser_service"]
