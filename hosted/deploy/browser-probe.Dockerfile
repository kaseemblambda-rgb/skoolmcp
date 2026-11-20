FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
COPY hosted/deploy/requirements-browser.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && python -m playwright install --with-deps chromium && chmod -R a+rX /opt/playwright && rm /tmp/requirements.txt
RUN groupadd --gid 10001 stealth && useradd --uid 10001 --gid stealth --create-home stealth
COPY catknows/__init__.py /app/catknows/__init__.py
COPY catknows/auth.py /app/catknows/auth.py
COPY catknows/hosted_browser_service.py /app/catknows/hosted_browser_service.py
COPY catknows/hosted_security.py /app/catknows/hosted_security.py
COPY catknows/hosted_private_tls.py /app/catknows/hosted_private_tls.py
COPY hosted/deploy/probe/requirements.txt /tmp/probe-requirements.txt
RUN pip install --no-cache-dir -r /tmp/probe-requirements.txt && rm /tmp/probe-requirements.txt
COPY hosted/deploy/probe/__init__.py /app/hosted_probe/__init__.py
COPY hosted/deploy/probe/common.py /app/hosted_probe/common.py
COPY hosted/deploy/probe/tls.py /app/hosted_probe/tls.py
COPY hosted/deploy/probe/main.py /app/hosted_probe/main.py
COPY hosted/deploy/probe/browser.py /app/hosted_probe/browser.py
USER 10001:10001
CMD ["python", "-m", "hosted_probe.main", "--mode", "browser", "--container", "--serve", "--private-service", "--live-browser"]
