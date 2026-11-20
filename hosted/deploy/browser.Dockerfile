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
USER 10001:10001
CMD ["python", "-m", "catknows.hosted_browser_service"]
