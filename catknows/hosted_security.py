"""Hosted-only transport and logging boundaries. No local-client side effects."""
import logging
import time
from urllib.parse import urlsplit

EVENTS = frozenset({"tool_succeeded", "tool_denied", "tool_failed", "tool_busy"})


def install_private_logging():
    """Drop free-form messages, arguments and tracebacks before any handler sees them."""
    if getattr(logging.getLogRecordFactory(), "_stealth_private", False):
        return
    def factory(*args, **kwargs):
        record = logging.LogRecord(*args, **kwargs)
        event = record.msg if record.name == "stealth.hosted.audit" and isinstance(record.msg, str) else None
        if record.name == "stealth.hosted.blocked_host":
            import re
            host = record.msg if isinstance(record.msg,str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}",record.msg) else "invalid-host"
            record.msg = "blocked_host="+host
        elif record.name == "stealth.hosted.login_diagnostics":
            import json
            record.msg = "login_diagnostics="+json.dumps(safe_login_diagnostics(record.msg),sort_keys=True,separators=(",",":"))
        elif record.name == "stealth.hosted.blocked_request":
            import json
            record.msg = "blocked_request="+json.dumps(safe_blocked_request(record.msg),sort_keys=True,separators=(",",":"))
        else:
            record.msg = event if event in EVENTS else "hosted_diagnostic"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        record.name = "stealth.hosted"
        return record
    factory._stealth_private = True
    logging.setLogRecordFactory(factory)
    # Uvicorn's access formatter expects raw request arguments. Never enable it.
    logging.getLogger("uvicorn.access").disabled = True


def audit(event):
    if event not in EVENTS:
        raise ValueError("Unknown audit event")
    logger = logging.getLogger("stealth.hosted.audit")
    logger.setLevel(logging.INFO)
    logger.info(event)


def blocked_host(host):
    """The only dynamic log value is a parsed hostname, never a URL or payload."""
    logging.getLogger("stealth.hosted.blocked_host").warning(host)


def safe_login_diagnostics(values):
    """Fixed bounded counts/statuses only; never request URLs, cookies or payloads."""
    safe={}
    if isinstance(values,dict):
        for name in ("blocked_requests","failed_requests","login_status","waf_status","challenge_status"):
            value=values.get(name)
            if type(value) is int and (0<=value<=10000 if name.endswith("_requests") else 100<=value<=599):
                safe[name]=value
    return safe


def login_diagnostics(values):
    logger=logging.getLogger("stealth.hosted.login_diagnostics")
    logger.setLevel(logging.INFO)
    logger.info(safe_login_diagnostics(values))


def safe_blocked_request(values):
    """Temporary policy diagnostics: fixed categories and redacted path only."""
    import re
    if not isinstance(values,dict):
        values={}
    method=values.get("method")
    resource=values.get("resource_type")
    host=values.get("host")
    path=values.get("path")
    # Opaque IDs, build hashes and tokens can occur in paths, not just queries.
    known=frozenset(("login","auth","_next","static","data","assets","favicon.ico",
        "challenge.js","challenge","inputs","verify","verifycaptcha","captcha","collect",
        "events","event","telemetry","v1","v2","api","pixel","index.html"))
    parts=path.split("/") if isinstance(path,str) and len(path)<=4096 else []
    redacted="/"+"/".join(part if part in known else "<redacted>" for part in parts if part)[:512]
    return dict(method=method if method in ("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD") else "unknown",
        resource_type=resource if resource in ("document","stylesheet","image","media","font","script",
            "texttrack","xhr","fetch","eventsource","websocket","manifest","ping","other") else "unknown",
        host=host if isinstance(host,str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}",host) else "invalid-host",
        path=redacted)


def blocked_request(url,method,resource_type):
    """Never inspect request headers/body or log a raw URL/query/fragment."""
    try:
        parsed=urlsplit(url)
        values=dict(method=method,resource_type=resource_type,host=parsed.hostname or "invalid-host",path=parsed.path)
    except (ValueError,UnicodeError,TypeError):
        values={}
    logging.getLogger("stealth.hosted.blocked_request").warning(safe_blocked_request(values))


class ReadOnlyTransport:
    """Only GETs to exact Skool HTTPS origins; credentials never follow redirects."""
    def __init__(self, transport):
        self.__transport = transport

    def get(self, url, **kwargs):
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname not in ("www.skool.com", "api2.skool.com")
                or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment):
            raise PermissionError("Read-only Skool origin required")
        kwargs["allow_redirects"] = False
        response = self.__transport.get(url, **kwargs)
        if 300 <= response.status_code < 400:
            raise PermissionError("Skool redirect refused")
        return response

    def close(self):
        return self.__transport.close()

    def __getattr__(self, name):
        raise PermissionError("Read-only transport")


class RateBudget:
    """Bounded per-process fixed-window limit; use one worker until distributed limits exist."""
    def __init__(self, limit, window=60, capacity=4096, clock=time.monotonic):
        self.limit, self.window, self.capacity, self.clock = limit, window, capacity, clock
        self.entries = {}

    def available(self, subject):
        """Inspect completed failures without reserving in-flight requests."""
        now = self.clock()
        entry = self.entries.get(subject)
        if entry is not None and now-entry[0] < self.window:
            return entry[1] < self.limit
        return (len(self.entries) < self.capacity
                or any(now-start >= self.window for start,_ in self.entries.values()))

    def allow(self, subject):
        now = self.clock()
        for key, (started, count) in list(self.entries.items()):
            if now-started >= self.window:
                del self.entries[key]
        entry = self.entries.get(subject)
        if entry is None:
            if len(self.entries) >= self.capacity:
                return False
            self.entries[subject] = (now, 1)
            return True
        started, count = entry
        if count >= self.limit:
            return False
        self.entries[subject] = (started, count+1)
        return True


SECURITY_HEADERS = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}


class ClientIPResolver:
    """Trust XFF only from explicitly configured Render peers, walking right to left."""
    def __init__(self, render_peers=None, forwarded_hops=None):
        import ipaddress
        import json
        import os
        peers = render_peers if render_peers is not None else json.loads(os.environ.get("HOSTED_RENDER_PROXY_CIDRS", "[]"))
        hops = forwarded_hops if forwarded_hops is not None else json.loads(os.environ.get("HOSTED_FORWARDED_PROXY_CIDRS", "[]"))
        self.peers = tuple(ipaddress.ip_network(v) for v in peers)
        self.hops = self.peers + tuple(ipaddress.ip_network(v) for v in hops)
        if any(n.prefixlen == 0 for n in self.hops):
            raise ValueError("Wildcard proxy trust is forbidden")
        if os.environ.get("RENDER") == "true" and not self.peers:
            raise ValueError("Configure verified Render proxy CIDRs before serving traffic")

    def resolve(self, scope):
        import ipaddress
        def address(value):
            if '%' in value:
                raise ValueError("Scoped IP is not a client address")
            ip = ipaddress.ip_address(value)
            return getattr(ip, "ipv4_mapped", None) or ip
        peer = address((scope.get('client') or ('',))[0])
        if not any(peer in network for network in self.peers):
            return str(peer)  # Never trust a direct client's forwarded headers.
        headers = [v for k,v in scope.get('headers',[]) if k.lower()==b'x-forwarded-for']
        if len(headers)!=1 or len(headers[0])>2048:
            raise ValueError("Trusted proxy must supply one bounded XFF chain")
        chain = headers[0].decode('ascii').split(',')
        if not 1<=len(chain)<=16:
            raise ValueError("Invalid proxy chain")
        for ip in reversed([address(v.strip()) for v in chain]):
            if not any(ip in network for network in self.hops):
                return str(ip)
        raise ValueError("No untrusted client address in proxy chain")


def client_ip(scope):
    return scope.get('stealth.client_ip') or ClientIPResolver().resolve(scope)


class OAuthBoundary:
    """Bound bodies, trusted proxy resolution, response headers and OAuth invariants."""
    def __init__(self, app, resource):
        import os
        import secrets
        self.app, self.resource = app, resource
        self.ips = ClientIPResolver()
        key = os.environ.get('HOSTED_IP_HASH_SECRET')
        if os.environ.get('RENDER')=='true' and (not key or len(key)<32):
            raise ValueError("Configure a strong IP hash secret before serving traffic")
        self.ip_key = key.encode() if key else secrets.token_bytes(32)
        self.registration_budget = RateBudget(100, window=3600)
        self.authorization_budget = RateBudget(10)
        self.failed_bearer_budget = RateBudget(300)

    def __getattr__(self, name):
        return getattr(self.app, name)

    async def __call__(self, scope, receive, send):
        from starlette.responses import JSONResponse, Response
        async def secure_send(message):
            if message['type']=='http.response.start':
                headers = [(k,v) for k,v in message['headers'] if k.lower() not in (b'x-frame-options',b'x-content-type-options')]
                message = {**message,'headers':headers+[(k.lower().encode(),v.encode()) for k,v in SECURITY_HEADERS.items()]}
            await send(message)
        if scope['type'] not in ('http','websocket'):
            return await self.app(scope,receive,secure_send)
        # Render probes carry no XFF. This fixed liveness response uses no identity,
        # database or auth, and bypasses IP parsing only for this exact route.
        if scope['type']=='http' and scope['path']=='/healthz' and scope['method'] in ('GET','HEAD'):
            return await Response('ok' if scope['method']=='GET' else '',media_type='text/plain')(scope,receive,secure_send)
        try:
            scope = {**scope,'stealth.client_ip':self.ips.resolve(scope)}
        except (ValueError,UnicodeError):
            if scope['type']=='websocket':
                return await send({'type':'websocket.close','code':1008})
            return await JSONResponse({'error':'invalid_request'},status_code=400)(scope,receive,secure_send)
        if scope['type']=='http' and (scope['path']=='/mcp' or scope['path'].startswith('/mcp/')):
            source = client_ip(scope)
            if not self.failed_bearer_budget.available(source):
                return await JSONResponse({'error':'temporarily_unavailable'},status_code=429)(scope,receive,secure_send)
            status = None
            async def bearer_send(message):
                nonlocal status
                if message['type']=='http.response.start':
                    status = message['status']
                await secure_send(message)
            await self.dispatch(scope,receive,bearer_send)
            # Shared provider IPs: charge completed 401s only. In-flight valid
            # requests never consume the failure budget.
            if status==401:
                self.failed_bearer_budget.allow(source)
            return
        if scope['type']=='http' and scope['path']=='/authorize':
            import secrets
            import hmac
            import hashlib
            from .hosted_oauth import authorization_browser, authorization_source
            if not self.authorization_budget.allow(client_ip(scope)):
                return await JSONResponse({'error':'temporarily_unavailable'},status_code=429)(scope,receive,secure_send)
            browser = "st_b_" + secrets.token_urlsafe(32)
            token = authorization_browser.set(browser)
            source = authorization_source.set(hmac.new(self.ip_key,client_ip(scope).encode(),hashlib.sha256).hexdigest())
            async def bound_send(message):
                if message['type']=='http.response.start' and message['status']==302:
                    response = Response()
                    response.set_cookie('__Host-stealth_oauth',browser,secure=True,httponly=True,
                        samesite='strict',path='/',max_age=300)
                    message = {**message,'headers':list(message['headers'])+
                        [(k,v) for k,v in response.raw_headers if k==b'set-cookie']}
                await secure_send(message)
            try:
                return await self.dispatch(scope,receive,bound_send)
            finally:
                authorization_browser.reset(token)
                authorization_source.reset(source)
        return await self.dispatch(scope,receive,secure_send)

    async def dispatch(self, scope, receive, send):
        from starlette.responses import JSONResponse
        from urllib.parse import parse_qs
        if scope['type']=='http' and scope['path']=='/authorize' and scope['method']=='GET':
            try:
                fields = parse_qs(scope['query_string'].decode(),keep_blank_values=True)
                if fields.get('code_challenge_method')!=['S256'] or any(len(v)!=1 for v in fields.values()):
                    raise ValueError("Explicit S256 required")
            except (ValueError,UnicodeError):
                return await JSONResponse({'error':'invalid_request'},status_code=400)(scope,receive,send)
        if scope['type']!='http' or scope['method']!='POST':
            return await self.app(scope,receive,send)
        body = bytearray()
        while True:
            message = await receive()
            if message['type']=='http.disconnect':
                return
            body.extend(message.get('body',b''))
            if len(body)>65536:
                return await JSONResponse({'error':'invalid_request'},status_code=413)(scope,receive,send)
            if not message.get('more_body',False):
                break
        if scope['path']=='/register' and not self.registration_budget.allow(client_ip(scope)):
            return await JSONResponse({'error':'temporarily_unavailable'},status_code=429)(scope,receive,send)
        if scope['path'] in ('/token','/authorize'):
            try:
                fields = parse_qs(body.decode(),keep_blank_values=True,strict_parsing=True)
                if any(len(v)!=1 for v in fields.values()):
                    raise ValueError("Repeated parameter")
                if scope['path']=='/token' and fields.get('resource')!=[self.resource]:
                    raise ValueError("Invalid resource")
                if scope['path']=='/authorize' and fields.get('code_challenge_method')!=['S256']:
                    raise ValueError("Explicit S256 required")
            except (ValueError,UnicodeError):
                error = 'invalid_target' if scope['path']=='/token' else 'invalid_request'
                return await JSONResponse({'error':error},status_code=400,
                    headers={'Cache-Control':'no-store'})(scope,receive,send)
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {'type':'http.request','body':bytes(body),'more_body':False}
            return await receive()
        return await self.app(scope,replay,send)
