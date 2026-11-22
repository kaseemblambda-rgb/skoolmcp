"""Private browser service. Receives only an internal secret and temporary job IDs."""
import asyncio
import base64
import hmac
import ipaddress
import socket
import os
import secrets
import tempfile
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

LOGIN="https://www.skool.com/login"


WAF_HOST = "017ae153ccc5.edge.sdk.awswaf.com"
BROWSER_HOSTS = frozenset({"www.skool.com", "ct.skool.com", "api2.skool.com", "assets.skool.com", WAF_HOST})


def allowed_request(url, method, resource, top_level=True):
    """Password login only. No provider redirects, email codes, or arbitrary hosts."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment
                or parsed.port not in (None,443) or parsed.hostname not in BROWSER_HOSTS):
            return False
        # The exact hostname allowlist also rejects every IP literal/metadata host.
        if resource == "document":
            return top_level and parsed.hostname == "www.skool.com" and parsed.path == "/login" and method == "GET"
        if parsed.hostname == "www.skool.com" and method == "GET" and parsed.path.startswith("/_next/static/"):
            return resource != "websocket"
        if parsed.hostname == "api2.skool.com":
            return method == "POST" and parsed.path == "/auth/login" and resource in ("fetch","xhr")
        if parsed.hostname == "ct.skool.com":
            if parsed.path.startswith("/auth/"):
                return False
            return (method in ("GET","POST") and resource in ("fetch","xhr","ping")) or (
                method == "GET" and resource in ("script","image"))
        if parsed.hostname == WAF_HOST:
            if parsed.path == "/auth" or parsed.path.startswith("/auth/"):
                return False
            if method == "GET" and resource == "script":
                return parsed.path.endswith("/challenge.js")
            if resource in ("fetch","xhr"):
                return (method == "GET" and parsed.path == "/inputs") or method == "POST"
            return method == "GET" and resource == "image"
        if parsed.hostname == "assets.skool.com":
            return method == "GET" and resource in ("script","stylesheet","font","image")
        return (parsed.hostname == "www.skool.com" and method == "GET"
            and parsed.path.startswith(("/_next/static/","/favicon","/assets/"))
            and resource in ("script","stylesheet","font","image"))
    except (ValueError,UnicodeError):
        return False


def public_host_rules():
    """Resolve only the allowlist, reject non-public answers, and pin browser DNS."""
    rules = []
    for host in sorted(BROWSER_HOSTS):
        addresses = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}
        if not addresses or any(not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved for ip in addresses):
            raise ValueError("Browser destination must have public addresses only")
        ip = sorted(addresses,key=lambda ip:(ip.version,str(ip)))[0]
        rules.append("MAP " + host + " " + (str(ip) if ip.version==4 else "["+str(ip)+"]"))
    # No second DNS lookup can rebind an allowed hostname to a private address.
    return ",".join(rules + ["MAP * ~NOTFOUND"])


PASSWORD_ONLY = r"""
(()=>{
 const hide=()=>{
  for(const node of document.querySelectorAll('button,a,[role="button"]')){
   const label=[node.textContent,node.getAttribute('aria-label'),node.getAttribute('title'),
    node.getAttribute('href'),node.getAttribute('id'),node.getAttribute('class'),
    ...Array.from(node.querySelectorAll?.('img,svg')||[]).map(n=>[n.getAttribute('alt'),n.getAttribute('aria-label')].join(' '))].join(' ');
   if(/google|apple|email.{0,30}code|code.{0,30}email/i.test(label)){
    node.hidden=true;node.setAttribute('aria-hidden','true');node.setAttribute('tabindex','-1');
    node.style.setProperty('display','none','important');
   }
  }
 };
 hide();new MutationObserver(hide).observe(document,{childList:true,subtree:true,characterData:true,
  attributes:true,attributeFilter:['aria-label','title','href','id','class']});
})();
"""


class LoginDiagnostics:
    """Only fixed categories, counts and HTTP statuses; never URLs or payloads."""
    def __init__(self):
        self.blocked_requests=0
        self.failed_requests=0
        self.login_status=None
        self.waf_status=None
        self.challenge_status=None
        self._logged=None

    def log(self):
        from .hosted_security import login_diagnostics
        values=dict(blocked_requests=self.blocked_requests,failed_requests=self.failed_requests,
            login_status=self.login_status,waf_status=self.waf_status,challenge_status=self.challenge_status)
        if values != self._logged:
            login_diagnostics(values)
            self._logged=values.copy()

    def blocked(self):
        self.blocked_requests=min(10000,self.blocked_requests+1)

    def failed(self):
        self.failed_requests=min(10000,self.failed_requests+1)

    def response(self,url,status):
        parsed=urlsplit(url)
        if parsed.hostname=="api2.skool.com" and parsed.path in (
                "/auth/login","/auth/login-with-code","/auth/login-with-code-init","/auth/login-with-token"):
            self.login_status=status
        elif parsed.hostname=="017ae153ccc5.edge.sdk.awswaf.com":
            self.waf_status=status
        elif parsed.hostname=="challenges.cloudflare.com":
            self.challenge_status=status

    def snapshot(self,session,challenge_frame=False):
        self.log()
        return dict(blocked_requests=self.blocked_requests,failed_requests=self.failed_requests,
            login_status=self.login_status,waf_status=self.waf_status,challenge_status=self.challenge_status,
            auth_cookie_present=session.is_valid,waf_cookie_present=bool(session.waf_token),
            challenge_frame_present=challenge_frame)


class LoginBrowser:
    def __init__(self):
        self.network=LoginDiagnostics()
        self.page=None

    async def start(self):
        from playwright.async_api import async_playwright
        self.directory=tempfile.TemporaryDirectory(prefix="stealth-login-")
        self.driver=await async_playwright().start()
        dns_rules=await asyncio.to_thread(public_host_rules)
        self.browser=await self.driver.chromium.launch(headless=True,chromium_sandbox=True,
            args=["--host-resolver-rules="+dns_rules],
            env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),"HOME":self.directory.name,
                 "TMPDIR":self.directory.name,"LANG":"C.UTF-8"})
        self.context=await self.browser.new_context(viewport={"width":1024,"height":768},
            accept_downloads=False,service_workers="block",permissions=[])
        await self.context.add_init_script(PASSWORD_ONLY)
        self.context.on("response",lambda response:self.network.response(response.url,response.status))
        self.context.on("requestfailed",lambda request:self.network.failed())
        await self.context.route("**/*",self.route_request)
        # No page-created sockets, and no navigation can escape through a new page.
        await self.context.route_web_socket("**/*",lambda socket:socket.close())
        self.context.on("page",self.opened_page)
        self.page=await self.context.new_page()
        self.page.on("framenavigated",lambda frame:asyncio.create_task(self.check_navigation(frame)))
        await self.page.goto(LOGIN,wait_until="domcontentloaded",timeout=20000)

    def opened_page(self, page):
        if self.page is None:
            self.page=page
        elif page is not self.page:
            asyncio.create_task(page.close())

    async def check_navigation(self, frame):
        if frame is self.page.main_frame and not allowed_request(frame.url,"GET","document",True):
            from .hosted_security import blocked_host, blocked_request
            try: host=urlsplit(frame.url).hostname or "invalid-host"
            except ValueError: host="invalid-host"
            blocked_host(host)
            blocked_request(frame.url,"GET","document")
            await self.page.close()

    async def route_request(self, route):
        from .hosted_security import blocked_host, blocked_request
        request=route.request
        try:
            frame=request.frame
            accepted=(frame.page is self.page and allowed_request(request.url,request.method,
                request.resource_type,frame is self.page.main_frame))
        except Exception:
            accepted=False
        if accepted:
            await route.continue_()
        else:
            self.network.blocked()
            try: host=urlsplit(request.url).hostname or "invalid-host"
            except ValueError: host="invalid-host"
            blocked_host(host)
            blocked_request(request.url,request.method,request.resource_type)
            await route.abort("blockedbyclient")

    async def command(self, command):
        kind=command.get("type")
        if kind=="click":
            x,y=command.get("x"),command.get("y")
            if type(x) not in (int,float) or type(y) not in (int,float) or not 0<=x<1024 or not 0<=y<768:
                raise ValueError("Invalid position")
            await self.page.mouse.click(x,y)
        elif kind in ("text","type","paste"):
            text=command.get("text")
            if not isinstance(text,str) or len(text)>512:
                raise ValueError("Invalid input")
            if kind=="type":
                await self.page.keyboard.type(text)
            else:
                # Paste directly into the focused remote element. Never read or
                # write a server clipboard, password database, log or recording.
                await self.page.keyboard.insert_text(text)
        elif kind=="key":
            key=command.get("key")
            modifiers=command.get("modifiers",[])
            if (not isinstance(modifiers,list) or len(modifiers)>2
                    or any(m not in ("ControlOrMeta","Shift") for m in modifiers)
                    or len(set(modifiers))!=len(modifiers)):
                raise ValueError("Invalid modifiers")
            if key not in ("Tab","Enter","Backspace","Delete","ArrowLeft","ArrowRight","ArrowUp","ArrowDown",
                           "Home","End","PageUp","PageDown","Escape","a"):
                raise ValueError("Invalid key")
            if key=="a" and modifiers!=["ControlOrMeta"]:
                raise ValueError("Invalid shortcut")
            if "ControlOrMeta" in modifiers and key not in ("a","Backspace","Delete","ArrowLeft","ArrowRight","Home","End"):
                raise ValueError("Invalid shortcut")
            await self.page.keyboard.press("+".join([*modifiers,key]))
        elif kind!="frame":
            raise ValueError("Invalid command")
        from .auth import _cookies_to_session
        # Only cookies for Skool's own URL enter the saved session.
        session=_cookies_to_session(await self.context.cookies(["https://www.skool.com/"]))
        self.network.log()
        if session.is_valid and session.waf_token:
            return {"session":{"cookie_header":session.cookie_header,
                    "auth_token":session.auth_token,"waf_token":session.waf_token}}
        frame=await self.page.screenshot(type="jpeg",quality=65)
        challenge=any(urlsplit(frame.url).hostname=="challenges.cloudflare.com"
                      for frame in getattr(self.page,"frames",[]))
        return {"frame":base64.b64encode(frame).decode(),
                "diagnostics":self.network.snapshot(session,challenge)}

    async def close(self):
        try:
            if hasattr(self,"browser"):
                await self.browser.close()
        finally:
            try:
                if hasattr(self,"driver"):
                    await self.driver.stop()
            finally:
                if hasattr(self,"directory"):
                    self.directory.cleanup()


def build_browser_app(factory=LoginBrowser, secret=None):
    from .hosted_security import install_private_logging
    install_private_logging()
    from .hosted_security import SECURITY_HEADERS
    def reply(content,status_code=200,headers=None):
        return JSONResponse(content,status_code=status_code,
            headers={**SECURITY_HEADERS,"Cache-Control":"no-store",**(headers or {})})
    secret=secret or os.environ["BROWSER_SERVICE_SECRET"]
    if len(secret)<32:
        raise ValueError("Strong internal secret required")
    jobs={}
    lock=asyncio.Lock()
    timers=set()

    async def destroy(job):
        value=jobs.pop(job,None)
        if value:
            async with value["lock"]:
                await value["browser"].close()

    async def expire(job):
        await asyncio.sleep(180)
        await destroy(job)

    async def endpoint(request):
        if not hmac.compare_digest(request.headers.get("x-browser-secret","").encode(),secret.encode()):
            return reply({"error":"Unauthorized"},status_code=401)
        body=bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body)>4096:
                return reply({"error":"Request too large"},status_code=413)
        import json
        try:
            data=json.loads(body)
            operation=data.get("operation")
            job=data.get("job")
            if operation not in ("start","command","close"):
                raise ValueError("Invalid operation")
            if not isinstance(job,str) or len(job)!=64 or any(c not in "0123456789abcdef" for c in job):
                raise ValueError("Invalid job")
            if operation=="start":
                async with lock:
                    if len(jobs)>=2 or job in jobs:
                        return reply({"error":"Browser capacity unavailable"},status_code=429)
                    browser=factory()
                    jobs[job]={"browser":browser,"lock":asyncio.Lock()}
                # Start/commands/expiry all serialize on this browser's lock.
                async with jobs[job]["lock"]:
                    try:
                        await asyncio.wait_for(browser.start(),timeout=25)
                    except BaseException:
                        jobs.pop(job,None)
                        await browser.close()
                        raise
                timer=asyncio.create_task(expire(job))
                timers.add(timer)
                timer.add_done_callback(timers.discard)
                return reply({"started":True})
            if operation=="close":
                await destroy(job)
                return reply({"closed":True})
            value=jobs[job]
            async with value["lock"]:
                result=await value["browser"].command(data.get("command")or{})
            if "session" in result:
                await destroy(job)
            return reply(result,headers={"Cache-Control":"no-store"})
        except Exception:
            await destroy(data.get("job") if isinstance(locals().get("data"),dict) else None)
            return reply({"error":"Login browser unavailable"},status_code=400)

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            for timer in list(timers):
                timer.cancel()
            await asyncio.gather(*list(timers),return_exceptions=True)
            for job in list(jobs):
                await destroy(job)

    return Starlette(routes=[Route("/job",endpoint,methods=["POST"])],lifespan=lifespan)


def main():
    # Keep all database and encryption credentials out of this service.
    if any(os.environ.get(k) for k in ("SUPABASE_SERVICE_ROLE_KEY","SUPABASE_ACCESS_TOKEN","SKOOL_SESSION_ENCRYPTION_KEY","SKOOL_SESSION_PREVIOUS_KEYS","CATKNOWS_COOKIE","CATKNOWS_PROFILE_DIR","HOSTED_OWNER_PROFILE_DIR")) or any(k.startswith(('HOSTED_DB_','HOSTED_EXPORT_')) for k in os.environ):
        raise SystemExit("Browser service contains forbidden configuration")
    import uvicorn
    from .hosted_security import install_private_logging
    from .hosted_private_tls import browser_server_tls
    install_private_logging()
    try:
        with browser_server_tls() as tls:
            uvicorn.run(build_browser_app(),host="0.0.0.0",port=int(os.environ.get("PORT","8001")),
                        access_log=False,log_level="warning",proxy_headers=False,**tls)
    except Exception:
        raise SystemExit('Browser service startup failed') from None


if __name__=="__main__":
    main()
