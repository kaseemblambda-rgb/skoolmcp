"""One authorization window: Skool stream, then explicit connector consent."""
import asyncio
import json
import secrets
import re
import time
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute

from .auth import Session
from .hosted_connect import BrowserBridge, SCRIPT as KEYBOARD_SCRIPT
from .hosted_keys import keyring, encrypt_session
from .hosted_oauth import hashed, secret, skool_identity, authorization_redirect
from .hosted_security import RateBudget, SECURITY_HEADERS, client_ip

COOKIE = "__Host-stealth_oauth"
MANAGEMENT_COOKIE = "__Host-stealth_manage"
PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Connect Stealth MCP</title><style>
body{font:16px Arial,sans-serif;max-width:1050px;margin:24px auto;padding:16px;color:#17202a;background:#faf9fa}
button{font:inherit;padding:12px 24px;border:1px solid #ddd;border-radius:10px;background:white;cursor:pointer}
#approve{background:#f0175e;color:white;border-color:#f0175e}img{max-width:100%;border:1px solid #ddd}
img:focus-visible,button:focus-visible{outline:2px solid #f0175e;outline-offset:3px}
#consent{background:white;border:1px solid #ddd;border-radius:16px;padding:24px}#message{min-height:24px}
[hidden]{display:none!important}</style>
<h1>Connect Stealth MCP</h1><p>Your typing passes through this temporary browser service to Skool. Passwords are not saved.</p><p id="message" role="status">Preparing your Skool sign-in.</p>
<p id="diagnostics" role="status" aria-live="polite"></p>
<img id="screen" alt="Skool email and password sign-in" tabindex="0" hidden>
<button id="connect" hidden>Connect Skool</button><button id="disconnect" hidden>Disconnect Skool</button>
<section id="consent" hidden><h2>Allow this connector to read your Skool communities?</h2>
<p id="client"></p><p>Read-only access to communities where you are an owner or admin. No posting or messages.</p>
<button id="approve">Approve</button> <button id="deny">Deny</button></section>
<script src="/connect/popup.js" defer></script>'''

# Reuse the tested keyboard, paste, input queue and screenshot scaling implementation.
SCRIPT = KEYBOARD_SCRIPT.replace("let ws=null, busy=false, timer=null;", """let ws=null, busy=false, timer=null, flow=null, complete=false;
const consent=document.querySelector('#consent');
const initialTicket=location.hash.slice(1);
history.replaceState(null,'',location.pathname);""")
start = SCRIPT.index("async function post(")
end = SCRIPT.index("function transmit(")
SCRIPT = SCRIPT[:start] + """async function post(path,body={}){
 const r=await fetch(path,{method:'POST',headers:{'X-Stealth-CSRF':'1','X-Stealth-Flow':flow||'',
  'Content-Type':'application/json'},body:JSON.stringify(body)});
 if(r.status===429)throw Error('Secure browser capacity reached. Try connecting again shortly.');
 if(!r.ok)throw Error('Connection unavailable. Start the connection again from your AI app.');
 return r.json();
}
""" + SCRIPT[end:]
SCRIPT = SCRIPT.replace("/account/skool/stream", "/connect/stream").replace("JSON.stringify({ticket})", "JSON.stringify({flow})")
start = SCRIPT.index("  if(v.connected){")
end = SCRIPT.index("  if(v.diagnostics){")
SCRIPT = SCRIPT[:start] + """  if(v.error){complete=true;clearStream();message.textContent=v.error;return;}
  if(v.ready){
   complete=true;
   clearStream();
   consent.hidden=false;
   message.textContent='Skool sign-in verified. Review access below.';
   return;
  }
""" + SCRIPT[end:]
SCRIPT = SCRIPT.replace("  if(!message.textContent.startsWith('Skool connected')", "  if(!complete&&!message.textContent.startsWith('Skool connected')")
start = SCRIPT.index("connect.onclick=")
end = SCRIPT.index("screen.onclick=")
SCRIPT = SCRIPT[:start] + """
async function decide(approve){
 const buttons=[document.querySelector('#approve'),document.querySelector('#deny')];
 buttons.forEach(b=>b.disabled=true);
 try{const value=await post('/connect/decision',{approve});location.replace(value.redirect);}
 catch(e){message.textContent=e.message;buttons.forEach(b=>b.disabled=false);}
}
document.querySelector('#approve').onclick=()=>decide(true);
document.querySelector('#deny').onclick=()=>decide(false);
document.querySelector('#disconnect').onclick=async()=>{
 try{await post('/connect/disconnect');clearStream();consent.hidden=true;complete=true;
  if(ws)ws.close();message.textContent='Skool disconnected.';
 }catch(e){message.textContent=e.message;}
};
(async()=>{
 if(!initialTicket){document.querySelector('#disconnect').hidden=false;message.textContent='Start Connect from your AI app. You can disconnect a previously saved session here.';return;}
 try{
  const value=await post('/connect/bootstrap',{ticket:initialTicket});
  flow=value.flow;
  document.querySelector('#client').textContent=value.client_name+' ('+value.redirect_origin+')';
  await post('/connect/start');
  openLogin();
 }catch(e){message.textContent=e.message;}
})();
""" + SCRIPT[end:]


def routes(settings, provider, identity_reader=skool_identity, bridge_factory=BrowserBridge):
    active = set()
    attempts = RateBudget(10)
    def csrf(request):
        return request.headers.get("origin") == settings.public_origin and request.headers.get("x-stealth-csrf") == "1"
    def result(data, status=200):
        return JSONResponse(data, status_code=status, headers={**SECURITY_HEADERS,"Cache-Control":"no-store","Referrer-Policy":"no-referrer"})
    async def body(request):
        raw = await request.body()
        if len(raw) > 2048:
            raise ValueError("Invalid request")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Invalid request")
        return data
    def binding(request, flow=None):
        cookie = request.cookies.get(COOKIE, "")
        handle = flow if flow is not None else request.headers.get("x-stealth-flow", "")
        if not 32 <= len(cookie) <= 128 or not isinstance(handle,str) or len(handle) != 64:
            raise ValueError("Login binding unavailable")
        return dict(browser_hash=hashed(cookie), handle_hash=handle)
    async def page(request):
        return HTMLResponse(PAGE, headers={**SECURITY_HEADERS,"Cache-Control":"no-store","Referrer-Policy":"no-referrer",
            "Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
    async def script(request):
        return Response(SCRIPT, media_type="application/javascript", headers={**SECURITY_HEADERS,"Cache-Control":"no-store"})
    async def bootstrap(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        try:
            if not attempts.allow(client_ip(request.scope)):
                return result({"error":"Retry in one minute"},429)
            ticket = (await body(request)).get("ticket")
            if not isinstance(ticket,str) or not ticket.startswith("st_l_") or len(ticket)>128:
                raise ValueError("Invalid login")
            cookie = request.cookies.get(COOKIE, "")
            if not cookie.startswith("st_b_") or not 32<=len(cookie)<=128:
                raise ValueError("Authorization browser required")
            handle = hashed(ticket)
            row = await provider.call("flow_bind", handle_hash=handle, browser_hash=hashed(cookie))
            if not row:
                raise ValueError("Login expired")
            client = await provider.get_client(row["client_id"])
            response = result(dict(flow=handle, client_name=client.client_name or "MCP connector",
                redirect_origin=urlsplit(row["request"]["redirect_uri"]).netloc))
            response.set_cookie(COOKIE,cookie,secure=True,httponly=True,samesite="strict",path="/",max_age=300)
            return response
        except Exception:
            return result({"error":"Login unavailable. Start again from your AI app."},400)
    async def start(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        args=None
        try:
            args=binding(request)
            reserved=await provider.call("flow_reserve",**args)
            if isinstance(reserved,dict) and reserved.get("capacity"):
                await provider.call("flow_abort",**args)
                return result({"error":"Secure browser capacity reached"},429)
            if reserved is not True:
                return result({"error":"Login unavailable"},400)
            return result({"reserved":True})
        except Exception:
            if args:
                try: await provider.call("flow_abort",**args)
                except Exception: pass
            return result({"error":"Login unavailable"},503)
    async def decision(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        try:
            data = await body(request)
            if type(data.get("approve")) is not bool:
                raise ValueError("Invalid choice")
            code = secret("st_c_")
            management = secret("st_m_")
            row = await provider.call("flow_decide", **binding(request), approve=data["approve"],
                code_hash=hashed(code), management_hash=hashed(management))
            if not row:
                raise ValueError("Consent expired")
            req = row["request"]
            args = {"code":code} if data["approve"] else {"error":"access_denied"}
            response = result({"redirect":authorization_redirect(provider,req["redirect_uri"],
                state=req.get("state"),**args)})
            if data["approve"]:
                response.set_cookie(MANAGEMENT_COOKIE,management,secure=True,httponly=True,
                    samesite="strict",path="/",max_age=30*86400)
            response.delete_cookie(COOKIE,path="/",secure=True,httponly=True,samesite="strict")
            return response
        except Exception:
            try: await provider.call("flow_abort",**binding(request))
            except Exception: pass
            return result({"error":"Consent unavailable. Start again from your AI app."},400)
    async def disconnect(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        cookie = request.cookies.get(MANAGEMENT_COOKIE, "")
        if not 32 <= len(cookie) <= 128:
            return result({"error":"Unauthorized"},401)
        try:
            if not await provider.call("disconnect", browser_hash=hashed(cookie)):
                return result({"error":"Unauthorized"},401)
            response = result({"disconnected":True})
            response.delete_cookie(MANAGEMENT_COOKIE,path="/",secure=True,httponly=True,samesite="strict")
            return response
        except Exception:
            return result({"error":"Disconnect unavailable"},503)
    async def stream(socket):
        if socket.headers.get("origin") != settings.public_origin:
            await socket.close(code=1008)
            return
        bridge = None
        key = None
        args = None
        claimed = False
        ready = False
        await socket.accept()
        job = secrets.token_hex(32)
        try:
            first = await asyncio.wait_for(socket.receive_text(),10)
            if len(first)>256:
                raise ValueError("Invalid binding")
            args = binding(socket,json.loads(first).get("flow"))
            key = args["handle_hash"]
            if key in active or not await provider.call("flow_claim",**args):
                raise ValueError("Login already started")
            active.add(key)
            claimed = True
            bridge = bridge_factory()
            await asyncio.to_thread(bridge.call,"start",job)
            deadline = time.monotonic()+160
            command = {"type":"frame"}
            while time.monotonic()<deadline:
                if not await provider.call("flow_get",**args):
                    raise ValueError("Login ended")
                data = await asyncio.to_thread(bridge.call,"command",job,command)
                if "session" in data:
                    session = Session(**data.pop("session"))
                    if not session.is_valid or not session.waf_token:
                        raise ValueError("Skool authentication unavailable")
                    skool_id = await asyncio.to_thread(identity_reader,session)
                    # Never accept an identity from a browser command or OAuth client.
                    if not isinstance(skool_id,str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}",skool_id):
                        raise ValueError("Invalid Skool identity")
                    account = await provider.call("account",skool_user_id=skool_id)
                    if not account or await provider.call("paid",account_id=account["id"]) is not True:
                        await socket.send_json({"error":"Paid SFC membership is required."})
                        return
                    version,keys = keyring()
                    encrypted = encrypt_session(account["id"],session,version,keys[version])
                    session = None
                    if await provider.call("flow_ready",**args,account_id=account["id"],encrypted_session=encrypted) is not True:
                        raise ValueError("Login invalidated")
                    await socket.send_json({"ready":True})
                    ready = True
                    return
                safe = {}
                for name in ("blocked_requests","failed_requests","login_status","waf_status","challenge_status"):
                    value = (data.get("diagnostics") or {}).get(name)
                    if type(value) is int and 0<=value<=10000:
                        safe[name]=value
                for name in ("auth_cookie_present","waf_cookie_present","challenge_frame_present"):
                    value=(data.get("diagnostics") or {}).get(name)
                    if type(value) is bool:
                        safe[name]=value
                await socket.send_json({"frame":data["frame"],"diagnostics":safe})
                raw = await asyncio.wait_for(socket.receive_text(),timeout=min(15,max(.1,deadline-time.monotonic())))
                if len(raw)>2048:
                    raise ValueError("Invalid input")
                command=json.loads(raw)
        except (Exception,asyncio.CancelledError):
            pass
        finally:
            if claimed:
                active.discard(key)
            if bridge:
                try: await asyncio.to_thread(bridge.call,"close",job)
                except Exception: pass
                else:
                    if claimed and args:
                        try: await provider.call("job_release",**args)
                        except Exception: pass
            elif claimed and args:
                try: await provider.call("job_release",**args)
                except Exception: pass
            if claimed and not ready and args:
                try: await provider.call("flow_abort",**args)
                except Exception: pass
            try: await socket.close()
            except Exception: pass
    return [Route("/connect/skool",page),Route("/connect/popup.js",script),
        Route("/connect/bootstrap",bootstrap,methods=["POST"]),Route("/connect/start",start,methods=["POST"]),Route("/connect/decision",decision,methods=["POST"]),
        Route("/connect/disconnect",disconnect,methods=["POST"]),WebSocketRoute("/connect/stream",stream)]
