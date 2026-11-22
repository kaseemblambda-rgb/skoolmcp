"""Authenticated account API and public streaming gateway; browser jobs receive no identity."""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener
from uuid import UUID

import jwt
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute

from .hosted_keys import keyring, encrypt_session
from .hosted_server import NoRedirects, get_json, MemberVerifier, https_origin
from .hosted_membership import eligible
from datetime import datetime, timezone

COOKIE="__Host-stealth_account"


def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()


class AccountVerifier(MemberVerifier):
    """Verify an existing Supabase account login, scoped to the account API."""
    def identity_sync(self,token):
        try:
            if len(token)>16384:
                return None
            key=self.keys.get_signing_key_from_jwt(token)
            claims=jwt.decode(token,key.key,algorithms=["RS256","ES256"],
                issuer=self.settings.issuer,audience="authenticated",
                options={"require":["exp","iat","sub","iss","aud"]})
            subject=str(UUID(claims["sub"]))
            identity=get_json(self.settings.issuer+"/user",
                {"apikey":self.settings.service_key,"Authorization":"Bearer "+token})
            if identity.get("id")!=subject or not identity.get("email_confirmed_at"):
                return None
            email=identity.get("email")
            if not isinstance(email,str) or not email.strip():
                return None
            return subject,email.strip().lower()
        except Exception:
            return None

    def verify_sync(self,token):
        try:
            identity=self.identity_sync(token)
            if identity is None:
                return None
            subject,email=identity
            query=urlencode({"select":"tier,lifecycle,paid_through_at,observed_at","email":"eq."+email})
            rows=get_json(self.settings.supabase_origin+"/rest/v1/hosted_entitlements?"+query,
                {"apikey":self.settings.service_key,"Authorization":"Bearer "+self.settings.service_key})
            if len(rows)!=1 or not eligible(rows[0],self.settings.paid_tiers,datetime.now(timezone.utc)):
                return None
            return subject
        except Exception:
            return None

    async def verify_identity_token(self,token):
        try:
            await asyncio.wait_for(self.slots.acquire(),timeout=0.1)
        except TimeoutError:
            return None
        try:
            identity=await asyncio.to_thread(self.identity_sync,token)
            return identity[0] if identity else None
        finally:
            self.slots.release()


class Store:
    def __init__(self,settings):
        self.database=settings.database
        self.origin=settings.supabase_origin
        self.headers={"apikey":settings.service_key,"Authorization":"Bearer "+settings.service_key}

    def rpc(self,name,payload):
        if self.database is not None:
            return self.database.rpc(name,payload)
        request=Request(self.origin+"/rest/v1/rpc/"+name,method="POST",data=json.dumps(payload).encode(),
                        headers={**self.headers,"Content-Type":"application/json"})
        with build_opener(NoRedirects()).open(request,timeout=10) as response:
            return json.loads(response.read(65536))

    def rows(self):
        if self.database is not None:
            raise PermissionError('Rotation requires a separately authorized maintenance role')
        cursor=None
        while True:
            params={"select":"user_id,ciphertext,nonce,key_version,revoked_at","order":"user_id","limit":"1"}
            if cursor:
                params["user_id"]="gt."+cursor
            rows=get_json(self.origin+"/rest/v1/hosted_skool_sessions?"+urlencode(params),self.headers)
            if not rows:
                return
            yield rows[0]
            cursor=rows[0]["user_id"]


class BrowserBridge:
    def __init__(self):
        self.origin=https_origin(os.environ["BROWSER_SERVICE_URL"])
        self.secret=os.environ["BROWSER_SERVICE_SECRET"]
        if len(self.secret)<32:
            raise ValueError("Strong browser-service credential required")
        from .hosted_private_tls import browser_client_context
        self.tls=browser_client_context()

    def call(self,operation,job,command=None):
        request=Request(self.origin+"/job",method="POST",
            data=json.dumps(dict(operation=operation,job=job,command=command)).encode(),
            headers={"Content-Type":"application/json","x-browser-secret":self.secret})
        from urllib.request import HTTPSHandler
        with build_opener(NoRedirects(),HTTPSHandler(context=self.tls)).open(request,timeout=30) as response:
            body=response.read(2000001)
            if len(body)>2000000:
                raise ValueError("Browser response too large")
            return json.loads(body)


PAGE="""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Connect Skool</title><style>body{font:16px Arial;max-width:1050px;margin:32px auto;padding:16px}button{padding:12px;border-radius:8px}img{max-width:100%;border:1px solid #ddd}img:focus-visible{outline:2px solid #f0175e;outline-offset:3px}#message{min-height:24px}</style>
<h1>Connect Skool</h1><p>Sign in on Skool's streamed login page. Disconnect deletes your saved Skool session.</p>
<button id="connect">Connect Skool</button> <button id="disconnect">Disconnect Skool</button>
<p id="message"></p><img id="screen" alt="Skool login page" tabindex="0" hidden>
<script src="/connect/skool.js" defer></script>"""
SCRIPT="""
const message=document.querySelector('#message');
const screen=document.querySelector('#screen');
const connect=document.querySelector('#connect');
let ws=null, busy=false, timer=null;
const pending=[];
async function post(path){
 const r=await fetch(path,{method:'POST',headers:{'X-Stealth-CSRF':'1'}});
 if(!r.ok)throw Error('Connection unavailable. Check your sign-in and try again.');
 return r.json();
}
function transmit(command){
 if(!ws||ws.readyState!==1)return false;
 if(busy){
  if(command.type==='frame')return false;
  const last=pending[pending.length-1];
  if(command.type==='type'&&last&&last.type==='type'&&last.text.length+command.text.length<=256){
   last.text+=command.text;
   return true;
  }
  if(pending.length<64){pending.push(command);return true;}
  message.textContent='Input is catching up. Wait for the stream, then re-enter this field.';
  return false;
 }
 busy=true;
 ws.send(JSON.stringify(command));
 return true;
}
function clearStream(){
 clearInterval(timer);
 pending.length=0;
 busy=false;
 screen.hidden=true;
 screen.removeAttribute('src');
}
function openLogin(ticket){
 if(ws)ws.close();
 clearStream();
 message.textContent='Opening the secure Skool login…';
 const socket=new WebSocket('wss://'+location.host+'/account/skool/stream');
 ws=socket;
 socket.onopen=()=>{if(ws===socket)socket.send(JSON.stringify({ticket}));};
 socket.onmessage=e=>{
  if(ws!==socket)return;
  busy=false;
  const v=JSON.parse(e.data);
  if(v.connected){
   clearStream();
   message.textContent='Skool connected. You can close this tab.';
   return;
  }
  if(v.frame){
   screen.hidden=false;
   screen.src='data:image/jpeg;base64,'+v.frame;
   message.textContent='Click a field in the Skool image and type normally. Tab, Enter and paste work here.';
  }
  if(pending.length)transmit(pending.shift());
 };
 socket.onerror=()=>{
  if(ws===socket)message.textContent='The secure browser stream could not connect. Start Connect Skool again.';
 };
 socket.onclose=()=>{
  if(ws!==socket)return;
  clearStream();
  if(!message.textContent.startsWith('Skool connected')&&!message.textContent.includes('could not connect')){
   message.textContent='Login ended. Start Connect Skool again if needed.';
  }
 };
 timer=setInterval(()=>transmit({type:'frame'}),1500);
}
connect.onclick=async()=>{
 connect.disabled=true;
 message.textContent='Starting your secure browser…';
 try{
  const v=await post('/account/skool/start');
  const link=new URL(v.url);
  if(link.origin!==location.origin||link.pathname!==location.pathname||!link.hash){
   throw Error('Invalid login link. Please try again.');
  }
  // Fragment-only navigation does not reload this script. Start explicitly.
  openLogin(link.hash.slice(1));
 }catch(e){message.textContent=e.message;}
 finally{connect.disabled=false;}
};
document.querySelector('#disconnect').onclick=async()=>{
 try{
  await post('/account/skool/disconnect');
  const previous=ws;
  ws=null;
  if(previous)previous.close();
  clearStream();
  message.textContent='Skool disconnected.';
 }catch(e){message.textContent=e.message;}
};
const initialTicket=location.hash.slice(1);
history.replaceState(null,'',location.pathname);
if(initialTicket)openLogin(initialTicket);
screen.onclick=e=>{
 screen.focus({preventScroll:true});
 const r=screen.getBoundingClientRect();
 transmit({type:'click',x:(e.clientX-r.left)*1024/r.width,y:(e.clientY-r.top)*768/r.height});
};
screen.onkeydown=e=>{
 if(e.isComposing)return;
 const primary=e.ctrlKey||e.metaKey;
 // Allow the local browser to produce a paste event, then forward its text.
 if(primary&&e.key.toLowerCase()==='v')return;
 const navigation=['Tab','Enter','Backspace','Delete','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','PageUp','PageDown','Escape'];
 if(primary&&e.key.toLowerCase()==='a'){
  e.preventDefault();
  transmit({type:'key',key:'a',modifiers:['ControlOrMeta']});
 }else if(navigation.includes(e.key)&&!e.altKey){
  if(primary&&!['Backspace','Delete','ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;
  e.preventDefault();
  const modifiers=[];
  if(primary)modifiers.push('ControlOrMeta');
  if(e.shiftKey)modifiers.push('Shift');
  transmit({type:'key',key:e.key,modifiers});
 }else if(!primary&&!e.altKey&&Array.from(e.key).length===1){
  e.preventDefault();
  transmit({type:'type',text:e.key});
 }
};
screen.onpaste=e=>{
 e.preventDefault();
 const characters=Array.from(e.clipboardData.getData('text/plain'));
 for(let offset=0;offset<characters.length;offset+=256){
  if(!transmit({type:'paste',text:characters.slice(offset,offset+256).join('')}))break;
 }
};
screen.oncompositionend=e=>{
 if(e.data)transmit({type:'type',text:e.data});
};

"""


def routes(settings,store=None,verifier=None,bridge_factory=BrowserBridge):
    store=store or Store(settings)
    verifier=verifier or AccountVerifier(settings)
    active={}
    from .hosted_security import RateBudget
    login_budget=RateBudget(3)
    async def user(request,privacy_only=False):
        token=request.cookies.get(COOKIE,"")
        if not token:
            return None
        check=verifier.verify_identity_token if privacy_only else verifier.verify_token
        return await check(token)

    def csrf(request):
        return request.headers.get("origin")==settings.public_origin and request.headers.get("x-stealth-csrf")=="1"

    def result(body,status=200):
        return JSONResponse(body,status_code=status,headers={"Cache-Control":"no-store","Referrer-Policy":"no-referrer"})

    async def account_session(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        authorization=request.headers.get("authorization","")
        token=authorization[7:] if authorization.startswith("Bearer ") else ""
        if not token or await verifier.verify_identity_token(token) is None:
            return result({"error":"Unauthorized"},401)
        response=result({"signed_in":True})
        response.set_cookie(COOKIE,token,secure=True,httponly=True,samesite="strict",max_age=3600,path="/")
        return response

    async def page(request):
        if await user(request,privacy_only=True) is None:
            return HTMLResponse("Sign in to Stealth Tools and open Connect Skool from your account.",status_code=401,
                                headers={"Cache-Control":"no-store"})
        return HTMLResponse(PAGE,headers={"Cache-Control":"no-store","Referrer-Policy":"no-referrer",
            "Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})

    async def script(request):
        from starlette.responses import Response
        return Response(SCRIPT,media_type="application/javascript",headers={"Cache-Control":"no-store"})

    async def start(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        subject=await user(request)
        if subject is None:
            return result({"error":"Unauthorized"},401)
        if not login_budget.allow(subject):
            return result({"error":"Login limit reached; retry in one minute"},429)
        ticket=secrets.token_urlsafe(32)
        try:
            await asyncio.to_thread(store.rpc,"begin_hosted_login",dict(p_user=subject,p_hash=fingerprint(ticket)))
            if subject in active:
                active[subject].cancel()
            return result({"url":settings.public_origin+"/connect/skool#"+ticket,"expires_in":180})
        except Exception:
            return result({"error":"Connection unavailable"},503)

    async def disconnect(request):
        if not csrf(request):
            return result({"error":"Forbidden"},403)
        subject=await user(request,privacy_only=True)
        if subject is None:
            return result({"error":"Unauthorized"},401)
        try:
            await asyncio.to_thread(store.rpc,"disconnect_hosted_skool",dict(p_user=subject))
            if subject in active:
                active[subject].cancel()
            return result({"disconnected":True})
        except Exception:
            return result({"error":"Disconnect unavailable"},503)

    async def stream(socket):
        if socket.headers.get("origin")!=settings.public_origin:
            await socket.close(code=1008)
            return
        subject=await user(socket)
        if subject is None or subject in active:
            await socket.close(code=1008)
            return
        active[subject]=asyncio.current_task()
        await socket.accept()
        job=secrets.token_hex(32)
        bridge=None
        try:
            first=await asyncio.wait_for(socket.receive_text(),timeout=10)
            if len(first)>512:
                raise ValueError("Invalid grant")
            ticket=json.loads(first).get("ticket","")
            if not isinstance(ticket,str) or not 32<=len(ticket)<=128:
                raise ValueError("Invalid grant")
            hashed=fingerprint(ticket)
            consumed=await asyncio.to_thread(store.rpc,"consume_hosted_login",dict(p_user=subject,p_hash=hashed))
            if consumed is not True:
                raise ValueError("Grant unavailable")
            bridge=bridge_factory()
            await asyncio.to_thread(bridge.call,"start",job)
            deadline=time.monotonic()+160
            command={"type":"frame"}
            while time.monotonic()<deadline:
                if (await user(socket)!=subject or
                    await asyncio.to_thread(store.rpc,"valid_hosted_login",dict(p_user=subject,p_hash=hashed)) is not True):
                    raise ValueError("Access ended")
                data=await asyncio.to_thread(bridge.call,"command",job,command)
                if "session" in data:
                    from .auth import Session
                    session=Session(**data["session"])
                    version,keys=keyring()
                    encrypted=encrypt_session(subject,session,version,keys[version])
                    if await user(socket)!=subject:
                        raise ValueError("Access ended")
                    saved=await asyncio.to_thread(store.rpc,"save_hosted_login",dict(p_user=subject,p_hash=hashed,
                        p_ciphertext=encrypted["ciphertext"],p_nonce=encrypted["nonce"],p_version=version))
                    if saved is not True:
                        raise ValueError("Connection invalidated")
                    await socket.send_json({"connected":True})
                    return
                await socket.send_json({"frame":data["frame"]})
                incoming=await asyncio.wait_for(socket.receive_text(),timeout=min(15,max(0.1,deadline-time.monotonic())))
                if len(incoming)>2048:
                    raise ValueError("Invalid input")
                command=json.loads(incoming)
        except (Exception,asyncio.CancelledError):
            pass
        finally:
            if active.get(subject) is asyncio.current_task():
                active.pop(subject,None)
            if bridge:
                try:
                    await asyncio.to_thread(bridge.call,"close",job)
                except Exception:
                    pass
            try:
                await socket.close()
            except Exception:
                pass

    return [Route("/account/session",account_session,methods=["POST"]),
        Route("/connect/skool",page),Route("/connect/skool.js",script),
        Route("/account/skool/start",start,methods=["POST"]),
        Route("/account/skool/disconnect",disconnect,methods=["POST"]),
        WebSocketRoute("/account/skool/stream",stream)]
