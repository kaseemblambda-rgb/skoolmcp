"""Offline login gateway, browser boundary and rotation security regressions."""
import asyncio
import json
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from catknows.auth import Session
from catknows.hosted_browser_service import allowed_request,build_browser_app
from catknows.hosted_connect import routes,COOKIE
from catknows.hosted_keys import encrypt_session,rotate
from catknows.hosted_sessions import decrypt_session
from catknows.hosted_server import Settings,build_app
from starlette.applications import Starlette


async def request(app,path,body=None,headers=None):
    messages=[]
    items=[(b"host",b"mcp.example.test")]
    items.extend((k.lower().encode(),v.encode()) for k,v in (headers or {}).items())
    payload=json.dumps(body or {}).encode()
    sent=False
    async def receive():
        nonlocal sent
        if sent:
            return {"type":"http.disconnect"}
        sent=True
        return {"type":"http.request","body":payload,"more_body":False}
    async def send(message):
        messages.append(message)
    await app({"type":"http","asgi":{"version":"3.0"},"http_version":"1.1","scheme":"https",
        "method":"POST","path":path,"raw_path":path.encode(),"query_string":b"",
        "headers":items,"server":("mcp.example.test",443),"client":("127.0.0.1",1)},receive,send)
    return messages[0]["status"],messages


class LoginTests(unittest.TestCase):
    def test_connect_script_starts_stream_without_page_navigation(self):
        import subprocess
        from catknows.hosted_connect import SCRIPT
        runner=r"""
const vm=require('node:vm'),assert=require('node:assert/strict'),fs=require('node:fs');
const source=fs.readFileSync(0,'utf8');
async function check(initial){
 const nodes={};
 for(const id of ['message','diagnostics','screen','connect','disconnect']){
  nodes['#'+id]={textContent:'',hidden:true,removeAttribute(){},focus(){this.focused=true;},getBoundingClientRect(){return {left:0,top:0,width:1024,height:768};}};
 }
 const sockets=[],requests=[];
 const location={origin:'https://local.example',host:'local.example',pathname:'/connect/skool',hash:initial};
 Object.defineProperty(location,'href',{set(){throw Error('Unexpected navigation')}});
 class Socket{
  readyState=1;
  constructor(url){this.url=url;this.sent=[];sockets.push(this);}
  close(){if(this.onclose)this.onclose();}
  send(body){this.sent.push(JSON.parse(body));}
 }
 const context=vm.createContext({
  document:{querySelector:id=>nodes[id]},location,URL,WebSocket:Socket,
  history:{replaceState(){location.hash='';}},
  fetch:async path=>{requests.push(path);return {ok:true,json:async()=>({
   url:'https://local.example/connect/skool#synthetic-ticket'})};},
  setInterval:()=>1,clearInterval:()=>{}
 });
 vm.runInContext(source,context);
 if(initial){assert.equal(sockets.length,1);sockets[0].onopen();
  assert.equal(sockets[0].sent[0].ticket,'initial-ticket');}
 await nodes['#connect'].onclick();
 assert.equal(requests[0],'/account/skool/start');
 const socket=sockets.at(-1);
 socket.onopen();
 assert.equal(socket.sent[0].ticket,'synthetic-ticket');
 assert.equal(socket.url,'wss://local.example/account/skool/stream');
 assert.match(nodes['#message'].textContent,/Opening/);
 socket.onmessage({data:JSON.stringify({frame:'synthetic-image'})});
 assert.equal(nodes['#screen'].hidden,false);
 assert.equal(nodes['#connect'].disabled,false);
 nodes['#screen'].onclick({clientX:100,clientY:200});
 assert.equal(nodes['#screen'].focused,true);
 const key=(key,extra={})=>nodes['#screen'].onkeydown({key,preventDefault(){},...extra});
 key('a');key('b');key('Tab');key('Enter');key('Backspace');key('Tab',{shiftKey:true});
 key('a',{metaKey:true});
 key('v',{metaKey:true});
 nodes['#screen'].onpaste({preventDefault(){},clipboardData:{getData:()=> 'synthetic pasted text'}});
 for(let i=0;i<20;i++)socket.onmessage({data:JSON.stringify({frame:'synthetic-image'})});
 const commands=socket.sent.filter(v=>v.type);
 assert.equal(commands[0].type,'click');
 assert.equal(commands[1].type,'type');
 assert.equal(commands[1].text,'ab');
 assert(commands.some(c=>c.type==='key'&&c.key==='Tab'&&c.modifiers.length===0));
 assert(commands.some(c=>c.type==='key'&&c.key==='Tab'&&c.modifiers[0]==='Shift'));
 assert(commands.some(c=>c.type==='key'&&c.key==='Enter'));
 assert(commands.some(c=>c.type==='key'&&c.key==='Backspace'));
 assert(commands.some(c=>c.type==='key'&&c.key==='a'&&c.modifiers[0]==='ControlOrMeta'));
 assert(commands.some(c=>c.type==='paste'&&c.text==='synthetic pasted text'));
 assert(!commands.some(c=>c.type==='key'&&c.key==='v'));
 const before=socket.sent.length;
 for(const character of 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')key(character);
 for(let i=0;i<10;i++)socket.onmessage({data:JSON.stringify({frame:'synthetic-image'})});
 const typed=socket.sent.slice(before).filter(c=>c.type==='type').map(c=>c.text).join('');
 assert.equal(typed,'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
 await nodes['#connect'].onclick();
 const current=sockets.at(-1);
 socket.onmessage({data:JSON.stringify({connected:true})});
 assert.match(nodes['#message'].textContent,/Opening/);
 current.onerror();
 current.onclose();
 assert.match(nodes['#message'].textContent,/could not connect/);
 await nodes['#disconnect'].onclick();
 assert.equal(nodes['#message'].textContent,'Skool disconnected.');
 assert.equal(nodes['#screen'].hidden,true);
}
(async()=>{await check('');await check('#initial-ticket');console.log('Connect script regressions passed');})()
.catch(()=>{console.error('Connect script regression failed');process.exitCode=1;});
"""
        result=subprocess.run(["node","-e",runner],input=SCRIPT,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_stream_has_no_separate_typing_box(self):
        from catknows.hosted_connect import PAGE, SCRIPT
        self.assertNotIn('id="entry"', PAGE)
        self.assertNotIn('id="send"', PAGE)
        self.assertNotIn("console.log", SCRIPT)

    def test_worker_keyboard_and_paste_commands(self):
        from catknows.hosted_browser_service import LoginBrowser
        from unittest.mock import AsyncMock
        browser=LoginBrowser()
        keyboard=SimpleNamespace(type=AsyncMock(),insert_text=AsyncMock(),press=AsyncMock())
        browser.page=SimpleNamespace(keyboard=keyboard,screenshot=AsyncMock(return_value=b"synthetic-image"))
        browser.context=SimpleNamespace(cookies=AsyncMock(return_value=[]))
        async def check():
            await browser.command({"type":"type","text":"synthetic"})
            keyboard.type.assert_awaited_once_with("synthetic")
            await browser.command({"type":"paste","text":"synthetic paste"})
            keyboard.insert_text.assert_awaited_once_with("synthetic paste")
            for key,modifiers,expected in [
                ("Tab",[],"Tab"),("Tab",["Shift"],"Shift+Tab"),("Enter",[],"Enter"),
                ("Backspace",[],"Backspace"),("a",["ControlOrMeta"],"ControlOrMeta+a")]:
                await browser.command({"type":"key","key":key,"modifiers":modifiers})
                self.assertEqual(keyboard.press.await_args.args,(expected,))
            for command in [
                {"type":"key","key":"F12"},
                {"type":"key","key":"Tab","modifiers":["ControlOrMeta"]},
                {"type":"key","key":"a","modifiers":[]},
                {"type":"key","key":"a","modifiers":["invalid"]},
                {"type":"paste","text":"x"*513}]:
                with self.assertRaises(ValueError):
                    await browser.command(command)
        asyncio.run(check())

    def test_waf_token_requests_and_private_diagnostics(self):
        from catknows.hosted_browser_service import LoginDiagnostics
        host="https://017ae153ccc5.edge.sdk.awswaf.com"
        self.assertTrue(allowed_request(host+"/inputs?client=browser","GET","fetch"))
        self.assertTrue(allowed_request(host+"/verify","POST","xhr"))
        self.assertFalse(allowed_request(host+"/inputs","GET","document"))
        self.assertFalse(allowed_request("https://other.edge.sdk.awswaf.com/inputs","GET","fetch"))
        diagnostic=LoginDiagnostics()
        diagnostic.response("https://api2.skool.com/auth/login?private=synthetic-private-value",403)
        diagnostic.response(host+"/inputs?private=synthetic-private-value",200)
        diagnostic.blocked()
        diagnostic.failed()
        values=diagnostic.snapshot(Session("synthetic","synthetic",""),True)
        serialized=json.dumps(values)
        self.assertEqual(values["login_status"],403)
        self.assertEqual(values["waf_status"],200)
        self.assertEqual(values["blocked_requests"],1)
        self.assertNotIn("synthetic-private-value",serialized)
        self.assertNotIn("https://",serialized)
        self.assertNotIn("cookie_header",serialized)
        self.assertTrue(values["auth_cookie_present"])
        self.assertFalse(values["waf_cookie_present"])

    def test_login_network_boundary(self):
        self.assertTrue(allowed_request("https://www.skool.com/login","GET","document"))
        self.assertTrue(allowed_request("https://api2.skool.com/auth/login","POST","fetch"))
        for url,method,kind in [
            ("http://www.skool.com/login","GET","document"),
            ("https://www.skool.com/stealth","GET","document"),
            ("https://api2.skool.com/groups/x","GET","fetch"),
            ("https://api2.skool.com/auth/change-password","POST","fetch"),
            ("https://api2.skool.com/auth/logout-all","POST","fetch"),
            ("https://127.0.0.1/login","GET","document"),
            ("https://www.skool.com.evil.test/login","GET","document"),
            ("https://user@www.skool.com/login","GET","document"),
        ]:
            self.assertFalse(allowed_request(url,method,kind),url)

    def test_encrypt_rotate_and_concurrent_disconnect(self):
        owner,other=str(uuid4()),str(uuid4())
        old,new=os.urandom(32),os.urandom(32)
        session=Session("test=value","synthetic","synthetic")
        row={**encrypt_session(owner,session,"v1",old),"user_id":owner,"revoked_at":None}
        self.assertNotEqual(encrypt_session(owner,session,"v1",old)["nonce"],row["nonce"])
        with self.assertRaises(Exception):
            decrypt_session(other,row,old,"v1")
        class Store:
            saved=None
            def rows(self):
                yield row
            def rpc(inner,name,data):
                self.assertEqual(name,"rotate_hosted_session")
                inner.saved=data
                return True
        store=Store()
        self.assertEqual(rotate(store,"v2",{"v1":old,"v2":new}),1)
        rotated=dict(ciphertext=store.saved["p_ciphertext"],nonce=store.saved["p_nonce"],
                     key_version="v2",revoked_at=None)
        self.assertTrue(decrypt_session(owner,rotated,new,"v2").is_valid)
        store.rpc=lambda *args:False  # Deleted/replaced rows cannot be recreated by rotation.
        self.assertEqual(rotate(store,"v2",{"v1":old,"v2":new}),0)

    def test_gateway_csrf_auth_and_subject_binding(self):
        owner,other=str(uuid4()),str(uuid4())
        class Verifier:
            paid=True
            async def verify_token(self,token):
                return {"account-one":owner,"account-two":other}.get(token) if self.paid else None
            async def verify_identity_token(self,token):
                return {"account-one":owner,"account-two":other}.get(token)
        class Store:
            calls=[]
            def rpc(self,name,payload):
                self.calls.append((name,payload))
                return {"generation":1}
        store=Store()
        settings=Settings("https://mcp.example.test","https://project.example.test","placeholder",frozenset({"paid"}))
        verifier=Verifier()
        app=build_app(settings,connect_store=store,account_verifier=verifier)
        async def check():
            origin={"origin":settings.public_origin,"x-stealth-csrf":"1"}
            status,_=await request(app,"/account/skool/start",headers=origin)
            self.assertEqual(status,401)
            status,_=await request(app,"/account/session",headers={**origin,"authorization":"Bearer account-one"})
            self.assertEqual(status,200)
            status,_=await request(app,"/account/skool/start",headers={**origin,"cookie":COOKIE+"=account-one"})
            self.assertEqual(status,200)
            self.assertEqual(store.calls[-1][1]["p_user"],owner)
            self.assertEqual(len(store.calls[-1][1]["p_hash"]),64)
            status,_=await request(app,"/account/skool/disconnect",headers={**origin,"cookie":COOKIE+"=account-two"})
            self.assertEqual(status,200)
            self.assertEqual(store.calls[-1][1]["p_user"],other)
            status,_=await request(app,"/account/skool/start",headers={
                "origin":"https://evil.test","x-stealth-csrf":"1","cookie":COOKIE+"=account-one"})
            self.assertEqual(status,403)
            verifier.paid=False
            status,_=await request(app,"/account/skool/start",headers={**origin,"cookie":COOKIE+"=account-one"})
            self.assertEqual(status,401)
            status,_=await request(app,"/account/skool/disconnect",headers={**origin,"cookie":COOKIE+"=account-one"})
            self.assertEqual(status,200)
        asyncio.run(check())

    def test_stream_is_user_bound_and_never_returns_session_material(self):
        import base64
        owner=str(uuid4())
        settings=Settings("https://mcp.example.test","https://project.example.test","placeholder",frozenset({"paid"}))
        class Verifier:
            async def verify_token(self,token):
                return owner if token=="account-one" else None
        class Store:
            valid=True
            calls=[]
            def rpc(self,name,payload):
                self.calls.append((name,payload))
                return self.valid
        store=Store()
        class Bridge:
            calls=[]
            def call(self,operation,job,command=None):
                self.calls.append(operation)
                if operation=="command":
                    return {"session":{"cookie_header":"synthetic","auth_token":"synthetic","waf_token":"synthetic"}}
                return {"ok":True}
        app=Starlette(routes=routes(settings,store,Verifier(),Bridge))
        async def stream():
            queue=asyncio.Queue()
            await queue.put({"type":"websocket.connect"})
            await queue.put({"type":"websocket.receive","text":json.dumps({"ticket":"synthetic-placeholder-ticket-value-0000"})})
            messages=[]
            async def send(message):
                messages.append(message)
            await app({"type":"websocket","asgi":{"version":"3.0"},"scheme":"wss",
                "path":"/account/skool/stream","raw_path":b"/account/skool/stream","query_string":b"",
                "headers":[(b"origin",settings.public_origin.encode()),(b"cookie",(COOKIE+"=account-one").encode())],
                "server":("mcp.example.test",443),"client":("127.0.0.1",1),"subprotocols":[]},queue.get,send)
            return messages
        env={"SKOOL_SESSION_KEY_VERSION":"v1","SKOOL_SESSION_ENCRYPTION_KEY":base64.b64encode(os.urandom(32)).decode(),
             "SKOOL_SESSION_PREVIOUS_KEYS":"{}"}
        with patch.dict(os.environ,env):
            messages=asyncio.run(stream())
        saved=next(payload for name,payload in store.calls if name=="save_hosted_login")
        self.assertEqual(saved["p_user"],owner)
        self.assertNotIn("synthetic",saved["p_ciphertext"])
        payloads=[json.loads(m["text"]) for m in messages if m["type"]=="websocket.send"]
        self.assertEqual(payloads,[{"connected":True}])
        self.assertEqual(Bridge.calls[-1],"close")
        store.valid=False
        Bridge.calls=[]
        with patch.dict(os.environ,env):
            asyncio.run(stream())
        self.assertEqual(Bridge.calls,[])  # Invalid/replayed grant cannot launch a browser.

    def test_worker_new_browser_cleanup_and_secret(self):
        created=[]
        class Browser:
            closed=False
            async def start(self):
                created.append(self)
            async def command(self,command):
                return {"session":{"cookie_header":"synthetic","auth_token":"synthetic","waf_token":"synthetic"}}
            async def close(self):
                self.closed=True
        secret="test-placeholder-"*3
        app=build_browser_app(Browser,secret)
        async def check():
            async with app.router.lifespan_context(app):
                headers={"x-browser-secret":secret}
                for n in ("a","b"):
                    job=n*64
                    status,_=await request(app,"/job",{"operation":"start","job":job},headers)
                    self.assertEqual(status,200)
                    status,_=await request(app,"/job",{"operation":"command","job":job,"command":{"type":"frame"}},headers)
                    self.assertEqual(status,200)
                self.assertEqual(len(created),2)
                self.assertIsNot(created[0],created[1])
                self.assertTrue(all(browser.closed for browser in created))
                status,_=await request(app,"/job",{"operation":"start","job":"c"*64})
                self.assertEqual(status,401)
        asyncio.run(check())


if __name__=="__main__":
    unittest.main()
