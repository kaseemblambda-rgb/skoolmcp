"""Synthetic one-popup OAuth regressions. No real accounts or browser profiles."""
import asyncio
import base64
import copy
import hashlib
import json
import os
import secrets
import subprocess
import time
import unittest
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit, parse_qs
from uuid import uuid4

from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.provider import AuthorizationParams, RegistrationError, AuthorizeError
from catknows.hosted_server import Settings, build_app
from catknows.hosted_oauth import SkoolOAuthProvider, hashed, skool_identity
from catknows.hosted_popup import COOKIE, SCRIPT, PAGE
from catknows.hosted_sessions import decrypt_session


class SyntheticStore:
    """Unit-test adapter; production uses the SQL state machine, tested separately."""
    def __init__(self):
        self.clients={};self.flows={};self.accounts={};self.sessions={};self.codes={};self.tokens={}
        self.paid={'synthetic-skool-a'}
    def call(self,op,**p):
        self.flows={k:v for k,v in self.flows.items()if v['expires']>time.time()}
        if op=='client_save':self.clients[p['client_id']]=p['metadata'];return True
        if op=='client_get':return self.clients.get(p['client_id'])
        if op=='flow_new':
            self.flows[p['handle_hash']]={**p,'phase':'new','created':time.time(),'expires':time.time()+300}
            return True
        if op=='flow_bind':
            row=self.flows.get(p['handle_hash'])
            if not row or row['phase']!='new' or row['expires']<=time.time()or row['expected_browser_hash']!=p['browser_hash']:return None
            row.update(browser_hash=p['browser_hash'],phase='bound');return copy.deepcopy(row)
        if op in ('flow_get','flow_reserve','flow_claim','flow_ready','flow_decide','flow_abort'):
            row=self.flows.get(p['handle_hash'])
            if not row or row.get('browser_hash')!=p['browser_hash']or row['expires']<=time.time():return None
            if op=='flow_get':return copy.deepcopy(row)
            if op=='flow_abort':del self.flows[p['handle_hash']];return True
            if op=='flow_reserve':
                if row['phase']!='bound':return None
                if sum(r['phase']in('reserved','streaming')for r in self.flows.values())>=2:return {'capacity':True}
                row['phase']='reserved';return True
            if op=='flow_claim':
                if row['phase']!='reserved':return None
                row['phase']='streaming';return copy.deepcopy(row)
            if op=='flow_ready':
                if row['phase']!='streaming':return None
                row.update(phase='consent',account_id=p['account_id'],encrypted_session=p['encrypted_session']);return True
            if p['approve']:
                if row['phase']!='consent':return None
                self.sessions[row['account_id']]=row['encrypted_session']
                self.codes[p['code_hash']]={**row,'used':False,'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat()}
            del self.flows[p['handle_hash']]
            return {'request':row['request']}
        if op=='account':
            self.accounts.setdefault(p['skool_user_id'],{'id':str(uuid4()),'skool_user_id':p['skool_user_id']})
            return self.accounts[p['skool_user_id']]
        if op=='paid':return any(a['id']==p['account_id']and k in self.paid for k,a in self.accounts.items())
        if op=='code_get':
            row=self.codes.get(p['code_hash'])
            return row if row and not row['used']and row['client_id']==p['client_id']else None
        if op=='code_exchange':
            row=self.codes.get(p['code_hash'])
            if not row or row['used']or row['client_id']!=p['client_id']:return None
            row['used']=True
            for kind in ('access','refresh'):
                self.tokens[p[kind+'_hash']]={'kind':kind,'account_id':row['account_id'],'client_id':p['client_id'],
                    'resource':p['resource'],'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=300)).isoformat()}
            return {'account_id':row['account_id']}
        if op=='token_get':
            row=self.tokens.get(p['token_hash'])
            return row if row and any(a['id']==row['account_id']and k in self.paid for k,a in self.accounts.items())else None
        if op=='job_release':return True
        if op=='disconnect':return None
        raise AssertionError('Unsupported synthetic operation')


async def http(app,path,method='GET',data=None,headers=None,client=('127.0.0.1',1)):
    parsed=urlsplit(path);messages=[];queue=asyncio.Queue()
    payload=data if isinstance(data,bytes)else json.dumps(data or {}).encode()
    await queue.put({'type':'http.request','body':payload,'more_body':False})
    async def send(value):messages.append(value)
    items={'host':'mcp.example.test','accept':'application/json, text/event-stream',**(headers or {})}
    await app(dict(type='http',asgi={'version':'3.0'},http_version='1.1',scheme='https',method=method,
        path=parsed.path,raw_path=parsed.path.encode(),query_string=parsed.query.encode(),
        headers=[(k.lower().encode(),v.encode())for k,v in items.items()],server=('mcp.example.test',443),client=client),queue.get,send)
    headers=dict(messages[0]['headers'])
    cookies=[v for k,v in messages[0]['headers']if k==b'set-cookie']
    if cookies:headers[b'set-cookie']=b'\n'.join(cookies)
    return messages[0]['status'],headers,b''.join(m.get('body',b'')for m in messages)


class PopupTests(unittest.TestCase):
    def setUp(self):
        self.settings=Settings('https://mcp.example.test','https://db.example.test','synthetic',frozenset({'premium'}))
        self.store=SyntheticStore();self.callback='https://connector.example.test/callback'
        self.provider=SkoolOAuthProvider(self.settings,self.store,[self.callback])
        self.client=OAuthClientInformationFull(client_id='synthetic-client',client_name='Synthetic Connector',
            redirect_uris=[self.callback],scope='mcp:read',token_endpoint_auth_method='none',grant_types=['authorization_code','refresh_token'])
        asyncio.run(self.provider.register_client(self.client))
        self.verifier='v'*43
        self.challenge=base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('=')
        self.params=AuthorizationParams(state='synthetic-state',scopes=['mcp:read'],code_challenge=self.challenge,
            redirect_uri=self.callback,redirect_uri_provided_explicitly=True,resource=self.settings.resource)
        self.identity='synthetic-skool-a';self.bridge_calls=[]
        parent=self
        class Bridge:
            def call(self,operation,job,command=None):
                parent.bridge_calls.append(operation)
                if operation=='command':return {'session':dict(cookie_header='synthetic-cookie=value',auth_token='synthetic-auth',waf_token='synthetic-waf')}
                return {'ok':True}
        self.app=build_app(self.settings,oauth_provider=self.provider,browser_factory=Bridge,identity_reader=lambda s:self.identity)
        self.env=patch.dict(os.environ,{'SKOOL_SESSION_KEY_VERSION':'v1','SKOOL_SESSION_ENCRYPTION_KEY':base64.b64encode(os.urandom(32)).decode(),'SKOOL_SESSION_PREVIOUS_KEYS':'{}'})
        self.env.start();self.addCleanup(self.env.stop)

    async def begin(self):
        query=urlencode({'client_id':self.client.client_id,'redirect_uri':self.callback,'response_type':'code',
            'scope':'mcp:read','state':'synthetic-state','code_challenge':self.challenge,'code_challenge_method':'S256','resource':self.settings.resource})
        status,headers,_=await http(self.app,'/authorize?'+query)
        self.assertEqual(status,302)
        target=headers[b'location'].decode();self.assertEqual(urlsplit(target).path,'/connect/skool')
        browser_cookie=headers[b'set-cookie'].decode().split(';')[0]
        status,_,page=await http(self.app,'/connect/skool');self.assertEqual(status,200)
        self.assertNotIn(b'magic',page.lower());self.assertNotIn(b'google',page.lower())
        status,headers,body=await http(self.app,'/connect/bootstrap','POST',{'ticket':urlsplit(target).fragment},
            {'origin':self.settings.public_origin,'x-stealth-csrf':'1','content-type':'application/json','cookie':browser_cookie})
        self.assertEqual(status,200)
        cookie=headers[b'set-cookie'].decode().split(';')[0]
        self.assertIn(b'HttpOnly',headers[b'set-cookie']);self.assertIn(b'Secure',headers[b'set-cookie'])
        self.flow=json.loads(body)['flow'];self.cookie=cookie;self.ticket=urlsplit(target).fragment

    async def stream(self,cookie=None,flow=None,origin=None):
        await http(self.app,'/connect/start','POST',{},
            {'origin':origin or self.settings.public_origin,'x-stealth-csrf':'1',
             'x-stealth-flow':flow or self.flow,'cookie':cookie or self.cookie})
        queue=asyncio.Queue();messages=[]
        await queue.put({'type':'websocket.connect'})
        await queue.put({'type':'websocket.receive','text':json.dumps({'flow':flow or self.flow,'user_id':'forged-user'})})
        async def send(m):messages.append(m)
        await self.app(dict(type='websocket',asgi={'version':'3.0'},scheme='wss',path='/connect/stream',raw_path=b'/connect/stream',query_string=b'',
            headers=[(b'origin',(origin or self.settings.public_origin).encode()),(b'cookie',(cookie or self.cookie).encode())],
            server=('mcp.example.test',443),client=('127.0.0.1',1),subprotocols=[]),queue.get,send)
        return [json.loads(m['text'])for m in messages if m['type']=='websocket.send']

    async def decide(self,approve=True):
        return await http(self.app,'/connect/decision','POST',{'approve':approve},
            {'origin':self.settings.public_origin,'x-stealth-csrf':'1','x-stealth-flow':self.flow,'cookie':self.cookie,'content-type':'application/json'})

    def test_complete_single_popup_skool_identity_consent_pkce_and_replay(self):
        async def check():
            async with self.app.router.lifespan_context(self.app):
                await self.begin();messages=await self.stream()
                self.assertEqual(messages,[{'ready':True}]);self.assertEqual(self.store.sessions,{})
                account=self.store.accounts[self.identity]['id'];pending=self.store.flows[self.flow]['encrypted_session']
                key=base64.b64decode(os.environ['SKOOL_SESSION_ENCRYPTION_KEY'])
                self.assertTrue(decrypt_session(account,{**pending,'revoked_at':None},key,'v1').is_valid)
                self.assertNotIn('synthetic-cookie',json.dumps(messages)+json.dumps(pending))
                status,headers,body=await self.decide();self.assertEqual(status,200)
                self.assertIn(b'__Host-stealth_manage=',headers[b'set-cookie'])
                self.assertEqual(set(self.store.sessions),{account})
                uri=json.loads(body)['redirect'];query=parse_qs(urlsplit(uri).query)
                self.assertEqual(query['state'],['synthetic-state']);self.assertEqual(query['iss'],[self.settings.public_origin])
                code=query['code'][0];self.assertNotIn(code,json.dumps(self.store.codes))
                fields=dict(grant_type='authorization_code',client_id=self.client.client_id,code=code,
                    code_verifier='wrong',redirect_uri=self.callback,resource=self.settings.resource)
                status,_,body=await http(self.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
                self.assertEqual(status,400);self.assertEqual(json.loads(body)['error'],'invalid_grant')
                fields['code_verifier']=self.verifier
                status,_,body=await http(self.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'})
                self.assertEqual(status,200);tokens=json.loads(body)
                self.assertNotIn(tokens['access_token'],json.dumps(self.store.tokens))
                status,_,_=await http(self.app,'/mcp','POST',{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'status','arguments':{}}},
                    {'authorization':'Bearer '+tokens['access_token'],'content-type':'application/json'})
                self.assertEqual(status,200)
                self.assertEqual((await http(self.app,'/token','POST',urlencode(fields).encode(),{'content-type':'application/x-www-form-urlencoded'}))[0],400)
                self.assertEqual((await self.decide())[0],400)
                self.assertEqual(self.bridge_calls[-1],'close')
        asyncio.run(check())

    def test_ticket_cannot_be_claimed_from_a_different_browser_before_bootstrap(self):
        async def check():
            query=urlencode({'client_id':self.client.client_id,'redirect_uri':self.callback,'response_type':'code',
                'scope':'mcp:read','code_challenge':self.challenge,'code_challenge_method':'S256','resource':self.settings.resource})
            status,headers,_=await http(self.app,'/authorize?'+query)
            self.assertEqual(status,302)
            ticket=urlsplit(headers[b'location'].decode()).fragment
            common={'origin':self.settings.public_origin,'x-stealth-csrf':'1','content-type':'application/json'}
            status,_,_=await http(self.app,'/connect/bootstrap','POST',{'ticket':ticket},
                {**common,'cookie':COOKIE+'=st_b_stolen-'+('x'*40)})
            self.assertEqual(status,400)
            status,_,_=await http(self.app,'/connect/bootstrap','POST',{'ticket':ticket},
                {**common,'cookie':headers[b'set-cookie'].decode().split(';')[0]})
            self.assertEqual(status,200)
        asyncio.run(check())

    def test_deny_never_saves_a_session_or_authorization_code(self):
        async def check():
            await self.begin();await self.stream()
            status,headers,body=await self.decide(False);self.assertEqual(status,200)
            self.assertNotIn(b'__Host-stealth_manage',headers.get(b'set-cookie',b''))
            self.assertIn('error=access_denied',json.loads(body)['redirect'])
            self.assertEqual(self.store.sessions,{});self.assertEqual(self.store.codes,{});self.assertEqual(self.store.flows,{})
        asyncio.run(check())

    def test_nonmember_and_forged_identity_are_denied(self):
        async def check():
            self.identity='synthetic-skool-b';await self.begin();messages=await self.stream()
            self.assertEqual(messages,[{'error':'Paid SFC membership is required.'}])
            self.assertEqual(self.store.sessions,{})
            self.assertNotIn('forged-user',self.store.accounts)
            self.assertEqual((await self.decide())[0],400)
            self.assertEqual(self.bridge_calls[-1],'close')
        asyncio.run(check())

    def test_browser_binding_replay_origin_and_csrf(self):
        async def check():
            await self.begin()
            self.assertEqual(await self.stream(cookie=COOKIE+'=synthetic-unbound-cookie-'*3),[])
            self.assertEqual(await self.stream(origin='https://evil.example.test'),[])
            self.assertEqual(self.bridge_calls,[])
            status,_,_=await http(self.app,'/connect/bootstrap','POST',{'ticket':self.ticket},
                {'origin':self.settings.public_origin,'x-stealth-csrf':'1'})
            self.assertEqual(status,400)
            status,_,_=await http(self.app,'/connect/decision','POST',{'approve':True},
                {'origin':'https://evil.example.test','x-stealth-csrf':'1','cookie':self.cookie,'x-stealth-flow':self.flow})
            self.assertEqual(status,403)
            self.assertEqual(await self.stream(),[{'ready':True}])
        asyncio.run(check())

    def test_registration_scope_redirect_and_resource_fail_closed(self):
        async def check():
            for changes in ({'redirect_uris':['https://evil.example.test/callback']},{'client_secret':'synthetic-secret','token_endpoint_auth_method':'client_secret_post'},
                            {'scope':'mcp:write'},{'grant_types':['authorization_code','password']}):
                with self.assertRaises(RegistrationError):await self.provider.register_client(self.client.model_copy(update=changes))
            for changes in ({'resource':'https://evil.example.test/mcp'},{'code_challenge':'short'},{'scopes':['mcp:write']}):
                with self.assertRaises(AuthorizeError):await self.provider.authorize(self.client,self.params.model_copy(update=changes))
            for fields in ({'resource':'https://evil.example.test/mcp'},{}):
                status,_,body=await http(self.app,'/token','POST',urlencode(fields).encode())
                self.assertEqual(status,400);self.assertEqual(json.loads(body)['error'],'invalid_target')
            self.assertEqual((await http(self.app,'/register','POST',b'x'*65537))[0],413)
            self.assertEqual((await http(self.app,'/account/session','POST'))[0],404)
            self.assertEqual((await http(self.app,'/account/skool/start','POST'))[0],404)
        asyncio.run(check())

    def test_upstream_identity_never_comes_from_email_or_display_name(self):
        session=SimpleNamespace()
        for payload in ({'name':'synthetic','email':'synthetic@example.test'},{'id':''},{'id':'../../other'}):
            client=SimpleNamespace(http=SimpleNamespace(_http=SimpleNamespace(close=lambda:None)),self_user=lambda:payload)
            with patch('catknows.client.SkoolClient',return_value=client):
                with self.assertRaises(ValueError):skool_identity(session)

    def test_real_skool_controls_hide_social_and_code_login_without_reading_inputs(self):
        from catknows.hosted_browser_service import PASSWORD_ONLY
        runner=r"""
const vm=require('node:vm'),assert=require('node:assert/strict'),fs=require('node:fs');
let observer;
function node(text){return {textContent:text,hidden:false,attributes:{},style:{setProperty(k,v){this[k]=v}},
 getAttribute(){return ''},setAttribute(k,v){this.attributes[k]=v}}}
const emailPassword=node('LOG IN'),google=node('Continue with Google'),apple=node('Continue with Apple'),code=node('Email me a code');
const nodes=[emailPassword,google,apple,code];
vm.runInNewContext(fs.readFileSync(0,'utf8'),{document:{querySelectorAll:()=>nodes},MutationObserver:class{
 constructor(fn){observer=fn}observe(){}}});
assert.equal(emailPassword.hidden,false);
for(const n of [google,apple,code]){assert.equal(n.hidden,true);assert.equal(n.style.display,'none');assert.equal(n.attributes.tabindex,'-1')}
const late=node('Sign in with Google');nodes.push(late);observer();assert.equal(late.hidden,true);
"""
        result=subprocess.run(['node','-e',runner],input=PASSWORD_ONLY,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for forbidden in ('console.','fetch(','.value','localStorage','sessionStorage'):
            self.assertNotIn(forbidden,PASSWORD_ONLY)

    def test_two_browser_flows_cannot_approve_each_others_identity(self):
        async def check():
            await self.begin();first=(self.flow,self.cookie)
            await self.begin();second=(self.flow,self.cookie)
            self.assertNotEqual(first,second)
            self.flow,self.cookie=first[0],second[1]
            self.assertEqual(await self.stream(),[])
            self.assertEqual((await self.decide())[0],400)
            self.assertEqual(self.store.sessions,{})
            self.flow,self.cookie=first
            self.assertEqual(await self.stream(),[{'ready':True}])
        asyncio.run(check())

    def test_expired_flow_and_unverified_skool_response_do_not_create_session(self):
        async def check():
            await self.begin();self.store.flows[self.flow]['expires']=0
            self.assertEqual(await self.stream(),[]);self.assertEqual(self.store.sessions,{})
            await self.begin();self.identity='../../forged'
            self.assertEqual(await self.stream(),[{"error":"Skool sign-in could not finish. Start Connect again from your AI app."}]);self.assertEqual(self.store.accounts,{})
        asyncio.run(check())

    def test_popup_keyboard_consent_and_no_second_window(self):
        runner=r"""
const vm=require('node:vm'),assert=require('node:assert/strict'),fs=require('node:fs');
const nodes={};for(const id of ['message','diagnostics','screen','connect','disconnect','consent','client','approve','deny']){
 nodes['#'+id]={hidden:true,textContent:'',removeAttribute(){},focus(){},getBoundingClientRect(){return {left:0,top:0,width:1024,height:768}}};}
const sockets=[],posts=[],redirects=[];
class Socket {readyState=1;constructor(url){this.url=url;this.sent=[];sockets.push(this)}send(v){this.sent.push(JSON.parse(v))}close(){if(this.onclose)this.onclose()}}
const location={hash:'#st_l_synthetic',host:'mcp.example.test',origin:'https://mcp.example.test',pathname:'/connect/skool',replace:v=>redirects.push(v)};
const context=vm.createContext({document:{querySelector:id=>nodes[id]},location,URL,WebSocket:Socket,
 history:{replaceState(){location.hash=''}},setInterval:()=>1,clearInterval(){},
 fetch:async(path,options)=>{posts.push({path,options});return {ok:true,json:async()=>path.endsWith('bootstrap')?{flow:'a'.repeat(64),client_name:'Synthetic Connector',redirect_origin:'connector.example.test'}:{redirect:'https://connector.example.test/callback?code=synthetic'}}}});
vm.runInContext(fs.readFileSync(0,'utf8'),context);
(async()=>{
 for(let i=0;i<30;i++)await Promise.resolve();
 assert.equal(location.hash,'');assert.equal(sockets.length,1);
 const socket=sockets[0];socket.onopen();assert.equal(socket.sent[0].flow,'a'.repeat(64));
 socket.onmessage({data:JSON.stringify({frame:'synthetic-image'})});
 nodes['#screen'].onclick({clientX:10,clientY:20});
 nodes['#screen'].onkeydown({key:'Tab',preventDefault(){}});
 nodes['#screen'].onpaste({preventDefault(){},clipboardData:{getData:()=> 'synthetic paste'}});
 for(let i=0;i<5;i++)socket.onmessage({data:JSON.stringify({frame:'synthetic-image'})});
 assert(socket.sent.some(v=>v.key==='Tab'));assert(socket.sent.some(v=>v.type==='paste'));
 socket.onmessage({data:JSON.stringify({ready:true})});socket.onclose();
 assert.equal(nodes['#consent'].hidden,false);assert.match(nodes['#message'].textContent,/verified/);
 assert.equal(nodes['#screen'].hidden,true);
 await nodes['#approve'].onclick();
 assert.equal(posts.at(-1).path,'/connect/decision');assert.equal(JSON.parse(posts.at(-1).options.body).approve,true);
 assert.equal(posts.at(-1).options.headers['X-Stealth-Flow'],'a'.repeat(64));assert.equal(redirects.length,1);
 console.log('Popup keyboard and consent regressions passed');
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        result=subprocess.run(['node','-e',runner],input=SCRIPT,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('window.open',SCRIPT);self.assertNotIn('signInWithOtp',SCRIPT+PAGE)
        self.assertNotIn('cookie_header',SCRIPT+PAGE)
