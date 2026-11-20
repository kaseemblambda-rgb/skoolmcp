"""Real gateway/SDK and session-provider wiring with synthetic DB responses only."""
from datetime import datetime,timezone,timedelta
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

from catknows.hosted_server import Settings,build_app
from catknows.hosted_sessions import SessionProvider
from catknows.hosted_oauth import hashed
from .common import require,request,offline

ACCOUNT_A='00000000-0000-4000-8000-000000000001'
ACCOUNT_B='00000000-0000-4000-8000-000000000002'
TOKEN='st_a_'+('synthetic-only-'*4)
RESOURCE='https://probe.example.test/mcp'


class SyntheticDatabase:
    """No SQL engine, connection, network fallback or real session exists here."""
    def __init__(self):self.eligible=True;self.revoked=False;self.expired=False;self.closed=False;self.calls=0
    def rpc(self,name,payload):
        self.calls+=1
        if name=='hosted_oauth':
            operation=payload['p_op'];p=payload['p']
            if operation=='token_get':
                if not self.eligible or self.revoked or p.get('token_hash')!=hashed(TOKEN):return None
                return dict(kind='access',account_id=ACCOUNT_A,client_id='synthetic-client',resource=RESOURCE,
                    expires_at=(datetime.now(timezone.utc)+timedelta(minutes=-1 if self.expired else 5)).isoformat())
            if operation=='client_get':return None
            raise AssertionError('Unexpected synthetic operation')
        if name=='hosted_server_session':
            if self.eligible and payload==dict(p_account=ACCOUNT_A,p_token_hash=hashed(TOKEN),p_resource=RESOURCE):
                return dict(ciphertext='synthetic-not-a-session',nonce='synthetic',key_version='synthetic',revoked_at=None)
            return None
        raise AssertionError('No database fallback')
    def close(self):self.closed=True


async def check_gateway():
    db=SyntheticDatabase();settings=Settings('https://probe.example.test','','',frozenset({'premium','standard'}),db)
    # Explicit fixture construction: production Settings.from_env is never called.
    with patch.dict(os.environ,{},clear=True),offline():
        app=build_app(settings)
        async with app.app.router.lifespan_context(app.app):
            status,_,body=await request(app,'/healthz')
            require(status==200 and body==b'ok','E_GATEWAY_HEALTH')
            message={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'status','arguments':{}}}
            for headers in ({},{'authorization':'Bearer invalid'}):
                status,_,_=await request(app,'/mcp','POST',message,headers)
                require(status in (401,403),'E_GATEWAY_ANONYMOUS')
            status,_,body=await request(app,'/mcp','POST',message,{'authorization':'Bearer '+TOKEN})
            require(status==200 and b'Stealth MCP' in body,'E_GATEWAY_PAID_STATUS')
            for flag in ('expired','revoked'):
                setattr(db,flag,True)
                status,_,_=await request(app,'/mcp','POST',message,{'authorization':'Bearer '+TOKEN})
                require(status in (401,403),'E_GATEWAY_TOKEN_DENIAL')
                setattr(db,flag,False)
            db.eligible=False
            status,_,_=await request(app,'/mcp','POST',message,{'authorization':'Bearer '+TOKEN})
            require(status in (401,403),'E_GATEWAY_UNPAID')
            provider=SessionProvider(settings);db.eligible=True
            token=SimpleNamespace(subject=ACCOUNT_A,token=TOKEN)
            with patch('mcp.server.auth.middleware.auth_context.get_access_token',return_value=token):
                require(len(provider.rows(ACCOUNT_A))==1,'E_SESSION_BINDING')
                try:provider.rows(ACCOUNT_B)
                except PermissionError:pass
                else:raise AssertionError('Cross-account session accepted')
                db.eligible=False
                require(provider.rows(ACCOUNT_A)==[],'E_SESSION_DENIAL')
        require(db.closed,'E_GATEWAY_SHUTDOWN')
    return ['gateway_health','gateway_anonymous_denied','gateway_paid_status','gateway_expired_denied','gateway_revoked_denied',
            'gateway_unpaid_denied','session_request_binding','gateway_shutdown']
