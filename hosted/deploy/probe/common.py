"""Fixed results, in-process HTTP and a fail-closed no-network boundary."""
import asyncio
from contextlib import contextmanager
import json
import os
import socket
from unittest.mock import patch


class ProbeFailure(Exception):
    pass


def require(value,code):
    if not value:raise ProbeFailure(code)


def clean_environment():
    # Inspect names only. Never read .env, the Keychain, profiles or local config.
    blocked=('SUPABASE_','HOSTED_DB_','HOSTED_EXPORT_','SKOOL_SESSION_','CATKNOWS_','PG')
    exact={'DATABASE_URL','HOSTED_OWNER_PROFILE_DIR','BROWSER_SERVICE_SECRET',
           'BROWSER_TLS_KEY_PEM','BROWSER_TLS_CERT_PEM','BROWSER_TLS_CA_PEM'}
    require(not any(k.startswith(blocked) or k in exact for k in os.environ),'E_PROBE_ENV')


@contextmanager
def offline():
    def denied(*args,**kwargs):raise ProbeFailure('E_NETWORK_FORBIDDEN')
    with patch('socket.getaddrinfo',denied),patch('socket.socket.connect',denied), \
         patch('socket.socket.connect_ex',denied),patch('socket.create_connection',denied):
        yield


async def request(app,path,method='GET',data=None,headers=None):
    messages=[];queue=asyncio.Queue()
    body=json.dumps(data or {}).encode()
    await queue.put({'type':'http.request','body':body,'more_body':False})
    items={'host':'probe.example.test','accept':'application/json, text/event-stream',
           'content-type':'application/json',**(headers or {})}
    async def send(message):messages.append(message)
    await asyncio.wait_for(app(dict(type='http',asgi={'version':'3.0'},http_version='1.1',scheme='https',
        method=method,path=path,raw_path=path.encode(),query_string=b'',
        headers=[(k.lower().encode(),v.encode())for k,v in items.items()],
        server=('probe.example.test',443),client=('127.0.0.1',1)),queue.get,send),30)
    return messages[0]['status'],dict(messages[0]['headers']),b''.join(m.get('body',b'')for m in messages)
