"""Browser job protocol checks; real Chromium requires explicit container mode."""
import asyncio
import json
import os
from pathlib import Path
import secrets

from catknows.hosted_browser_service import build_browser_app,LoginBrowser
from .common import require,request,offline


class FakeBrowser:
    def __init__(self):self.closed=False;self.marker=secrets.token_hex(8)
    async def start(self):pass
    async def command(self,command):
        if command.get('type')!='frame':raise ValueError('Synthetic invalid command')
        return {'frame':'synthetic-frame','marker':self.marker}
    async def close(self):self.closed=True


def descendants():
    records={}
    for path in Path('/proc').glob('[0-9]*/status'):
        try:
            fields=dict(line.split(':',1)for line in path.read_text().splitlines()if ':' in line)
            records[int(path.parent.name)]=(int(fields['PPid']),fields,path.parent)
        except (OSError,ValueError,KeyError):pass
    own=set();changed=True
    while changed:
        changed=False
        for pid,(parent,_,_)in records.items():
            if pid not in own and (parent==os.getpid()or parent in own):own.add(pid);changed=True
    return {pid:records[pid]for pid in own}


def sandbox_check():
    children=descendants();renderers=[]
    for pid,(_,fields,root)in children.items():
        try:args=(root/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        if b'--type=renderer' in args:
            require(b'--no-sandbox' not in args,'E_SANDBOX_DISABLED')
            require(fields.get('NoNewPrivs','').strip()=='1','E_SANDBOX_PRIVILEGES')
            require(fields.get('Seccomp','').strip()=='2','E_SANDBOX_SECCOMP')
            require(int(fields.get('CapEff','1'),16)==0,'E_SANDBOX_CAPABILITIES')
            renderers.append(pid)
    require(bool(renderers),'E_SANDBOX_UNVERIFIED')
    return set(children)


async def check_browser(live=False):
    instances=[];observed=set();secret=secrets.token_urlsafe(32)
    def factory():
        browser=LoginBrowser()if live else FakeBrowser();instances.append(browser);return browser
    app=build_browser_app(factory=factory,secret=secret)
    async def job(operation,index,command=None,authorized=True):
        status,_,body=await request(app,'/job','POST',dict(operation=operation,job=f'{index:064x}',command=command),
            {'x-browser-secret':secret if authorized else 'invalid-synthetic'})
        return status,json.loads(body)
    async with app.router.lifespan_context(app):
        require((await job('start',1,authorized=False))[0]==401,'E_BROWSER_AUTH')
        results=await asyncio.gather(job('start',1),job('start',2))
        require(all(status==200 for status,_ in results),'E_BROWSER_START')
        require(len(instances)==2 and instances[0]is not instances[1],'E_BROWSER_ISOLATION')
        require((await job('start',3))[0]==429,'E_BROWSER_CAPACITY')
        if live:
            a,b=instances
            require(a.context is not b.context and a.browser is not b.browser,'E_BROWSER_SHARED_CONTEXT')
            require(a.directory.name!=b.directory.name,'E_BROWSER_SHARED_DIRECTORY')
            # A harmless synthetic cookie, never a Skool auth/session cookie.
            await a.context.add_cookies([{'name':'probe_isolation','value':'synthetic-only','url':'https://www.skool.com/'}])
            require(not any(c['name']in('probe_isolation','auth_token')for c in await b.context.cookies()),'E_BROWSER_COOKIE_LEAK')
            require(not any(c['name']=='auth_token'for c in await a.context.cookies()),'E_BROWSER_UNEXPECTED_LOGIN')
            observed=sandbox_check()
        frames=[await job('command',i,{'type':'frame'})for i in (1,2)]
        require(all(status==200 and 'frame'in body and 'session'not in body for status,body in frames),'E_BROWSER_FRAME')
        if not live:require(frames[0][1]['marker']!=frames[1][1]['marker'],'E_BROWSER_FAKE_ISOLATION')
        require((await job('command',1,{'type':'unsupported'}))[0]==400,'E_BROWSER_BAD_COMMAND')
        require((await job('command',2,{'type':'frame'}))[0]==200,'E_BROWSER_OTHER_JOB_CLOSED')
        require((await job('close',2))[0]==200,'E_BROWSER_CLOSE')
        # Keep one job open so application shutdown must clean it too.
        require((await job('start',3))[0]==200,'E_BROWSER_SLOT_RELEASE')
        if live:observed|=set(descendants())
    if live:
        require(all(not b.browser.is_connected()and not Path(b.directory.name).exists()for b in instances),'E_BROWSER_CLEANUP')
        for _ in range(30):
            lingering=[p for p in observed if Path(f'/proc/{p}/status').exists()]
            if not lingering:break
            await asyncio.sleep(.1)
        require(not lingering,'E_BROWSER_CHILD_CLEANUP')
    else:require(all(b.closed for b in instances),'E_BROWSER_FAKE_CLEANUP')
    return [('chromium_'if live else 'fake_browser_')+name for name in
        ('auth_denial','two_jobs','isolation','capacity','frame','error_cleanup','shutdown_cleanup')]+(['chromium_sandbox_verified']if live else [])


async def check_fake_browser():
    with offline():return await check_browser(False)
