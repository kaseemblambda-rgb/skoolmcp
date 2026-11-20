"""Browser job protocol checks; real Chromium requires explicit container mode."""
import asyncio
import json
import os
from pathlib import Path
import secrets

from catknows.hosted_browser_service import build_browser_app,LoginBrowser
from .common import require,request,offline,ProbeFailure,safe_counts


class FakeBrowser:
    def __init__(self):self.closed=False;self.marker=secrets.token_hex(8)
    async def start(self):pass
    async def command(self,command):
        if command.get('type')!='frame':raise ValueError('Synthetic invalid command')
        return {'frame':'synthetic-frame','marker':self.marker}
    async def close(self):self.closed=True


def process_snapshot():
    """Inspect status metadata only; raw fields/IDs never enter result payloads."""
    records={};counts=dict(proc_entries=0,proc_listing_failed=0,proc_scan_truncated=0,
        status_readable=0,status_denied=0,status_disappeared=0,status_invalid=0,
        self_status_present=0,parentless_statuses=0)
    try:
        paths=Path('/proc').iterdir()
        for root in paths:
            if not root.name.isdecimal():continue
            if counts['proc_entries']>=4096:
                counts['proc_scan_truncated']=1;break
            counts['proc_entries']+=1
            try:
                fields=dict(line.split(':',1)for line in (root/'status').read_text().splitlines()if ':' in line)
                parent=int(fields['PPid']);pid=int(root.name)
                if parent<0:raise ValueError()
                records[pid]=(parent,fields,root)
                counts['status_readable']+=1
                counts['self_status_present']+=int(pid==os.getpid())
                counts['parentless_statuses']+=int(parent==0)
            except PermissionError:counts['status_denied']+=1
            except (FileNotFoundError,ProcessLookupError):counts['status_disappeared']+=1
            except (OSError,UnicodeError,ValueError,KeyError):counts['status_invalid']+=1
    except OSError:counts['proc_listing_failed']=1
    return records,counts


def descendants(records=None):
    if records is None:records,_=process_snapshot()
    own=set();changed=True
    while changed:
        changed=False
        for pid,(parent,_,_)in records.items():
            if pid not in own and (parent==os.getpid()or parent in own):own.add(pid);changed=True
    return {pid:records[pid]for pid in own}


def sandbox_check(records=None,counts=None):
    if records is None:records,counts=process_snapshot()
    counts=dict(counts or {})
    children=descendants(records);renderers=[]
    counts.update(descendants=len(children),cmdline_readable=0,cmdline_denied=0,
        cmdline_disappeared=0,renderer_matches=0,sandbox_disabled=0,
        no_new_privs_confirmed=0,seccomp_filter_confirmed=0,zero_caps_confirmed=0,security_fields_missing=0)
    def check(value,code):
        if not value:raise ProbeFailure(code,counts)
    check(not counts.get('proc_scan_truncated'),'E_SANDBOX_UNVERIFIED')
    for pid,(_,fields,root)in children.items():
        try:
            args=(root/'cmdline').read_bytes().split(b'\0')
            counts['cmdline_readable']+=1
        except (FileNotFoundError,ProcessLookupError):
            counts['cmdline_disappeared']+=1;continue
        except OSError:
            counts['cmdline_denied']+=1;continue
        if b'--type=renderer' in args:
            counts['renderer_matches']+=1
            counts['sandbox_disabled']+=int(b'--no-sandbox'in args)
            counts['no_new_privs_confirmed']+=int(fields.get('NoNewPrivs','').strip()=='1')
            counts['seccomp_filter_confirmed']+=int(fields.get('Seccomp','').strip()=='2')
            try:caps=int(fields.get('CapEff',''),16)
            except ValueError:caps=None
            counts['zero_caps_confirmed']+=int(caps==0)
            counts['security_fields_missing']+=int(not all(fields.get(k,'').strip()for k in ('NoNewPrivs','Seccomp','CapEff')))
            check(b'--no-sandbox'not in args,'E_SANDBOX_DISABLED')
            check(fields.get('NoNewPrivs','').strip()=='1','E_SANDBOX_PRIVILEGES')
            check(fields.get('Seccomp','').strip()=='2','E_SANDBOX_SECCOMP')
            check(caps==0,'E_SANDBOX_CAPABILITIES')
            renderers.append(pid)
    check(bool(renderers),'E_SANDBOX_UNVERIFIED')
    return set(children),safe_counts(counts)


async def cdp_process_counts(instances,records,children):
    """Read browser process metadata only. It can diagnose, never authorize a pass."""
    counts=dict(cdp_queries_ok=0,cdp_queries_failed=0,cdp_rows_truncated=0)
    renderers=set()
    for instance in instances:
        session=None
        try:
            session=await asyncio.wait_for(instance.browser.new_browser_cdp_session(),1)
            info=await asyncio.wait_for(session.send('SystemInfo.getProcessInfo'),1)
            rows=info.get('processInfo',[])
            if not isinstance(rows,list):raise ValueError()
            counts['cdp_rows_truncated']+=int(len(rows)>4096)
            for row in rows[:4096]:
                if isinstance(row,dict)and row.get('type')=='renderer':
                    pid=row.get('id')
                    if type(pid)is int and pid>0:renderers.add(pid)
            counts['cdp_queries_ok']+=1
        except Exception:counts['cdp_queries_failed']+=1
        finally:
            if session is not None:
                try:await asyncio.wait_for(session.detach(),.2)
                except Exception:pass
    counts.update(cdp_renderer_ids=len(renderers),cdp_renderer_visible=len(renderers&set(records)),
                  cdp_renderer_descendants=len(renderers&set(children)))
    return counts


async def verify_sandbox(instances):
    # Retry discovery only, at most four snapshots and three 250 ms waits.
    # An observed unsafe renderer fails immediately, without a retry/fallback.
    for attempt in range(1,5):
        records,counts=process_snapshot();counts['scan_attempts']=attempt
        try:
            observed,counts=sandbox_check(records,counts)
            counts.update(await cdp_process_counts(instances,records,observed))
            return observed,safe_counts(counts)
        except ProbeFailure as exc:
            if str(exc)=='E_SANDBOX_UNVERIFIED'and attempt<4:
                await asyncio.sleep(.25);continue
            counts=exc.counts
            counts.update(await cdp_process_counts(instances,records,descendants(records)))
            raise ProbeFailure(str(exc),counts)from None


async def check_browser(live=False,diagnostics=None):
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
            observed,counts=await verify_sandbox(instances)
            if diagnostics is not None:diagnostics.update(safe_counts(counts))
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
