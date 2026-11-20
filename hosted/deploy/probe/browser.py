"""Browser job protocol checks; real Chromium requires explicit container mode."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import stat

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


def descendants(records=None,root_pid=None):
    if records is None:records,_=process_snapshot()
    own=set();changed=True
    while changed:
        changed=False
        for pid,(parent,_,_)in records.items():
            if pid not in own and (parent==(os.getpid()if root_pid is None else root_pid)or parent in own):own.add(pid);changed=True
    return {pid:records[pid]for pid in own}


def process_evidence(pid,proc=Path('/proc')):
    """Pin a proc directory, read bounded kernel evidence, detect exit/PID reuse.

    Internal return values contain identifiers. Only safe_counts may be emitted.
    No cmdline, environment, page contents or cookies are read here.
    """
    fd=None
    try:
        fd=os.open(proc/str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        def read(name):
            child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            with os.fdopen(child,'r')as stream:value=stream.read(65537)
            if len(value)>65536:raise ValueError()
            return value
        def start(value):
            prefix,tail=value.rsplit(')',1)
            if int(prefix.split('(',1)[0])!=pid:raise ValueError()
            result=int(tail.split()[19])
            if result<0:raise ValueError()
            return result
        first=start(read('stat'))
        fields=dict(line.split(':',1)for line in read('status').splitlines()if ':'in line)
        if int(fields['Pid'])!=pid:raise ValueError()
        nspid=tuple(map(int,fields['NSpid'].split()))
        uid=tuple(map(int,fields['Uid'].split()))
        if not nspid or nspid[0]!=pid or min(nspid)<=0 or len(uid)!=4:raise ValueError()
        exe=os.stat('exe',dir_fd=fd)
        namespaces={name:(value.st_dev,value.st_ino)for name in ('pid','net','user')
                    for value in [os.stat('ns/'+name,dir_fd=fd)]}
        security={name:int(fields[name],16 if name=='CapEff'else 10)
                  for name in ('NoNewPrivs','Seccomp','CapEff','Seccomp_filters')}
        if min(security.values())<0:raise ValueError()
        if start(read('stat'))!=first:raise ValueError()
        return dict(pid=pid,nspid=nspid,uid=uid,start=first,exe=(exe.st_dev,exe.st_ino),
                    namespaces=namespaces,**security)
    except (FileNotFoundError,ProcessLookupError):
        raise ProbeFailure('E_SANDBOX_UNVERIFIED')from None
    except PermissionError:
        raise ProbeFailure('E_SANDBOX_EVIDENCE_DENIED')from None
    except (OSError,ValueError,KeyError,IndexError,UnicodeError):
        raise ProbeFailure('E_SANDBOX_EVIDENCE_INVALID')from None
    finally:
        if fd is not None:os.close(fd)


DISABLED_SANDBOX_FLAGS=frozenset({
    '--no-sandbox','--disable-seccomp-filter-sandbox','--disable-namespace-sandbox',
    '--disable-setuid-sandbox','--disable-gpu-sandbox','--single-process','--no-zygote',
    '--allow-sandbox-debugging','--in-process-gpu',
})


async def cdp_inventory(instances,counts):
    """CDP establishes process roles, never proves their kernel restrictions."""
    inventories=[];all_ids=set()
    for instance in instances:
        session=None
        try:
            session=await asyncio.wait_for(instance.browser.new_browser_cdp_session(),1)
            info=await asyncio.wait_for(session.send('SystemInfo.getProcessInfo'),1)
            command=await asyncio.wait_for(session.send('Browser.getBrowserCommandLine'),1)
            rows=info['processInfo'];args=command['arguments']
            if not isinstance(rows,list)or len(rows)>4096:
                counts['cdp_rows_truncated']=int(isinstance(rows,list)and len(rows)>4096)
                raise ValueError()
            if not isinstance(args,list)or not args or len(args)>4096 or any(
                not isinstance(arg,str)or len(arg)>65536 for arg in args):raise ValueError()
            disabled=any(arg.split('=',1)[0]in DISABLED_SANDBOX_FLAGS for arg in args)
            counts['sandbox_disabled']=int(disabled)
            if disabled:raise ProbeFailure('E_SANDBOX_DISABLED')
            browser=[];renderers=[]
            for row in rows:
                if not isinstance(row,dict):raise ValueError()
                if row.get('type')not in ('browser','renderer'):continue
                pid=row.get('id')
                if type(pid)is not int or pid<=0:raise ValueError()
                (browser if row['type']=='browser'else renderers).append(pid)
            if len(browser)!=1 or not renderers:raise ProbeFailure('E_SANDBOX_UNVERIFIED')
            ids=browser+renderers
            if len(set(ids))!=len(ids)or all_ids.intersection(ids):raise ValueError()
            all_ids.update(ids)
            inventories.append((browser[0],tuple(sorted(renderers)),tuple(args)))
            counts['cdp_queries_ok']=counts.get('cdp_queries_ok',0)+1
            counts['cdp_renderer_ids']=counts.get('cdp_renderer_ids',0)+len(renderers)
        except ProbeFailure:raise
        except Exception:
            counts['cdp_queries_failed']=counts.get('cdp_queries_failed',0)+1
            raise ProbeFailure('E_SANDBOX_CDP_INVALID')from None
        finally:
            if session is not None:
                try:await asyncio.wait_for(session.detach(),.2)
                except Exception:pass
    if not inventories:raise ProbeFailure('E_SANDBOX_UNVERIFIED')
    return inventories


def trusted_executable(argument):
    """Only the immutable, root-installed Playwright binary can establish identity."""
    try:
        path=Path(argument)
        if not path.is_absolute():raise ValueError()
        path=path.resolve(strict=True)
        if not path.is_relative_to('/opt/playwright'):raise ValueError()
        for item in (path,*path.parents):
            value=item.stat()
            if value.st_uid!=0 or value.st_mode&0o022:raise ValueError()
        value=path.stat()
        if not stat.S_ISREG(value.st_mode)or not value.st_mode&0o111:raise ValueError()
        return value.st_dev,value.st_ino
    except (OSError,ValueError):raise ProbeFailure('E_SANDBOX_IDENTITY')from None


def kernel_verification(inventories,records,counts):
    """Map browser-namespace CDP IDs to procfs IDs via NSpid, without argv roles."""
    def check(value,code):
        if not value:raise ProbeFailure(code)
    try:self_pid=int(os.readlink('/proc/self'))
    except (OSError,ValueError):raise ProbeFailure('E_SANDBOX_IDENTITY')from None
    own=process_evidence(self_pid);index=len(own['nspid'])-1
    check(own['nspid'][-1]==os.getpid(),'E_SANDBOX_IDENTITY')
    children=descendants(records,self_pid)
    counts['descendants']=len(children)
    evidence={self_pid:own};used=set()
    def mapped(cdp_pid):
        candidates=[]
        for pid,(_,fields,_)in records.items():
            try:ids=tuple(map(int,fields.get('NSpid','').split()))
            except ValueError:continue
            if len(ids)>index and ids[index]==cdp_pid:candidates.append(pid)
        check(len(candidates)==1,'E_SANDBOX_UNVERIFIED')
        pid=candidates[0]
        check(pid not in used,'E_SANDBOX_IDENTITY');used.add(pid)
        value=process_evidence(pid)
        check(len(value['nspid'])>index and value['nspid'][index]==cdp_pid,'E_SANDBOX_IDENTITY')
        check(value['uid']==(os.geteuid(),)*4,'E_SANDBOX_IDENTITY')
        evidence[pid]=value
        return value
    for browser_id,renderer_ids,args in inventories:
        browser=mapped(browser_id)
        check(browser['pid']in children and len(browser['nspid'])==index+1 and
              browser['namespaces']['pid']==own['namespaces']['pid'],'E_SANDBOX_IDENTITY')
        executable=trusted_executable(args[0])
        check(browser['exe']==executable,'E_SANDBOX_IDENTITY')
        for renderer_id in renderer_ids:
            renderer=mapped(renderer_id)
            counts['cdp_renderer_visible']=counts.get('cdp_renderer_visible',0)+1
            counts['cdp_renderer_descendants']=counts.get('cdp_renderer_descendants',0)+int(renderer['pid']in children)
            check(renderer['exe']==executable,'E_SANDBOX_IDENTITY')
            for field,expected,code,counter in (
                ('NoNewPrivs',1,'E_SANDBOX_PRIVILEGES','no_new_privs_confirmed'),
                ('Seccomp',2,'E_SANDBOX_SECCOMP','seccomp_filter_confirmed'),
                ('CapEff',0,'E_SANDBOX_CAPABILITIES','zero_caps_confirmed')):
                check(renderer[field]==expected,code)
                counts[counter]=counts.get(counter,0)+1
            check(renderer['Seccomp_filters']>browser['Seccomp_filters'],'E_SANDBOX_INHERITED_SECCOMP')
            counts['extra_seccomp_filter_confirmed']=counts.get('extra_seccomp_filter_confirmed',0)+1
            check(len(renderer['nspid'])>len(browser['nspid'])and all(
                renderer['namespaces'][name]!=browser['namespaces'][name]for name in ('pid','net')),
                'E_SANDBOX_NAMESPACES')
            counts['namespace_confirmed']=counts.get('namespace_confirmed',0)+1
            counts['renderer_evidence_confirmed']=counts.get('renderer_evidence_confirmed',0)+1
    return evidence,set(children)|used


async def verify_sandbox(instances):
    # Bounded retry only for discovery/exit races. Unsafe/unreadable evidence fails.
    for attempt in range(1,5):
        records,counts=process_snapshot();counts['scan_attempts']=attempt
        try:
            if counts.get('proc_listing_failed')or counts.get('proc_scan_truncated'):
                raise ProbeFailure('E_SANDBOX_UNVERIFIED')
            inventories=await cdp_inventory(instances,counts)
            evidence,observed=kernel_verification(inventories,records,counts)
            # Independent repeat proves stable CDP role association and kernel identity.
            if await cdp_inventory(instances,{})!=inventories:
                raise ProbeFailure('E_SANDBOX_UNVERIFIED')
            for pid,expected in evidence.items():
                if process_evidence(pid)!=expected:raise ProbeFailure('E_SANDBOX_IDENTITY')
            return observed,safe_counts(counts)
        except ProbeFailure as exc:
            if str(exc)=='E_SANDBOX_UNVERIFIED'and attempt<4:
                await asyncio.sleep(.25);continue
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
