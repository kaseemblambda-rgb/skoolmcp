"""Test-image-only entry point. Fixed results, no real accounts or database."""
import argparse
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
import re
import sys

from .common import ProbeFailure,clean_environment,require,offline,safe_counts


@contextmanager
def quiet():
    sys.stdout.flush();sys.stderr.flush();saved=[os.dup(1),os.dup(2)]
    try:
        with open(os.devnull,'w')as sink:
            os.dup2(sink.fileno(),1);os.dup2(sink.fileno(),2)
            yield
    finally:
        os.dup2(saved[0],1);os.dup2(saved[1],2)
        for fd in saved:os.close(fd)


def run(mode,live_browser=False,container=False):
    clean_environment()
    require(mode in ('gateway','browser','all'),'E_PROBE_MODE')
    if container:require(sys.platform=='linux'and os.geteuid()==10001,'E_PROBE_CONTAINER_USER')
    require(not live_browser or(container and mode=='browser'),'E_PROBE_LIVE_REQUIRES_CONTAINER')
    from catknows.hosted_security import install_private_logging
    install_private_logging()
    from .tls import check_tls
    with offline():checks=check_tls()
    if mode in ('gateway','all'):
        from .gateway import check_gateway
        checks+=asyncio.run(check_gateway())
    diagnostics={}
    if mode in ('browser','all'):
        from .browser import check_fake_browser,check_browser
        checks+=asyncio.run(check_fake_browser())
        if live_browser:checks+=asyncio.run(check_browser(True,diagnostics))
    report=dict(result='PASS',mode=mode,container_runtime_checked=container,
        real_chromium_checked=live_browser,checks=checks)
    if diagnostics:report['sandbox_counts']=safe_counts(diagnostics)
    return report


def serve(report,private=False):
    # This listener exposes results/liveness only, never the gateway or /job.
    payload=json.dumps(report,sort_keys=True).encode()
    class Handler(BaseHTTPRequestHandler):
        def setup(self):super().setup();self.connection.settimeout(5)
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path=='/healthz':body=b'ok';status=200
            elif self.path=='/result':body=payload;status=200
            else:body=b'not found';status=404
            self.send_response(status);self.send_header('Content-Type','application/json'if self.path=='/result'else'text/plain')
            self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY')
            self.end_headers();self.wfile.write(body)
    port=int(os.environ.get('PORT','8000'));require(1024<=port<=65535,'E_PROBE_PORT')
    with HTTPServer(('0.0.0.0'if private else'127.0.0.1',port),Handler)as server:server.serve_forever()


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',choices=('gateway','browser','all'),required=True)
    parser.add_argument('--container',action='store_true')
    parser.add_argument('--live-browser',action='store_true')
    parser.add_argument('--serve',action='store_true')
    parser.add_argument('--private-service',action='store_true')
    args=parser.parse_args(argv)
    try:
        require(not args.private_service or(args.container and args.serve),'E_PROBE_PRIVATE_MODE')
        with quiet():report=run(args.mode,args.live_browser,args.container)
    except Exception as exc:
        code=str(exc)if isinstance(exc,ProbeFailure)else'E_PROBE_FAILED'
        if not re.fullmatch(r'E_[A-Z_]{1,64}',code):code='E_PROBE_FAILED'
        report={'result':'FAIL','code':code}
        counts=safe_counts(exc.counts)if isinstance(exc,ProbeFailure)else{}
        if counts:report['sandbox_counts']=counts
        print(json.dumps(report,sort_keys=True),flush=True)
        return 1
    print(json.dumps(report,sort_keys=True),flush=True)
    if args.serve:
        try:serve(report,args.private_service)
        except KeyboardInterrupt:pass
        except Exception:
            print('{"code":"E_PROBE_LISTENER","result":"FAIL"}',flush=True);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
