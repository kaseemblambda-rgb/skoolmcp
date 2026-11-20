"""Verified private-browser TLS; environment secrets become temporary 0600 files."""
from contextlib import contextmanager
import os
from pathlib import Path
import ssl
import tempfile


def browser_client_context():
    context=ssl.create_default_context()
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    ca=os.environ.get('BROWSER_TLS_CA_PEM')
    if os.environ.get('RENDER')=='true' and not ca:
        raise ValueError('Private browser CA required')
    if ca:
        if 'PRIVATE KEY' in ca or len(ca)>65536:
            raise ValueError('Invalid private browser CA')
        context.load_verify_locations(cadata=ca)
    # No CERT_NONE, hostname exceptions or process-wide CA overrides.
    return context


@contextmanager
def browser_server_tls():
    certificate=os.environ.get('BROWSER_TLS_CERT_PEM')
    key=os.environ.get('BROWSER_TLS_KEY_PEM')
    if not certificate or not key or len(certificate)>65536 or len(key)>16384:
        raise ValueError('Browser TLS certificate and key required')
    with tempfile.TemporaryDirectory(prefix='stealth-browser-tls-') as folder:
        root=Path(folder)
        root.chmod(0o700)
        paths=[]
        for name,value in (('certificate.pem',certificate),('key.pem',key)):
            path=root/name
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as stream:stream.write(value)
            paths.append(str(path))
        check=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        check.minimum_version=ssl.TLSVersion.TLSv1_2
        check.load_cert_chain(*paths)
        try:
            yield dict(ssl_certfile=paths[0],ssl_keyfile=paths[1],ssl_version=ssl.PROTOCOL_TLS_SERVER,
                       ssl_ciphers='ECDHE+AESGCM:ECDHE+CHACHA20')
        finally:
            # TemporaryDirectory removes both files even after startup failure.
            pass
