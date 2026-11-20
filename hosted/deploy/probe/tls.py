"""Throwaway in-memory TLS fixtures; no real credentials or certificate files read."""
from datetime import datetime,timezone,timedelta
import os
from pathlib import Path
import socket
import ssl
import threading
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from catknows.hosted_private_tls import browser_client_context,browser_server_tls
from .common import require


def material(expired=False):
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'browser.example.test')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
        .not_valid_after(now-timedelta(days=1) if expired else now+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('browser.example.test')]),False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode(),key.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()


def handshake(client,files,hostname):
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(files['ssl_certfile'],files['ssl_keyfile'])
    left,right=socket.socketpair();left.settimeout(3);right.settimeout(3);errors=[]
    def serve():
        try:
            with server.wrap_socket(left,server_side=True) as stream:
                if stream.recv(1)==b'x':stream.sendall(b'y')
        except ssl.SSLError:pass
        except Exception:errors.append(True)
        finally:left.close()
    thread=threading.Thread(target=serve);thread.start()
    try:
        with client.wrap_socket(right,server_hostname=hostname) as stream:
            stream.sendall(b'x');require(stream.recv(1)==b'y','E_TLS_EXCHANGE')
    finally:
        right.close();thread.join(4)
        require(not thread.is_alive() and not errors,'E_TLS_THREAD')


def check_tls():
    for expired in (False,True):
        cert,key=material(expired)
        with patch.dict(os.environ,{'RENDER':'true','BROWSER_TLS_CA_PEM':cert,
            'BROWSER_TLS_CERT_PEM':cert,'BROWSER_TLS_KEY_PEM':key},clear=True):
            client=browser_client_context()
            require(client.check_hostname and client.verify_mode==ssl.CERT_REQUIRED,'E_TLS_VERIFY_DISABLED')
            with browser_server_tls() as files:
                paths=[Path(files[k])for k in ('ssl_certfile','ssl_keyfile')]
                require(all(p.stat().st_mode&0o777==0o600 for p in paths),'E_TLS_MODE')
                cases=[(client,'browser.example.test',expired)]
                if not expired:cases.extend([(client,'wrong.example.test',True),(ssl.create_default_context(),'browser.example.test',True)])
                for context,host,should_fail in cases:
                    try:handshake(context,files,host)
                    except ssl.SSLCertVerificationError:require(should_fail,'E_TLS_TRUST')
                    else:require(not should_fail,'E_TLS_ACCEPTED_INVALID')
            require(all(not p.exists()for p in paths),'E_TLS_CLEANUP')
    return ['tls_verified','tls_bad_hostname_denied','tls_untrusted_denied','tls_expired_denied','tls_private_files_cleaned']
