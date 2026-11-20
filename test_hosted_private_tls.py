"""Real TLS handshakes over local socketpairs; no external network or real keys."""
from datetime import datetime,timezone,timedelta
import os
from pathlib import Path
import socket
import ssl
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from catknows.hosted_private_tls import browser_client_context,browser_server_tls


def certificate(expired=False):
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


class PrivateTLSTests(unittest.TestCase):
    def handshake(self,client,files,hostname):
        server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(files['ssl_certfile'],files['ssl_keyfile'])
        left,right=socket.socketpair();left.settimeout(3);right.settimeout(3)
        def serve():
            try:
                with server.wrap_socket(left,server_side=True) as stream:
                    if stream.recv(1)==b'x':stream.sendall(b'y')
            except ssl.SSLError:pass
            finally:left.close()
        thread=threading.Thread(target=serve);thread.start()
        try:
            with client.wrap_socket(right,server_hostname=hostname) as stream:
                stream.sendall(b'x');self.assertEqual(stream.recv(1),b'y')
        finally:right.close();thread.join(4);self.assertFalse(thread.is_alive())

    def test_tls_trust_hostname_verification_and_private_file_cleanup(self):
        cert,key=certificate()
        env={'RENDER':'true','BROWSER_TLS_CA_PEM':cert,'BROWSER_TLS_CERT_PEM':cert,'BROWSER_TLS_KEY_PEM':key}
        with patch.dict(os.environ,env,clear=True):
            client=browser_client_context();self.assertTrue(client.check_hostname)
            self.assertEqual(client.verify_mode,ssl.CERT_REQUIRED)
            self.assertGreater(len(client.get_ca_certs()),1)
            with browser_server_tls() as files:
                paths=[Path(files[k]) for k in ('ssl_certfile','ssl_keyfile')]
                self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in paths))
                self.assertEqual(paths[0].parent.stat().st_mode&0o777,0o700)
                self.handshake(client,files,'browser.example.test')
                with self.assertRaises(ssl.SSLCertVerificationError):self.handshake(client,files,'wrong.example.test')
                with self.assertRaises(ssl.SSLCertVerificationError):self.handshake(ssl.create_default_context(),files,'browser.example.test')
            self.assertTrue(all(not p.exists() for p in paths))

    def test_expired_certificate_is_denied(self):
        cert,key=certificate(expired=True)
        with patch.dict(os.environ,{'BROWSER_TLS_CA_PEM':cert,'BROWSER_TLS_CERT_PEM':cert,'BROWSER_TLS_KEY_PEM':key},clear=True):
            with browser_server_tls() as files,self.assertRaises(ssl.SSLCertVerificationError):
                self.handshake(browser_client_context(),files,'browser.example.test')

    def test_missing_ca_key_and_mismatched_key_fail_closed(self):
        with patch.dict(os.environ,{'RENDER':'true'},clear=True):
            with self.assertRaises(ValueError):browser_client_context()
            with self.assertRaises(ValueError):
                with browser_server_tls():pass
        cert,_=certificate();_,wrong=certificate()
        with patch.dict(os.environ,{'BROWSER_TLS_CERT_PEM':cert,'BROWSER_TLS_KEY_PEM':wrong},clear=True),self.assertRaises(ssl.SSLError):
            with browser_server_tls():pass

    def test_browser_rejects_database_credentials_before_starting(self):
        from catknows.hosted_browser_service import main
        for env in ({'HOSTED_DB_PASSWORD':'synthetic'},{'HOSTED_EXPORT_DB_USER':'synthetic'},
                    {'SKOOL_SESSION_ENCRYPTION_KEY':'synthetic'},{'HOSTED_OWNER_PROFILE_DIR':'/synthetic'}):
            with patch.dict(os.environ,env,clear=True),patch('uvicorn.run') as run,self.assertRaises(SystemExit):main()
            run.assert_not_called()


if __name__=='__main__':unittest.main()
