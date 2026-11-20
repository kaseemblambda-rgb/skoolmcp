"""Environment-only keyring, version-bound encryption and optimistic rotation."""
import base64
from dataclasses import asdict
import json
import os
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def keyring():
    active = os.environ["SKOOL_SESSION_KEY_VERSION"]
    previous = json.loads(os.environ.get("SKOOL_SESSION_PREVIOUS_KEYS", "{}"))
    keys = {version:base64.b64decode(value,validate=True) for version,value in previous.items()}
    keys[active]=base64.b64decode(os.environ["SKOOL_SESSION_ENCRYPTION_KEY"],validate=True)
    if not active or any(not isinstance(v,str) or not v or len(k)!=32 for v,k in keys.items()):
        raise ValueError("Invalid keyring")
    return active,keys


def encrypt_session(subject, session, version, key):
    subject=str(UUID(subject))
    if not version or len(key)!=32 or not session.is_valid:
        raise ValueError("Invalid encryption inputs")
    if not all(isinstance(v,str) and v and "\r" not in v and "\n" not in v for v in asdict(session).values()):
        raise ValueError("Incomplete session")
    nonce=os.urandom(12)
    body=json.dumps(asdict(session)).encode()
    ciphertext=AESGCM(key).encrypt(nonce,body,(subject+":"+version).encode())
    return dict(ciphertext=base64.b64encode(ciphertext).decode(),
                nonce=base64.b64encode(nonce).decode(),key_version=version)


def rotate(store, active, keys):
    """Store paging is by user UUID; concurrent writes use compare-and-swap."""
    from .hosted_sessions import decrypt_session
    rotated=0
    for row in store.rows():
        if row["revoked_at"] is not None or row["key_version"]==active:
            continue
        old=row["key_version"]
        session=decrypt_session(row["user_id"],row,keys[old],old)
        encrypted=encrypt_session(row["user_id"],session,active,keys[active])
        if store.rpc("rotate_hosted_session",dict(p_user=row["user_id"],
            p_old_ciphertext=row["ciphertext"],p_old_version=old,
            p_ciphertext=encrypted["ciphertext"],p_nonce=encrypted["nonce"],p_version=active)):
            rotated+=1
    return rotated



def main():
    import argparse
    from .hosted_connect import Store
    from .hosted_server import Settings
    parser=argparse.ArgumentParser(description="Activate an environment key version and rotate saved sessions")
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--expected-version")
    args=parser.parse_args()
    store=Store(Settings.from_env())
    active,keys=keyring()
    if args.activate and not store.rpc("activate_hosted_key",dict(p_expected=args.expected_version,p_version=active)):
        raise ValueError("Encryption key configuration changed")
    count=rotate(store,active,keys)
    print("Sessions rotated:",count)


if __name__=="__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Key rotation failed; retain previous keys and retry")
