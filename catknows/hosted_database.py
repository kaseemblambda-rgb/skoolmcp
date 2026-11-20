"""Restricted hosted-server SQL adapter. Never uses a Supabase API/admin key."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
import threading


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    ca_file: str

    @classmethod
    def from_env(cls):
        host = os.environ['HOSTED_DB_HOST']
        user = os.environ['HOSTED_DB_USER']
        port = os.environ['HOSTED_DB_PORT']
        password = os.environ['HOSTED_DB_PASSWORD']
        ca = Path(os.environ['HOSTED_DB_SSLROOTCERT'])
        if (not re.fullmatch(r'[a-z0-9-]+\.pooler\.supabase\.com', host)
                or not re.fullmatch(r'hosted_server\.[a-z0-9]{8,40}', user)
                or port != '5432' or os.environ['HOSTED_DB_NAME'] != 'postgres'
                or len(password) < 32 or not ca.is_absolute() or ca.is_symlink()):
            raise ValueError('Invalid hosted database configuration')
        info = ca.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError('Invalid hosted database CA')
        return cls(host, int(port), user, password, str(ca))


class RestrictedDatabase:
    def __init__(self, config):
        from psycopg_pool import ConnectionPool
        self._pool = ConnectionPool(open=False, min_size=0, max_size=4, timeout=5,
            max_waiting=16, reconnect_timeout=10, max_lifetime=600,
            kwargs=dict(host=config.host, port=config.port, user=config.user,
                password=config.password, dbname='postgres', sslmode='verify-full',
                sslrootcert=config.ca_file, connect_timeout=5, prepare_threshold=None,
                application_name='stealth-hosted-server',
                options='-c statement_timeout=10000 -c idle_in_transaction_session_timeout=15000'))
        self._lock = threading.Lock()
        self._opened = False

    def rpc(self, name, payload):
        # Fixed query strings and bound parameters only. No generic SQL gateway.
        from psycopg.types.json import Jsonb
        if name == 'hosted_oauth' and set(payload) == {'p_op', 'p'}:
            query = 'select public.hosted_server_oauth(%s,%s)'
            params = (payload['p_op'], Jsonb(payload['p']))
        elif name == 'hosted_server_session' and set(payload) == {'p_account', 'p_token_hash', 'p_resource'}:
            query = 'select public.hosted_server_session(%s,%s,%s)'
            params = (payload['p_account'], payload['p_token_hash'], payload['p_resource'])
        else:
            raise PermissionError('Hosted database operation unavailable')
        try:
            with self._lock:
                if not self._opened:
                    self._pool.open(wait=False)
                    self._opened = True
            with self._pool.connection() as connection:
                # Pool context commits before returning, including deny-path
                # expiry deletion/revocation performed inside the SQL function.
                result = connection.execute(query, params).fetchone()[0]
            return result
        except Exception:
            raise ValueError('Hosted database unavailable') from None

    def close(self):
        self._pool.close()
