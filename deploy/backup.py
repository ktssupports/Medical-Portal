"""Encrypt a custom-format pg_dump from stdin. Never write plaintext dumps to disk."""
import os,sys
from pathlib import Path
from cryptography.fernet import Fernet
if len(sys.argv)!=2: raise SystemExit('Usage: pg_dump -Fc | python deploy/backup.py OUTPUT.dump.enc')
key=os.environ['BACKUP_ENCRYPTION_KEY'].encode()
body=sys.stdin.buffer.read()
if not body.startswith(b'PGDMP'): raise SystemExit('Input is not a PostgreSQL custom-format dump.')
Path(sys.argv[1]).write_bytes(Fernet(key).encrypt(body))
