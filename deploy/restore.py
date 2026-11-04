"""Decrypt to stdout; pipe directly to pg_restore against a separate test database."""
import os,sys
from pathlib import Path
from cryptography.fernet import Fernet
if len(sys.argv)!=2:raise SystemExit('Usage: python deploy/restore.py INPUT.dump.enc | pg_restore ...')
sys.stdout.buffer.write(Fernet(os.environ['BACKUP_ENCRYPTION_KEY'].encode()).decrypt(Path(sys.argv[1]).read_bytes()))
