"""Initialize schema and optionally provision the first administrator."""
import os
from app import app,init_db,q,execute,db
from werkzeug.security import generate_password_hash

def initialize():
    with app.app_context():
        init_db()
        if q('SELECT id FROM users LIMIT 1'): return
        uid=os.getenv('INITIAL_ADMIN_ID','').strip().upper()
        password=os.getenv('INITIAL_ADMIN_PASSWORD','')
        if not uid or len(password)<12:
            raise RuntimeError('Empty production database requires INITIAL_ADMIN_ID and INITIAL_ADMIN_PASSWORD (12+ characters).')
        execute('INSERT INTO organizations VALUES(?,?,?)',('ORG-101',os.getenv('INITIAL_ORGANIZATION','MediCore Medical Center'),'Hospital'))
        execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,os.getenv('INITIAL_ADMIN_NAME','Portal Administrator'),'admin',generate_password_hash(password),'approved','ORG-101'))
        db().commit()
        print('Initial administrator created. Remove INITIAL_ADMIN_PASSWORD from deployment secrets.')
if __name__=='__main__': initialize()
