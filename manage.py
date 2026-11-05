"""Initialize schema and optionally provision the first administrator."""
import os, secrets, time
from app import app,init_db,q,execute,db
from werkzeug.security import generate_password_hash, check_password_hash

def reset_admin():
    password = os.getenv('RESET_ADMIN_PASSWORD')
    if password is None:
        return
    if len(password) < 12:
        raise RuntimeError('RESET_ADMIN_PASSWORD must contain at least 12 characters.')
    uid = os.getenv('INITIAL_ADMIN_ID', 'ADM-101').strip().upper()
    account = q("SELECT * FROM users WHERE id=? AND role='admin' AND status='approved'", (uid,), one=True)
    if not account:
        raise RuntimeError('Password reset requires an existing approved administrator.')
    # A restart with the same reset value must not revoke fresh sessions again.
    if check_password_hash(account['password'], password):
        return
    execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(password), uid))
    execute('DELETE FROM sessions WHERE user_id=?', (uid,))
    execute('DELETE FROM login_attempts WHERE account=?', (uid,))
    execute('INSERT INTO audit VALUES(?,?,?,?,?)', (secrets.token_hex(16), uid, 'admin_password_reset', uid, time.time()))
    db().commit()
    print('Administrator password reset. Remove RESET_ADMIN_PASSWORD from Render environment settings.')

def initialize():
    with app.app_context():
        init_db()
        if q('SELECT id FROM users LIMIT 1'):
            reset_admin()
            return
        uid=os.getenv('INITIAL_ADMIN_ID','').strip().upper()
        password=os.getenv('INITIAL_ADMIN_PASSWORD','')
        if not uid or len(password)<12:
            raise RuntimeError('Empty production database requires INITIAL_ADMIN_ID and INITIAL_ADMIN_PASSWORD (12+ characters).')
        execute('INSERT INTO organizations VALUES(?,?,?)',('ORG-101',os.getenv('INITIAL_ORGANIZATION','MediCore Medical Center'),'Hospital'))
        execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,os.getenv('INITIAL_ADMIN_NAME','Portal Administrator'),'admin',generate_password_hash(password),'approved','ORG-101'))
        db().commit()
        print('Initial administrator created. Remove INITIAL_ADMIN_PASSWORD from deployment secrets.')
if __name__=='__main__': initialize()
