"""MediCore: four-role portal for Render + Supabase free-tier deployment."""
import os, time, secrets, hashlib, sqlite3, functools, io
from pathlib import Path
import requests
from flask import Flask, request, session, g, redirect, url_for, render_template, flash, abort, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).parent
DEMO = os.getenv('DEMO_MODE') == '1'
DATABASE = os.getenv('DATABASE_URL')
secret = os.getenv('SECRET_KEY')
if not DEMO and (not secret or len(secret) < 32 or not DATABASE):
    raise RuntimeError('Production requires DATABASE_URL and a random SECRET_KEY of at least 32 characters.')
app = Flask(__name__)
app.config.update(SECRET_KEY=secret or secrets.token_hex(32), MAX_CONTENT_LENGTH=6*1024*1024,
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=not DEMO,
    PERMANENT_SESSION_LIFETIME=28800)
DATA = Path(os.getenv('DATA_DIR', str(ROOT/'data')))
if DEMO: DATA.mkdir(exist_ok=True)

def db():
    if 'db' not in g:
        if DATABASE:
            import psycopg
            from psycopg.rows import dict_row
            g.db = psycopg.connect(DATABASE, row_factory=dict_row, prepare_threshold=None,
                sslmode='require', connect_timeout=10)
            g.db.execute('SET search_path TO medicore')
        else:
            g.db = sqlite3.connect(DATA/'demo.db')
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop('db', None)
    if conn is not None: conn.close()

def q(sql, args=(), one=False):
    rows = db().execute(sql.replace('?', '%s') if DATABASE else sql, args).fetchall()
    rows = [dict(r) for r in rows]
    return (rows[0] if rows else None) if one else rows

def execute(sql, args=()):
    return db().execute(sql.replace('?', '%s') if DATABASE else sql, args)

def audit(action, target):
    execute('INSERT INTO audit VALUES(?,?,?,?,?)', (secrets.token_hex(16), g.user['id'], action, target, time.time()))

def init_db():
    if DATABASE: db().execute('CREATE SCHEMA IF NOT EXISTS medicore')
    for stmt in (ROOT/'deploy/schema.sql').read_text().split(';'):
        if stmt.strip(): execute(stmt)
    db().commit()

def can_read(pid):
    if g.user['role'] == 'admin': return True
    if g.user['role'] == 'patient': return g.user['id'] == pid
    if g.user['role'] == 'doctor':
        return bool(q('SELECT * FROM access WHERE patient_id=? AND doctor_id=? AND granted=1', (pid,g.user['id']),one=True))
    return False

def roles(*allowed):
    def wrapper(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            if not g.user: return redirect(url_for('login'))
            if g.user['role'] not in allowed: abort(403)
            return fn(*args, **kwargs)
        return inner
    return wrapper

@app.before_request
def before():
    g.user = None
    if session.get('token'):
        g.user = q('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.id=? AND s.expires>? AND u.status=?',
            (hashlib.sha256(session['token'].encode()).hexdigest(), time.time(), 'approved'), one=True)
    if 'csrf' not in session: session['csrf'] = secrets.token_hex(24)
    if request.method == 'POST':
        if not secrets.compare_digest(str(session.get('csrf','')), str(request.form.get('csrf',''))): abort(400, 'Invalid form token. Reload and try again.')

@app.after_request
def secure(response):
    response.headers.update({'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',
        'Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
    if not DEMO: response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

@app.context_processor
def context():
    return dict(user=g.user, demo=DEMO, csrf=session.get('csrf'), year=time.localtime().tm_year)

@app.template_filter('date')
def date(value): return time.strftime('%d %b %Y',time.localtime(value))

@app.get('/health')
def health():
    try:
        q('SELECT 1'); return jsonify(status='ok')
    except Exception: return jsonify(status='unavailable'),503

@app.route('/login',methods=['GET','POST'])
def login():
    if g.user: return redirect(url_for('dashboard'))
    role=request.args.get('role','doctor')
    if role not in ('doctor','patient','laboratory','admin'): role='doctor'
    if request.method=='POST':
        uid=request.form.get('id','').strip().upper()
        attempts=q('SELECT COUNT(*) AS n FROM login_attempts WHERE account=? AND created>?',(uid,time.time()-900),one=True)['n']
        if attempts>=10: return render_template('login.html',role=role,error='Too many attempts. Try again in 15 minutes.'),429
        execute('INSERT INTO login_attempts VALUES(?,?,?)',(secrets.token_hex(16),uid,time.time())); db().commit()
        u=q('SELECT * FROM users WHERE id=?',(uid,),one=True)
        valid=check_password_hash(u['password'] if u else app.config['DUMMY_HASH'],request.form.get('password',''))
        if not valid or not u or u['status']!='approved':
            return render_template('login.html',role=role,error='Invalid credentials or account not approved.'),401
        session.clear();session.permanent=True;session['csrf']=secrets.token_hex(24);session['token']=secrets.token_urlsafe(32)
        execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(session['token'].encode()).hexdigest(),u['id'],time.time()+28800))
        g.user=u;audit('login',u['id']);db().commit()
        return redirect(url_for('dashboard'))
    return render_template('login.html',role=role)

@app.post('/logout')
def logout():
    if session.get('token'): execute('DELETE FROM sessions WHERE id=?',(hashlib.sha256(session['token'].encode()).hexdigest(),));db().commit()
    session.clear();return redirect(url_for('login'))

def workspace():
    role=g.user['role'];uid=g.user['id']
    patients=q('SELECT * FROM patients ORDER BY created DESC') if role=='admin' else q('SELECT * FROM patients WHERE id=?',(uid,)) if role=='patient' else q('SELECT p.* FROM patients p JOIN access a ON a.patient_id=p.id WHERE a.doctor_id=? AND a.granted=1 ORDER BY p.created DESC',(uid,)) if role=='doctor' else []
    ids={p['id'] for p in patients}
    if role=='laboratory':
        orders=q('SELECT * FROM orders WHERE lab_id=? ORDER BY created DESC',(uid,))
        reports=q('SELECT * FROM reports WHERE lab_id=? ORDER BY created DESC',(uid,))
    elif role=='admin':
        orders=q('SELECT * FROM orders ORDER BY created DESC'); reports=q('SELECT * FROM reports ORDER BY created DESC')
    else:
        orders=[];reports=[]
        for pid in ids:
            orders+=q('SELECT * FROM orders WHERE patient_id=?',(pid,));reports+=q('SELECT * FROM reports WHERE patient_id=?',(pid,))
    return patients,orders,reports

@app.get('/')
@roles('doctor','patient','laboratory','admin')
def dashboard():
    patients,orders,reports=workspace()
    organizations=q('SELECT * FROM organizations') if g.user['role']=='admin' else []
    readings=q('SELECT * FROM readings WHERE patient_id=? ORDER BY created DESC',(g.user['id'],)) if g.user['role']=='patient' else []
    audit('view_dashboard',g.user['id']);db().commit()
    return render_template('dashboard.html',active='dashboard',patients=patients,orders=orders,reports=reports,organizations=organizations,readings=readings)

@app.get('/patients')
@roles('doctor','admin')
def patients():
    records,_,_=workspace();search=request.args.get('search','').strip()
    if search: records=[p for p in records if search.lower() in (p['id']+' '+p['name']).lower()]
    audit('search_patients',g.user['id']);db().commit()
    return render_template('patients.html',active='patients',patients=records,search=search)

@app.route('/patients/register',methods=['GET','POST'])
@roles('doctor','admin')
def register_patient():
    if request.method=='POST':
        name=request.form.get('name','').strip();age=request.form.get('age','');phone=request.form.get('phone','').strip();gender=request.form.get('gender','')
        if not age.isdigit() or not 0<int(age)<130 or not name or len(name)>150 or not phone or gender not in ('Female','Male','Other','Prefer not to say'): abort(400,'Check the patient details.')
        pid='PAT-'+secrets.token_hex(4).upper()
        execute('INSERT INTO patients VALUES(?,?,?,?,?,?,?)',(pid,name,int(age),gender,phone,g.user['org_id'],time.time()))
        if g.user['role']=='doctor': execute('INSERT INTO access VALUES(?,?,?)',(pid,g.user['id'],1))
        audit('register_patient',pid);db().commit();flash('Patient registered. Unique ID: '+pid)
        return redirect(url_for('patient_detail',pid=pid))
    return render_template('register.html',active='register')

@app.get('/patients/<pid>')
@roles('doctor','admin','patient')
def patient_detail(pid):
    if not can_read(pid): abort(403)
    p=q('SELECT * FROM patients WHERE id=?',(pid,),one=True)
    if not p: abort(404)
    readings=q('SELECT * FROM readings WHERE patient_id=? ORDER BY created DESC',(pid,))
    reports=q('SELECT * FROM reports WHERE patient_id=? ORDER BY created DESC',(pid,))
    audit('view_patient',pid);db().commit()
    return render_template('patient.html',active='history' if g.user['role']=='patient' else 'patients',patient=p,readings=readings,reports=reports)

@app.post('/readings')
@roles('doctor')
def add_reading():
    pid=request.form.get('patient_id','')
    if not can_read(pid): abort(403)
    try: sys,dia,sugar=[int(request.form[k]) for k in ('systolic','diastolic','sugar')]
    except (KeyError,ValueError):abort(400,'Enter numeric readings.')
    if not (50<=sys<=300 and 30<=dia<=200 and dia<sys and 20<=sugar<=700): abort(400,'Readings outside allowed ranges.')
    execute('INSERT INTO readings VALUES(?,?,?,?,?,?,?)',(secrets.token_hex(16),pid,sys,dia,sugar,time.time(),g.user['id']))
    audit('add_reading',pid);db().commit();flash('Health readings saved.')
    return redirect(url_for('patient_detail',pid=pid))

@app.route('/permissions',methods=['GET','POST'])
@roles('patient','admin')
def permissions():
    patients,_,_=workspace()
    doctors=q("SELECT id,name FROM users WHERE role='doctor' AND status='approved'")
    if request.method=='POST':
        pid=request.form.get('patient_id','') if g.user['role']=='admin' else g.user['id'];doctor=request.form.get('doctor_id','');grant=request.form.get('granted')=='1'
        if not q('SELECT id FROM patients WHERE id=?',(pid,),one=True) or not any(d['id']==doctor for d in doctors):abort(400,'Select a patient and an approved doctor.')
        execute('INSERT INTO access VALUES(?,?,?) ON CONFLICT(patient_id,doctor_id) DO UPDATE SET granted=excluded.granted',(pid,doctor,int(grant)))
        audit('grant_access' if grant else 'revoke_access',pid+':'+doctor);db().commit();flash('Doctor access updated.');return redirect(url_for('permissions'))
    access=q('SELECT * FROM access') if g.user['role']=='admin' else q('SELECT * FROM access WHERE patient_id=?',(g.user['id'],))
    return render_template('permissions.html',active='permissions',doctors=doctors,patients=patients,access=access)

@app.route('/orders',methods=['GET','POST'])
@roles('doctor','laboratory','admin')
def orders():
    patients,orders,reports=workspace()
    labs=q("SELECT id,name FROM users WHERE role='laboratory' AND status='approved'") if g.user['role']=='doctor' else []
    if request.method=='POST':
        if g.user['role']=='doctor':
            pid=request.form.get('patient_id','');lab=request.form.get('lab_id','');test=request.form.get('test','').strip()
            if not can_read(pid):abort(403)
            if not test or len(test)>150 or not any(l['id']==lab for l in labs):abort(400,'Select an approved laboratory and test.')
            oid='ORD-'+secrets.token_hex(4).upper()
            execute('INSERT INTO orders VALUES(?,?,?,?,?,?,?)',(oid,pid,g.user['id'],lab,test,'pending',time.time()));audit('create_test_order',oid)
        elif g.user['role']=='laboratory':
            oid=request.form.get('order_id','');order=q('SELECT * FROM orders WHERE id=? AND lab_id=?',(oid,g.user['id']),one=True)
            if not order:abort(403)
            if order['status']!='pending':abort(400,'Only pending orders can start processing.')
            execute("UPDATE orders SET status='processing' WHERE id=?",(oid,));audit('process_test',oid)
        else:abort(403)
        db().commit();flash('Test order updated.');return redirect(url_for('orders'))
    return render_template('orders.html',active='orders',patients=patients,orders=orders,labs=labs)

@app.route('/reports',methods=['GET','POST'])
@roles('doctor','patient','laboratory','admin')
def reports():
    _,orders,reports=workspace()
    if request.method=='POST':
        if g.user['role']!='laboratory':abort(403)
        oid=request.form.get('order_id','');order=q('SELECT * FROM orders WHERE id=? AND lab_id=?',(oid,g.user['id']),one=True)
        if not order or order['status']=='completed':abort(403)
        f=request.files.get('report');body=f.read(5*1024*1024+1) if f else b''
        if not body.startswith(b'%PDF-') or len(body)>5*1024*1024:abort(400,'Upload a PDF file up to 5 MB.')
        rid=secrets.token_hex(24)
        store_report(rid,body)
        execute('INSERT INTO reports VALUES(?,?,?,?,?,?)',(rid,order['patient_id'],g.user['id'],f.filename[:150],time.time(),oid))
        execute("UPDATE orders SET status='completed' WHERE id=?",(oid,));audit('upload_report',rid);db().commit();flash('Report uploaded. Test completed.')
        return redirect(url_for('reports'))
    audit('view_reports',g.user['id']);db().commit()
    return render_template('reports.html',active='reports',reports=reports,orders=[o for o in orders if o['status']!='completed'])

def storage_request(method,rid,body=None):
    url=os.getenv('SUPABASE_URL','').rstrip('/');key=os.getenv('SUPABASE_SERVICE_ROLE_KEY');bucket=os.getenv('SUPABASE_STORAGE_BUCKET','medical-reports')
    if not url.startswith('https://') or not key:abort(503,'Private report storage is not configured.')
    response=requests.request(method,f'{url}/storage/v1/object/{bucket}/{rid}',headers={'apikey':key,'Authorization':'Bearer '+key,'Content-Type':'application/pdf'},data=body,timeout=30,allow_redirects=False)
    if response.status_code not in (200,201):abort(503,'Report storage is temporarily unavailable.')
    return response.content

def store_report(rid,body):
    if DEMO:
        (DATA/'reports').mkdir(exist_ok=True);(DATA/'reports'/rid).write_bytes(body)
    else:storage_request('POST',rid,body)

@app.get('/reports/<rid>')
@roles('doctor','patient','laboratory','admin')
def download_report(rid):
    report=q('SELECT * FROM reports WHERE id=?',(rid,),one=True)
    if not report or not (can_read(report['patient_id']) or (g.user['role']=='laboratory' and report['lab_id']==g.user['id'])):abort(403)
    audit('download_report',rid);db().commit()
    body=(DATA/'reports'/rid).read_bytes() if DEMO else storage_request('GET',rid)
    return send_file(io.BytesIO(body),mimetype='application/pdf',as_attachment=request.args.get('view')!='1',download_name='medical-report.pdf')

@app.route('/admin/organizations',methods=['GET','POST'])
@roles('admin')
def organizations():
    if request.method=='POST':
        name=request.form.get('name','').strip();kind=request.form.get('type','')
        if not name or len(name)>150 or kind not in ('Hospital','Clinic','Laboratory'):abort(400)
        oid='ORG-'+secrets.token_hex(4).upper();execute('INSERT INTO organizations VALUES(?,?,?)',(oid,name,kind));audit('register_organization',oid);db().commit();flash('Organization registered.')
        return redirect(url_for('organizations'))
    return render_template('organizations.html',active='organizations',organizations=q('SELECT * FROM organizations'))

@app.route('/admin/accounts',methods=['GET','POST'])
@roles('admin')
def accounts():
    if request.method=='POST':
        action=request.form.get('action');uid=request.form.get('id','').strip().upper()
        if action=='create':
            name=request.form.get('name','').strip();role=request.form.get('role');password=request.form.get('password','');org=request.form.get('org_id')
            if not uid or len(uid)>80 or not name or len(password)<12 or role not in ('doctor','patient','laboratory','admin') or not q('SELECT id FROM organizations WHERE id=?',(org,),one=True):abort(400,'Check the account details. Password needs at least 12 characters.')
            if q('SELECT id FROM users WHERE id=?',(uid,),one=True):abort(400,'Account ID already exists.')
            if role=='patient' and not q('SELECT id FROM patients WHERE id=?',(uid,),one=True):abort(400,'Register the patient first, then use their exact patient ID.')
            execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,name,role,generate_password_hash(password),'pending',org));audit('create_account',uid)
        elif action=='update':
            status=request.form.get('status');role=request.form.get('role')
            if uid==g.user['id'] or status not in ('approved','pending','suspended') or role not in ('doctor','laboratory','patient','admin'):abort(400,'Invalid account change.')
            existing=q('SELECT * FROM users WHERE id=?',(uid,),one=True)
            if not existing:abort(404)
            # Patient identities must stay bound to medical records. Staff roles may change.
            if (existing['role']=='patient') != (role=='patient'):abort(400,'Create a separate account when changing between patient and staff.')
            execute('UPDATE users SET role=?,status=? WHERE id=?',(role,status,uid));execute('DELETE FROM sessions WHERE user_id=?',(uid,));audit('update_account_permissions',uid)
        else:abort(400)
        db().commit();flash('Account saved.');return redirect(url_for('accounts'))
    return render_template('accounts.html',active='accounts',accounts=q('SELECT id,name,role,status,org_id FROM users'),organizations=q('SELECT * FROM organizations'))

@app.get('/admin/audit')
@roles('admin')
def audit_log():return render_template('audit.html',active='audit',events=q('SELECT * FROM audit ORDER BY created DESC LIMIT 100'))

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(503)
def expected_error(error):return render_template('error.html',code=error.code,message=error.description),error.code

app.config['DUMMY_HASH']=generate_password_hash(secrets.token_urlsafe(24))

def seed_demo():
    if q('SELECT id FROM users LIMIT 1'):return
    execute('INSERT INTO organizations VALUES(?,?,?)',('ORG-101','MediCore Medical Center','Hospital'))
    for uid,name,role in [('DOC-101','Dr. Sarah Mitchell','doctor'),('PAT-4921','Olivia Rhye','patient'),('LAB-101','Clarity Diagnostics','laboratory'),('ADM-101','Alex Morgan','admin')]:
        execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,name,role,generate_password_hash('DemoPass123!'),'approved','ORG-101'))
    for pid,name,age,gender,phone in [('PAT-4921','Olivia Rhye',32,'Female','+1 415 555 0124'),('PAT-4922','Phoenix Baker',45,'Male','+1 415 555 0198'),('PAT-4923','Lana Steiner',28,'Female','+1 415 555 0162')]:
        execute('INSERT INTO patients VALUES(?,?,?,?,?,?,?)',(pid,name,age,gender,phone,'ORG-101',time.time()));execute('INSERT INTO access VALUES(?,?,?)',(pid,'DOC-101',1))
    for i,(sys,dia,sugar) in enumerate([(124,82,108),(122,80,104),(128,84,112),(120,78,98),(118,78,102),(122,80,106)]):
        execute('INSERT INTO readings VALUES(?,?,?,?,?,?,?)',(secrets.token_hex(8),'PAT-4921',sys,dia,sugar,time.time()-(5-i)*86400,'DOC-101'))
    execute('INSERT INTO orders VALUES(?,?,?,?,?,?,?)',('ORD-2041','PAT-4921','DOC-101','LAB-101','Complete blood count','pending',time.time()));db().commit()

if DEMO:
    with app.app_context():init_db();seed_demo()
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.getenv('PORT','8000')),debug=False)
