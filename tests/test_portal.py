import os, tempfile, unittest, io
from unittest.mock import patch, Mock
TEST_DATA=tempfile.TemporaryDirectory()
os.environ['DEMO_MODE']='1';os.environ['DATA_DIR']=TEST_DATA.name
os.environ.pop('DATABASE_URL',None)
from app import app,db,q,seed_demo,storage_request

class PortalTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING']=True
        with app.app_context():
            for table in ['audit','sessions','login_attempts','reports','orders','readings','access','patients','users','organizations']:db().execute('DELETE FROM '+table)
            db().commit();seed_demo()
        self.doctor=self.login('DOC-101');self.patient=self.login('PAT-4921');self.lab=self.login('LAB-101');self.admin=self.login('ADM-101')
    def csrf(self,client):
        client.get('/login')
        with client.session_transaction() as session:return session['csrf']
    def post(self,c,path,data=None,**kw):
        payload={'csrf':self.csrf(c),**(data or {})}
        return c.post(path,data=payload,**kw)
    def login(self,uid):
        c=app.test_client();r=self.post(c,'/login',{'id':uid,'password':'DemoPass123!'})
        self.assertEqual(r.status_code,302);return c
    def test_all_portal_pages_render(self):
        for c,paths in [(self.doctor,['/','/patients','/patients?search=PAT-4921','/patients/register','/patients/PAT-4921','/orders','/reports']),(self.patient,['/','/patients/PAT-4921','/permissions','/reports']),(self.lab,['/','/orders','/reports']),(self.admin,['/','/patients','/patients/register','/permissions','/orders','/reports','/admin/organizations','/admin/accounts','/admin/audit'])]:
            for path in paths:
                with self.subTest(path=path):self.assertEqual(c.get(path).status_code,200)
    def test_anonymous_and_role_boundaries(self):
        self.assertEqual(app.test_client().get('/patients/PAT-4921').status_code,302)
        self.assertEqual(self.patient.get('/patients/PAT-4922').status_code,403)
        self.assertEqual(self.lab.get('/patients/PAT-4921').status_code,403)
        self.assertEqual(self.doctor.get('/admin/accounts').status_code,403)
        self.assertEqual(self.post(self.patient,'/patients/register',{'name':'Forbidden'}).status_code,403)
        self.assertEqual(self.lab.get('/').data.count(b'Olivia Rhye'),0)
    def test_csrf_login_and_logout(self):
        c=app.test_client();self.assertEqual(c.post('/login',data={'id':'DOC-101','password':'DemoPass123!'}).status_code,400)
        self.assertEqual(self.post(c,'/login',{'id':'DOC-101','password':'wrong'}).status_code,401)
        self.assertEqual(self.post(self.doctor,'/logout').status_code,302)
        self.assertEqual(self.doctor.get('/').status_code,302)
    def test_revocation_and_readings(self):
        fields={'patient_id':'PAT-4921','systolic':'121','diastolic':'81','sugar':'103'}
        self.assertEqual(self.post(self.doctor,'/readings',fields).status_code,302)
        self.assertEqual(self.post(self.doctor,'/readings',{**fields,'systolic':'70'}).status_code,400)
        self.post(self.patient,'/permissions',{'doctor_id':'DOC-101','granted':'0'})
        self.assertEqual(self.doctor.get('/patients/PAT-4921').status_code,403)
        self.assertNotIn(b'Olivia Rhye',self.doctor.get('/patients').data)
        self.assertEqual(self.post(self.doctor,'/readings',fields).status_code,403)
        self.post(self.patient,'/permissions',{'doctor_id':'DOC-101','granted':'1'})
        self.assertEqual(self.doctor.get('/patients/PAT-4921').status_code,200)
    def test_registration_orders_reports(self):
        r=self.post(self.doctor,'/patients/register',{'name':'Test Patient','age':'42','gender':'Female','phone':'555-0100'})
        self.assertEqual(r.status_code,302);pid=r.location.rsplit('/',1)[-1]
        self.assertEqual(self.post(self.doctor,'/orders',{'patient_id':pid,'lab_id':'LAB-101','test':'CBC'}).status_code,302)
        with app.app_context():oid=q('SELECT id FROM orders WHERE patient_id=?',(pid,),one=True)['id']
        self.assertEqual(self.post(self.lab,'/orders',{'order_id':oid}).status_code,302)
        invalid=self.post(self.lab,'/reports',{'order_id':oid,'report':(io.BytesIO(b'not pdf'),'bad.pdf')},content_type='multipart/form-data')
        self.assertEqual(invalid.status_code,400)
        content=b'%PDF-1.4\nSynthetic test document\n%%EOF'
        result=self.post(self.lab,'/reports',{'order_id':oid,'report':(io.BytesIO(content),'CBC.pdf')},content_type='multipart/form-data')
        self.assertEqual(result.status_code,302)
        with app.app_context():rid=q('SELECT id FROM reports WHERE patient_id=?',(pid,),one=True)['id']
        for c in [self.doctor,self.lab,self.admin]:self.assertEqual(c.get('/reports/'+rid).data,content)
        self.assertEqual(self.patient.get('/reports/'+rid).status_code,403)
        self.assertEqual(self.doctor.get('/reports/'+rid+'?view=1').headers['Content-Disposition'],'inline; filename=medical-report.pdf')
        self.assertEqual(self.post(self.lab,'/reports',{'order_id':'UNASSIGNED','report':(io.BytesIO(content),'x.pdf')},content_type='multipart/form-data').status_code,403)
    def test_admin_approval_and_session_revocation(self):
        r=self.post(self.admin,'/admin/accounts',{'action':'create','id':'DOC-102','name':'New Doctor','role':'doctor','org_id':'ORG-101','password':'StrongPassword123!'})
        self.assertEqual(r.status_code,302)
        c=app.test_client();self.assertEqual(self.post(c,'/login',{'id':'DOC-102','password':'StrongPassword123!'}).status_code,401)
        self.assertEqual(self.post(self.admin,'/admin/accounts',{'action':'update','id':'DOC-102','role':'doctor','status':'approved'}).status_code,302)
        self.assertEqual(self.post(c,'/login',{'id':'DOC-102','password':'StrongPassword123!'}).status_code,302)
        self.post(self.admin,'/admin/accounts',{'action':'update','id':'DOC-102','role':'doctor','status':'suspended'})
        self.assertEqual(c.get('/').status_code,302)
        self.assertEqual(self.post(self.admin,'/admin/accounts',{'action':'update','id':'ADM-101','role':'doctor','status':'approved'}).status_code,400)
    def test_patient_account_and_organization(self):
        self.assertEqual(self.post(self.admin,'/admin/organizations',{'name':'New Clinic','type':'Clinic'}).status_code,302)
        self.assertIn(b'New Clinic',self.admin.get('/admin/organizations').data)
        self.assertEqual(self.post(self.admin,'/admin/accounts',{'action':'create','id':'PAT-MISSING','name':'Missing','role':'patient','org_id':'ORG-101','password':'StrongPassword123!'}).status_code,400)
    def test_audit_and_security_headers(self):
        self.doctor.get('/patients/PAT-4921')
        page=self.admin.get('/admin/audit')
        self.assertIn(b'view patient',page.data)
        self.assertIn("frame-ancestors 'none'",page.headers['Content-Security-Policy'])
        self.assertEqual(page.headers['Cache-Control'],'no-store')
        self.assertEqual(self.admin.get('/health').json,{'status':'ok'})
    def test_storage_adapter_keeps_secrets_server_side(self):
        with app.test_request_context('/'),patch.dict(os.environ,{'SUPABASE_URL':'https://test.supabase.co','SUPABASE_SERVICE_ROLE_KEY':'server-secret'}),patch('app.requests.request') as call:
            call.return_value=Mock(status_code=200,content=b'%PDF-test')
            self.assertEqual(storage_request('GET','abc'),b'%PDF-test')
            args,kwargs=call.call_args
            self.assertEqual(args,('GET','https://test.supabase.co/storage/v1/object/medical-reports/abc'))
            self.assertEqual(kwargs['headers']['Authorization'],'Bearer server-secret')
            self.assertFalse(kwargs['allow_redirects'])
    def test_admin_password_reset(self):
        from manage import initialize
        with patch.dict(os.environ, {'INITIAL_ADMIN_ID':'ADM-101','RESET_ADMIN_PASSWORD':'NewPrivatePassword123!'}):
            initialize()
            self.assertEqual(self.admin.get('/').status_code,302)
            c=app.test_client()
            self.assertEqual(self.post(c,'/login',{'id':'ADM-101','password':'DemoPass123!'}).status_code,401)
            self.assertEqual(self.post(c,'/login',{'id':'ADM-101','password':'NewPrivatePassword123!'}).status_code,302)
            initialize()
            self.assertEqual(c.get('/').status_code,200)
            with app.app_context():
                self.assertEqual(q("SELECT COUNT(*) AS n FROM audit WHERE action='admin_password_reset'",one=True)['n'],1)
    def test_login_rate_limit(self):
        c=app.test_client()
        for _ in range(10):self.assertEqual(self.post(c,'/login',{'id':'UNKNOWN','password':'bad'}).status_code,401)
        self.assertEqual(self.post(c,'/login',{'id':'UNKNOWN','password':'bad'}).status_code,429)
if __name__=='__main__':unittest.main()
