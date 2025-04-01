import os
import pytest
from app import create_app, db
from models import User, Scan, MonitoredSite, SecurityEvent, PasswordPolicy

@pytest.fixture
def app():
    """إنشاء نسخة اختبار من التطبيق"""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """إنشاء عميل اختبار"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """إنشاء عداء أوامر Flask"""
    return app.test_cli_runner()

@pytest.fixture
def user(app):
    """إنشاء مستخدم للاختبار"""
    user = User(
        username='testuser',
        email='test@example.com'
    )
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def auth(client, user):
    """تسجيل دخول المستخدم"""
    client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    })

def test_index_page(client):
    """اختبار الصفحة الرئيسية"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'فاحص أمان المواقع' in response.data

def test_register(client):
    """اختبار التسجيل"""
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'password123',
        'confirm_password': 'password123'
    })
    assert response.status_code == 302
    assert User.query.filter_by(username='newuser').first() is not None

def test_login(client, user):
    """اختبار تسجيل الدخول"""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 302
    assert 'user_id' in client.get_cookie('session')

def test_logout(client, auth):
    """اختبار تسجيل الخروج"""
    response = client.get('/logout')
    assert response.status_code == 302
    assert 'user_id' not in client.get_cookie('session')

def test_dashboard(client, auth):
    """اختبار لوحة التحكم"""
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'لوحة التحكم' in response.data

def test_scan(client, auth):
    """اختبار فحص موقع"""
    response = client.post('/scan', data={
        'url': 'https://example.com',
        'scan_type': 'full',
        'generate_report': True,
        'add_to_monitoring': False
    })
    assert response.status_code == 302
    assert Scan.query.filter_by(url='https://example.com').first() is not None

def test_monitored_sites(client, auth):
    """اختبار المواقع المراقبة"""
    # إضافة موقع للفحص
    client.post('/scan', data={
        'url': 'https://example.com',
        'scan_type': 'full',
        'generate_report': False,
        'add_to_monitoring': True,
        'check_interval': 24
    })
    
    response = client.get('/monitored-sites')
    assert response.status_code == 200
    assert MonitoredSite.query.filter_by(url='https://example.com').first() is not None

def test_settings(client, auth):
    """اختبار الإعدادات"""
    response = client.post('/settings', data={
        'min_length': 10,
        'require_numbers': True,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_special': True
    })
    assert response.status_code == 302
    policy = PasswordPolicy.query.first()
    assert policy.min_length == 10
    assert policy.require_numbers is True

def test_security_events(client, auth):
    """اختبار أحداث الأمان"""
    # تسجيل خروج
    client.get('/logout')
    # تسجيل دخول
    client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    })
    
    events = SecurityEvent.query.filter_by(event_type='login').all()
    assert len(events) > 0

def test_error_handlers(client):
    """اختبار معالجة الأخطاء"""
    response = client.get('/nonexistent')
    assert response.status_code == 404
    assert b'الصفحة غير موجودة' in response.data 