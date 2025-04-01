import os
import pytest
from app import create_app, db

@pytest.fixture(scope='session')
def app():
    """إنشاء نسخة اختبار من التطبيق"""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='session')
def client(app):
    """إنشاء عميل اختبار"""
    return app.test_client()

@pytest.fixture(scope='session')
def runner(app):
    """إنشاء عداء أوامر Flask"""
    return app.test_cli_runner()

@pytest.fixture(scope='session')
def user(app):
    """إنشاء مستخدم للاختبار"""
    from models import User
    
    user = User(
        username='testuser',
        email='test@example.com'
    )
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture(scope='session')
def auth(client, user):
    """تسجيل دخول المستخدم"""
    client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    }) 