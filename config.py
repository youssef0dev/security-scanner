import os
from dotenv import load_dotenv
from datetime import timedelta

# تحميل المتغيرات البيئية
load_dotenv()

class Config:
    """الإعدادات الأساسية للتطبيق"""
    # الإعدادات الأساسية
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # إعدادات الأمان
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # إعدادات البريد الإلكتروني
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = [os.environ.get('ADMIN_EMAIL')]
    
    # إعدادات الفحص
    MAX_SCAN_DEPTH = 3
    SCAN_TIMEOUT = 30  # ثواني
    MAX_CONCURRENT_SCANS = 5
    
    # إعدادات التقارير
    REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    MAX_REPORTS_PER_USER = 10
    
    # إعدادات المراقبة
    MIN_CHECK_INTERVAL = 60  # دقائق
    MAX_CHECK_INTERVAL = 10080  # دقائق (أسبوع)
    MAX_MONITORED_SITES = 10
    
    @staticmethod
    def init_app(app):
        """تهيئة التطبيق"""
        # إنشاء مجلد التقارير إذا لم يكن موجوداً
        if not os.path.exists(Config.REPORT_DIR):
            os.makedirs(Config.REPORT_DIR)

class DevelopmentConfig(Config):
    """إعدادات بيئة التطوير"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

class TestingConfig(Config):
    """إعدادات بيئة الاختبار"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

class ProductionConfig(Config):
    """إعدادات بيئة الإنتاج"""
    DEBUG = False
    TESTING = False
    
    @classmethod
    def init_app(cls, app):
        """تهيئة التطبيق في بيئة الإنتاج"""
        Config.init_app(app)
        
        # إعداد تسجيل الأخطاء
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        file_handler = RotatingFileHandler(
            'logs/app.log', 
            maxBytes=10240, 
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('بدء تشغيل التطبيق')

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 