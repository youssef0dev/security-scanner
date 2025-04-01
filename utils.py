import re
import hashlib
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import ssl
import socket
import dns.resolver
from bs4 import BeautifulSoup
from config import Config
import tempfile
import time
import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle

def check_password_strength(password: str) -> Tuple[int, List[Dict[str, any]]]:
    """
    فحص قوة كلمة المرور وإرجاع درجة القوة والتغذية الراجعة
    
    Args:
        password: كلمة المرور المراد فحصها
        
    Returns:
        Tuple[int, List[Dict[str, any]]]: درجة القوة (0-100) وقائمة التغذية الراجعة
    """
    score = 0
    feedback = []
    
    # فحص الطول
    if len(password) < 8:
        feedback.append({
            'type': 'length',
            'message': 'كلمة المرور قصيرة جداً. يجب أن تكون 8 أحرف على الأقل.',
            'severity': 'high'
        })
    else:
        score += 20
    
    # فحص الأرقام
    if not re.search(r"\d", password):
        feedback.append({
            'type': 'numbers',
            'message': 'يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.',
            'severity': 'medium'
        })
    else:
        score += 20
    
    # فحص الأحرف الكبيرة
    if not re.search(r"[A-Z]", password):
        feedback.append({
            'type': 'uppercase',
            'message': 'يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل.',
            'severity': 'medium'
        })
    else:
        score += 20
    
    # فحص الأحرف الصغيرة
    if not re.search(r"[a-z]", password):
        feedback.append({
            'type': 'lowercase',
            'message': 'يجب أن تحتوي كلمة المرور على حرف صغير واحد على الأقل.',
            'severity': 'medium'
        })
    else:
        score += 20
    
    # فحص الرموز الخاصة
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        feedback.append({
            'type': 'special',
            'message': 'يجب أن تحتوي كلمة المرور على رمز خاص واحد على الأقل.',
            'severity': 'medium'
        })
    else:
        score += 20
    
    # فحص التكرار
    if re.search(r"(.)\1{2,}", password):
        feedback.append({
            'type': 'repeated',
            'message': 'تجنب تكرار نفس الحرف أكثر من مرتين.',
            'severity': 'low'
        })
    
    return score, feedback

def check_password_breach(password: str) -> Optional[int]:
    """
    فحص ما إذا كانت كلمة المرور موجودة في قواعد البيانات المسربة
    
    Args:
        password: كلمة المرور المراد فحصها
        
    Returns:
        Optional[int]: عدد مرات ظهور كلمة المرور في قواعد البيانات المسربة
    """
    try:
        # تحويل كلمة المرور إلى SHA-1
        sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        # استخدام API Have I Been Pwned
        headers = {
            'hibp-api-key': Config.HIBP_API_KEY,
            'user-agent': Config.APP_NAME
        }
        
        response = requests.get(
            f"{Config.HIBP_API_URL}/range/{prefix}",
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return int(count)
        
        return None
        
    except Exception as e:
        print(f"خطأ في فحص كلمة المرور: {str(e)}")
        return None

def log_security_event(user_id: Optional[int], event_type: str, ip_address: str, 
                      user_agent: str, details: Optional[Dict] = None) -> None:
    """
    تسجيل حدث أمني في قاعدة البيانات
    
    Args:
        user_id: معرف المستخدم (اختياري)
        event_type: نوع الحدث
        ip_address: عنوان IP
        user_agent: معلومات المتصفح
        details: تفاصيل إضافية (اختياري)
    """
    try:
        from models import SecurityEvent, db
        
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
        
        db.session.add(event)
        db.session.commit()
        
    except Exception as e:
        print(f"خطأ في تسجيل الحدث الأمني: {str(e)}")

def format_datetime(dt: datetime) -> str:
    """
    تنسيق التاريخ والوقت باللغة العربية
    
    Args:
        dt: كائن التاريخ والوقت
        
    Returns:
        str: التاريخ والوقت المنسق
    """
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(dt)

def validate_url(url: str) -> bool:
    """
    التحقق من صحة عنوان URL
    
    Args:
        url: عنوان URL المراد التحقق منه
        
    Returns:
        bool: صحة العنوان
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_ssl_info(url: str) -> Dict:
    """
    الحصول على معلومات شهادة SSL
    
    Args:
        url: عنوان الموقع
        
    Returns:
        Dict: معلومات شهادة SSL
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'status': 'valid',
                    'issuer': cert['issuer'],
                    'expiry': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z'),
                    'protocol': ssock.version()
                }
    except Exception as e:
        return {
            'status': 'invalid',
            'error': str(e)
        }

def get_dns_info(url: str) -> Dict:
    """
    الحصول على معلومات DNS
    
    Args:
        url: عنوان الموقع
        
    Returns:
        Dict: معلومات DNS
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        return {
            'status': 'valid',
            'records': records
        }
    except Exception as e:
        return {
            'status': 'invalid',
            'error': str(e)
        }

def check_security_headers(url: str) -> Dict:
    """
    فحص رؤوس HTTP الأمنية
    
    Args:
        url: عنوان الموقع
        
    Returns:
        Dict: معلومات رؤوس HTTP الأمنية
    """
    try:
        response = requests.get(url, verify=Config.SSL_VERIFY, 
                              timeout=Config.REQUEST_TIMEOUT)
        headers = dict(response.headers)
        
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'missing')
        }
        
        return {
            'status': 'valid',
            'headers': security_headers
        }
    except Exception as e:
        return {
            'status': 'invalid',
            'error': str(e)
        }

def scan_vulnerabilities(url: str) -> List[Dict]:
    """
    فحص الثغرات الشائعة
    
    Args:
        url: عنوان الموقع
        
    Returns:
        List[Dict]: قائمة الثغرات المكتشفة
    """
    vulnerabilities = []
    
    try:
        response = requests.get(url, verify=Config.SSL_VERIFY, 
                              timeout=Config.REQUEST_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # فحص النماذج
        forms = soup.find_all('form')
        for form in forms:
            if not form.get('action', '').startswith('https'):
                vulnerabilities.append({
                    'type': 'insecure_form',
                    'description': 'نموذج يستخدم HTTP بدلاً من HTTPS',
                    'severity': 'medium',
                    'element': str(form)
                })
        
        # فحص الروابط
        links = soup.find_all('a')
        for link in links:
            href = link.get('href', '')
            if href.startswith('http://'):
                vulnerabilities.append({
                    'type': 'insecure_link',
                    'description': f'رابط يستخدم HTTP: {href}',
                    'severity': 'low',
                    'element': str(link)
                })
        
        # فحص الصور
        images = soup.find_all('img')
        for img in images:
            src = img.get('src', '')
            if src.startswith('http://'):
                vulnerabilities.append({
                    'type': 'insecure_image',
                    'description': f'صورة تستخدم HTTP: {src}',
                    'severity': 'low',
                    'element': str(img)
                })
        
    except Exception as e:
        vulnerabilities.append({
            'type': 'scan_error',
            'description': str(e),
            'severity': 'high'
        })
    
    return vulnerabilities

def generate_pdf_report(results, url):
    """
    إنشاء تقرير PDF من نتائج الفحص
    
    Args:
        results (dict): نتائج الفحص
        url (str): عنوان الموقع المفحوص
        
    Returns:
        str: مسار ملف PDF
    """
    try:
        # إنشاء ملف PDF مؤقت
        pdf_path = os.path.join(tempfile.gettempdir(), f'security_report_{int(time.time())}.pdf')
        doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        elements = []
        
        # إضافة العنوان
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1
        )
        elements.append(Paragraph(f"تقرير فحص أمان الموقع: {url}", title_style))
        
        # إضافة تاريخ الفحص
        date_style = ParagraphStyle(
            'CustomDate',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=20,
            alignment=1
        )
        elements.append(Paragraph(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
        
        # إضافة ملخص النتائج
        summary_style = ParagraphStyle(
            'CustomSummary',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=20
        )
        elements.append(Paragraph("ملخص النتائج", summary_style))
        
        # إضافة حالة SSL
        ssl_status = "✅ آمن" if results['ssl_status']['valid'] else "❌ غير آمن"
        ssl_color = "green" if results['ssl_status']['valid'] else "red"
        ssl_text = f"حالة شهادة SSL: <font color='{ssl_color}'>{ssl_status}</font>"
        elements.append(Paragraph(ssl_text, styles['Normal']))
        
        if results['ssl_status']['valid']:
            elements.append(Paragraph(f"تاريخ انتهاء الصلاحية: {results['ssl_status']['expiry_date']}", styles['Normal']))
            elements.append(Paragraph(f"قوة التشفير: {results['ssl_status']['encryption']}", styles['Normal']))
        
        # إضافة حالة DNS
        dns_status = "✅ جيدة" if results['dns_status']['valid'] else "❌ ضعيفة"
        dns_color = "green" if results['dns_status']['valid'] else "red"
        dns_text = f"حالة DNS: <font color='{dns_color}'>{dns_status}</font>"
        elements.append(Paragraph(dns_text, styles['Normal']))
        
        # إضافة عدد الثغرات المكتشفة
        vuln_count = len(results['vulnerabilities'])
        vuln_status = "✅ آمن" if vuln_count == 0 else "⚠️ يحتاج إلى اهتمام"
        vuln_color = "green" if vuln_count == 0 else "orange"
        vuln_text = f"عدد الثغرات المكتشفة: {vuln_count} <font color='{vuln_color}'>({vuln_status})</font>"
        elements.append(Paragraph(vuln_text, styles['Normal']))
        
        # إضافة الثغرات المكتشفة
        if vuln_count > 0:
            elements.append(Paragraph("الثغرات المكتشفة", summary_style))
            for vuln in results['vulnerabilities']:
                vuln_text = f"• {vuln['title']} (مستوى الخطورة: {vuln['severity']})"
                elements.append(Paragraph(vuln_text, styles['Normal']))
                elements.append(Paragraph(f"  {vuln['description']}", styles['Normal']))
                elements.append(Paragraph(f"  الحل المقترح: {vuln['solution']}", styles['Normal']))
                elements.append(Paragraph("<br/>", styles['Normal']))
        
        # إضافة التوصيات
        elements.append(Paragraph("التوصيات", summary_style))
        for rec in results['recommendations']:
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
        
        # إضافة معلومات إضافية
        elements.append(Paragraph("معلومات إضافية", summary_style))
        elements.append(Paragraph(f"• نوع الفحص: {results['scan_type']}", styles['Normal']))
        elements.append(Paragraph(f"• مدة الفحص: {results['scan_duration']} ثانية", styles['Normal']))
        
        # إضافة تذييل الصفحة
        elements.append(Paragraph("<br/><br/>", styles['Normal']))
        footer_style = ParagraphStyle(
            'CustomFooter',
            parent=styles['Normal'],
            fontSize=10,
            alignment=1
        )
        elements.append(Paragraph("تم إنشاء هذا التقرير بواسطة فاحص أمان المواقع", footer_style))
        
        # إنشاء PDF
        doc.build(elements)
        return pdf_path
        
    except Exception as e:
        print(f"خطأ في إنشاء تقرير PDF: {str(e)}")
        return None 