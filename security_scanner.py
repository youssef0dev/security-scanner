from typing import Dict, List, Any
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from utils import (
    get_ssl_info,
    get_dns_info,
    check_security_headers,
    scan_vulnerabilities
)
import ssl
import socket
import dns.resolver
import whois
import concurrent.futures
from datetime import datetime
import json
import re
import nmap
import subprocess
import sys
import os
import time

class SecurityScanner:
    """فئة فحص أمان المواقع"""
    
    def __init__(self, url: str, scan_type: str = 'full'):
        """
        تهيئة فاحص الأمان
        
        Args:
            url: عنوان الموقع المراد فحصه
            scan_type: نوع الفحص (full, ssl, dns, headers, vulnerabilities)
        """
        self.url = url
        self.scan_type = scan_type
        self.results = {
            'ssl_status': {'status': 'unknown', 'details': '', 'expiry_date': None},
            'dns_status': {'status': 'unknown', 'details': '', 'records': []},
            'vulnerabilities': [],
            'recommendations': []
        }
    
    def run_scan(self):
        """تشغيل الفحص الأمني"""
        start_time = time.time()
        
        try:
            # التحقق من صحة URL
            if not self._validate_url():
                raise ValueError("عنوان URL غير صالح")
            
            # فحص SSL
            ssl_status = self._check_ssl()
            
            # فحص DNS
            dns_status = self._check_dns()
            
            # فحص الثغرات
            vulnerabilities = self._check_vulnerabilities()
            
            # إضافة التوصيات
            recommendations = self._add_recommendations()
            
            # حساب مدة الفحص
            scan_duration = time.time() - start_time
            
            return {
                'scan_type': 'full',
                'scan_duration': round(scan_duration, 2),
                'ssl_status': ssl_status,
                'dns_status': dns_status,
                'vulnerabilities': vulnerabilities,
                'recommendations': recommendations
            }
            
        except Exception as e:
            print(f"خطأ أثناء الفحص: {str(e)}")
            return {
                'scan_type': 'full',
                'scan_duration': round(time.time() - start_time, 2),
                'ssl_status': {'valid': False, 'error': str(e)},
                'dns_status': {'valid': False, 'error': str(e)},
                'vulnerabilities': [],
                'recommendations': ['حدث خطأ أثناء الفحص. يرجى المحاولة مرة أخرى.']
            }
    
    def _validate_url(self) -> bool:
        """التحقق من صحة عنوان URL"""
        try:
            result = urlparse(self.url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _check_ssl(self) -> Dict[str, Any]:
        """فحص شهادة SSL"""
        try:
            hostname = urlparse(self.url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # التحقق من صلاحية الشهادة
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if datetime.now() > not_after:
                        self.results['ssl_status'] = {
                            'status': 'expired',
                            'details': 'شهادة SSL منتهية الصلاحية',
                            'expiry_date': not_after.strftime('%Y-%m-%d')
                        }
                    else:
                        self.results['ssl_status'] = {
                            'status': 'valid',
                            'details': 'شهادة SSL صالحة',
                            'expiry_date': not_after.strftime('%Y-%m-%d')
                        }
                    
                    # التحقق من قوة التشفير
                    cipher = ssock.cipher()
                    if cipher[2] < 128:
                        self.results['vulnerabilities'].append({
                            'title': 'تشفير ضعيف',
                            'description': f'يستخدم الموقع تشفير {cipher[0]} بضعف {cipher[2]} بت',
                            'severity': 'medium',
                            'recommendation': 'تحديث خوارزمية التشفير إلى 256 بت على الأقل'
                        })
                        
            return self.results['ssl_status']
            
        except Exception as e:
            self.results['ssl_status'] = {
                'status': 'invalid',
                'details': f'خطأ في شهادة SSL: {str(e)}',
                'expiry_date': None
            }
            return self.results['ssl_status']
    
    def _check_dns(self) -> Dict[str, Any]:
        """فحص إعدادات DNS"""
        try:
            domain = urlparse(self.url).netloc
            records = []
            
            # فحص سجلات A
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                records.extend([f'A: {rdata.to_text()}' for rdata in a_records])
            except:
                self.results['vulnerabilities'].append({
                    'title': 'سجلات DNS غير مكتملة',
                    'description': 'لم يتم العثور على سجلات A',
                    'severity': 'high',
                    'recommendation': 'إضافة سجلات A للموقع'
                })
            
            # فحص سجلات MX
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                records.extend([f'MX: {rdata.to_text()}' for rdata in mx_records])
            except:
                pass
            
            # فحص سجلات TXT
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                records.extend([f'TXT: {rdata.to_text()}' for rdata in txt_records])
            except:
                pass
            
            # فحص SPF
            spf_found = False
            for record in records:
                if 'TXT: v=spf1' in record:
                    spf_found = True
                    break
            
            if not spf_found:
                self.results['vulnerabilities'].append({
                    'title': 'عدم وجود سجل SPF',
                    'description': 'لم يتم العثور على سجل SPF للموقع',
                    'severity': 'medium',
                    'recommendation': 'إضافة سجل SPF لحماية البريد الإلكتروني'
                })
            
            self.results['dns_status'] = {
                'status': 'valid',
                'details': 'إعدادات DNS صحيحة',
                'records': records
            }
            
            return self.results['dns_status']
            
        except Exception as e:
            self.results['dns_status'] = {
                'status': 'invalid',
                'details': f'خطأ في DNS: {str(e)}',
                'records': []
            }
            return self.results['dns_status']
    
    def _check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """فحص نقاط الضعف"""
        try:
            # فحص رأس HTTP
            response = requests.get(self.url, verify=False)
            headers = response.headers
            
            # فحص HSTS
            if 'Strict-Transport-Security' not in headers:
                self.results['vulnerabilities'].append({
                    'title': 'عدم تفعيل HSTS',
                    'description': 'لم يتم العثور على رأس HSTS',
                    'severity': 'medium',
                    'recommendation': 'تفعيل HSTS لحماية الاتصالات',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'
                })
            
            # فحص XSS Protection
            if 'X-XSS-Protection' not in headers:
                self.results['vulnerabilities'].append({
                    'title': 'عدم تفعيل حماية XSS',
                    'description': 'لم يتم العثور على رأس X-XSS-Protection',
                    'severity': 'medium',
                    'recommendation': 'تفعيل حماية XSS',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                })
            
            # فحص Content Security Policy
            if 'Content-Security-Policy' not in headers:
                self.results['vulnerabilities'].append({
                    'title': 'عدم وجود سياسة أمان المحتوى',
                    'description': 'لم يتم العثور على رأس Content-Security-Policy',
                    'severity': 'high',
                    'recommendation': 'إضافة سياسة أمان المحتوى',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
                })
            
            # فحص Clickjacking Protection
            if 'X-Frame-Options' not in headers:
                self.results['vulnerabilities'].append({
                    'title': 'عدم تفعيل حماية Clickjacking',
                    'description': 'لم يتم العثور على رأس X-Frame-Options',
                    'severity': 'medium',
                    'recommendation': 'تفعيل حماية Clickjacking',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'
                })
            
            # فحص Server Information Disclosure
            if 'Server' in headers:
                self.results['vulnerabilities'].append({
                    'title': 'كشف معلومات الخادم',
                    'description': f'يتم كشف معلومات الخادم: {headers["Server"]}',
                    'severity': 'low',
                    'recommendation': 'إخفاء معلومات الخادم',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Information_Exposure_Cheat_Sheet.html'
                })
            
            # فحص Content Type
            if 'X-Content-Type-Options' not in headers:
                self.results['vulnerabilities'].append({
                    'title': 'عدم تفعيل حماية MIME Type',
                    'description': 'لم يتم العثور على رأس X-Content-Type-Options',
                    'severity': 'low',
                    'recommendation': 'تفعيل حماية MIME Type',
                    'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/MIME_Type_Cheat_Sheet.html'
                })
            
            # فحص Robots.txt
            try:
                robots_response = requests.get(f"{self.url}/robots.txt")
                if robots_response.status_code == 200:
                    robots_content = robots_response.text
                    if "User-agent: *" in robots_content and "Allow: /" in robots_content:
                        self.results['vulnerabilities'].append({
                            'title': 'إعدادات Robots.txt غير آمنة',
                            'description': 'يسمح robots.txt بالوصول الكامل للموقع',
                            'severity': 'low',
                            'recommendation': 'تقييد الوصول في robots.txt',
                            'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Robots_Cheat_Sheet.html'
                        })
            except:
                pass
            
            # فحص Directory Listing
            try:
                dir_response = requests.get(f"{self.url}/images/")
                if "Index of /images/" in dir_response.text:
                    self.results['vulnerabilities'].append({
                        'title': 'تفعيل عرض المجلدات',
                        'description': 'تم تفعيل عرض محتويات المجلدات',
                        'severity': 'medium',
                        'recommendation': 'تعطيل عرض محتويات المجلدات',
                        'reference': 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Directory_Traversal_Cheat_Sheet.html'
                    })
            except:
                pass
            
            return self.results['vulnerabilities']
            
        except Exception as e:
            self.results['vulnerabilities'].append({
                'title': 'خطأ في فحص نقاط الضعف',
                'description': str(e),
                'severity': 'info'
            })
            return self.results['vulnerabilities']
    
    def _add_recommendations(self) -> List[str]:
        """إضافة التوصيات العامة"""
        # توصيات SSL
        if self.results['ssl_status']['status'] != 'valid':
            self.results['recommendations'].append(
                'تحديث شهادة SSL أو الحصول على شهادة جديدة'
            )
        
        # توصيات DNS
        if self.results['dns_status']['status'] != 'valid':
            self.results['recommendations'].append(
                'مراجعة إعدادات DNS وإصلاح أي مشاكل'
            )
        
        # توصيات عامة
        self.results['recommendations'].extend([
            'تحديث جميع البرمجيات والأنظمة إلى أحدث إصدار',
            'تنفيذ نظام WAF (جدار حماية تطبيقات الويب)',
            'إجراء فحص أمني دوري للموقع',
            'تنفيذ نظام نسخ احتياطي دوري',
            'تشفير جميع البيانات الحساسة',
            'تنفيذ نظام مصادقة قوي',
            'مراقبة سجلات النظام بشكل دوري'
        ])
        
        return self.results['recommendations']
    
    def generate_report(self) -> str:
        """
        توليد تقرير نصي عن نتائج الفحص
        
        Returns:
            str: التقرير النصي
        """
        report = []
        report.append(f"تقرير فحص أمان الموقع: {self.url}")
        report.append("=" * 50)
        
        # معلومات عامة
        report.append("\nمعلومات عامة:")
        report.append("-" * 20)
        report.append(f"نوع الفحص: {self.scan_type}")
        report.append(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # حالة SSL
        if self.results['ssl_status']['status']:
            report.append("\nحالة SSL:")
            report.append("-" * 20)
            report.append(f"الحالة: {self.results['ssl_status']['status']}")
        
        # حالة DNS
        if self.results['dns_status']['status']:
            report.append("\nحالة DNS:")
            report.append("-" * 20)
            report.append(f"الحالة: {self.results['dns_status']['status']}")
        
        # الثغرات
        if self.results['vulnerabilities']:
            report.append("\nالثغرات المكتشفة:")
            report.append("-" * 20)
            for vuln in self.results['vulnerabilities']:
                report.append(f"النوع: {vuln['title']}")
                report.append(f"الوصف: {vuln['description']}")
                report.append(f"الخطورة: {vuln['severity']}")
                report.append("-" * 10)
        
        # التوصيات
        if self.results['recommendations']:
            report.append("\nالتوصيات:")
            report.append("-" * 20)
            for rec in self.results['recommendations']:
                report.append(f"النوع: {rec}")
                report.append("-" * 10)
        
        return "\n".join(report) 