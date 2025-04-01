import pytest
from security_scanner import SecurityScanner
from utils import validate_url, get_ssl_info, get_dns_info, check_security_headers, scan_vulnerabilities

def test_validate_url():
    """اختبار التحقق من صحة URL"""
    assert validate_url('https://example.com') is True
    assert validate_url('http://example.com') is True
    assert validate_url('ftp://example.com') is False
    assert validate_url('not-a-url') is False

def test_get_ssl_info():
    """اختبار الحصول على معلومات SSL"""
    info = get_ssl_info('https://example.com')
    assert isinstance(info, dict)
    assert 'valid' in info
    assert 'expiry' in info
    assert 'issuer' in info

def test_get_dns_info():
    """اختبار الحصول على معلومات DNS"""
    info = get_dns_info('example.com')
    assert isinstance(info, dict)
    assert 'a_records' in info
    assert 'mx_records' in info
    assert 'txt_records' in info

def test_check_security_headers():
    """اختبار فحص رؤوس الأمان"""
    headers = check_security_headers('https://example.com')
    assert isinstance(headers, dict)
    assert 'hsts' in headers
    assert 'xss_protection' in headers
    assert 'content_security_policy' in headers

def test_scan_vulnerabilities():
    """اختبار فحص الثغرات"""
    vulnerabilities = scan_vulnerabilities('https://example.com')
    assert isinstance(vulnerabilities, list)
    for vuln in vulnerabilities:
        assert isinstance(vuln, dict)
        assert 'type' in vuln
        assert 'description' in vuln
        assert 'severity' in vuln

def test_security_scanner_full_scan():
    """اختبار الفحص الكامل"""
    scanner = SecurityScanner('https://example.com', 'full')
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'ssl_status' in results
    assert 'dns_status' in results
    assert 'headers_status' in results
    assert 'vulnerabilities' in results
    assert 'recommendations' in results

def test_security_scanner_ssl_scan():
    """اختبار فحص SSL فقط"""
    scanner = SecurityScanner('https://example.com', 'ssl')
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'ssl_status' in results
    assert 'dns_status' not in results
    assert 'headers_status' not in results
    assert 'vulnerabilities' not in results
    assert 'recommendations' in results

def test_security_scanner_dns_scan():
    """اختبار فحص DNS فقط"""
    scanner = SecurityScanner('https://example.com', 'dns')
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'ssl_status' not in results
    assert 'dns_status' in results
    assert 'headers_status' not in results
    assert 'vulnerabilities' not in results
    assert 'recommendations' in results

def test_security_scanner_headers_scan():
    """اختبار فحص الرؤوس فقط"""
    scanner = SecurityScanner('https://example.com', 'headers')
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'ssl_status' not in results
    assert 'dns_status' not in results
    assert 'headers_status' in results
    assert 'vulnerabilities' not in results
    assert 'recommendations' in results

def test_security_scanner_vulnerabilities_scan():
    """اختبار فحص الثغرات فقط"""
    scanner = SecurityScanner('https://example.com', 'vulnerabilities')
    results = scanner.run_scan()
    
    assert isinstance(results, dict)
    assert 'ssl_status' not in results
    assert 'dns_status' not in results
    assert 'headers_status' not in results
    assert 'vulnerabilities' in results
    assert 'recommendations' in results

def test_security_scanner_invalid_url():
    """اختبار URL غير صالح"""
    with pytest.raises(ValueError):
        SecurityScanner('not-a-url', 'full')

def test_security_scanner_invalid_scan_type():
    """اختبار نوع فحص غير صالح"""
    with pytest.raises(ValueError):
        SecurityScanner('https://example.com', 'invalid') 