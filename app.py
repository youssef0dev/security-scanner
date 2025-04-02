from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, make_response, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime
import os
import tempfile
import time
from forms import LoginForm, RegisterForm, ScanForm
from models import db, User, ScanResult, SecurityEvent
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from io import BytesIO
from reportlab.lib import colors

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def init_db():
    with app.app_context():
        db.create_all()

init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
        # Update last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Log security event
        event = SecurityEvent(
            user_id=user.id,
            event_type='login',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(event)
        db.session.commit()
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('dashboard')
        return redirect(next_page)
    
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Log security event
            event = SecurityEvent(
                user_id=user.id,
                event_type='registration',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(event)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
@login_required
def logout():
    # Log security event before logging out
    if current_user.is_authenticated:
        event = SecurityEvent(
            user_id=current_user.id,
            event_type='logout',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(event)
        db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent scans for the current user
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.scan_date.desc()).limit(5).all()
    
    # Calculate total scans
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    
    # Get security statistics
    security_stats = {
        'total_vulnerabilities': sum(len(scan.vulnerabilities) for scan in recent_scans),
        'high_risk_scans': sum(1 for scan in recent_scans if scan.risk_level == 'high'),
        'medium_risk_scans': sum(1 for scan in recent_scans if scan.risk_level == 'medium'),
        'low_risk_scans': sum(1 for scan in recent_scans if scan.risk_level == 'low')
    }
    
    return render_template('dashboard.html',
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         security_stats=security_stats,
                         ScanResult=ScanResult)

@app.route('/')
def welcome():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('welcome.html')

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        try:
            # Simulate scanning process
            time.sleep(2)  # Simulate scan duration
            
            # Enhanced scan results with detailed vulnerability checks
            scan_results = {
                'url': form.url.data,
                'scan_date': datetime.utcnow(),
                'security_score': 75,  # Lower score due to vulnerabilities
                'risk_level': 'high',  # High risk due to critical vulnerabilities
                'scan_duration': 2.5,
                'server_info': {
                    'server': 'nginx/1.18.0',
                    'powered_by': 'PHP/7.4.27',
                    'content_type': 'text/html; charset=UTF-8'
                },
                'technologies': [
                    'PHP',
                    'MySQL',
                    'jQuery',
                    'Bootstrap',
                    'WordPress'
                ],
                'headers': {
                    'X-Frame-Options': 'Missing',
                    'X-XSS-Protection': 'Missing',
                    'X-Content-Type-Options': 'Missing',
                    'Strict-Transport-Security': 'Missing',
                    'Content-Security-Policy': 'Missing',
                    'Referrer-Policy': 'Missing'
                },
                'vulnerabilities': [
                    {
                        'title': 'Critical: SQL Injection Vulnerability',
                        'description': 'SQL injection vulnerability detected in the contact form',
                        'severity': 'high',
                        'location': '/contact.php',
                        'impact': 'Potential unauthorized database access and data theft'
                    },
                    {
                        'title': 'High: Cross-Site Scripting (XSS)',
                        'description': 'Reflected XSS vulnerability found in search functionality',
                        'severity': 'high',
                        'location': '/search.php',
                        'impact': 'Potential execution of malicious scripts in user\'s browser'
                    },
                    {
                        'title': 'Medium: Missing Security Headers',
                        'description': 'Several important security headers are missing',
                        'severity': 'medium',
                        'location': 'All pages',
                        'impact': 'Reduced protection against common web vulnerabilities'
                    },
                    {
                        'title': 'Medium: Outdated WordPress Version',
                        'description': 'WordPress version 5.8.1 is outdated and has known vulnerabilities',
                        'severity': 'medium',
                        'location': 'WordPress core',
                        'impact': 'Potential exploitation of known vulnerabilities'
                    },
                    {
                        'title': 'Low: Weak Password Policy',
                        'description': 'No password complexity requirements enforced',
                        'severity': 'low',
                        'location': 'User registration',
                        'impact': 'Increased risk of account compromise'
                    }
                ],
                'recommendations': [
                    {
                        'title': 'Fix SQL Injection',
                        'description': 'Implement prepared statements and input validation in contact form',
                        'priority': 'high',
                        'steps': [
                            'Use parameterized queries',
                            'Validate and sanitize all user inputs',
                            'Implement proper error handling'
                        ]
                    },
                    {
                        'title': 'Address XSS Vulnerability',
                        'description': 'Implement proper output encoding and input validation',
                        'priority': 'high',
                        'steps': [
                            'Use HTML encoding for output',
                            'Implement Content Security Policy',
                            'Validate and sanitize search inputs'
                        ]
                    },
                    {
                        'title': 'Add Security Headers',
                        'description': 'Implement missing security headers',
                        'priority': 'medium',
                        'steps': [
                            'Add X-Frame-Options header',
                            'Add X-XSS-Protection header',
                            'Add Content-Security-Policy header',
                            'Add Strict-Transport-Security header'
                        ]
                    },
                    {
                        'title': 'Update WordPress',
                        'description': 'Update WordPress to the latest version',
                        'priority': 'medium',
                        'steps': [
                            'Backup website before update',
                            'Update WordPress core',
                            'Test website functionality after update'
                        ]
                    },
                    {
                        'title': 'Strengthen Password Policy',
                        'description': 'Implement stronger password requirements',
                        'priority': 'low',
                        'steps': [
                            'Require minimum password length',
                            'Enforce password complexity',
                            'Implement password expiration'
                        ]
                    }
                ]
            }
            
            # Create new scan result
            scan_result = ScanResult(
                user_id=current_user.id,
                url=scan_results['url'],
                scan_date=scan_results['scan_date'],
                security_score=scan_results['security_score'],
                risk_level=scan_results['risk_level'],
                scan_duration=scan_results['scan_duration'],
                server_info=scan_results['server_info'],
                technologies=scan_results['technologies'],
                headers=scan_results['headers'],
                vulnerabilities=scan_results['vulnerabilities'],
                recommendations=scan_results['recommendations']
            )
            
            db.session.add(scan_result)
            db.session.commit()
            
            # Store results in session for PDF generation
            session['scan_results'] = scan_results
            return render_template('site_results.html', results=scan_results)
            
        except Exception as e:
            flash('An error occurred during the scan. Please try again.', 'error')
            return redirect(url_for('index'))
    
    return render_template('index.html', form=form)

@app.route('/download_report')
@login_required
def download_report():
    try:
        # Get scan results from session
        results = session.get('scan_results')
        if not results:
            flash('No scan results found. Please run a scan first.', 'error')
            return redirect(url_for('index'))

        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Get styles
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        elements.append(Paragraph("Security Scan Report", title_style))

        # Scan Information
        info_style = ParagraphStyle(
            'Info',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=12
        )
        elements.append(Paragraph(f"URL: {results['url']}", info_style))
        elements.append(Paragraph(f"Scan Date: {results['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        elements.append(Paragraph(f"Scan Duration: {results['scan_duration']} seconds", info_style))
        elements.append(Paragraph(f"Security Score: {results['security_score']}/100", info_style))
        elements.append(Paragraph(f"Risk Level: {results['risk_level'].title()}", info_style))
        elements.append(Spacer(1, 20))

        # Server Information
        elements.append(Paragraph("Server Information", styles['Heading2']))
        server_info = results['server_info']
        elements.append(Paragraph(f"Server: {server_info['server']}", info_style))
        elements.append(Paragraph(f"Powered By: {server_info['powered_by']}", info_style))
        elements.append(Paragraph(f"Content Type: {server_info['content_type']}", info_style))
        elements.append(Spacer(1, 20))

        # Technologies
        elements.append(Paragraph("Detected Technologies", styles['Heading2']))
        tech_list = [Paragraph(f"• {tech}", info_style) for tech in results['technologies']]
        elements.extend(tech_list)
        elements.append(Spacer(1, 20))

        # Security Headers
        elements.append(Paragraph("Security Headers", styles['Heading2']))
        for header, value in results['headers'].items():
            status = "Present" if value != "Missing" else "Missing"
            color = "green" if status == "Present" else "red"
            elements.append(Paragraph(f"• {header}: <font color='{color}'>{status}</font>", info_style))
        elements.append(Spacer(1, 20))

        # Vulnerabilities
        elements.append(Paragraph("Vulnerabilities Found", styles['Heading2']))
        if results['vulnerabilities']:
            for vuln in results['vulnerabilities']:
                elements.append(Paragraph(f"• {vuln['title']}", info_style))
                elements.append(Paragraph(f"Description: {vuln['description']}", info_style))
                elements.append(Paragraph(f"Severity: {vuln['severity'].title()}", info_style))
                elements.append(Paragraph(f"Location: {vuln['location']}", info_style))
                elements.append(Paragraph(f"Impact: {vuln['impact']}", info_style))
                elements.append(Spacer(1, 20))
        else:
            elements.append(Paragraph("No vulnerabilities found.", info_style))
        elements.append(Spacer(1, 20))

        # Recommendations
        elements.append(Paragraph("Recommendations", styles['Heading2']))
        for rec in results['recommendations']:
            elements.append(Paragraph(f"• {rec['title']}", info_style))
            elements.append(Paragraph(f"Description: {rec['description']}", info_style))
            elements.append(Paragraph(f"Priority: {rec['priority'].upper()}", info_style))
            elements.append(Paragraph(f"Steps: {', '.join(rec['steps'])}", info_style))
            elements.append(Spacer(1, 20))

        # Footer
        elements.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.gray
        )
        elements.append(Paragraph("Report generated by Security Scanner", footer_style))

        # Build PDF
        doc.build(elements)

        # Get the value of the BytesIO buffer
        pdf = buffer.getvalue()

        # Create response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=security_report.pdf'
        return response

    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/scan-history')
@login_required
def scan_history():
    scans = current_user.scan_results.order_by(ScanResult.scan_date.desc()).all()
    return render_template('scan_history.html', scans=scans, ScanResult=ScanResult)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    
    # Ensure the user can only view their own scan results
    if scan.user_id != current_user.id:
        abort(403)
    
    # Format the scan results for display
    results = {
        'security_score': scan.security_score,
        'risk_level': scan.risk_level,
        'scan_duration': scan.scan_duration,
        'server_info': scan.server_info,
        'technologies': scan.technologies,
        'headers': scan.headers,
        'vulnerabilities': scan.vulnerabilities,
        'recommendations': scan.recommendations
    }
    
    return render_template('site_results.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
