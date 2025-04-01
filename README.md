# Security Scanner Web Application

A Flask-based web application for scanning websites for security vulnerabilities and generating detailed reports.

## Features

- User authentication (login/register)
- Website security scanning
- Detailed vulnerability reports
- PDF report generation
- Dashboard with security statistics
- Scan history tracking
- Security event logging

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Configuration

1. Set up environment variables (optional):
```bash
# Windows
set SECRET_KEY=your-secret-key

# Linux/Mac
export SECRET_KEY=your-secret-key
```

## Running the Application

1. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

2. Run the application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

## Project Structure

```
security-scanner/
├── app.py              # Main application file
├── models.py           # Database models
├── forms.py            # Form classes
├── requirements.txt    # Project dependencies
├── templates/         # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── site_results.html
│   └── scan_history.html
└── static/           # Static files (CSS, JS, images)
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Flask framework
- SQLAlchemy ORM
- ReportLab for PDF generation 