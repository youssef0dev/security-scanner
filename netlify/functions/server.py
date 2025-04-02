from flask import Flask, request, Response
from app import create_app
import json
import os
import base64

app = create_app()

def handler(event, context):
    """Handle incoming requests."""
    try:
        # Get request details
        path = event.get('path', '/')
        method = event.get('httpMethod', 'GET')
        headers = event.get('headers', {})
        body = event.get('body', '')
        host = headers.get('host', '')
        
        print(f"Processing request: {method} {path}")  # Debug log
        
        # Handle static files
        if path.startswith('/static/'):
            try:
                static_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static', path[8:])
                print(f"Looking for static file: {static_path}")  # Debug log
                if os.path.exists(static_path):
                    with open(static_path, 'rb') as f:
                        content = f.read()
                    content_type = 'text/css' if path.endswith('.css') else 'application/javascript' if path.endswith('.js') else 'image/png' if path.endswith('.png') else 'image/jpeg' if path.endswith('.jpg') else 'text/plain'
                    return {
                        'statusCode': 200,
                        'headers': {
                            'Content-Type': content_type,
                            'Cache-Control': 'public, max-age=31536000'
                        },
                        'body': base64.b64encode(content).decode('utf-8'),
                        'isBase64Encoded': True
                    }
            except Exception as e:
                print(f"Error serving static file: {str(e)}")
        
        # Create WSGI environment
        environ = {
            'REQUEST_METHOD': method,
            'PATH_INFO': path,
            'QUERY_STRING': event.get('queryStringParameters', {}) or {},
            'SCRIPT_NAME': '',
            'SERVER_NAME': host,
            'SERVER_PORT': '443',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'https',
            'wsgi.input': body.encode() if body else b'',
            'wsgi.errors': [],
            'wsgi.multithread': False,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
        }
        
        # Add headers to environment
        for key, value in headers.items():
            key = key.upper().replace('-', '_')
            if key not in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
                key = f'HTTP_{key}'
            environ[key] = value
        
        # Process request through Flask app
        with app.request_context(environ):
            try:
                response = app.full_dispatch_request()
                
                # Convert response to Netlify format
                response_headers = dict(response.headers)
                response_body = response.get_data()
                
                # Handle binary responses
                is_binary = isinstance(response_body, bytes)
                if is_binary:
                    response_body = base64.b64encode(response_body).decode('utf-8')
                
                return {
                    'statusCode': response.status_code,
                    'headers': response_headers,
                    'body': response_body,
                    'isBase64Encoded': is_binary
                }
            except Exception as e:
                print(f"Error dispatching request: {str(e)}")
                raise
            
    except Exception as e:
        # Log error and return 500 response
        print(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        } 