from flask import Flask, request, Response
from app import create_app
import json
import os

app = create_app()

def handler(event, context):
    """Handle incoming requests."""
    try:
        # Get request details
        path = event.get('path', '/')
        method = event.get('httpMethod', 'GET')
        headers = event.get('headers', {})
        body = event.get('body', '')
        
        # Create WSGI environment
        environ = {
            'REQUEST_METHOD': method,
            'PATH_INFO': path,
            'QUERY_STRING': event.get('queryStringParameters', {}),
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'https',
            'wsgi.input': body,
            'wsgi.errors': [],
            'wsgi.multithread': False,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
        }
        
        # Add headers to environment
        for key, value in headers.items():
            environ[f'HTTP_{key.upper().replace("-", "_")}'] = value
        
        # Process request through Flask app
        with app.request_context(environ):
            response = app.full_dispatch_request()
            
            # Convert response to Netlify format
            return {
                'statusCode': response.status_code,
                'headers': dict(response.headers),
                'body': response.get_data(as_text=True)
            }
            
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