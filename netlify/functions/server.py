from http.server import BaseHTTPRequestHandler
import json
from app import app
import os
import base64

def handler(event, context):
    """Handle incoming requests"""
    try:
        # Get request details from the event
        path = event.get('path', '/')
        method = event.get('httpMethod', 'GET')
        headers = event.get('headers', {})
        body = event.get('body', '')
        query_string = event.get('queryStringParameters', {})
        host = headers.get('host', '')

        # Create base URL
        base_url = f"https://{host}"
        
        # Handle static files
        if path.startswith('/static/'):
            static_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static', path[8:])
            if os.path.exists(static_path):
                with open(static_path, 'rb') as f:
                    content = f.read()
                content_type = 'text/css' if static_path.endswith('.css') else 'application/javascript' if static_path.endswith('.js') else 'image/png' if static_path.endswith('.png') else 'image/jpeg' if static_path.endswith('.jpg') else 'text/plain'
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': content_type},
                    'body': content.decode('utf-8') if content_type.startswith('text/') else base64.b64encode(content).decode('utf-8'),
                    'isBase64Encoded': not content_type.startswith('text/')
                }
            return {'statusCode': 404, 'body': 'Not Found'}

        # Create a test request context
        with app.test_request_context(
            path=path,
            base_url=base_url,
            method=method,
            input_stream=body.encode() if body else None,
            query_string=query_string,
            headers=headers
        ):
            # Process the request through Flask
            response = app.full_dispatch_request()
            
            # Get response data
            response_data = response.get_data()
            
            # Convert response headers to dict and ensure they're strings
            response_headers = {}
            for key, value in response.headers:
                response_headers[key] = str(value)
            
            # Return the response
            return {
                'statusCode': response.status_code,
                'headers': {
                    'Content-Type': response.content_type,
                    **response_headers
                },
                'body': response_data.decode('utf-8') if isinstance(response_data, bytes) else str(response_data),
                'isBase64Encoded': False
            }
            
    except Exception as e:
        print(f"Error processing request: {str(e)}")  # Log the error
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': 'Internal Server Error',
                'message': str(e),
                'path': path,
                'method': method
            })
        } 