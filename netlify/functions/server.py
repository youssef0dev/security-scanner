from http.server import BaseHTTPRequestHandler
import json
from app import app

def handler(event, context):
    """Handle incoming requests"""
    try:
        # Get request details from the event
        path = event.get('path', '/')
        method = event.get('httpMethod', 'GET')
        headers = event.get('headers', {})
        body = event.get('body', '')
        
        # Create a test request context
        with app.test_request_context(
            path=path,
            base_url=headers.get('host', ''),
            method=method,
            input_stream=body,
            content_type=headers.get('content-type'),
            headers=headers
        ):
            # Process the request
            response = app.full_dispatch_request()
            
            # Return the response
            return {
                'statusCode': response.status_code,
                'headers': dict(response.headers),
                'body': response.get_data(as_text=True)
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        } 