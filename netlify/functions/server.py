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
        query_string = event.get('queryStringParameters', {})
        
        # Create a test request context
        with app.test_request_context(
            path=path,
            base_url=f"https://{headers.get('host', '')}",
            method=method,
            input_stream=body.encode() if body else None,
            query_string=query_string,
            content_type=headers.get('content-type'),
            headers=headers
        ):
            # Process the request
            response = app.full_dispatch_request()
            
            # Get response data
            response_data = response.get_data()
            
            # Return the response
            return {
                'statusCode': response.status_code,
                'headers': {
                    'Content-Type': response.content_type,
                    **dict(response.headers)
                },
                'body': response_data.decode('utf-8') if isinstance(response_data, bytes) else response_data,
                'isBase64Encoded': False
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': str(e),
                'path': path,
                'method': method
            })
        } 