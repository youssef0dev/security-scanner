from http.server import BaseHTTPRequestHandler
from app import app

def handler(request):
    """Handle incoming requests"""
    with app.test_request_context(
        path=request.get('path', '/'),
        base_url=request.get('headers', {}).get('host', ''),
        method=request.get('method', 'GET'),
        input_stream=request.get('body'),
        content_type=request.get('headers', {}).get('content-type'),
        headers=request.get('headers', {})
    ):
        try:
            response = app.full_dispatch_request()
            return {
                'statusCode': response.status_code,
                'headers': dict(response.headers),
                'body': response.get_data(as_text=True)
            }
        except Exception as e:
            return {
                'statusCode': 500,
                'body': str(e)
            } 