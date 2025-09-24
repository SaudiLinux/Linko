#!/usr/bin/env python3
"""
Simple HTTP server to serve the cloud test content
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import threading
import time

class TestContentHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            # Serve our test cloud content
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            with open('test_cloud_content.html', 'rb') as f:
                self.wfile.write(f.read())
        else:
            # Serve other files normally
            super().do_GET()

def run_server():
    # Change to the script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    server_address = ('', 8081)
    httpd = HTTPServer(server_address, TestContentHandler)
    
    print("Serving cloud test content on http://localhost:8081")
    print("Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()