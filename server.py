from http.server import BaseHTTPRequestHandler, HTTPServer
import random
from http.cookies import SimpleCookie

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    session_store = {}

    def do_GET(self):
        session_id = None
        self.protocol_version = 'HTTP/1.1'

        # Check if a cookie is set
        if 'Cookie' in self.headers:
            cookie = SimpleCookie(self.headers.get('Cookie'))
            if 'session' in cookie:
                session_id = cookie['session'].value
                print(f"Received cookie: {session_id}")

        # If no valid session ID, generate a new one
        if not session_id or session_id not in self.session_store:
            session_id = str(random.randint(1000, 9999))
            self.session_store[session_id] = True
            cookie = SimpleCookie()
            cookie['session'] = session_id
            cookie['session']['path'] = '/'
            cookie['session']['httponly'] = True
            self.send_header('Set-Cookie', cookie.output(header='', sep='').strip())
            print(f"Setting new cookie: {session_id}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", 40)
        self.end_headers()
        self.wfile.write(f"Hello, your session ID is {session_id}".encode())

    def end_headers(self):
        BaseHTTPRequestHandler.end_headers(self)

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
