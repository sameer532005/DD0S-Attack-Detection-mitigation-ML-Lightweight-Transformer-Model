from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import time

class SlowHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        time.sleep(2)  # 🔥 delay add (2 sec)
        super().do_GET()

server = ThreadingHTTPServer(("10.0.0.6", 8080), SlowHandler)
print("Slow server running on port 8080...")
server.serve_forever()
