from web_ui import AegisWebHandler, ThreadingHTTPServer
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), AegisWebHandler)
    print(f"Listening on 0.0.0.0:{port}")
    server.serve_forever()
