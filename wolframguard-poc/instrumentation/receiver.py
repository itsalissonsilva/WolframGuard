"""Local-only, bounded synthetic receiver; deliberately has no forwarding code."""
import argparse
import datetime as dt
import http.server
import json
import pathlib
import threading

def make_receiver(log_path, port=8765):
    log_path = pathlib.Path(log_path)
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.path != "/collect" or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 <= length <= 4096:
                self.send_error(413)
                return
            self.connection.settimeout(3)
            try:
                body = self.rfile.read(length)
            except TimeoutError:
                self.send_error(408)
                return
            if len(body) != length:
                self.send_error(400)
                return
            event = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                     "peer": self.client_address[0], "path": self.path,
                     "body": body.decode("utf-8", "replace")}
            with lock, log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(event) + "\n")
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=pathlib.Path, required=True)
    args = parser.parse_args()
    make_receiver(args.log).serve_forever()
