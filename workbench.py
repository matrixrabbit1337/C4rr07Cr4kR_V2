#!/usr/bin/env python3
"""Launch the bundled Artifact Workbench in the user's browser."""
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import webbrowser

ASSETS = {
    "/cracker-worker.mjs": ("cracker-worker.mjs", "text/javascript"),
    "/": ("index.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/app.js": ("app.js", "text/javascript"),
    "/engine.mjs": ("engine.mjs", "text/javascript"),
}
ROOT = Path(__file__).resolve().parent / "workbench_ui"


class WorkbenchHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.serve_asset(send_body=True)

    def do_HEAD(self):
        self.serve_asset(send_body=False)

    def serve_asset(self, send_body):
        if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
            self.send_error(403)
            return
        asset = ASSETS.get(urlsplit(self.path).path)
        if asset is None:
            self.send_error(404)
            return
        filename, media_type = asset
        data = (ROOT / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{media_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def log_message(self, *_args):
        pass


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true", help="print the local URL without opening it")
    args = parser.parse_args(argv)
    if not all((ROOT / filename).is_file() for filename, _ in ASSETS.values()):
        parser.exit(1, "Workbench files are missing. Extract the complete ZIP before launching.\n")
    with ThreadingHTTPServer(("127.0.0.1", 0), WorkbenchHandler) as server:
        url = f"http://127.0.0.1:{server.server_port}/"
        print(f"C4rr07 Artifact Workbench\n{url}\nLeave this window open while using the Workbench. Press Ctrl+C here to stop.", flush=True)
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except (OSError, webbrowser.Error):
                print("Open the address above in your browser.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
