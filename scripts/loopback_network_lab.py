#!/usr/bin/env python3
"""Loopback-only network lab for optional nmap/tcpdump validation.

The script refuses non-loopback hosts and never scans or loads remote systems.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import shutil
import socket
import subprocess  # nosec B404
import threading
import time
from pathlib import Path

HOST = "127.0.0.1"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        body = b"local security lab\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.requests <= 1_000:
        raise SystemExit("--requests must be between 1 and 1000")

    server = http.server.ThreadingHTTPServer((HOST, 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    capture = None
    pcap_path = None
    if args.capture and shutil.which("tcpdump"):
        pcap_path = Path("security_reports/loopback_capture.pcap").resolve()
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        tcpdump_path = shutil.which("tcpdump")
        if tcpdump_path is None:
            raise RuntimeError("tcpdump disappeared after availability check")
        capture = subprocess.Popen(  # noqa: S603  # nosec B603
            [
                tcpdump_path,
                "-i",
                "lo",
                "-U",
                "-w",
                str(pcap_path),
                "tcp",
                "port",
                str(port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.3)

    started = time.perf_counter()
    connection = http.client.HTTPConnection(HOST, port, timeout=2)
    try:
        for _ in range(args.requests):
            connection.request("GET", "/")
            response = connection.getresponse()
            response.read(64)
            if response.status != 200:
                raise RuntimeError(f"unexpected local status: {response.status}")
    finally:
        connection.close()
    elapsed = time.perf_counter() - started

    with socket.create_connection((HOST, port), timeout=2):
        python_tcp_probe = "open"

    nmap_output = "nmap not installed; Python loopback TCP probe used"
    nmap_path = shutil.which("nmap")
    if nmap_path:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [nmap_path, "-sT", "-Pn", "-p", str(port), HOST],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        nmap_output = result.stdout

    server.shutdown()
    server.server_close()
    if capture is not None:
        capture.terminate()
        try:
            capture.wait(timeout=3)
        except subprocess.TimeoutExpired:
            capture.kill()

    result = {
        "scope": "loopback_only",
        "host": HOST,
        "port": port,
        "requests": args.requests,
        "elapsed_seconds": round(elapsed, 4),
        "requests_per_second": round(args.requests / elapsed, 2),
        "python_tcp_probe": python_tcp_probe,
        "nmap": nmap_output,
        "pcap": str(pcap_path) if pcap_path and pcap_path.exists() else None,
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
