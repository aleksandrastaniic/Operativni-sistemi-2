#!/usr/bin/env python3
"""Simple TCP server (mini 'netcat' receive example).
Run: python3 netcat_server.py
Then send with the client below in another terminal.
"""
import socket

HOST = "127.0.0.1"
PORT = 42424
BACKLOG = 5
SIZE = 1024

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(BACKLOG)
        print(f"[server] listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print("[server] connection from", addr)
            data = b""
            while True:
                chunk = conn.recv(SIZE)
                if not chunk:
                    break
                data += chunk
            print("[server] received:\n", data.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
