#!/usr/bin/env python3
"""Simple TCP client (mini 'netcat' send example).
Run: python3 netcat_client.py
Make sure the server is already listening.
"""
import socket

HOST = "127.0.0.1"
PORT = 42424

def main():
    with socket.create_connection((HOST, PORT)) as s:
        message = "Egg, bacon, sausage and spam\n"
        s.sendall(message.encode("utf-8"))
        print("[client] sent:", message.strip())

if __name__ == "__main__":
    main()
