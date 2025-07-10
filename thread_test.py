#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import os
import socket
import struct
import threading
import sys
import time
from enum import IntEnum
from typing import Dict, List

# General config
PORT = 51511
PEER_REQUEST_PERIOD = 5    # seconds between PeerRequest
MD5LEN = 16                # nonce and hash bytes
MAX_CHAT_LEN = 255

_u8  = struct.Struct("!B")
_u32 = struct.Struct("!I")

class Msg(IntEnum):
    PEER_REQ  = 0x1
    PEER_LIST = 0x2
    ARCH_REQ  = 0x3
    ARCH_RESP = 0x4
    NOTIFY    = 0x5

# ----------------
# Packing helpers
# ----------------
def pack_peer_request():
    return _u8.pack(Msg.PEER_REQ)

def pack_peer_list(peers):
    buf = bytearray(_u8.pack(Msg.PEER_LIST))
    buf += _u32.pack(len(peers))
    for ip in peers:
        buf += _u32.pack(int(ipaddress.IPv4Address(ip)))
    return bytes(buf)

def pack_archive_request():
    return _u8.pack(Msg.ARCH_REQ)

def pack_archive_response(b):
    return _u8.pack(Msg.ARCH_RESP) + b

def pack_notify(msg):
    d = msg.encode("ascii")[:MAX_CHAT_LEN]
    return _u8.pack(Msg.NOTIFY) + _u8.pack(len(d)) + d

# ----------------
# Reading helpers
# ----------------
def recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)

# --------------------
# Chat and Blockchain
# --------------------
HEADER = _u8

class Chat:
    __slots__ = ("text","nonce","md5")
    def __init__(self, text, nonce, md5):
        self.text, self.nonce, self.md5 = text, nonce, md5
    def pack(self):
        return HEADER.pack(len(self.text)) + self.text + self.nonce + self.md5

class Blockchain:
    def __init__(self, chats=None):
        self.chats = chats[:] if chats else []

    def valid(self):
        if not self.chats: 
            return True
        for i in range(1, len(self.chats)+1):
            if not self._tail_valid(self.chats[:i]): 
                return False
        return True

    @staticmethod
    def _tail_valid(ch):
        tail = ch[-1]
        if tail.md5[:2] != b"\x00\x00": 
            return False
        window = ch[-20:]
        blob = b"".join(c.pack() for c in window[:-1]) + tail.pack()[:-MD5LEN]
        return hashlib.md5(blob).digest() == tail.md5

    def mine(self, txt_str):
        txt = txt_str.encode("ascii")[:MAX_CHAT_LEN]
        prefix = HEADER.pack(len(txt)) + txt
        prev = b"".join(c.pack() for c in self.chats[-19:])
        while True:
            nonce = os.urandom(MD5LEN)
            md5 = hashlib.md5(prev + prefix + nonce).digest()
            if md5[:2] == b"\x00\x00":
                return Blockchain(self.chats+[Chat(txt,nonce,md5)])

    def to_bytes(self):
        out = bytearray(_u32.pack(len(self.chats)))
        for c in self.chats: 
            out += c.pack()
        return bytes(out)

    @staticmethod
    def from_stream(sock):
        raw = recvall(sock, _u32.size)
        if raw is None: 
            raise ConnectionError
        count, = _u32.unpack(raw)
        chats = []
        for _ in range(count):
            ln_raw = recvall(sock, 1); ln, = _u8.unpack(ln_raw)
            txt   = recvall(sock, ln)
            nonce = recvall(sock, MD5LEN)
            md5   = recvall(sock, MD5LEN)
            chats.append(Chat(txt,nonce,md5))
        return Blockchain(chats)

    def __len__(self): return len(self.chats)

# ----------------------
# P2P connection thread
# ----------------------
class PeerThread(threading.Thread):
    def __init__(self, sock, ip, node):
        super().__init__(daemon=True)
        self.sock, self.ip, self.node = sock, ip, node
        self.alive = True

    def send(self, data: bytes):
        try: self.sock.sendall(data)
        except OSError: self.alive = False

    def run(self):
        try:
            while self.alive:
                hdr = self.sock.recv(1)
                if not hdr:
                    break
                code = hdr[0]

                if code == Msg.PEER_REQ:
                    self.send(pack_peer_list(self.node.known_peers()))

                elif code == Msg.PEER_LIST:
                    raw_n = recvall(self.sock, _u32.size)
                    n, = _u32.unpack(raw_n)
                    ips = []
                    for _ in range(n):
                        raw_ip = recvall(self.sock, _u32.size)
                        ip_int, = _u32.unpack(raw_ip)
                        ips.append(str(ipaddress.IPv4Address(ip_int)))
                    self.node.merge_peers(ips)

                elif code == Msg.ARCH_REQ:
                    self.send(pack_archive_response(self.node.bc.to_bytes()))

                elif code == Msg.ARCH_RESP:
                    bc = Blockchain.from_stream(self.sock)
                    self.node.consider_archive(bc)

                elif code == Msg.NOTIFY:
                    ln_raw = recvall(self.sock, _u8.size)
                    ln, = _u8.unpack(ln_raw)
                    recvall(self.sock, ln)  # drops or treat

                else:
                    self.alive = False 
        finally:
            self.node.drop(self.ip)
            self.sock.close()

# ----------
# Main node
# ----------
class Node:
    def __init__(self, ip, bootstrap=None):
        self.ip = ip
        self.bootstrap = bootstrap
        self.bc = Blockchain()
        self.peers: Dict[str,PeerThread] = {}
        self.lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._ticker, daemon=True).start()

        if self.bootstrap and self.bootstrap != self.ip:    # Initial connect
            self._connect(self.bootstrap)

    def _accept(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.ip, PORT))
        srv.listen()
        while True:
            sock, addr = srv.accept()
            self._attach(sock, addr[0])

    def _ticker(self):
        while True:
            time.sleep(PEER_REQUEST_PERIOD)
            with self.lock:
                for p in list(self.peers.values()):
                    p.send(pack_peer_request())

    def _connect(self, host):
        try:
            addr = socket.gethostbyname(host)
        except socket.gaierror:
            addr = host
        with self.lock:
            if addr in self.peers or addr == self.ip:
                return
        try:
            sock = socket.create_connection((addr, PORT), timeout=5)
        except OSError:
            return
        self._attach(sock, addr)

    def _attach(self, sock, ip):
        p = PeerThread(sock, ip, self)
        with self.lock:
            self.peers[ip] = p
        p.start()
        p.send(pack_archive_request())   # gets history and peers
        p.send(pack_peer_request())

    def drop(self, ip):
        with self.lock:
            self.peers.pop(ip, None)

    def known_peers(self):
        with self.lock:
            return list(self.peers.keys()) + [self.ip]

    def merge_peers(self, ips):
        for ip in ips:
            self._connect(ip)

    def consider_archive(self, bc: Blockchain):
        if bc.valid() and len(bc) > len(self.bc):
            self.bc = bc
            raw = pack_archive_response(bc.to_bytes())
            with self.lock:
                for p in self.peers.values():
                    p.send(raw)

    def chat(self, txt):
        self.bc = self.bc.mine(txt)
        raw = pack_archive_response(self.bc.to_bytes())
        with self.lock:
            for p in self.peers.values():
                p.send(raw)

    # Shows chat history on terminal
    def print_history(self):
        print("=== Chat History ===")
        for idx, chat in enumerate(self.bc.chats, start=1):
            txt = chat.text.decode("ascii", errors="ignore")
            print(f"{idx:03d}: {txt}")
        print("====================")

    def print_detailed_history(self):
        print("=== Chat History ===")
        for idx, chat in enumerate(self.bc.chats, start=1):
            size = len(chat.text)
            msg_ascii = chat.text.decode("ascii", errors="ignore")
            msg_hex = chat.text.hex()
            nonce = chat.nonce.hex()
            md5 = chat.md5.hex()
            print(f"{idx:03d}:")
            print(f"   Size: {size} bytes")
            print(f"   Message (ASCII): {msg_ascii}")
            print(f"   Message (hex): {msg_hex}")
            print(f"   Verification code (nonce): {nonce}")
            print(f"   Hash MD5: {md5}")
        print("====================")

# ----
# CLI
# ----
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--bootstrap")
    args = ap.parse_args()

    node = Node(args.ip, args.bootstrap)
    node.start()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line.lower() == "/history":
            node.print_history()
        if line.lower() == "/history detail":
            node.print_detailed_history()
        else:
            node.chat(line)