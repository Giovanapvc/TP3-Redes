#!/usr/bin/env python3


import argparse
import hashlib
import ipaddress
import os
import socket
import struct
import threading
import time
from enum import IntEnum
from typing import Dict, List

# -------------------------------------------------------------------
# Configurações gerais
# -------------------------------------------------------------------
PORT = 51511
PEER_REQUEST_PERIOD = 5    # segundos entre PeerRequest
MD5LEN = 16                # bytes de nonce e hash
MAX_CHAT_LEN = 255         # máximo de bytes ASCII no texto

_u8  = struct.Struct("!B")  # uint8 network order
_u32 = struct.Struct("!I")  # uint32 network order

class Msg(IntEnum):
    PEER_REQ  = 0x1
    PEER_LIST = 0x2
    ARCH_REQ  = 0x3
    ARCH_RESP = 0x4
    NOTIFY    = 0x5

# -------------------------------------------------------------------
# Serialização de mensagens
# -------------------------------------------------------------------
def pack_peer_request() -> bytes:
    return _u8.pack(Msg.PEER_REQ)

def pack_peer_list(peers: List[str]) -> bytes:
    buf = bytearray(_u8.pack(Msg.PEER_LIST))
    buf += _u32.pack(len(peers))
    for ip in peers:
        buf += _u32.pack(int(ipaddress.IPv4Address(ip)))
    return bytes(buf)

def pack_archive_request() -> bytes:
    return _u8.pack(Msg.ARCH_REQ)

def pack_archive_response(payload: bytes) -> bytes:
    return _u8.pack(Msg.ARCH_RESP) + payload

def pack_notify(msg: str) -> bytes:
    data = msg.encode("ascii")[:MAX_CHAT_LEN]
    return _u8.pack(Msg.NOTIFY) + _u8.pack(len(data)) + data

# -------------------------------------------------------------------
# Blockchain & Chat
# -------------------------------------------------------------------
HEADER = _u8  # 1-byte length

class Chat:
    __slots__ = ("text", "nonce", "md5")
    def __init__(self, text: bytes, nonce: bytes, md5: bytes):
        self.text, self.nonce, self.md5 = text, nonce, md5
    def pack(self) -> bytes:
        return HEADER.pack(len(self.text)) + self.text + self.nonce + self.md5

class Blockchain:
    def __init__(self, chats: List[Chat] = None):
        self.chats = list(chats) if chats else []

    def valid(self) -> bool:
        if not self.chats:
            return True
        for i in range(1, len(self.chats) + 1):
            if not self._tail_valid(self.chats[:i]):
                return False
        return True

    @staticmethod
    def _tail_valid(chats: List[Chat]) -> bool:
        tail = chats[-1]
        if tail.md5[:2] != b"\x00\x00":
            return False
        window = chats[-20:]
        blob = b"".join(c.pack() for c in window[:-1]) + tail.pack()[:-MD5LEN]
        return hashlib.md5(blob).digest() == tail.md5

    def mine(self, text_ascii: str) -> "Blockchain":
        txt = text_ascii.encode("ascii")[:MAX_CHAT_LEN]
        prefix = HEADER.pack(len(txt)) + txt
        prev = b"".join(c.pack() for c in self.chats[-19:])
        while True:
            nonce = os.urandom(MD5LEN)
            digest = hashlib.md5(prev + prefix + nonce).digest()
            if digest[:2] == b"\x00\x00":
                return Blockchain(self.chats + [Chat(txt, nonce, digest)])

    def to_bytes(self) -> bytes:
        out = bytearray(_u32.pack(len(self.chats)))
        for c in self.chats:
            out += c.pack()
        return bytes(out)

    @staticmethod
    def from_socket(sock: socket.socket) -> "Blockchain":
        raw = recvall(sock, _u32.size)
        if raw is None:
            raise ConnectionError
        n, = _u32.unpack(raw)
        chats: List[Chat] = []
        for _ in range(n):
            ln_raw = recvall(sock, 1); ln, = _u8.unpack(ln_raw)
            txt   = recvall(sock, ln)
            nonce = recvall(sock, MD5LEN)
            md5   = recvall(sock, MD5LEN)
            chats.append(Chat(txt, nonce, md5))
        return Blockchain(chats)

    def __len__(self):
        return len(self.chats)

# -------------------------------------------------------------------
# IO utilitário
# -------------------------------------------------------------------
def recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)

# -------------------------------------------------------------------
# Thread que representa um peer
# -------------------------------------------------------------------
class PeerConnection(threading.Thread):
    def __init__(self, sock: socket.socket, ip: str, node: "Node"):
        super().__init__(daemon=True)
        self.sock = sock
        self.ip = ip
        self.node = node
        self.alive = True

    def send(self, payload: bytes):
        try:
            self.sock.sendall(payload)
        except OSError:
            self.alive = False

    def run(self):
        try:
            while self.alive:
                code_raw = recvall(self.sock, 1)
                if not code_raw:
                    break
                code = code_raw[0]

                if code == Msg.PEER_REQ:
                    self.send(pack_peer_list(self.node.known_peers()))

                elif code == Msg.PEER_LIST:
                    self._handle_peer_list()

                elif code == Msg.ARCH_REQ:
                    # Responde ao pedido de histórico completo
                    self.send(pack_archive_response(self.node.bc.to_bytes()))

                elif code == Msg.ARCH_RESP:
                    self._handle_archive_resp()

                # poderá incluir Msg.NOTIFY aqui se desejar

        finally:
            self.node.drop_peer(self.ip)
            self.sock.close()

    def _handle_peer_list(self):
        raw_n = recvall(self.sock, 4); n, = _u32.unpack(raw_n)
        ips: List[str] = []
        for _ in range(n):
            raw_ip = recvall(self.sock, 4)
            ip_int, = _u32.unpack(raw_ip)
            ips.append(str(ipaddress.IPv4Address(ip_int)))
        self.node.merge_peers(ips)

    def _handle_archive_resp(self):
        try:
            bc = Blockchain.from_socket(self.sock)
            self.node.consider_archive(bc)
        except ConnectionError:
            self.alive = False

# -------------------------------------------------------------------
# O nó principal
# -------------------------------------------------------------------
class Node:
    def __init__(self, ip: str, bootstrap: str = None):
        self.ip = ip
        self.bootstrap = bootstrap
        self.bc = Blockchain()
        self.peers: Dict[str, PeerConnection] = {}
        self.lock = threading.Lock()

    def log(self, msg: str):
        print(time.strftime("[%H:%M:%S]"), msg)

    def _accept_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.ip, PORT))
        srv.listen(128)
        while True:
            sock, addr = srv.accept()
            self._attach(sock, addr[0])

    def _peer_request_loop(self):
        while True:
            time.sleep(PEER_REQUEST_PERIOD)
            with self.lock:
                peers_copy = list(self.peers.values())
            for p in peers_copy:
                p.send(pack_peer_request())

    def start(self):
        # Thread de accept
        threading.Thread(target=self._accept_loop, daemon=True).start()
        # Thread de PeerRequest periódico
        threading.Thread(target=self._peer_request_loop, daemon=True).start()
        # Conecta ao bootstrap se fornecido
        if self.bootstrap and self.bootstrap != self.ip:
            self._connect(self.bootstrap)
        self.log(f"Node ready on {self.ip}:{PORT}")

    def _connect(self, ip: str):
        with self.lock:
            if ip in self.peers or ip == self.ip:
                return
        try:
            sock = socket.create_connection((ip, PORT), timeout=5)
        except OSError:
            return
        self._attach(sock, ip)

    def _attach(self, sock: socket.socket, ip: str):
        peer = PeerConnection(sock, ip, self)
        with self.lock:
            self.peers[ip] = peer
        peer.start()
        self.log(f"Connected to {ip}")
        # Puxa imediatamente o histórico completo
        peer.send(pack_archive_request())
        # Também dispara um PeerRequest para lista de peers
        peer.send(pack_peer_request())

    def drop_peer(self, ip: str):
        with self.lock:
            self.peers.pop(ip, None)
        self.log(f"Peer {ip} disconnected")

    def known_peers(self) -> List[str]:
        with self.lock:
            return list(self.peers.keys()) + [self.ip]

    def merge_peers(self, ips: List[str]):
        for ip in ips:
            self._connect(ip)

    def consider_archive(self, bc: Blockchain):
        if not bc.valid():
            self.log("Received invalid archive")
            return
        with self.lock:
            if len(bc) > len(self.bc):
                self.bc = bc
                raw = pack_archive_response(bc.to_bytes())
                for p in self.peers.values():
                    p.send(raw)
                self.log(f"Archive updated: {len(bc)} chats")

    def chat(self, text: str):
        self.log(f"Mining chat: '{text}'")
        new_bc = self.bc.mine(text)
        self.consider_archive(new_bc)

# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DCC P2P Chat – threaded node")
    parser.add_argument("--ip", required=True, help="IPv4 local address")
    parser.add_argument("--bootstrap", help="IP of an existing peer")
    args = parser.parse_args()

    node = Node(args.ip, args.bootstrap)
    node.start()

    try:
        while True:
            line = input("> ").strip()
            if line:
                node.chat(line)
    except KeyboardInterrupt:
        print()
        node.log("Shutting down")
