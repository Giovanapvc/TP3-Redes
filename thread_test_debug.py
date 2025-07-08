#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import os
import socket
import struct
import threading
import time
import sys
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
# Serialização de mensagens com debug
# -------------------------------------------------------------------
def pack_peer_request() -> bytes:
    data = _u8.pack(Msg.PEER_REQ)
    print(f"[DEBUG] Sending PeerRequest (0x1) => {data.hex()}")
    return data

def pack_peer_list(peers: List[str]) -> bytes:
    buf = bytearray(_u8.pack(Msg.PEER_LIST))
    buf += _u32.pack(len(peers))
    for ip in peers:
        buf += _u32.pack(int(ipaddress.IPv4Address(ip)))
    print(f"[DEBUG] Sending PeerList (0x2), count={len(peers)} => {buf.hex()}")
    return bytes(buf)

def pack_archive_request() -> bytes:
    data = _u8.pack(Msg.ARCH_REQ)
    print(f"[DEBUG] Sending ArchiveRequest (0x3) => {data.hex()}")
    return data

def pack_archive_response(payload: bytes) -> bytes:
    data = _u8.pack(Msg.ARCH_RESP) + payload
    print(f"[DEBUG] Sending ArchiveResponse (0x4), payload_len={len(payload)}")
    return data

def pack_notify(msg: str) -> bytes:
    data = msg.encode("ascii")[:MAX_CHAT_LEN]
    packet = _u8.pack(Msg.NOTIFY) + _u8.pack(len(data)) + data
    print(f"[DEBUG] Sending Notify (0x5), msg='{msg}' => {packet.hex()}")
    return packet

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
        print(f"[DEBUG] Start mining chat '{text_ascii}'")
        while True:
            nonce = os.urandom(MD5LEN)
            digest = hashlib.md5(prev + prefix + nonce).digest()
            if digest[:2] == b"\x00\x00":
                print(f"[DEBUG] Found nonce={nonce.hex()} md5={digest.hex()}")
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
        print(f"[DEBUG] Received ArchiveResponse header, count={n}")
        chats: List[Chat] = []
        for idx in range(n):
            ln_raw = recvall(sock, 1); ln, = _u8.unpack(ln_raw)
            txt   = recvall(sock, ln)
            nonce = recvall(sock, MD5LEN)
            md5   = recvall(sock, MD5LEN)
            print(f"[DEBUG] Received Chat #{idx+1}: text={txt.decode()} nonce={nonce.hex()} md5={md5.hex()}")
            chats.append(Chat(txt, nonce, md5))
        return Blockchain(chats)

    def __len__(self):
        return len(self.chats)

# -------------------------------------------------------------------
# IO utilitário com debug
# -------------------------------------------------------------------
def recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    print(f"[DEBUG] recvall: {buf.hex()}")
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
        print(f"[DEBUG] New PeerConnection thread for {ip}")

    def send(self, payload: bytes):
        print(f"[DEBUG] send() to {self.ip}: {payload.hex()}")
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
                print(f"[DEBUG] run(): received code=0x{code:02x} from {self.ip}")

                if code == Msg.PEER_REQ:
                    self.send(pack_peer_list(self.node.known_peers()))

                elif code == Msg.PEER_LIST:
                    self._handle_peer_list()

                elif code == Msg.ARCH_REQ:
                    self.send(pack_archive_response(self.node.bc.to_bytes()))

                elif code == Msg.ARCH_RESP:
                    self._handle_archive_resp()

        finally:
            print(f"[DEBUG] PeerConnection for {self.ip} terminating")
            self.node.drop_peer(self.ip)
            self.sock.close()

    def _handle_peer_list(self):
        raw_n = recvall(self.sock, 4); n, = _u32.unpack(raw_n)
        print(f"[DEBUG] _handle_peer_list: n={n}")
        ips: List[str] = []
        for _ in range(n):
            raw_ip = recvall(self.sock, 4)
            ip_int, = _u32.unpack(raw_ip)
            s = str(ipaddress.IPv4Address(ip_int))
            ips.append(s)
            print(f"[DEBUG] _handle_peer_list: got peer {s}")
        self.node.merge_peers(ips)

    def _handle_archive_resp(self):
        try:
            bc = Blockchain.from_socket(self.sock)
            self.node.consider_archive(bc)
        except ConnectionError:
            self.alive = False

# -------------------------------------------------------------------
# O nó principal com debug e histórico
# -------------------------------------------------------------------
class Node:
    def __init__(self, ip: str, bootstrap: str = None):
        self.ip = ip
        self.bootstrap = bootstrap
        self.bc = Blockchain()
        self.peers: Dict[str, PeerConnection] = {}
        self.lock = threading.Lock()
        print(f"[DEBUG] Node init: ip={ip}, bootstrap={bootstrap}")

    def _accept_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.ip, PORT))
        srv.listen(128)
        print(f"[DEBUG] Listening on {self.ip}:{PORT}")
        while True:
            sock, addr = srv.accept()
            print(f"[DEBUG] Accepted connection from {addr[0]}")
            self._attach(sock, addr[0])

    def _peer_request_loop(self):
        while True:
            time.sleep(PEER_REQUEST_PERIOD)
            with self.lock:
                peers_copy = list(self.peers.values())
            for p in peers_copy:
                print(f"[DEBUG] Periodic PeerRequest to {p.ip}")
                p.send(pack_peer_request())

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._peer_request_loop, daemon=True).start()
        if self.bootstrap and self.bootstrap != self.ip:
            print(f"[DEBUG] Connecting to bootstrap {self.bootstrap}")
            self._connect(self.bootstrap)

    def _connect(self, ip: str):
        try:
            addr = socket.gethostbyname(ip)
        except socket.gaierror:
            addr = ip
        with self.lock:
            if addr in self.peers or addr == self.ip:
                return
        print(f"[DEBUG] Creating connection to {addr}:{PORT}")
        try:
            sock = socket.create_connection((addr, PORT), timeout=5)
        except OSError as e:
            print(f"[DEBUG] Connection to {addr} failed: {e}")
            return
        self._attach(sock, addr)

    def _attach(self, sock: socket.socket, ip: str):
        print(f"[DEBUG] Attaching peer {ip}")
        peer = PeerConnection(sock, ip, self)
        with self.lock:
            self.peers[ip] = peer
        peer.start()
        peer.send(pack_archive_request())
        peer.send(pack_peer_request())

    def drop_peer(self, ip: str):
        with self.lock:
            if ip in self.peers:
                print(f"[DEBUG] Dropping peer {ip}")
                del self.peers[ip]

    def known_peers(self) -> List[str]:
        with self.lock:
            return list(self.peers.keys()) + [self.ip]

    def merge_peers(self, ips: List[str]):
        for ip in ips:
            self._connect(ip)

    def consider_archive(self, bc: Blockchain):
        if not bc.valid():
            print(f"[DEBUG] Received invalid archive with {len(bc)} chats")
            return
        with self.lock:
            if len(bc) > len(self.bc):
                print(f"[DEBUG] Replacing local archive {len(self.bc)} -> {len(bc)}")
                self.bc = bc
                raw = pack_archive_response(bc.to_bytes())
                for p in self.peers.values():
                    p.send(raw)

    def chat(self, text: str):
        print(f"[DEBUG] chat(): mining '{text}'")
        new_bc = self.bc.mine(text)
        self.consider_archive(new_bc)

    def print_history(self):
        """Imprime todo o histórico local de chats."""
        print("=== Chat History ===")
        for idx, chat in enumerate(self.bc.chats, start=1):
            txt = chat.text.decode("ascii", errors="ignore")
            print(f"{idx:03d}: {txt}")
        print("====================")

# -------------------------------------------------------------------
# CLI principal
# -------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DCC P2P Chat – verbose debug mode")
    parser.add_argument("--ip", required=True, help="IPv4 local address or alias")
    parser.add_argument("--bootstrap", help="IP or hostname of an existing peer")
    args = parser.parse_args()

    node = Node(args.ip, args.bootstrap)
    node.start()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line.lower() == "/history":
            node.print_history()
        else:
            node.chat(line)
