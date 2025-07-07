
from __future__ import annotations
import asyncio
import argparse
import ipaddress
import hashlib
import logging
import os
import struct
from enum import IntEnum
from typing import List, Tuple

###############################################################################
# Constantes
###############################################################################
PORT = 51511
PEER_REQUEST_PERIOD = 5  # segundos
MD5LEN = 16
MAX_CHAT_LEN = 255
###############################################################################
# Empacotamento das mensagens
###############################################################################
_u8 = struct.Struct("!B")   # 1 byte unsigned
_u32 = struct.Struct("!I")  # 4 bytes unsigned

class Msg(IntEnum):
    PEER_REQ  = 0x1  # PeerRequest
    PEER_LIST = 0x2  # PeerList
    ARCH_REQ  = 0x3  # ArchiveRequest
    ARCH_RESP = 0x4  # ArchiveResponse
    NOTIFY    = 0x5  # NotificationMessage (opcional)

# ---- helpers -------------------------------------------------------------

def pack_peer_request() -> bytes:
    return _u8.pack(Msg.PEER_REQ)


def pack_peer_list(peers: List[str]) -> bytes:
    buf = bytearray()
    buf += _u8.pack(Msg.PEER_LIST)
    buf += _u32.pack(len(peers))
    for ip in peers:
        buf += _u32.pack(int(ipaddress.IPv4Address(ip)))
    return bytes(buf)


def pack_archive_response(raw: bytes) -> bytes:
    return _u8.pack(Msg.ARCH_RESP) + raw


def pack_archive_request() -> bytes:
    return _u8.pack(Msg.ARCH_REQ)

# notification opcional

def pack_notify(msg: str) -> bytes:
    payload = msg.encode("ascii")[:MAX_CHAT_LEN]
    return _u8.pack(Msg.NOTIFY) + _u8.pack(len(payload)) + payload

###############################################################################
# Estruturas de blockchain / chat
###############################################################################
HEADER = _u8  # tamanho 1 byte

class Chat:
    __slots__ = ("text", "nonce", "md5")
    def __init__(self, text: bytes, nonce: bytes, md5: bytes):
        self.text = text      # bytes ASCII
        self.nonce = nonce    # 16 bytes
        self.md5 = md5        # 16 bytes

    # serialização ---------------------------------------------------------
    def pack(self) -> bytes:
        return HEADER.pack(len(self.text)) + self.text + self.nonce + self.md5

    @staticmethod
    def unpack(reader: asyncio.StreamReader) -> "Chat":
        n_raw = await_read(reader, HEADER.size)
        n, = HEADER.unpack(n_raw)
        if n > MAX_CHAT_LEN:
            raise ValueError("chat len > 255")
        text = await_read(reader, n)
        nonce = await_read(reader, MD5LEN)
        md5 = await_read(reader, MD5LEN)
        return Chat(text, nonce, md5)


class Blockchain:
    """Mantém lista de chats + verificação/mineração."""

    def __init__(self, chats: List[Chat] | None = None):
        self.chats: List[Chat] = list(chats) if chats else []

    # ----------------------------- verificação ---------------------------
    def valid(self) -> bool:
        # histórico vazio é válido.
        if not self.chats:
            return True
        # verificação iterativa (evita recursão profunda):
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
        blob = b"".join(c.pack() for c in window[:-1])
        blob += tail.pack()[:-MD5LEN]  # sem md5 do último
        if hashlib.md5(blob).digest() != tail.md5:
            return False
        return True

    # ----------------------------- mineração -----------------------------
    def mine(self, text_ascii: str) -> "Blockchain":
        text = text_ascii.encode("ascii")
        if len(text) > MAX_CHAT_LEN:
            raise ValueError("chat > 255")
        prefix = HEADER.pack(len(text)) + text
        window = self.chats[-19:]
        blob_prev = b"".join(c.pack() for c in window)
        while True:
            nonce = os.urandom(MD5LEN)
            candidate = blob_prev + prefix + nonce
            md5 = hashlib.md5(candidate).digest()
            if md5[:2] == b"\x00\x00":
                new_chat = Chat(text, nonce, md5)
                return Blockchain(self.chats + [new_chat])

    # ----------------------------- serialização para rede ---------------
    def to_bytes(self) -> bytes:
        buf = bytearray()
        buf += _u32.pack(len(self.chats))
        for c in self.chats:
            buf += c.pack()
        return bytes(buf)

    @staticmethod
    async def from_reader(reader: asyncio.StreamReader) -> "Blockchain":
        raw_c = await_read(reader, _u32.size)
        c, = _u32.unpack(raw_c)
        chats: List[Chat] = []
        for _ in range(c):
            n_raw = await_read(reader, HEADER.size)
            n, = HEADER.unpack(n_raw)
            text = await_read(reader, n)
            nonce = await_read(reader, MD5LEN)
            md5 = await_read(reader, MD5LEN)
            chats.append(Chat(text, nonce, md5))
        return Blockchain(chats)

    # utilidades -----------------------------------------------------------
    def __len__(self):
        return len(self.chats)

    def __iter__(self):
        return iter(self.chats)

###############################################################################
# Função auxiliar de leitura exata (async)
###############################################################################
async def await_read(reader: asyncio.StreamReader, n: int) -> bytes:
    data = await reader.readexactly(n)
    if len(data) < n:
        raise asyncio.IncompleteReadError(data, n)
    return data

###############################################################################
# Camada de peer (TCP)  — cada conexão
###############################################################################
class Peer:
    def __init__(self, ip: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, node: "P2PNode"):
        self.ip = ip
        self.reader = reader
        self.writer = writer
        self.node = node
        self.task = asyncio.create_task(self._listen())

    # ----------------------- envio conveniente --------------------------
    def send(self, data: bytes):
        self.writer.write(data)

    async def send_and_drain(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

    # ----------------------- loop receptor ------------------------------
    async def _listen(self):
        try:
            while True:
                code_raw = await_read(self.reader, 1)
                code = code_raw[0]
                if code == Msg.PEER_REQ:
                    self.send(pack_peer_list(self.node.known_peers()))
                elif code == Msg.PEER_LIST:
                    await self._handle_peer_list()
                elif code == Msg.ARCH_REQ:
                    self.send(pack_archive_response(self.node.archive.to_bytes()))
                elif code == Msg.ARCH_RESP:
                    await self._handle_archive_resp()
                elif code == Msg.NOTIFY:
                    await self._consume_notify()
                else:
                    logging.warning("%s enviou msg desconhecida 0x%02x", self.ip, code)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            logging.info("Peer %s desconectou", self.ip)
        finally:
            self.node.drop_peer(self.ip)
            try:
                self.writer.close(); await self.writer.wait_closed()
            except Exception:  # noqa
                pass

    # ----------------------- handlers -----------------------------------
    async def _handle_peer_list(self):
        raw_n = await_read(self.reader, 4)
        n, = _u32.unpack(raw_n)
        ips = []
        for _ in range(n):
            raw_ip = await_read(self.reader, 4)
            ip_int, = _u32.unpack(raw_ip)
            ips.append(str(ipaddress.IPv4Address(ip_int)))
        self.node.merge_peers(ips)

    async def _handle_archive_resp(self):
        bc = await Blockchain.from_reader(self.reader)
        self.node.consider_archive(bc)

    async def _consume_notify(self):
        ln_raw = await_read(self.reader, 1)
        ln, = _u8.unpack(ln_raw)
        msg = (await_read(self.reader, ln)).decode("ascii", errors="ignore")
        logging.info("Notify de %s: %s", self.ip, msg)

###############################################################################
# Nó P2P – orquestra múltiplas conexões
###############################################################################
class P2PNode:
    def __init__(self, my_ip: str, bootstrap_ip: str | None = None):
        self.my_ip = my_ip
        self.bootstrap_ip = bootstrap_ip
        self.peers: dict[str, Peer] = {}
        self.archive = Blockchain()      # começa vazio

    # ------------------------- ciclo de vida ---------------------------
    async def start(self):
        server = await asyncio.start_server(self._on_accept, self.my_ip, PORT)
        logging.info("Servidor ouvindo em %s:%d", self.my_ip, PORT)
        if self.bootstrap_ip and self.bootstrap_ip != self.my_ip:
            asyncio.create_task(self._connect(self.bootstrap_ip))
        asyncio.create_task(self._ticker_peer_requests())
        async with server:
            await server.serve_forever()

    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        await self._attach(ip, reader, writer)

    async def _connect(self, ip: str):
        if ip in self.peers or ip == self.my_ip:
            return
        try:
            reader, writer = await asyncio.open_connection(ip, PORT)
            await self._attach(ip, reader, writer)
        except OSError:
            logging.warning("Falha ao conectar %s", ip)

    async def _attach(self, ip: str, reader, writer):
        self.peers[ip] = Peer(ip, reader, writer, self)
        logging.info("Conectado a %s", ip)

    def drop_peer(self, ip: str):
        self.peers.pop(ip, None)

    # ------------------------- peer discovery ---------------------------
    def known_peers(self) -> List[str]:
        return sorted(set(self.peers.keys()) | {self.my_ip})

    def merge_peers(self, ips: List[str]):
        for ip in ips:
            asyncio.create_task(self._connect(ip))

    async def _ticker_peer_requests(self):
        while True:
            await asyncio.sleep(PEER_REQUEST_PERIOD)
            for p in list(self.peers.values()):
                p.send(pack_peer_request())

    # ------------------------- histórico -------------------------------
    def consider_archive(self, bc: Blockchain):
        if not bc.valid():
            logging.warning("Arquivo inválido recebido (%d chats) de peer", len(bc))
            return
        if len(bc) > len(self.archive):
            logging.info("Atualizando histórico local: %d → %d chats", len(self.archive), len(bc))
            self.archive = bc
            raw = pack_archive_response(bc.to_bytes())
            for p in self.peers.values():
                p.send(raw)

    # ------------------------- API externa -----------------------------
    async def send_chat(self, text: str):
        logging.info("Minerando chat: '%s'", text)
        self.archive = self.archive.mine(text)
        raw = pack_archive_response(self.archive.to_bytes())
        for p in self.peers.values():
            p.send(raw)
        logging.info("Chat propagado para %d peers", len(self.peers))

###############################################################################
# Entry point CLI
###############################################################################
async def main():
    parser = argparse.ArgumentParser(description="DCC P2P Chat – nó")
    parser.add_argument("--ip", required=True, help="IPv4 local (127.0.0.X)")
    parser.add_argument("--bootstrap", help="IP de um peer existente")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    node = P2PNode(args.ip, args.bootstrap)
    asyncio.create_task(node.start())

    loop = asyncio.get_running_loop()
    # shell simples via stdin
    while True:
        text = await loop.run_in_executor(None, input, "> ")
        text = text.strip()
        if not text:
            continue
        await node.send_chat(text)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
        logging.info("Encerrado pelo usuário")
