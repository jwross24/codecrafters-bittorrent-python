import hashlib
import json
import socket
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

import bencodepy
import requests


@dataclass
class Peer:
    ip_address: str
    port: int


@dataclass
class TorrentFile:
    filename: str
    announce: str
    info_hash: bytes
    peer_id: str
    length: int
    piece_length: int
    hashes: List[bytes]

    def __init__(self, filename: str):
        self.filename = filename

    def get_torrent_info(self):
        with open(self.filename, "rb") as f:
            info = f.read()

        info_dict = bencodepy.Bencode().decode(info)
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"]))

        self.announce = info_dict[b"announce"].decode()
        self.info_hash = info_hash.digest()
        self.peer_id = "00112233445566778899"
        self.length = info_dict[b"info"][b"length"]
        self.piece_length = info_dict[b"info"][b"piece length"]

        HASH_LENGTH = 20
        self.hashes = [
            info_dict[b"info"][b"pieces"][i : i + HASH_LENGTH]
            for i in range(0, len(info_dict[b"info"][b"pieces"]), HASH_LENGTH)
        ]

    def get_peers(self) -> List[Peer]:
        PORT = 6881

        response = requests.get(
            self.announce,
            params={
                "info_hash": self.info_hash,
                "peer_id": self.peer_id,
                "port": PORT,
                "uploaded": 0,
                "downloaded": 0,
                "left": self.length,
                "compact": 1,
            },
        )

        decoded_response = bencodepy.Bencode().decode(response.content)
        peers_list = decoded_response[b"peers"]

        peers = []
        for p in range(0, len(peers_list), 6):
            ip_address = ".".join([str(i) for i in peers_list[p : p + 4]])
            port = int.from_bytes(peers_list[p + 4 : p + 6], byteorder="big")
            peers.append(Peer(ip_address, port))

        return peers


class MessageType(Enum):
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOT_INTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8


BLOCK_SIZE = 16 * 1024


def decode_bencode(bencoded_value):
    bc = bencodepy.Bencode(encoding="utf-8")

    return bc.decode(bencoded_value)


def do_handshake(conn: socket.socket, torrent_file: TorrentFile) -> bytes:
    PROTOCOL_STRING = b"BitTorrent protocol"
    PROTOCOL_LENGTH = len(PROTOCOL_STRING).to_bytes(1, byteorder="big")
    RESERVED_BYTES = b"\x00" * 8
    PEER_ID = b"01231234234534564567"

    handshake = (
        PROTOCOL_LENGTH
        + PROTOCOL_STRING
        + RESERVED_BYTES
        + torrent_file.info_hash
        + PEER_ID
    )
    conn.sendall(handshake)

    return conn.recv(len(handshake))


def do_handshake_with_peer(peer: Peer, torrent_file: TorrentFile) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((peer.ip_address, peer.port))
        received_handshake = do_handshake(sock, torrent_file)

    return received_handshake


def create_connection(peer: Peer, timeout_seconds: float = 1) -> socket.socket:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(timeout_seconds)
    conn.connect((peer.ip_address, peer.port))

    return conn


def close_connections(connections: Dict[str, socket.socket]):
    for conn in connections.values():
        conn.close()


def wait_for(conn: socket.socket, expected_message_type: MessageType) -> bytes:
    print(f"[+] Connected: {conn.getpeername()}")
    print(f"[!] Waiting for {expected_message_type}")

    retries = 0
    while True:
        message_length = conn.recv(4)

        print(f"[!] Received: {message_length.hex()}")

        if not message_length:
            time.sleep(0.1)
            if retries >= 2:
                raise socket.timeout
            retries += 1
            continue

        message_length = int.from_bytes(message_length, byteorder="big")
        # print(f"[+] Message length: {message_length}")

        message_type = int.from_bytes(conn.recv(1), byteorder="big")
        # print(f"[!] Received: {message_type} - Expected: {expected_message_type.value}")

        payload = bytearray()
        while len(payload) < message_length - 1:
            remaining_bytes = message_length - 1 - len(payload)
            if chunk := conn.recv(min(1024, remaining_bytes)):
                payload.extend(chunk)
            else:
                break

        if message_type != expected_message_type.value:
            continue

        # print(f"[+] Payload: {len(payload)}")
        # print(f"[+] Message type: {message_type}")

        return payload


def send_message(conn: socket.socket, message_type: MessageType, payload: bytes = b""):
    conn.sendall(create_peer_message(message_type, payload))


def create_peer_message(message_type: MessageType, payload: bytes) -> bytes:
    message_length = (len(payload) + 1).to_bytes(4, byteorder="big")
    message_type = message_type.value.to_bytes(1, byteorder="big")

    return message_length + message_type + payload


def create_request_payload(piece_index: int, begin: int, block_size: int) -> bytes:
    return (
        piece_index.to_bytes(4, byteorder="big")
        + begin.to_bytes(4, byteorder="big")
        + block_size.to_bytes(4, byteorder="big")
    )


def download_block(
    conn: socket.socket, piece_index: int, begin: int, block_size: int
) -> bytearray:
    try:
        request_payload = create_request_payload(piece_index, begin, block_size)
        send_message(conn, MessageType.REQUEST, request_payload)

        piece_payload = wait_for(conn, MessageType.PIECE)

        received_piece_index = int.from_bytes(piece_payload[:4], byteorder="big")
        if received_piece_index != piece_index:
            return bytearray()

        return piece_payload[8:]
    except socket.timeout:
        return bytearray()


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        filename = sys.argv[2]
        torrent_file = TorrentFile(filename)
        torrent_file.get_torrent_info()

        print(f"Tracker URL: {torrent_file.announce}")
        print(f"Length: {torrent_file.length}")
        print(f"Info Hash: {torrent_file.info_hash.hex()}")
        print(f"Piece Length: {torrent_file.piece_length}")
        print("Piece Hashes:")
        for hash in torrent_file.hashes:
            print(hash.hex())
    elif command == "peers":
        filename = sys.argv[2]
        torrent_file = TorrentFile(filename)
        torrent_file.get_torrent_info()

        peers = torrent_file.get_peers()

        for p in peers:
            print(f"{p.ip_address}:{p.port}")
    elif command == "handshake":
        filename = sys.argv[2]
        torrent_file = TorrentFile(filename)
        torrent_file.get_torrent_info()

        # Establish TCP connection with peer and send handshake
        peer_address = sys.argv[3]
        peer_ip, peer_port = peer_address.split(":")
        peer_port = int(peer_port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((peer_ip, peer_port))
            received_handshake = do_handshake(sock, torrent_file)

        received_peer_id = received_handshake[48:]
        print(f"Peer ID: {received_peer_id.hex()}")
    elif command == "download_piece":
        filename = sys.argv[4]
        torrent_file = TorrentFile(filename)
        torrent_file.get_torrent_info()

        peers = torrent_file.get_peers()

        piece_index = int(sys.argv[5])
        output_file_path = sys.argv[3]

        num_blocks = torrent_file.piece_length // BLOCK_SIZE
        last_block_size = torrent_file.piece_length % BLOCK_SIZE
        downloaded_blocks = [b""] * num_blocks
        if last_block_size:
            downloaded_blocks.append(b"")

        block_index = 0
        for peer in peers:
            conn = create_connection(peer)
            peer_address = f"{peer.ip_address}:{peer.port}"
            try:
                do_handshake(conn, torrent_file)
                wait_for(conn, MessageType.BITFIELD)
                send_message(conn, MessageType.INTERESTED)
                wait_for(conn, MessageType.UNCHOKE)

                while block_index < num_blocks:
                    print(f"Block number {block_index + 1}/{num_blocks}")
                    begin = block_index * BLOCK_SIZE

                    block_data = download_block(conn, piece_index, begin, BLOCK_SIZE)
                    if not block_data:
                        raise socket.timeout

                    downloaded_blocks[block_index] = block_data
                    block_index += 1

                if last_block_size:
                    begin = num_blocks * BLOCK_SIZE

                    block_data = download_block(
                        conn, piece_index, begin, last_block_size
                    )
                    if not block_data:
                        raise socket.timeout

                    downloaded_blocks[-1] = block_data

                combined_blocks = b"".join(downloaded_blocks)
                piece_hash = hashlib.sha1(combined_blocks).digest()
                expected_piece_hash = torrent_file.hashes[piece_index]

                if piece_hash != expected_piece_hash:
                    print(
                        f"Piece {piece_index} download failed. Integrity check failed."
                    )
                    return

                with open(output_file_path, "wb") as output_file:
                    output_file.write(combined_blocks)

                print(f"Piece {piece_index} downloaded to {output_file_path}.")
                conn.close()
                break

            except (socket.timeout, ConnectionResetError):
                print(f"Connection to {peer_address} failed. Trying next peer.")

                conn.close()

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
