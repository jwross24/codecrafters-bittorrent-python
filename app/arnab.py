import socket
from dataclasses import dataclass
import ipaddress
import json
import sys
from typing import Any
import bencodepy
import hashlib
import requests
import string
import random


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def generate_identifier(string_length: int):
    return "".join(
        random.choices(string.ascii_lowercase + string.digits, k=string_length)
    )


def ge_decoder_to_utf8_encoding():
    return bencodepy.Bencode(encoding="utf-8")


def get_decoder_to_byte_encoding():
    return bencodepy.Bencode()


def decode_bencode(decoder: bencodepy.Bencode, bencoded_value: bytes) -> Any:
    return decoder.decode(bencoded_value)


def encode_to_bencode(data: bytes) -> bytes:
    return bencodepy.encode(data)


@dataclass(frozen=True)
class TorrentInformation:
    tracker_url: str
    file_length: int
    info_hash_bytes: bytes
    info_hash: str
    piece_length: int
    piece_hashes: list[str]


def _get_info(file_name: str) -> TorrentInformation:
    with open(file=file_name, mode="rb") as f:
        data = f.read()
        decoder_to_bytes = get_decoder_to_byte_encoding()
        vals = decode_bencode(decoder=decoder_to_bytes, bencoded_value=data)
        info = vals[b"info"]
        bencode_info = encode_to_bencode(info)
        tracker_url = vals[b"announce"].decode()
        file_length = info[b"length"]
        info_hash = hashlib.sha1(bencode_info).hexdigest()
        info_hash_bytes = hashlib.sha1(bencode_info).digest()
        hash_length = 20
        pieces = info[b"pieces"]
        piece_hashes = []
        for i in range(0, len(pieces), hash_length):
            piece_hashes.append(pieces[i : i + hash_length].hex())
        return TorrentInformation(
            tracker_url=tracker_url,
            file_length=file_length,
            info_hash=info_hash,
            info_hash_bytes=info_hash_bytes,
            piece_length=info[b"piece length"],
            piece_hashes=piece_hashes,
        )


@dataclass(frozen=True)
class Peer:
    ip_address: ipaddress
    port: int


def _get_peers(
    torrent_info: TorrentInformation,
) -> list[Peer]:
    file_length = torrent_info.file_length
    info_hash = torrent_info.info_hash
    tracker_url = torrent_info.tracker_url
    peer_id = generate_identifier(string_length=20)
    port = 6881
    uploaded_amount = 0
    downloaded_amount = 0
    left = file_length
    compact = 1
    decoder_to_bytes = get_decoder_to_byte_encoding()
    info_hash = "".join(
        [f"%{info_hash[i: i + 2]}" for i in range(0, len(info_hash), 2)]
    )
    url = (
        f"{tracker_url}?info_hash={info_hash}&peer_id={peer_id}"
        f"&port={port}&uploaded={uploaded_amount}"
        f"&downloaded={downloaded_amount}&left={left}&compact={compact}"
    )
    response = requests.get(url)
    decoded_response = decode_bencode(
        decoder=decoder_to_bytes, bencoded_value=response.content
    )
    all_peers = decoded_response[b"peers"]
    list_of_peers = [
        all_peers[index : index + 6] for index in range(0, len(all_peers), 6)
    ]
    out = []
    for curr_peer in list_of_peers:
        peer_address_bytes = curr_peer[:4]
        ip_address = ipaddress.IPv4Address(peer_address_bytes)
        peer_port_bytes = curr_peer[4:]
        port = int(peer_port_bytes.hex(), 16)
        out.append(Peer(ip_address=ip_address, port=port))

    return out


@dataclass(frozen=True)
class PieceRequest:
    piece_index: int
    byte_offset: int
    size: int


def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoder_to_utf8 = ge_decoder_to_utf8_encoding()
        # Uncomment this block to pass the first stage
        print(
            json.dumps(
                decode_bencode(decoder=decoder_to_utf8, bencoded_value=bencoded_value)
            )
        )
    elif command == "info":
        torrent_info = _get_info(file_name=sys.argv[2])
        print("Tracker URL:", torrent_info.tracker_url)
        print("Length:", torrent_info.file_length)
        print("Info Hash:", torrent_info.info_hash)
        print("Piece Length:", torrent_info.piece_length)
        print("Piece Hashes:")
        for curr_piece_hash in torrent_info.piece_hashes:
            print(curr_piece_hash)
    elif command == "peers":
        peers = _get_peers(torrent_info=_get_info(file_name=sys.argv[2]))
        for curr_peer in peers:
            print(f"{curr_peer.ip_address}:{curr_peer.port}")
    elif command == "handshake":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            [host, port] = sys.argv[3].split(":")
            torrent_info = _get_info(file_name=sys.argv[2])
            info_hash_bytes = torrent_info.info_hash_bytes
            s.connect((host, int(port)))
            # 19 in decimal = x13 in hex
            data = (
                b"\x13"
                + b"BitTorrent protocol"
                + b"00000000"
                + info_hash_bytes
                + b"00112233445566778899"
            )
            s.sendall(data)
            response = s.recv(1024)
        print("Peer ID:", response[-20:].hex())
    elif command == "download_piece":
        torrent_info = _get_info(file_name=sys.argv[4])
        peers = _get_peers(torrent_info=torrent_info)
        # Assume that each peers has all the data
        peers = [peers[1]]
        for curr_peer in peers:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                host = str(curr_peer.ip_address)
                port = curr_peer.port
                info_hash_bytes = torrent_info.info_hash_bytes
                s.connect((host, port))
                # 19 in decimal = x13 in hex
                handshake_data = (
                    b"\x13"
                    + b"BitTorrent protocol"
                    + b"00000000"
                    + info_hash_bytes
                    + b"00112233445566778899"
                )
                s.sendall(handshake_data)
                peer_id_response = s.recv(1024)
                # Express interest - no need to wait for bitfield since we have no data
                # "Downloaders which don't have anything yet may skip the 'bitfield' message"
                interested_data = b"0001" + b"\x02"
                s.sendall(interested_data)
                interested_data_response = s.recv(1024)
                max_size = 16_384
                request_message_id = 6
                curr_offset_in_piece = 0
                total_bytes = 0
                all_requests_for_file = []
                curr_piece = 0
                while total_bytes < torrent_info.file_length:
                    remaining_bytes_in_piece = (
                        torrent_info.piece_length - curr_offset_in_piece
                    )
                    if remaining_bytes_in_piece == 0:
                        curr_piece += 1
                        remaining_bytes_in_piece = torrent_info.piece_length
                        curr_offset_in_piece = 0
                    remaining_bytes_in_file = torrent_info.file_length - total_bytes
                    size = min(
                        min(remaining_bytes_in_file, remaining_bytes_in_piece), max_size
                    )
                    if size < 0:
                        break
                    all_requests_for_file.append(
                        PieceRequest(
                            piece_index=curr_piece,
                            byte_offset=curr_offset_in_piece,
                            size=size,
                        )
                    )
                    curr_offset_in_piece += size
                    total_bytes += size
                print(all_requests_for_file)
                print(torrent_info)
                specified_piece = int(sys.argv[5])
                response_out = []
                curr_request_index = 0
                # TODO: update
                curr_piece_index = specified_piece
                curr_val = b""
                all_requests = [
                    request
                    for request in all_requests_for_file
                    if request.piece_index == specified_piece
                ]
                print(all_requests)
                while curr_request_index < len(all_requests):
                    print("curr val", len(curr_val))
                    expected_size = 0
                    curr_requests_list = []
                    expected_response_prefix = []
                    while len(curr_requests_list) < 5 and curr_request_index < len(
                        all_requests
                    ):
                        if (
                            all_requests[curr_request_index].piece_index
                            > curr_piece_index
                        ):
                            break
                        curr_request = all_requests[curr_request_index]
                        torrent_data_piece = (
                            b"\x00\x00\x00\x0d"
                            + (request_message_id.to_bytes(1, byteorder="big"))
                            + (curr_request.piece_index.to_bytes(4, byteorder="big"))
                            + (curr_request.byte_offset.to_bytes(4, byteorder="big"))
                            + (curr_request.size.to_bytes(4, byteorder="big"))
                        )
                        expected_size += curr_request.size
                        s.sendall(torrent_data_piece)
                        curr_requests_list.append(curr_request_index)
                        response_message_id = 7
                        expected_response_prefix.append(
                            (curr_request.size + 9).to_bytes(4, byteorder="big")
                            + (response_message_id.to_bytes(1, byteorder="big"))
                            # + torrent_data_piece[5:-4]
                        )
                        curr_request_index += 1
                    curr_request_out = b""
                    while True:
                        out = s.recv(curr_request.size)
                        if len(out) >= 5 and out[4] == 7:
                            curr_request_out += out[13:]
                        elif len(curr_request_out) > 0:
                            curr_request_out += out
                        for expected in expected_response_prefix:
                            if expected in curr_request_out:
                                ind = curr_request_out.index(expected)
                                curr_request_out = curr_request_out.replace(
                                    curr_request_out[ind : ind + 13], b""
                                )
                        if len(curr_request_out) == expected_size:
                            break
                    curr_val += curr_request_out
                    if (
                        curr_request_index >= len(all_requests)
                        or all_requests[curr_request_index].piece_index
                        != curr_piece_index
                    ):
                        response_out.append(curr_val)
                        curr_piece_index += 1
                        curr_val = b""
        file_name = sys.argv[3]
        curr_response_index = 0
        with open(file=file_name, mode="wb") as f:
            f.write(response_out[curr_response_index])
        assert (
            hashlib.sha1(response_out[curr_response_index]).hexdigest()
            == torrent_info.piece_hashes[specified_piece]
        )
        print(f"Piece {specified_piece} downloadaed to {file_name}.")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
