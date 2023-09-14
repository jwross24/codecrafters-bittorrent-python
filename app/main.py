import hashlib
import json
import socket
import sys

import bencodepy
import requests

bc = bencodepy.Bencode(encoding="utf-8")


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)


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
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()

        info_dict = bencodepy.Bencode().decode(info)
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"]))

        print(f'Tracker URL: {info_dict[b"announce"].decode()}')
        print(f'Length: {info_dict[b"info"][b"length"]}')
        print(f"Info Hash: {info_hash.hexdigest()}")
        print(f'Piece Length: {info_dict[b"info"][b"piece length"]}')

        print("Piece Hashes:")
        for i in range(0, len(info_dict[b"info"][b"pieces"]), 20):
            print(info_dict[b"info"][b"pieces"][i : i + 20].hex())
    elif command == "peers":
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()

        info_dict = bencodepy.Bencode().decode(info)
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"]))
        tracker_url = info_dict[b"announce"].decode()

        response = requests.get(
            tracker_url,
            params={
                "info_hash": info_hash.digest(),
                "peer_id": "00112233445566778899",
                "port": 6881,
                "uploaded": 0,
                "downloaded": 0,
                "left": info_dict[b"info"][b"length"],
                "compact": 1,
            },
        )

        decoded_response = bencodepy.Bencode().decode(response.content)
        peers = decoded_response[b"peers"]
        for p in range(0, len(peers), 6):
            ip_address = ".".join([str(i) for i in peers[p : p + 4]])
            port = int.from_bytes(peers[p + 4 : p + 6], byteorder="big")
            print(f"{ip_address}:{port}")
    elif command == "handshake":
        with open(sys.argv[2], "rb") as torrent_file:
            info = torrent_file.read()

        info_dict = bencodepy.Bencode().decode(info)
        info_hash = hashlib.sha1(bencodepy.encode(info_dict[b"info"]))

        protocol_length = 19
        protocol_string = b"BitTorrent protocol"
        reserved_bytes = b"\x00" * 8
        info_hash = info_hash.digest()
        peer_id = b"00112233445566778899"

        handshake = (
            bytes([protocol_length])
            + protocol_string
            + reserved_bytes
            + info_hash
            + peer_id
        )

        # Establish TCP connection with peer and send handshake
        peer_ip_port = sys.argv[3]
        peer_ip = peer_ip_port.split(":")[0]
        peer_port = int(peer_ip_port.split(":")[1])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer_ip, peer_port))
        sock.sendall(handshake)

        # Receive handshake from peer
        received_handshake = sock.recv(68)
        sock.close()

        received_peer_id = received_handshake[48:]
        print(f"Peer ID: {received_peer_id.hex()}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
