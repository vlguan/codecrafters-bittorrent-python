import json
import sys
import hashlib
import binascii
import requests
from urllib.parse import urlencode
import struct
# import bencodepy - available if you need it!
# import requests - available if you need it!

def encode_bencode(decoded_value):
    if isinstance(decoded_value, int):
        return f"i{decoded_value}e".encode()
    elif isinstance(decoded_value, str):
        return f"{len(decoded_value)}:{decoded_value}".encode()
    elif isinstance(decoded_value, bytes):
        return f"{len(decoded_value)}:".encode()+decoded_value
    elif isinstance(decoded_value, list):
        res = "l".encode()
        for i in decoded_value:
            res += encode_bencode(i)
        res += "e".encode()
        return res
    elif isinstance(decoded_value, dict):
        res = "d".encode()
        for key, val in decoded_value.items():
            res += encode_bencode(key) + encode_bencode(val)
        res += "e".encode()
        return res
    else:
        raise TypeError("Unsupported type")
def infoHasher(sha_hash ,decoded_data):
    hash_obj = hashlib.sha1(sha_hash)
    hex_dig = hash_obj.hexdigest()
    pieces = decoded_data['info']['pieces']
    piece_hashes=[]
    for i in range(0, len(pieces), 20):
        piece_hashes.append(pieces[i:i+20]) 
    piece_hashes = [binascii.hexlify(piece).decode() for piece in piece_hashes]
    return hex_dig, piece_hashes
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        num_chars = int(bencoded_value[0:first_colon_index])
        chars = num_chars + first_colon_index + 1
        return bencoded_value[first_colon_index+1: chars], chars
    elif chr(bencoded_value[0]) == 'i':
        # print(bencoded_value)
        end = bencoded_value.find(b"e")
        start = bencoded_value.find(b'i')
        if start ==-1 or end ==-1:
            raise ValueError("Invalid encoded value")
        # print(bencoded_value[1:integer])
        return int(bencoded_value[start+1:end].replace(b"~", b"-")), end + 1
    elif chr(bencoded_value[0]) == 'l':
        res, chars= decode_bencode_list(bencoded_value)
        # print(res, chars)
        return res, chars
    elif chr(bencoded_value[0]) == 'd':
        res, chars = decode_bencode_dict(bencoded_value)
        return res, chars
def decode_bencode_list(bencoded_value):
    res=[]
    cursor =1
    while(chr(bencoded_value[cursor])!= "e"):
        # print(bencoded_value[cursor:])
        decoded, chars = decode_bencode(bencoded_value[cursor:])
        # print(decoded, chars)
        res.append(decoded)
        cursor+=chars
    chars= cursor+1
    # print(res)
    return res, chars
def decode_bencode_dict(bencoded_value):
    res = {}
    cursor =1
    while(chr(bencoded_value[cursor])!= "e"):
        decodedKey, kchars = decode_bencode(bencoded_value[cursor:])
        cursor += kchars
        decodedValue, vchars = decode_bencode(bencoded_value[cursor:])
        cursor += vchars
        res[decodedKey.decode('utf-8')] = decodedValue
    chars = cursor+1
    return res, chars

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

        # Uncomment this block to pass the first stage
        # print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
        decoded, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded, default=bytes_to_str))
    elif command == "info":
        filepath = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
        with open(filepath, 'rb') as file:
            decoded_data, _ = decode_bencode(file.read())
            sha_hash = encode_bencode(decoded_data['info'])
            hex_dig, piece_hashes = infoHasher(sha_hash, decoded_data)
            print(f"Tracker URL: {decoded_data['announce'].decode()}")
            print(f"Length: {decoded_data['info']['length']}")
            print(f"Info Hash: {hex_dig}") 
            print(f"Piece Length: {decoded_data['info']['piece length']}")
            print("Piece Hashes:")
            for piece_hash in piece_hashes:
                print(piece_hash)
    elif command == "peers":
        filepath = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
        with open(filepath, 'rb') as file:
            decoded_data, _ = decode_bencode(file.read())
            piece_hash = hashlib.sha1(encode_bencode(decoded_data['info'])).digest()
            params = {
                'info_hash': piece_hash,
                'peer_id': '00112233445566778899',
                'port': 6881,
                'uploaded': 0,
                'downloaded':0,
                'left': decoded_data['info']['length'],
                'compact':1
            }
            track_url = decoded_data['announce'].decode()
            response = requests.get(track_url, params=urlencode(params))
            response_data = response.content
            decoded_response = decode_bencode(response_data)
            print(decoded_response)
            peers = decoded_response['peers']
            for i in range(0, len(peers)):
                peer = peers[i:i+6]
                ip = struct.unpack('!BBBB', peer[:4])
                port = struct.unpack('!H', peer[4:])[0]
                print(f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}:{port}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
