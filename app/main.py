import json
import sys
import re
# import bencodepy - available if you need it!
# import requests - available if you need it!

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
        return int(bencoded_value[start+1:end]), end + 1
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
    array =[]
    cursor =1
    while(chr(bencoded_value[cursor])!= "e"):
        decoded, chars = decode_bencode(bencoded_value[cursor:])
        if (isinstance(decoded, bytes)):
            array.append(decoded.decode('utf-8'))
        else:
            array.append(decoded)
        cursor+=chars
    chars = cursor+1
    p1=0
    p2=1
    while p2 < len(array):
        res[array[p1]]=array[p2]
        p1+=2
        p2+=2
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
        with open(filepath, 'rb') as file:
            decoded_data, _ = decode_bencode(file.read())
            print(decoded_data)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
