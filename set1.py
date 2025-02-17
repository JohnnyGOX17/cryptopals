#!/usr/bin/env python3

import math
import base64
from urllib.request import urlopen
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hexstr_to_base64_str(x: str) -> str:
    """Convert hex string (w/o leading 0x) to base64 string"""
    byte_data = bytes.fromhex(x)
    base64_bytes = base64.b64encode(byte_data)
    return base64_bytes.decode("ascii")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences together"""
    if len(a) != len(b):
        raise ValueError("Inputs must be of same length!")
    return bytes(a_i ^ b_i for a_i, b_i in zip(a, b))


def xor_strs(a: str, b: str) -> str:
    """Take two equal-length hex strings and produce XOR of them"""
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    return xor_bytes(a_bytes, b_bytes).hex()


def char_frequency(c: str) -> float:
    """Returns the relative frequency of the given character, inclusive of space
    to do frequency analysis of a string.

    Source: https://en.wikipedia.org/wiki/Letter_frequency"""
    if len(c) != 1:
        raise ValueError("Only works on one character at a time")

    match c.lower():
        case "a":
            return 0.082
        case "b":
            return 0.015
        case "c":
            return 0.028
        case "d":
            return 0.043
        case "e":
            return 0.127
        case "f":
            return 0.022
        case "g":
            return 0.02
        case "h":
            return 0.061
        case "i":
            return 0.07
        case "j":
            return 0.0015
        case "k":
            return 0.0077
        case "l":
            return 0.04
        case "m":
            return 0.024
        case "n":
            return 0.067
        case "o":
            return 0.075
        case "p":
            return 0.019
        case "q":
            return 0.00095
        case "r":
            return 0.06
        case "s":
            return 0.063
        case "t":
            return 0.091
        case "u":
            return 0.028
        case "v":
            return 0.0098
        case "w":
            return 0.024
        case "x":
            return 0.0015
        case "y":
            return 0.02
        case "z":
            return 0.00074
        case " ":
            # In English, the space character occurs almost twice as frequently as the top letter (e)
            return 0.254
        case _:
            return 0.0


def find_xor_and_decrypt(x: bytes):
    """Given bytes that have been XOR'd against a single character/byte, find
    the key and decrypt the message"""
    top_score = 0.0
    top_char = 0
    top_str = ""

    # only go to range of regular ASCII https://www.asciitable.com/
    for i in range(128):
        try:
            xored_str = bytes(a_char ^ i for a_char in x).decode("ascii")
        except UnicodeDecodeError:
            xored_str = ""

        curr_score = 0.0
        for ch in xored_str:
            curr_score += char_frequency(ch)
        if curr_score > top_score:
            top_score = curr_score
            top_char = i
            top_str = xored_str

    return chr(top_char), top_str, top_score


def hamming_distance(a: bytes, b: bytes) -> int:
    """Calculate the Hamming Distance of two equal-length byte sequences"""
    if len(a) != len(b):
        raise ValueError("Inputs must be of same length!")

    dist = 0
    # Hamming distance is the number of differing bits- so XOR each byte to set
    # bit positions where they differ, then count the number of ones (popcount)
    for b1, b2 in zip(a, b):
        dist += bin(b1 ^ b2).count("1")
    return dist


def test_ch1():
    """Challenge 1- Convert hex to base64"""
    assert (
        hexstr_to_base64_str(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
        == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )


def test_ch2():
    """Challenge 2- Fixed XOR"""
    assert (
        xor_strs(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        )
        == "746865206b696420646f6e277420706c6179"
    )


def test_ch3():
    """Challenge 3- single-byte XOR cipher"""
    top_char, top_str, _ = find_xor_and_decrypt(
        bytes.fromhex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        )
    )
    assert top_char == "X"
    assert top_str == "Cooking MC's like a pound of bacon"


def test_ch4():
    """Challenge 4- Detect single-character XOR"""
    # Use example text file from online

    top_score = 0.0
    top_str = ""
    for line in urlopen("https://cryptopals.com/static/challenge-data/4.txt"):
        input_str = line.decode("ascii").replace("\n", "")
        _, curr_str, curr_score = find_xor_and_decrypt(bytes.fromhex(input_str))
        if curr_score > top_score:
            top_score = curr_score
            top_str = curr_str
    assert top_str == "Now that the party is jumping\n"


def test_ch5():
    """Challenge 5- implement repeating-key XOR"""
    input_str = (
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    input_key = "ICE"

    # repeat key to same length as input to XOR together
    key_mult = math.ceil(len(input_str) / len(input_key))
    xor_key = (input_key * key_mult)[: len(input_str)]
    key_repeat_out_str = xor_bytes(input_str.encode("ascii"), xor_key.encode("ascii"))

    assert (
        key_repeat_out_str.hex()
        == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )


def test_ch6():
    """Challenge 6- break repeating-key XOR"""
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37

    with urlopen("https://cryptopals.com/static/challenge-data/6.txt") as resp:
        input_bytes = base64.b64decode(resp.read().decode("ascii"))

    smallest_dist = 10000.0  # arb big
    prob_keysize = 0

    # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE
    # worth of bytes, and find the edit distance between them. Normalize this result
    # by dividing by KEYSIZE.
    for keysize in range(2, 41):
        idx = 0
        curr_hamming_dist = 0
        cycle_count = 0

        while idx + 2 * keysize < len(input_bytes):
            tmp_a = input_bytes[idx : idx + keysize]
            idx += keysize
            tmp_b = input_bytes[idx : idx + keysize]
            idx += keysize

            curr_hamming_dist += hamming_distance(tmp_a, tmp_b)
            cycle_count += 1

        # normalize hamming distance based on key length and the number of
        # cycles/measurements taken of hamming distance tests
        curr_hamming_dist /= keysize * cycle_count

        # The KEYSIZE with the smallest normalized edit distance is probably the key.
        if curr_hamming_dist < smallest_dist:
            smallest_dist = curr_hamming_dist
            prob_keysize = keysize

    assert prob_keysize == 29

    # Now transpose the blocks: make a block that is the first byte of every block,
    # and a block that is the second byte of every block, and so on. Solve each
    # block as if it was single-character XOR (which we already have from previous)
    prob_key = ""
    for i in range(prob_keysize):
        block = input_bytes[i::prob_keysize]
        key_char, _, _ = find_xor_and_decrypt(block)
        prob_key += key_char
    assert prob_key == "Terminator X: Bring the noise"

    # Finally
    # repeat key to same length as input to XOR together and get plaintext
    # from input ciphertext
    xor_key = prob_key.encode("ascii")
    key_mult = math.ceil(len(input_bytes) / len(xor_key))
    xor_key = (xor_key * key_mult)[: len(input_bytes)]
    output_bytes = xor_bytes(input_bytes, xor_key)
    # print(f"/// XOR Key: {prob_key}\n")
    # print("/// Plaintext:")
    # print(output_bytes.decode("ascii"))


def test_ch7():
    """Challenge 7- decode a file, encrypted w/AES-128 in ECB mode with a given key"""
    # Given 128b key
    aes_key = "YELLOW SUBMARINE"
    with urlopen("https://cryptopals.com/static/challenge-data/7.txt") as resp:
        ct = base64.b64decode(resp.read().decode("ascii"))

    # Create an AES-128 cipher class in ECB mode
    # This is rightfully in the "Insecure" mode of ciphers as each block of data
    # is encrypted in the exact same way, leaving patterns in the output:
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
    cipher = Cipher(algorithms.AES128(aes_key.encode("ascii")), modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    # print(pt.decode("ascii"))


def test_ch8():
    """Challenge 8- Detect AES in ECB mode
    In the file are a bunch of hex-encoded ciphertexts. One of them has been encrypted
    with ECB. Detect it. Remember that the problem with ECB is that it is stateless
    and deterministic; the same 16 byte plaintext block will always produce the same
    16 byte ciphertext.
    """

    cipher_len = 16
    line_idx = 0
    line_num = 0
    for line in urlopen("https://cryptopals.com/static/challenge-data/8.txt"):
        input_str = line.decode("ascii").replace("\n", "")
        # use dictionary/hashmap to see when a repeat block is found
        block_dict = {}
        for i in range(len(input_str) // cipher_len):
            curr_block = input_str[i * cipher_len : (i + 1) * cipher_len]
            if curr_block in block_dict:
                line_num = line_idx
            else:
                block_dict[curr_block] = 1
        line_idx += 1
    assert line_num == 132


if __name__ == "__main__":
    test_ch1()
    test_ch2()
    test_ch3()
    test_ch4()
    test_ch5()
    test_ch6()
    test_ch7()
    test_ch8()
