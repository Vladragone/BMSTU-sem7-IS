from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data: bytes) -> bytes:
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_file(input_file: str, output_file: str, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, "rb") as f:
        plaintext = f.read()

    padded_data = pad(plaintext)
    ciphertext = cipher.encrypt(padded_data)

    with open(output_file, "wb") as f:
        f.write(cipher.iv + ciphertext)

def decrypt_file(input_file: str, output_file: str, key: bytes):
    with open(input_file, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data)

    with open(output_file, "wb") as f:
        f.write(unpadded_data)


if __name__ == "__main__":
    key = b"thisisasecretkey"

    encrypt_file("input.rar", "encrypted.bin", key)
    decrypt_file("encrypted.bin", "output.rar", key)

    print("Шифрование и расшифровка завершены.")
