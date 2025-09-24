from Crypto.Cipher import DES
import os

def pad(data: bytes) -> bytes:
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_file(input_file: str, output_file: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file, "rb") as f:
        plaintext = f.read()

    padded_data = pad(plaintext)
    ciphertext = cipher.encrypt(padded_data)

    with open(output_file, "wb") as f:
        f.write(ciphertext)

def decrypt_file(input_file: str, output_file: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file, "rb") as f:
        ciphertext = f.read()

    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data)

    with open(output_file, "wb") as f:
        f.write(unpadded_data)


if __name__ == "__main__":
    key = b"8bytekey"

    encrypt_file("input.zip", "encrypted.bin", key)
    decrypt_file("encrypted.bin", "output.zip", key)

    print("Шифрование и расшифровка завершены.")
