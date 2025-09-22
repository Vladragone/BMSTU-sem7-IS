from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import os

def pad(data: bytes) -> bytes:
    while len(data) % 8 != 0:
        data += b' '
    return data

def encrypt_file(input_file: str, output_file: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padded_data = pad(plaintext)
    ciphertext = cipher.encrypt(padded_data)

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(input_file: str, output_file: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    decrypted_data = cipher.decrypt(ciphertext)
    decrypted_data = decrypted_data.rstrip(b' ')

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)


if __name__ == "__main__":
    key = b'8bytekey'

    encrypt_file("input_rus.txt", "enc_rus.bin", key)
    decrypt_file("enc_rus.bin", "dec_rus.txt", key)

    encrypt_file("input_eng.txt", "enc_eng.bin", key)
    decrypt_file("enc_eng.bin", "dec_eng.txt", key)

    print("Шифрование и дешифрование завершено.")
