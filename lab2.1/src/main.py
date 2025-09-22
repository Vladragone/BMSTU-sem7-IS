from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def generate_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)

def encrypt_file(input_file, output_file, public_key_file):
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(public_key)

    with open(input_file, "rb") as f:
        data = f.read()

    block_size = public_key.size_in_bytes() - 42
    encrypted = b""
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted += cipher.encrypt(block)

    with open(output_file, "wb") as f:
        f.write(encrypted)

def decrypt_file(input_file, output_file, private_key_file):
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)

    with open(input_file, "rb") as f:
        encrypted = f.read()

    block_size = private_key.size_in_bytes()
    decrypted = b""
    for i in range(0, len(encrypted), block_size):
        block = encrypted[i:i + block_size]
        decrypted += cipher.decrypt(block)

    with open(output_file, "wb") as f:
        f.write(decrypted)


if __name__ == "__main__":
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        generate_keys()

    encrypt_file("input.zip", "encrypted.bin", "public.pem")
    decrypt_file("encrypted.bin", "output.zip", "private.pem")

    print("Шифрование и дешифровка завершены.")
