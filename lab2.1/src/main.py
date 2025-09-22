from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

def load_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def encrypt_file(input_filename, output_filename, public_key_file="public.pem"):
    public_key = load_key(public_key_file)
    cipher = PKCS1_OAEP.new(public_key)

    with open(input_filename, "rb") as f:
        data = f.read()

    encrypted_data = b""
    chunk_size = 190
    for i in range(0, len(data), chunk_size):
        encrypted_data += cipher.encrypt(data[i:i+chunk_size])

    with open(output_filename, "wb") as f:
        f.write(encrypted_data)

    print(f"Файл {input_filename} зашифрован в {output_filename}")

def decrypt_file(input_filename, output_filename, private_key_file="private.pem"):
    private_key = load_key(private_key_file)
    cipher = PKCS1_OAEP.new(private_key)

    with open(input_filename, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = b""
    chunk_size = 256
    for i in range(0, len(encrypted_data), chunk_size):
        decrypted_data += cipher.decrypt(encrypted_data[i:i+chunk_size])

    with open(output_filename, "wb") as f:
        f.write(decrypted_data)

    print(f"Файл {input_filename} расшифрован в {output_filename}")


if __name__ == "__main__":
    generate_keys() 
    encrypt_file("input.txt", "encrypted.bin")
    decrypt_file("encrypted.bin", "decrypted.txt")
