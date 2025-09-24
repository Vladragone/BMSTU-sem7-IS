from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)

def sign_file(input_file, signature_file, private_key_file):
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())

    with open(input_file, "rb") as f:
        data = f.read()

    h = SHA256.new(data)

    signature = pkcs1_15.new(private_key).sign(h)

    with open(signature_file, "wb") as f:
        f.write(signature)

def verify_signature(input_file, signature_file, public_key_file):
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())

    with open(input_file, "rb") as f:
        data = f.read()

    with open(signature_file, "rb") as f:
        signature = f.read()

    h = SHA256.new(data)

    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("Подпись корректна")
        return True
    except (ValueError, TypeError):
        print("Подпись недействительна")
        return False


if __name__ == "__main__":
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        generate_keys()
    sign_file("input_eng.txt", "signature_eng.bin", "private.pem")
    verify_signature("input_eng.txt", "signature_rus.bin", "public.pem")
