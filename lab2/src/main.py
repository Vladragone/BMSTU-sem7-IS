from rotor import Rotor
from reflector import Reflector
from plugboard import Plugboard
import random

def read_settings(filename):
    with open(filename, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    rotor_types = lines[0].split()
    positions = [int(x) for x in lines[1].split()]
    ring_settings = [int(x) for x in lines[2].split()]

    plug_idx = next(i for i, line in enumerate(lines) if line.startswith("Plugboard"))
    refl_idx = next(i for i, line in enumerate(lines) if line.startswith("Reflector"))

    plug_pairs = [tuple(map(int, line.split())) for line in lines[plug_idx+1:refl_idx]]
    refl_pairs = [tuple(map(int, line.split())) for line in lines[refl_idx+1:]]

    return rotor_types, positions, ring_settings, plug_pairs, refl_pairs

def build_rotor(rotor_type, ring_setting, position):
    rng = random.Random(int(rotor_type))
    wiring = list(range(256))
    rng.shuffle(wiring)
    notch = rng.randint(0, 255)
    return Rotor(wiring, notch, ring_setting, position)

def build_machine(rotor_types, positions, ring_settings, plug_pairs, refl_pairs):
    rotors = [build_rotor(rtype, ring_settings[i], positions[i]) for i, rtype in enumerate(rotor_types)]
    plugboard = Plugboard(plug_pairs)
    reflector = Reflector(refl_pairs)
    return rotors, plugboard, reflector

def step_rotors(rotors):
    right, middle, left = rotors
    middle_on_notch = middle.position == middle.notch
    right.step()
    if right.position == right.notch or middle_on_notch:
        middle.step()
        if middle.position == middle.notch:
            left.step()

def encode_message(data: bytes, rotors, plugboard, reflector) -> bytes:
    out = bytearray()
    for byte in data:
        step_rotors(rotors)
        c = plugboard.encode(byte)
        for rotor in reversed(rotors):
            c = rotor.encode_forward(c)
        c = reflector.reflect(c)
        for rotor in rotors:
            c = rotor.encode_backward(c)
        c = plugboard.encode(c)
        out.append(c)
    return bytes(out)

if __name__ == "__main__":
    rotor_types, positions, ring_settings, plug_pairs, refl_pairs = read_settings("settings.txt")
    rotors, plugboard, reflector = build_machine(rotor_types, positions, ring_settings, plug_pairs, refl_pairs)

    with open("archive.rar", "rb") as f:
        data = f.read()

    result = encode_message(data, rotors, plugboard, reflector)

    with open("archive.rar", "wb") as f:
        f.write(result)

    print("Файл зашифрован.")
