from rotor import Rotor
from reflector import Reflector
from plugboard import Plugboard

ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

ROTOR_WIRINGS = {
    "1": ("БВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА", "Я"),
    "2": ("ВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯАБ", "Ю"),
    "3": ("ГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯАБВ", "Э"),
    "4": ("ДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯАБВГ", "Ы"),
    "5": ("ЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯАБВГД", "Ш"),
}

def read_settings(filename):
    with open(filename, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    rotor_types = lines[0].split()
    positions = [int(x) for x in lines[1].split()]
    ring_settings = [int(x) for x in lines[2].split()]
    plug_idx = next(i for i, line in enumerate(lines) if line.startswith("Plugboard"))
    reflector_idx = next(i for i, line in enumerate(lines) if line.startswith("Reflector"))
    plugboard_pairs = lines[plug_idx+1:reflector_idx]
    reflector_pairs = lines[reflector_idx+1:]
    return rotor_types, positions, ring_settings, plugboard_pairs, reflector_pairs

def build_machine(rotor_types, positions, ring_settings, plugboard_pairs, reflector_pairs):
    rotors = []
    for i, rtype in enumerate(rotor_types):
        wiring, notch = ROTOR_WIRINGS[rtype]
        rotors.append(Rotor(wiring, notch, ring_setting=ring_settings[i], position=positions[i]))
    plugboard = Plugboard(plugboard_pairs)
    reflector = Reflector(reflector_pairs)
    return rotors, plugboard, reflector

def step_rotors(rotors):
    right, middle, left = rotors
    middle_on_notch = ALPHABET[middle.position] == middle.notch
    right.step()
    if ALPHABET[right.position] == right.notch or middle_on_notch:
        middle.step()
        if ALPHABET[middle.position] == middle.notch:
            left.step()

def encode_message(message, rotors, plugboard, reflector):
    result = ""
    for letter in message.upper():
        if letter not in ALPHABET:
            result += letter
            continue
        step_rotors(rotors)
        c = plugboard.encode(letter)
        for rotor in reversed(rotors):
            c = rotor.encode_forward(c)
        c = reflector.reflect(c)
        for rotor in rotors:
            c = rotor.encode_backward(c)
        c = plugboard.encode(c)
        result += c
    return result

if __name__ == "__main__":
    rotor_types, positions, ring_settings, plugboard_pairs, reflector_pairs = read_settings("settings.txt")
    rotors, plugboard, reflector = build_machine(rotor_types, positions, ring_settings, plugboard_pairs, reflector_pairs)
    with open("message.txt", "r", encoding="utf-8") as f:
        message = f.read()
    result = encode_message(message, rotors, plugboard, reflector)
    with open("result.txt", "w", encoding="utf-8") as f:
        f.write(result)
    print("Сообщение зашифровано.")
