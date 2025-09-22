ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

class Rotor:
    def __init__(self, wiring, notch, ring_setting=0, position=0):
        self.wiring = wiring
        self.notch = notch
        self.ring_setting = ring_setting
        self.position = position

    def step(self):
        self.position = (self.position + 1) % len(ALPHABET)
        return self.position == ALPHABET.index(self.notch)

    def encode_forward(self, c):
        idx = ALPHABET.index(c)
        shifted_idx = (idx + self.position - self.ring_setting) % len(ALPHABET)
        encoded_char = self.wiring[shifted_idx]
        out_idx = (ALPHABET.index(encoded_char) - self.position + self.ring_setting) % len(ALPHABET)
        return ALPHABET[out_idx]

    def encode_backward(self, c):
        idx = ALPHABET.index(c)
        shifted_idx = (idx + self.position - self.ring_setting) % len(ALPHABET)
        encoded_idx = self.wiring.index(ALPHABET[shifted_idx])
        out_idx = (encoded_idx - self.position + self.ring_setting) % len(ALPHABET)
        return ALPHABET[out_idx]
