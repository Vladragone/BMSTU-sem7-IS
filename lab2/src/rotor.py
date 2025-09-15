ALPHABET = list(range(256))

class Rotor:
    def __init__(self, wiring, notch, ring_setting=0, position=0):
        self.wiring = wiring
        self.notch = notch
        self.ring_setting = ring_setting
        self.position = position

    def step(self):
        self.position = (self.position + 1) % 256
        return self.position == self.notch

    def encode_forward(self, c: int) -> int:
        idx = (c + self.position - self.ring_setting) % 256
        encoded = self.wiring[idx]
        out = (encoded - self.position + self.ring_setting) % 256
        return out

    def encode_backward(self, c: int) -> int:
        idx = (c + self.position - self.ring_setting) % 256
        encoded_idx = self.wiring.index(idx)
        out = (encoded_idx - self.position + self.ring_setting) % 256
        return out
