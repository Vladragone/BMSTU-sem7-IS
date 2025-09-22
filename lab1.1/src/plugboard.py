ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

class Plugboard:
    def __init__(self, pairs=None):
        self.mapping = {}
        for ch in ALPHABET:
            self.mapping[ch] = ch
        if pairs:
            for pair in pairs:
                if len(pair) == 2:
                    a, b = pair[0].upper(), pair[1].upper()
                    if a in ALPHABET and b in ALPHABET:
                        self.mapping[a] = b
                        self.mapping[b] = a

    def encode(self, c):
        return self.mapping.get(c.upper(), c)
