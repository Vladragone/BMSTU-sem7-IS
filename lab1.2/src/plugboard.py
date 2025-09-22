class Plugboard:
    def __init__(self, pairs=None):
        self.mapping = {i: i for i in range(256)}
        if pairs:
            for a, b in pairs:
                self.mapping[a] = b
                self.mapping[b] = a

    def encode(self, c: int) -> int:
        return self.mapping.get(c, c)
