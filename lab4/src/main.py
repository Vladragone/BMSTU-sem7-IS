import math
from collections import Counter, defaultdict
from functools import reduce
import os

def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

RUS_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

ENG_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def get_alphabet(lang: str) -> str:
    lang = lang.lower()
    if lang.startswith("ru"):
        return RUS_ALPHABET
    elif lang.startswith("en"):
        return ENG_ALPHABET
    else:
        raise ValueError(f"Неизвестный язык: {lang}")


def normalize_text(text: str, lang: str) -> str:
    alphabet = get_alphabet(lang)
    text = text.upper()
    return "".join(ch for ch in text if ch in alphabet)


def build_char_maps(alphabet: str):
    char_to_idx = {ch: i for i, ch in enumerate(alphabet)}
    idx_to_char = {i: ch for i, ch in enumerate(alphabet)}
    return char_to_idx, idx_to_char


def vigenere_encrypt(text: str, key: str, lang: str = "ru") -> str:
    alphabet = get_alphabet(lang)
    char_to_idx, idx_to_char = build_char_maps(alphabet)

    text = text.upper()
    key = key.upper()

    res = []
    key_len = len(key)
    key_pos = 0

    for ch in text:
        if ch in char_to_idx:
            t_idx = char_to_idx[ch]
            k_ch = key[key_pos % key_len]
            k_idx = char_to_idx[k_ch]
            c_idx = (t_idx + k_idx) % len(alphabet)
            res.append(idx_to_char[c_idx])
            key_pos += 1
        else:
            res.append(ch)
    return "".join(res)


def vigenere_decrypt(cipher: str, key: str, lang: str = "ru") -> str:
    alphabet = get_alphabet(lang)
    char_to_idx, idx_to_char = build_char_maps(alphabet)

    cipher = cipher.upper()
    key = key.upper()

    res = []
    key_len = len(key)
    key_pos = 0

    for ch in cipher:
        if ch in char_to_idx:
            c_idx = char_to_idx[ch]
            k_ch = key[key_pos % key_len]
            k_idx = char_to_idx[k_ch]
            t_idx = (c_idx - k_idx) % len(alphabet)
            res.append(idx_to_char[t_idx])
            key_pos += 1
        else:
            res.append(ch)
    return "".join(res)


def letter_frequencies(text: str, alphabet: str) -> dict:
    counts = Counter(ch for ch in text if ch in alphabet)
    total = sum(counts.values())
    if total == 0:
        return {ch: 0.0 for ch in alphabet}
    return {ch: counts.get(ch, 0) / total for ch in alphabet}


def index_of_coincidence(text: str, alphabet: str) -> float:
    counts = Counter(ch for ch in text if ch in alphabet)
    N = sum(counts.values())
    if N <= 1:
        return 0.0
    num = sum(f * (f - 1) for f in counts.values())
    den = N * (N - 1)
    return num / den


def find_repeated_sequences(cipher: str,
                            seq_len_min: int = 3,
                            seq_len_max: int = 5):
    repeats = defaultdict(list)
    L = len(cipher)
    for n in range(seq_len_min, seq_len_max + 1):
        for i in range(L - n + 1):
            seq = cipher[i:i + n]
            repeats[seq].append(i)

    repeats = {seq: pos for seq, pos in repeats.items() if len(pos) > 1}
    return repeats


def kasiski_examination(cipher: str,
                        seq_len_min: int = 3,
                        seq_len_max: int = 5,
                        max_key_len: int = 32):

    repeats = find_repeated_sequences(cipher, seq_len_min, seq_len_max)
    distances = []

    for positions in repeats.values():
        for i in range(len(positions) - 1):
            d = positions[i + 1] - positions[i]
            if d > 0:
                distances.append(d)

    factor_counts = Counter()
    for d in distances:
        for f in range(2, max_key_len + 1):
            if d % f == 0:
                factor_counts[f] += 1

    gcd_all = reduce(math.gcd, distances) if distances else None

    return {
        "repeats": repeats,
        "distances": distances,
        "factor_counts": factor_counts,
        "gcd_all": gcd_all,
    }

RUS_FREQ_RAW = {
    "О": 0.1097, "Е": 0.0845, "А": 0.0801, "И": 0.0735, "Н": 0.0670,
    "Т": 0.0626, "С": 0.0547, "Р": 0.0473, "В": 0.0454, "Л": 0.0440,
    "К": 0.0349, "М": 0.0321, "Д": 0.0298, "П": 0.0281, "У": 0.0262,
    "Я": 0.0201, "Ы": 0.0190, "Ь": 0.0174, "Г": 0.0170, "З": 0.0165,
    "Б": 0.0159, "Ч": 0.0144, "Й": 0.0121, "Х": 0.0097, "Ж": 0.0094,
    "Ш": 0.0073, "Ю": 0.0064, "Ц": 0.0048, "Щ": 0.0036, "Э": 0.0032,
    "Ф": 0.0026, "Ъ": 0.0004,
    "Ё": 0.0004,
}

ENG_FREQ_RAW = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074,
}


def get_language_freqs(lang: str, alphabet: str) -> list:
    lang = lang.lower()
    if lang.startswith("ru"):
        raw = RUS_FREQ_RAW
    elif lang.startswith("en"):
        raw = ENG_FREQ_RAW
    else:
        raise ValueError(f"Неизвестный язык: {lang}")

    temp = dict(raw)

    for ch in alphabet:
        if ch not in temp:
            temp[ch] = 0.0001

    total = sum(temp[ch] for ch in alphabet)
    return [temp[ch] / total for ch in alphabet]


def chi_square_stat(observed_counts, expected_freqs, N: int) -> float:
    chi2 = 0.0
    for o, p in zip(observed_counts, expected_freqs):
        e = N * p
        if e > 0:
            chi2 += (o - e) ** 2 / e
    return chi2


def best_caesar_shift(text: str, alphabet: str, lang: str) -> int:
    m = len(alphabet)
    char_to_idx, _ = build_char_maps(alphabet)
    expected = get_language_freqs(lang, alphabet)

    filtered = [ch for ch in text if ch in char_to_idx]
    N = len(filtered)
    if N == 0:
        return 0

    idxs = [char_to_idx[ch] for ch in filtered]

    best_shift = 0
    best_score = float("inf")

    for shift in range(m):
        counts = [0] * m
        for c in idxs:
            p = (c - shift) % m
            counts[p] += 1

        chi2 = chi_square_stat(counts, expected, N)
        if chi2 < best_score:
            best_score = chi2
            best_shift = shift

    return best_shift


def key_length_candidates_by_ic(cipher: str,
                                lang: str,
                                max_len: int = 20):
    alphabet = get_alphabet(lang)
    cipher = cipher.upper()
    results = []

    for L in range(1, max_len + 1):
        ics = []
        for offset in range(L):
            group = cipher[offset::L]
            ic = index_of_coincidence(group, alphabet)
            ics.append(ic)
        avg_ic = sum(ics) / len(ics)
        results.append((L, avg_ic))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def break_vigenere(cipher: str,
                   lang: str = "ru",
                   max_key_len: int = 20,
                   seq_len_min: int = 3,
                   seq_len_max: int = 5):
    cipher = cipher.upper()
    alphabet = get_alphabet(lang)

    kasiski_result = kasiski_examination(cipher, seq_len_min, seq_len_max, max_key_len)
    factor_counts = kasiski_result["factor_counts"]

    kasiski_lengths = [L for L, _cnt in factor_counts.most_common()]

    ic_candidates = key_length_candidates_by_ic(cipher, lang, max_key_len)

    candidates = []
    for L in kasiski_lengths:
        if L not in candidates and L <= max_key_len:
            candidates.append(L)
    for L, _ic in ic_candidates:
        if L not in candidates and L <= max_key_len:
            candidates.append(L)

    best_overall_score = float("inf")
    best_key = None
    best_plain = None
    best_L = None

    for L in candidates:
        shifts = []
        for offset in range(L):
            group = "".join(cipher[i] for i in range(offset, len(cipher), L)
                            if cipher[i] in alphabet)
            shift = best_caesar_shift(group, alphabet, lang)
            shifts.append(shift)

        key = "".join(alphabet[s] for s in shifts)
        plain = vigenere_decrypt(cipher, key, lang)

        char_to_idx, _ = build_char_maps(alphabet)
        counts = [0] * len(alphabet)
        filtered = [ch for ch in plain if ch in char_to_idx]
        for ch in filtered:
            counts[char_to_idx[ch]] += 1
        N = len(filtered)
        expected = get_language_freqs(lang, alphabet)
        score = chi_square_stat(counts, expected, N) if N > 0 else float("inf")

        if score < best_overall_score:
            best_overall_score = score
            best_key = key
            best_plain = plain
            best_L = L

    return {
        "kasiski": kasiski_result,
        "ic_candidates": ic_candidates,
        "tried_lengths": candidates,
        "best_key_length": best_L,
        "best_key": best_key,
        "best_plaintext": best_plain,
        "best_score": best_overall_score,
    }


if __name__ == "__main__":
    print("===============================================")
    print("                ЛАБОРАТОРНАЯ РАБОТА")
    print("   Криптоанализ полиалфавитных шифров Виженера")
    print("===============================================\n\n")

    # -------------------------------------------------------------
    #                     ЗАДАНИЕ 1
    # -------------------------------------------------------------
    print("===============================================")
    print("                    ЗАДАНИЕ 1")
    print("     Шифрование, расшифрование, статистика")
    print("===============================================\n")

    # ---- читаем данные ----
    txt_ru = read_file("input_ru.txt")
    key_ru_short = read_file("key_ru_short.txt").strip()
    key_ru_long = read_file("key_ru_long.txt").strip()

    norm_txt_ru = normalize_text(txt_ru, "ru")

    cipher_short = vigenere_encrypt(norm_txt_ru, key_ru_short, "ru")
    cipher_long = vigenere_encrypt(norm_txt_ru, key_ru_long, "ru")

    plain_short = vigenere_decrypt(cipher_short, key_ru_short, "ru")
    plain_long = vigenere_decrypt(cipher_long, key_ru_long, "ru")

    print("========== Русский текст ==========\n")
    print("Оригинал (фрагмент):")
    print(norm_txt_ru[:200] + "...\n")

    print("----- Короткий ключ -----")
    print("Ключ:", key_ru_short)
    print("Шифртекст:", cipher_short[:200] + "...")
    print("Расшифровка:", plain_short[:200] + "...\n")

    print("----- Длинный ключ -----")
    print("Ключ:", key_ru_long)
    print("Шифртекст:", cipher_long[:200] + "...")
    print("Расшифровка:", plain_long[:200] + "...\n")

    print("----- Индексы совпадений -----")
    print("IC исходного текста:", index_of_coincidence(norm_txt_ru, RUS_ALPHABET))
    print("IC шифртекста (короткий ключ):", index_of_coincidence(cipher_short, RUS_ALPHABET))
    print("IC шифртекста (длинный ключ):", index_of_coincidence(cipher_long, RUS_ALPHABET))
    print("\n===============================================\n\n")

    # -------------------------------------------------------------
    #                     ЗАДАНИЕ 2
    # -------------------------------------------------------------
    print("===============================================")
    print("                    ЗАДАНИЕ 2")
    print("      Метод Казиски + Индекс совпадений")
    print("===============================================\n")

    cipher_from_teacher = read_file("cipher_teacher.txt").strip()
    cipher_from_teacher = normalize_text(cipher_from_teacher, "ru")

    print("Длина криптограммы:", len(cipher_from_teacher), "символов")

    kasiski_res = kasiski_examination(cipher_from_teacher, 3, 6, 30)

    print("\n----- Повторяющиеся последовательности -----")
    for seq, pos in list(kasiski_res["repeats"].items())[:10]:
        print(f"{seq} → позиции {pos}")

    print("\n----- Расстояния -----")
    print(kasiski_res["distances"][:20], "...")

    print("\n----- Частоты делителей (кандидаты длин ключа) -----")
    print(kasiski_res["factor_counts"].most_common(10))

    print("\nНОД всех расстояний:", kasiski_res["gcd_all"])

    print("\n----- Топ-10 кандидатов по индексу совпадений -----")
    ic_cands = key_length_candidates_by_ic(cipher_from_teacher, "ru", 20)
    for L, ic in ic_cands[:10]:
        print(f"L={L}, IC={ic}")

    print("\n===============================================\n\n")

    # -------------------------------------------------------------
    #                     ЗАДАНИЕ 3
    # -------------------------------------------------------------
    print("===============================================")
    print("                    ЗАДАНИЕ 3")
    print("         Полный автоматический взлом")
    print("===============================================\n")

    result = break_vigenere(cipher_from_teacher, lang="ru", max_key_len=25)

    print("========== Результаты взлома ==========\n")

    print("Использованные длины ключа:", result["tried_lengths"])
    print("Лучшая длина ключа:", result["best_key_length"])
    print("Найденный ключ:", result["best_key"])
    print("χ² оценка:", result["best_score"])

    print("\n----- Расшифрованный текст (фрагмент) -----\n")
    print(result["best_plaintext"][:500] + "...\n")

    print("===============================================")
    print("             ЛАБОРАТОРНАЯ ЗАВЕРШЕНА")
    print("===============================================")