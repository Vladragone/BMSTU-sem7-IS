from faker import Faker
import random
import string

faker_ru = Faker("ru_RU")
faker_en = Faker("en_US")

# -------------------------------------------------------
# Генерация слов длиной 4+ (faker иногда даёт короткие)
# -------------------------------------------------------
def generate_words(faker_obj, count):
    words = []
    while len(words) < count:
        w = faker_obj.word()
        w = ''.join(ch for ch in w if ch.isalpha())  # убираем цифры/символы
        if len(w) >= 4:
            words.append(w.upper())
    return words

# -------------------------------------------------------
# Генерация случайного ключа
# -------------------------------------------------------
def generate_key(faker_obj, length):
    key = ""
    while len(key) < length:
        w = faker_obj.word().upper()
        w = ''.join(ch for ch in w if ch.isalpha())
        key += w
    return key[:length]


# -------------------------------------------------------
# Генерация случайной криптограммы
# -------------------------------------------------------
def generate_random_cipher(alphabet, length):
    return ''.join(random.choice(alphabet) for _ in range(length))


# -------------------------------------------------------
# Создаём ВСЕ файлы
# -------------------------------------------------------
def main():

    WORDS_COUNT = 25000

    print("Генерация файлов...")

    # ----------------------
    #  input_ru.txt
    # ----------------------
    words_ru = generate_words(faker_ru, WORDS_COUNT)
    text_ru = ''.join(words_ru)        # без пробелов
    with open("input_ru.txt", "w", encoding="utf-8") as f:
        f.write(text_ru)

    # ----------------------
    # key_ru_short.txt (4-5 символов)
    # ----------------------
    key_ru_short = generate_key(faker_ru, random.randint(4, 5))
    with open("key_ru_short.txt", "w", encoding="utf-8") as f:
        f.write(key_ru_short)

    # ----------------------
    # key_ru_long.txt (15+ символов)
    # ----------------------
    key_ru_long = generate_key(faker_ru, random.randint(15, 20))
    with open("key_ru_long.txt", "w", encoding="utf-8") as f:
        f.write(key_ru_long)

    # ----------------------
    # input_en.txt
    # ----------------------
    words_en = generate_words(faker_en, WORDS_COUNT)
    text_en = ''.join(words_en)
    with open("input_en.txt", "w", encoding="utf-8") as f:
        f.write(text_en)

    # ----------------------
    # key_en.txt
    # ----------------------
    key_en = generate_key(faker_en, random.randint(5, 8))
    with open("key_en.txt", "w", encoding="utf-8") as f:
        f.write(key_en)

    # ----------------------
    # cipher_teacher.txt (случайная криптограмма)
    # длиной как русский текст
    # ----------------------
    RUS_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    cipher = generate_random_cipher(RUS_ALPHABET, len(text_ru))
    with open("cipher_teacher.txt", "w", encoding="utf-8") as f:
        f.write(cipher)

    print("Готово! Созданы файлы:")
    print("- input_ru.txt")
    print("- key_ru_short.txt")
    print("- key_ru_long.txt")
    print("- input_en.txt")
    print("- key_en.txt")
    print("- cipher_teacher.txt")


if __name__ == "__main__":
    main()
