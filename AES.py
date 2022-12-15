from AES_consts import *


def sub_bytes(s: list[list]):
    """
    Выполнение замены байтов по таблице s так называемый S_BOX
    каждый байт последовательности заменяется на соответствующий ему в данной таблице
    :param s: Последовательность байтов для перестановки
    :return: Переставленная последовательность байтов
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s: list[list]):
    """
    Выполнение обратной замены байтов по таблице s так называемый INV_S_BOX
    каждый байт последовательности заменяется на соответствующий ему в данной таблице
    данная таблица обратна предыдущей и выполняет обратное преобразование
    :param s: Последовательность байтов для обратной перестановки
    :return: Исходная последовательность байтов до перестановки
    """
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s: list[list]):
    """
    Функция для смещения строк в матрице
    :param s: Матрица
    :return: Матрица со смещенными строками
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    """
    Функция для смещения строк в матрице в обратном направлении
    :param s: Матрица со смещенными строками
    :return: Матрица с восстановленными строками
    """
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    """
    Процедура для произведения операции исключающего или между матрицами
    :param s: Матрица для изменения
    :param k: Матрица с которой складываем
    :return:
    """
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


"""
Лямбда функция для вычисления нужной операции в поле галуа
"""
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    """
    Процедура для перемешивания одного единственного столбца
    :param a: Столбец для перемешивания
    :return:
    """
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    """
    Процедура для перемешивания всей матрицы
    :param s: Матрица
    :return: перемешанная матрица
    """
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    """
    Процедура обратная предыдушей
    :param s: Матрица
    :return: Восстановленная матрица
    """
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


def bytes2matrix(text: bytes):
    """
    Функция для преобразования последовательности байтов в матрицу из байтов
    :param text: последовательность байтов
    :return: матрица из байтов
    """
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix: list[list]):
    """
    Функция для преобразования матрицы в последовательность байт
    :param matrix: Матрица
    :return: последовательность байт
    """
    return bytes(sum(matrix, []))


def xor_bytes(a, b):
    """
    Функция для выполнения операции исключащющее или над двумя последовательностями байтов
    :param a: первая последовательность
    :param b: вторая последовательность
    :return: результат суммы в виде последовательности
    """
    return bytes(i ^ j for i, j in zip(a, b))


def generate_keys(master_key: bytes):
    """
    Функция для генерации раундовых ключей из исходного
    :param master_key: исходный ключ
    :return: массив матриц ключей
    """

    # Определяем колонки исходного ключа
    key_cols = bytes2matrix(master_key)
    # То сколько раз нам нужно выполнить последовательность действий для одного ключа то есть количество столбцов в
    # одной матрице ключа (всегда 16/4 = 4)
    iteration_size = len(master_key) // 4

    i = 1
    # Для AES-128 (128 бит = 16 байт) нужно 12 ключей каждый из которых по 4 столбца отсюда получается 12*4
    while len(key_cols) < 12 * 4 - 1:
        # Колонка над которой производится операция
        word = list(key_cols[-1])

        # Каждый четвертый столбец (каждый первый столбец очередного ключа)
        if len(key_cols) % iteration_size == 0:
            # Расширяем наше слово нашим словом без первого байта
            word.append(word.pop(0))
            # Преобразуем перестановкой
            word = [s_box[b] for b in word]
            # Ксорим с соответствующим значением в таблице R
            word[0] ^= r_con[i]
            # Увеличиваем счётчик
            i += 1

        # Ксорим нашу колонку с последней колонку ключа
        word = xor_bytes(word, key_cols[-iteration_size])
        # Добавляем в наш массив колонок
        key_cols.append(word)
    # Возвращаем наш список столбцов разбитый по ключам
    return [key_cols[4 * i: 4 * (i + 1)] for i in range(len(key_cols) // 4)]


def print_table(table):
    for row in table:
        byte_row = bytearray(row)
        print(byte_row.hex(" ").upper())
    print("\n")


def aes_encrypt(block: bytes, key: bytes):
    """
    Функция шифрования AES
    :param block: блок текста в виде 16-байтовой последовательности
    :param key: 16-байтовый ключ
    :return: зашифрованная последовательность байт длины 16
    """
    # Преобразуем наш блок текста в матрицу 4х4 - наше изначальное состояние
    state = bytes2matrix(block)

    # Генерируем ключи
    key_matrices = generate_keys(key)

    # Ксорим матрицу с исходным ключом
    add_round_key(state, bytes2matrix(key))

    # Производим 9 раундов шифрования
    for i in range(1, 10):
        # Выполняем s перестановку
        sub_bytes(state)
        # Смещаем строки матрицы
        shift_rows(state)
        # Перемешиваем строки матрицы
        mix_columns(state)
        # Ксорим с раундовым ключом
        add_round_key(state, key_matrices[i])

    # Выполняем конечное s преобразование
    sub_bytes(state)
    # Смещаем строки в последний раз
    shift_rows(state)
    # Применяем последний раундовый ключ
    add_round_key(state, key_matrices[-1])

    # Возвращаем последовательность байт
    return matrix2bytes(state)


def aes_decrypt(block: bytes, key: bytes):
    """
    Функция дешифрования алгоритма AES
    :param block: блок шифрованного текста в виде 16-байтовой последовательности
    :param key: 16-байтовый ключ
    :return: 16-байтовую расшифрованную последовательность (блок исходного текста)
    """

    # ДАЛЕЕ ПРОИЗВОДЯТСЯ ОБРАТНЫЕ ПРЕОБРАЗОВАНИЯ В ОБРАТНОМ ПОРЯДКЕ

    state = bytes2matrix(block)

    key_matrices = generate_keys(key)

    add_round_key(state, key_matrices[-1])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for i in range(9, 0, -1):
        add_round_key(state, key_matrices[i])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, key_matrices[0])

    return matrix2bytes(state)


def splt_str_on_blocks(encoded_str: bytearray, block_size: int) -> list[bytes]:
    """
    Разбивает массив байтов на кусочки заданной длины
    :param encoded_str: строка преобразованная в последовательность байтов
    :param block_size: размер куска
    :return: массив кусков исходного массива
    """
    # Разбиваем на чанки
    chunks = [encoded_str[i:i + block_size] for i in range(0, len(encoded_str), block_size)]
    # Преобразуем в последовательность байт из bytearray
    blocks = [bytes(chunk) for chunk in chunks]
    return blocks


def make_key_bytes(key: str):
    """
    Преобразует строку ключа в последовательность из 16 байтов
    :param key: строка ключа произвольной длины
    :return: 16-байтовая последвоательность
    """
    # Кодируем строку в байты кодировки UTF-8
    bytes_key = key.encode("UTF-8")
    # Преобразуем последовательность байт в изменяемый массив байт
    bytearray_key = bytearray(bytes_key)
    if len(bytearray_key) < 16:
        # Если длина ключа меньше 16 будем добавлять в конец нулевые байты
        while len(bytearray_key) != 16:
            bytearray_key.append(0x00)
    elif len(bytearray_key) > 16:
        # Если длина ключа больше 16 обрежем последовательнсть байт по первые 16
        bytearray_key = bytes_key[:16]
    return bytearray_key


def aes_cbc_encrypt(text: str, key: str):
    """
    Функция реализующая режим ECB (простой замены - электронной кодовой книги)
    :param text: Текст для шифровки
    :param key: ключ
    :return: последовательность байтов шифрованного текста
    """
    # Преобразуем текст в байты кодировки UTF-8
    bytes_text = bytearray(text.encode("UTF-8"))
    # Если не можем разбить на блоки по 16 будем добавлять нулевые байты пока не сможем
    while len(bytes_text) % 16 != 0:
        bytes_text.append(0x00)
    # Разбиваем текст на блоки по 16 байт
    blocks = splt_str_on_blocks(bytes_text, 16)
    # Преобразуем ключ в массив байтов
    bytearray_key = make_key_bytes(key)
    # Преобразуем ключ в последовательность байтов
    bytes_key = bytes(bytearray_key)
    # Определяем массив результата
    output = []
    # Проходимся по блокам текста
    for block in blocks:
        print(f"Блок текста:  {block.hex(' ').upper()}")
        print(f"Ключ          {bytes_key.hex(' ').upper()}")
        # Шифруем блок
        encryption = aes_encrypt(block, bytes_key)
        print(f"Блок шифра    {encryption.hex(' ').upper()}")
        # Добавляем в список нашего выхода
        output.append(encryption)
        print("============================================")
    return output


def aes_cbc_decrypt(encrypted_blocks: list[bytes], key: str):
    """
    Функция для расшифровки в режиме ECB
    :param encrypted_blocks: массив зашифрованных блоков исходного текста
    :param key: ключ использованный для шифрования строки
    :return: восстановленная строка текста
    """
    # Преобразуем в байты ключ
    bytes_key = bytes(make_key_bytes(key))
    output = []
    # Проходимся по блокам шифрованного текста
    for block in encrypted_blocks:
        print(f"Блок шифра:    {block.hex(' ').upper()}")
        print(f"Ключ:          {bytes_key.hex(' ').upper()}")
        # Расшифровываем блок текста
        decryption = aes_decrypt(block, bytes_key)
        print(f"Исходный блок  {decryption.hex(' ').upper()}")
        # Добавляем последовательность байт в выходной массив
        output.append(decryption)
        print("============================================")
    # Определяем массив байтов
    out_bytes = bytearray()
    # Заполняем массив байтов ненулевыми байтами (чтобы нулевые которые мы могли добавить при шифровке
    # не испортили нам мазу) - может привести к багам в очень крайних случаях
    for block in output:
        for byte in block:
            if byte != 0:
                out_bytes.append(byte)
    # Возвращаем строку декодированием в UTF-8
    return out_bytes.decode("UTF-8")
