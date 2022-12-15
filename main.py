from AES import *
#Читаем пользовательские сообщение и ключ
message = input("Введите сообщение: ")
key = input("Введите ключ: ")
enc = aes_cbc_encrypt(message, key)
#Формируем строку представляющие байты шифрованного сообщение в удобоваримом виде (с разделителями и заглавными буквами)
out = " ".join([block.hex(' ').upper() for block in enc])
print(f"Зашифрованное сообщение: {out}")
print("\n")
dec = aes_cbc_decrypt(enc, key)
print(f"Расшифрованное сообщение: {dec}")
