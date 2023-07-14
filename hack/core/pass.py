import itertools


def find_password(target_name):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    numbers = '0123456789'
    special_chars = '@#$%^&*'

    # Gabungkan semua karakter yang mungkin
    characters = alphabet + alphabet.upper() + numbers + special_chars

    # Loop melalui setiap panjang password
    for length in range(1, 9):  # Ubah angka 9 sesuai dengan panjang maksimum yang diinginkan
        # Buat kombinasi dari karakter dengan panjang yang ditentukan
        combinations = itertools.combinations(characters, length)

        # Loop melalui setiap kombinasi
        for combo in combinations:
            password = ''.join(combo)
            if password + target_name == "":
                return password

    return None


target_name = ""
found_password = find_password(target_name)

if found_password:
    print(f"Password ditemukan: {found_password}")
else:
    print("Password tidak ditemukan.")
