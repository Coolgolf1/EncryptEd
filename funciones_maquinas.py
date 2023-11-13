# Máquinas
import binascii
import base64
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from funciones_ct_gn import *


def maquinas_menu():
    while True:
        clear_terminal()
        maquinas_choice = input(
            "===== Máquinas =====\n1. Cifrados Clásicos\n2. Cifrado Simétricos\n3. Cifrados Asimétricos\n4. Hashes\n5. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_choice == "1":
            maquinas_cifrados_clasicos()
        elif maquinas_choice == "2":
            maquinas_cifrados_simetricos()
        elif maquinas_choice == "3":
            maquinas_cifrados_asimetricos()
        elif maquinas_choice == "5":
            return


def maquinas_cifrados_clasicos():
    while True:
        clear_terminal()
        maquinas_cifrados_clasicos_choice = input(
            "========= Máquinas ==========\n===== Cifrados Clásicos =====\n1. Cifrado César\n2. Cifrado Vigènere\n3. Cifrado Rail Fence\n4. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_clasicos_choice == "1":
            caesar_cipher()
        elif maquinas_cifrados_clasicos_choice == "2":
            vigenere_cipher()
        elif maquinas_cifrados_clasicos_choice == "3":
            rail_fence_cipher()
        elif maquinas_cifrados_clasicos_choice == "4":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def maquinas_cifrados_simetricos():
    while True:
        clear_terminal()
        maquinas_cifrados_simetricos_choice = input(
            "========== Máquinas ===========\n===== Cifrados Simétricos =====\n1. Cifrado AES-56\n2. Cifrado DES\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_simetricos_choice == "1":
            AES_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            DES_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def maquinas_cifrados_asimetricos():
    while True:
        clear_terminal()
        maquinas_cifrados_simetricos_choice = input(
            "=========== Máquinas ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_simetricos_choice == "1":
            RSA_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            ECC_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")
# Este es el proceso de encripción/desencripción del Cifrado César


def caesar_cipher_process(input_text_caesar, caesar_key, modo):
    # Hace módulo de la llave ya que tiene que estar entre 0 y 25
    caesar_key = int(caesar_key) % 26
    caesar_original = "abcdefghijklmnopqrstuvwxyz"
    shifted_text_caesar = ""
    for i in input_text_caesar:
        if i in caesar_original:
            original_index = caesar_original.index(i)
            if modo == "E":
                # Coge los índices de cada letra y le suma el índice que tiene que moverse por la llave y vuelve a hacer módulo por si es > 26
                shifted_index = (original_index + caesar_key) % 26
            elif modo == "D":
                # Coge los índices de cada letra y le resta el índice que tiene que moverse por la llave y vuelve a hacer módulo por si es > 26
                shifted_index = (original_index - caesar_key) % 26
            shifted_text_caesar += caesar_original[shifted_index]
        else:
            # Si la letra no está en el abecedario (caesar_original) la pasa sin cifrado
            shifted_text_caesar += i
    if modo == "E":
        return f"\nEl texto encriptado es: {shifted_text_caesar}\nCifrado César\nLlave: {caesar_key}\n"
    elif modo == "D":
        return f"\nEl texto desencriptado es: {shifted_text_caesar}\nCifrado César\nLlave: {caesar_key}\n"
# Admite los inputs y genera las respuestas llamando a la funcion caesar_cipher_process, y los imprime en la terminal


def caesar_cipher():
    # Printea un menú por estética
    print("=====Cifrado César=====")
    # Pide un input de encriptar/desencriptar
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Mira que la respuesta al input sea válida
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Recibe el texto que se quiere encriptar/desencriptar en lower() ya que el cifrado césar no admite mayúsculas
    plaintext = input("Introduce un texto: ").lower()
    # Mira si el texto introducido está vacío
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    # Pide la llave para los shifteos
    caesar_key = (input("Introduce el número de shifts (llave): "))
    while not caesar_key.isnumeric():
        # Mira que la llave sea válida, teniendo que ser númerica
        print("Error. La llave solo puede tener números.")
        caesar_key = (input("Introduce el número de shifts (llave): "))
    # Mientras sea mayor a 26 o menor a -26, tiene que hacer el módulo para que esté entre los valores permitidos
    while int(caesar_key) > 26 or int(caesar_key) < -26:
        caesar_key = int(caesar_key) % 26
    # Imprime la función caesar_cipher_process en modo encriptar/desencriptar dependiendo del modo (input)
    if modo == "E":
        print(caesar_cipher_process(plaintext, caesar_key, modo="E"))
    else:
        print(caesar_cipher_process(plaintext, caesar_key, modo="D"))
    input("Pulsa enter para continuar.")
# Es el proceso de encripción/desencripción del cifrado Vigènere


def vigenere_cipher_process(plaintext, vigenere_key, modo):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    # Extiende la llave para que pueda encriptar/desencriptar el plaintext entero
    extended_vigenerey_key = (
        vigenere_key * ((len(plaintext) // len(vigenere_key)) + 1))[:len(plaintext)]
    cipher_vigenere_text = ""
    # Mira letra por letra en el plaintext y va encriptándola/desencriptándola
    for i, char in enumerate(plaintext):
        if char in alphabet:
            # Coge el índice de la letra en el abecedario
            text_index = alphabet.index(char)
            # Coge el índice de la letra correspondiente a la letra del plaintext en el abecedario
            key_index = alphabet.index(extended_vigenerey_key[i])
            if modo == "E":
                # Suma los índices para saber la posición en el abecedario de la letra encriptada
                position = (text_index + key_index)
            elif modo == "D":
                # Resta los índices para saber la posición en el abecedario de la letra desencriptada
                position = (text_index - key_index)
            while position > 25:
                position -= 26
            # Guarda las letras en el texto
            cipher_vigenere_text += alphabet[position]
        else:
            # Si la letra no está en el abecedario la pasa sin cifrar
            cipher_vigenere_text += char
    if modo == "E":
        return f"\nEl texto encriptado es: {cipher_vigenere_text}\nCifrado Vigènere\nLlave: {vigenere_key}\n"
    elif modo == "D":
        return f"\nEl texto desencriptado es: {cipher_vigenere_text}\nCifrado Vigènere\nLlave: {vigenere_key}\n"
# Admite los inputs y genera las respuestas llamando a la funcion vigenere_cipher_process, y los imprime en la terminal


def vigenere_cipher():
    print("=====Cifrado Vigènere=====")
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Hace un check y valida que la opción elegida es correcta
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # El cifrado Vigènere no acepta mayúsculas
    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    vigenere_key = input("Introduce una llave: ").lower()
    # Si la llave es mayor al texto, la acorta para que sea igual de larga que el plaintext o texto
    while len(vigenere_key) > len(plaintext):
        vigenere_key = vigenere_key[:len(plaintext)]
    caracteres_no_permitidos = "1234567890ªº\|!@·#\"$%&/()=?¿'¡,.;:-_¨çÇ}{][+*`^"
    # Mira que la llave tenga solo caracteres permitidos
    while any(i in caracteres_no_permitidos for i in vigenere_key):
        print("Error. La llave debe solo tener letras.")
        # La llave tiene que estar en minúsculas
        vigenere_key = input("Introduce una llave: ").lower()
    # Imprime la función vigenere_cipher_process en modo encriptar/desencriptar dependiendo del modo (input)
    if modo == "E":
        print(vigenere_cipher_process(plaintext, vigenere_key, modo="E"))
    else:
        print(vigenere_cipher_process(plaintext, vigenere_key, modo="D"))
    input("Pulsa enter para continuar.")
# Es el proceso de encripción/desencripción del cifrado rail fence


def rail_fence_cipher_process(plaintext, rails, modo):
    # Si está en modo de encriptar corre esto:
    if modo == "E":
        # Crea el rail 0 una caja de este estilo: (este ejemplo sería para rails = 3)
        rail = [['_' for i in range(len(plaintext))] for j in range(rails)]
        # *___*___*___
        dir_down = False
        # _*_*_*_*_*_
        fila = 0
        # __*___*___*___........ (se colocan letras donde los asteriscos y el resto se deja en "_")
        columna = 0
        # Coge el índice (columna, como se vería en el dibujo de arriba) de cada letra
        for i in range(len(plaintext)):
            if fila == 0:                                                # Si está en la primera fila le dice que baje
                dir_down = True
            if fila == rails - 1:                                        # Si está en la última fila le dice que suba
                dir_down = False
            # En cada rail[fila][columna] coloca una letra colocándolo en las posiciones de los asteriscos en el dibujo
            rail[fila][columna] = plaintext[i]
            # Cada vez que coloca una letra tiene que pasar a la siguiente columna
            columna += 1
            # Dependiendo de si la dir_down = True o False por la línea 136-139, hace que suba o baje de filas
            if dir_down:
                fila += 1
            else:
                fila -= 1
        # Se declara la lista de resultado
        result = []
        for i in range(rails):
            for j in range(len(plaintext)):
                # Coge las coordenadas de cada hueco en rail (diagrama) y si es diferente a _: --> (siguiente línea)
                if rail[i][j] != '_':
                    # --> se guardan las coordenadas y ,por tanto, la letra en la lista result
                    result.append(rail[i][j])
        # Los elementos de la lista se unen a un string vacío con .join y se return de forma string y no lista
        texto_rail_fence = ("".join(result))
    # Si está en modo de desencriptar corre esto:
    else:
        # Se repite lo mismo que en el modo de encripción
        rail = [['_' for i in range(len(plaintext))] for j in range(rails)]
        dir_down = False
        fila = 0
        columna = 0
        # Coge el índice (columna, como se vería en el dibujo de arriba) de cada letra
        for i in range(len(plaintext)):
            if fila == 0:                                                # Si está en la primera fila le dice que baje
                dir_down = True
            if fila == rails - 1:
                dir_down = False
            # para cada sitio donde tiene que haber letas, se imprime un * que luego hará un "replace" manual con un bucle for
            rail[fila][columna] = '*'
            columna += 1
            # Dependiendo de si la dir_down = True o False por la línea 163-166, hace que suba o baje de filas
            if dir_down:
                fila += 1
            else:
                fila -= 1
        index = 0
        for i in range(rails):
            for j in range(len(plaintext)):
                # Si hay un asterisco en la coordenada: --> (siguiente línea)
                if ((rail[i][j] == '*') and (index < len(plaintext))):
                    # --> se imprime la letra correspondiente en esas coordenadas (se hace un tipo de "replace" de forma manual)
                    rail[i][j] = plaintext[index]
                    index += 1
        result = []
        fila = 0
        columna = 0
        # Este bucle for va mirando en zig-zag siguiendo la línea de los "*" del dibujo
        for i in range(len(plaintext)):
            if fila == 0:
                dir_down = True
            if fila == rails-1:
                dir_down = False
            # Guarda en la lista result las letras si no hay asterisco
            if (rail[fila][columna] != '*'):
                result.append(rail[fila][columna])
                columna += 1
            if dir_down:
                fila += 1
            else:
                fila -= 1
            texto_rail_fence = ("".join(result))
    if modo == "E":
        return f"\nEl texto encriptado es: {texto_rail_fence}\nCifrado Rail Fence\nLlave (Railes): {rails}\n"
    elif modo == "D":
        return f"\nEl texto desencriptado es: {texto_rail_fence}\nCifrado Rail Fence\nLlave (Railes): {rails}\n"
# Admite los inputs y genera las respuestas llamando a la funcion rail_fence_cipher_process, y los imprime en la terminal


def rail_fence_cipher():
    print("=====Cifrado Rail Fence=====")
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":  # Mira que el input para modo sea válido
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    plaintext = input("Introduce un texto: ")
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ")
    # El número de railes (llave)
    rails = input("Introduce el número de railes: ")
    # Tiene que ser númerica y además entre 1 y la longitud del texto ya que si no, no sirve de nada (con esto explico las siguientes líneas):
    while not rails.isnumeric():
        print("Error. El número de railes debe ser numérico.")
        rails = input("Introduce el número de railes: ")
    while (int(rails) >= len(plaintext)) or int(rails) == 1:
        print("Para que funcione el número de railes debe ser menor a la longitud del texto introducido y mayor que 1.")
        rails = input("Introduce el número de railes: ")
        while not rails.isnumeric():
            print("Error. El número de railes debe ser numérico.")
            rails = input("Introduce el número de railes: ")
        rails = int(rails)
    rails = int(rails)
    # Imprime la función rail_fence_cipher_process en modo encriptar/desencriptar dependiendo del modo (input)
    if modo == "E":
        print(rail_fence_cipher_process(plaintext, rails, "E"))
    else:
        print(rail_fence_cipher_process(plaintext, rails, "D"))
    input("Pulsa enter para continuar.")
# Es una función que coge la llave AES


def derive_key(AES_key: str, salt: bytes, iterations: int = 100000) -> bytes:
    # Salt es un código único que tiene cada contraseña que produce una encripción más segura
    # Usa un algoritmo PBKDF2 para hacer que la contraseña sea de 32 bytes
    llave = PBKDF2(AES_key, salt, dkLen=32,
                   count=iterations, hmac_hash_module=SHA256)
    return llave
# Es el proceso de encripción/desencripción del cifrado AES-256


def AES_cipher_process(plaintext, AES_key, modo):
    try:
        # Solamente usado en encripción
        salt = get_random_bytes(16)
        # Se crea una llave para crear el cifrado
        llave = derive_key(AES_key, salt)
        if modo == "E":
            # Se recogen los bytes del plaintext ya que se trabaja en bytes en AES
            plaintext_bytes = pad(plaintext.encode("utf-8"), AES.block_size)
            # Crea el cifrado que se usará para encriptar los plaintext_bytes
            cipher = AES.new(llave, AES.MODE_CBC)
            # Tiene lugar la primera parte de la encripción donde se crea el texto encriptado (ciphertext)
            ciphertext = cipher.encrypt(plaintext_bytes)
            # Se devuelven los bytes pasados a string (texto encriptado) con el salt, para mayor seguridad
            return binascii.hexlify(salt + cipher.iv + ciphertext).decode('utf-8')
            # El cipher.iv es un vector que hace que si un texto se vuelve a encriptar con la misma contraseña cambie cada vez
        elif modo == "D":
            # Pasa el plaintext binario a hex
            ciphertext = binascii.unhexlify(plaintext)
            # El salt se coge de los primeros 16 bytes (ya que lo encriptamos de esa forma nosotros)
            salt = ciphertext[:16]
            # El iv (vector) se coge del byte 16 al 32 (ya que lo encriptamos de esa forma nosotros)
            iv = ciphertext[16:32]
            # El resto del texto es el ciphertext que hay que desencriptar
            ciphertext = ciphertext[32:]
            # Consigue la llave a partir de la contraseña introducida, el salt y el iv
            llave = derive_key(AES_key, salt)
            # Crea el cifrado que usaremos para desencriptar
            cipher = AES.new(llave, AES.MODE_CBC, iv)
            # Se quita el padding que podría tener el ciphertext desencriptado con el cifrado
            plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            # Se devuelve los bytes decodificados en utf-8 ya que lo codificamos nosotros en utf-8
            return plaintext_bytes.decode('utf-8')
    except:
        print("\nError. La contraseña no es la correcta.")


def AES_cipher():
    # Printea un menú por estética
    print("=====Cifrado AES-256 =====")
    # Pide un input de encriptar/desencriptar
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Mira que la respuesta al input sea válida
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    if modo == "E":
        AES_key = input("Introduce una contraseña para encriptar: ")
    else:
        AES_key = input("Introduce la contraseña para desencriptar: ")
    while len(AES_key) < 32:
        AES_key += " "
    AES_key = AES_key[:32]
    if modo == "E":
        texto_encriptado = AES_cipher_process(plaintext, AES_key, "E")
        print(
            f"\nEl texto encriptado es: {texto_encriptado}\nCifrado AES-256\nLlave: {AES_key}\n")
    else:
        texto_desencriptado = AES_cipher_process(plaintext, AES_key, "D")
        print(
            f"\nEl texto desencriptado es: {texto_desencriptado}\nCifrado AES-256\nLlave: {AES_key}\n")
    input("Pulsa enter para continuar.")


def DES_cipher_process(plaintext, DES_key, modo):
    if len(DES_key) < 8:
        DES_key = DES_key.ljust(8)
    DES_key = DES_key[:8].encode()
    try:
        if modo == "E":
            iv = get_random_bytes(DES.block_size)
            # OFB (Using Output Feedback)
            cipher = DES.new(DES_key, DES.MODE_OFB, iv)
            plaintext_padded = pad(plaintext.encode(), DES.block_size)
            ciphertext = cipher.encrypt(plaintext_padded)
            return binascii.hexlify(iv + ciphertext).decode()
        else:
            encriptado = binascii.unhexlify(plaintext)
            iv = encriptado[:DES.block_size]
            ciphertext = encriptado[DES.block_size:]
            cipher = DES.new(DES_key, DES.MODE_OFB, iv)
            plaintext_padded = cipher.decrypt(ciphertext)
            return unpad(plaintext_padded, DES.block_size).decode()
    except:
        print("Error. La contraseña no es la correcta.")


def DES_cipher():
    # Printea un menú por estética
    print("=====Cifrado DES =====")
    # Pide un input de encriptar/desencriptar
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Mira que la respuesta al input sea válida
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    plaintext = ""
    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    DES_key = input("Introduce una contraseña para encriptar: ")
    if modo == "E":
        texto_encriptado = DES_cipher_process(plaintext, DES_key, "E")
        print(
            f"\nEl texto encriptado es: {texto_encriptado}\nCifrado DES\nLlave: {DES_key}\n")
    else:
        texto_desencriptado = DES_cipher_process(plaintext, DES_key, "D")
        print(
            f"\nEl texto desencriptado es: {texto_desencriptado}\nCifrado DES\nLlave: {DES_key}\n")
    input("Pulsa enter para continuar.")


def generar_RSA_keys():
    key = RSA.generate(2048)
    RSA_private_key = key.export_key()
    RSA_public_key = key.publickey().export_key()
    return RSA_private_key, RSA_public_key


def guardar_llave_en_archivo(key, filename):
    with open(f".\Llaves\RSA\{filename}", 'wb') as key_file:
        key_file.write(key)


def cargar_llave_de_archivo(filename):
    with open(f".\Llaves\RSA\{filename}", 'rb') as key_file:
        return RSA.import_key(key_file.read())


def RSA_cipher_process(plaintext, RSA_key, modo):
    if modo == "E":
        RSA_cipher = PKCS1_OAEP.new(RSA_key)
        encrypted_message = RSA_cipher.encrypt(plaintext.encode())
        return binascii.hexlify(encrypted_message).decode()
    else:
        RSA_cipher = PKCS1_OAEP.new(RSA_key)
        decrypted_message = RSA_cipher.decrypt(binascii.unhexlify(plaintext))
        return decrypted_message.decode()


def RSA_cipher():
    # Printea un menú por estética
    print("=====Cifrado RSA =====")
    # Pide un input de encriptar/desencriptar
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Mira que la respuesta al input sea válida
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    try:
        if modo == "E":
            generar = input("¿Quieres generar nuevas llaves? (Y/N): ").upper()
            if generar == 'Y':
                RSA_private_key, RSA_public_key = generar_RSA_keys()
                guardar_llave_en_archivo(RSA_private_key, "private_key.pem")
                guardar_llave_en_archivo(RSA_public_key, "public_key.pem")
                print("Llaves guardadas en \"private_key.pem\" y \"public_key.pem\".")
            RSA_public_key = cargar_llave_de_archivo("public_key.pem")
            encrypted_text = RSA_cipher_process(plaintext, RSA_public_key, "E")
            print(
                f"\nEl texto encriptado es: \n{encrypted_text}\n\nCifrado RSA\n\n")
        else:
            RSA_private_key = cargar_llave_de_archivo('private_key.pem')
            decrypted_text = RSA_cipher_process(
                plaintext, RSA_private_key, "D")
            print(
                f"\nEl texto desencriptado es: \n{decrypted_text}\n\nCifrado RSA\n\n")
        input("Pulsa enter para continuar.")
    except:
        print("Has introducido algún dato de forma incorrecta.")


def guardar_en_archivo(nombre_archivo, datos):
    ruta = f".\\Llaves\\ECC\\{nombre_archivo}"
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "w") as archivo:
        archivo.write(datos)


def leer_de_archivo(nombre_archivo):
    ruta = f".\\Llaves\\ECC\\{nombre_archivo}"
    with open(ruta, "r") as archivo:
        return archivo.read()


def generar_ECC_keys():
    ECC_key = ECC.generate(curve="P-256")
    ECC_private_key = ECC_key.export_key(format="PEM")
    ECC_public_key = ECC_key.public_key().export_key(format="PEM")
    return ECC_key, ECC_private_key, ECC_public_key


def encriptar_ECC(plaintext, ECC_public_key, ECC_key):
    receptor_key = ECC.import_key(ECC_public_key)
    shared_key = ECC_key.d * receptor_key.pointQ
    key_derivada = SHA256.new(str(shared_key.x).encode()).digest()[:16]
    AES_cipher = AES.new(key_derivada, AES.MODE_EAX)
    ciphertext, tag = AES_cipher.encrypt_and_digest(
        pad(plaintext.encode(), AES.block_size))
    return ECC_key.public_key().export_key(format='PEM'), AES_cipher.nonce, tag, ciphertext


def guardar_datos_encriptados(ECC_public_key, ECC_private_key, nonce, tag, ciphertext):
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    guardar_en_archivo("public_key.pem", ECC_public_key)
    guardar_en_archivo("private_key.pem", ECC_private_key)
    guardar_en_archivo("nonce.txt", nonce_b64)
    guardar_en_archivo("tag.txt", tag_b64)
    guardar_en_archivo("ciphertext.txt", ciphertext_b64)
    print("Guardado completado.")


def desencriptar_ECC(ECC_public_key, nonce, tag, ciphertext, ECC_private_key):
    compartido = ECC_private_key.d * ECC_public_key.pointQ
    llave_derivada = SHA256.new(str(compartido.x).encode()).digest()[:16]
    AES_cipher = AES.new(llave_derivada, AES.MODE_EAX, nonce)
    plaintext = unpad(AES_cipher.decrypt_and_verify(
        ciphertext, tag), AES.block_size)
    return plaintext


def ECC_cipher():
    # Printea un menú por estética
    print("===== Cifrado ECC =====")
    # Pide un input de encriptar/desencriptar
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Mira que la respuesta al input sea válida
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    ECC_key, ECC_private_key, ECC_public_key = generar_ECC_keys()
    if modo == "E":
        plaintext = input("Introduce un texto: ")
        while len(plaintext) < 1:
            print("Error. Introduce un texto válido.")
            plaintext = input("Introduce un texto: ")
        ECC_public_key, nonce, tag, ciphertext = encriptar_ECC(
            plaintext, ECC_public_key, ECC_key)
        guardar_datos_encriptados(
            ECC_public_key, ECC_private_key, nonce, tag, ciphertext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        print(f"El texto encriptado es: {ciphertext_b64}")
    else:
        try:
            ECC_public_key_pem = leer_de_archivo("public_key.pem")
            ECC_private_key_pem = leer_de_archivo("private_key.pem")
            nonce_b64 = leer_de_archivo("nonce.txt")
            tag_b64 = leer_de_archivo("tag.txt")
            ciphertext_b64 = input("Introduce el texto encriptado: ")
            ECC_public_key = ECC.import_key(ECC_public_key_pem)
            ECC_private_key = ECC.import_key(ECC_private_key_pem)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(ciphertext_b64)

            decrypted_message = desencriptar_ECC(
                ECC_public_key, nonce, tag, ciphertext, ECC_private_key)
            print(
                f"\nEl texto desencriptado es: \n{decrypted_message.decode()}\nCifrado ECC\n")
        except Exception as e:
            print("Error durante la desencriptación: ", e)

    input("Pulsa enter para continuar.")
    clear_terminal()
