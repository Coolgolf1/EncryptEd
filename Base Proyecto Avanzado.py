import os
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


# Esta función limpia la terminal por estética
def clear_terminal():
    os.system("cls")


# Esta función imprime el título del juego cuando se llame
def title():
    print("""\n\n             _|_|_|_|                                                      _|      _|_|_|_|        _|  
             _|        _|_|_|      _|_|_|  _|  _|_|  _|    _|  _|_|_|    _|_|_|_|  _|          _|_|_|  
             _|_|_|    _|    _|  _|        _|_|      _|    _|  _|    _|    _|      _|_|_|    _|    _|  
             _|        _|    _|  _|        _|        _|    _|  _|    _|    _|      _|        _|    _|  
             _|_|_|_|  _|    _|    _|_|_|  _|          _|_|_|  _|_|_|        _|_|  _|_|_|_|    _|_|_|  
                                                           _|  _|                                      
                                                         _|_|  _|   \n""")


def get_name():
    name = str(input("¿Cómo te llamas? "))
    while len(name) > 12:
        print("Error. Nombre demasiado largo.")
        name = str(input("¿Cómo te llamas? "))
    if name == "" or name in (" "*12):
        name = "user"
    return name


# Es el proceso de encripción/desencripción del cifrado césar
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


# Es el proceso de encripción/desencripción del cifrado vigénere
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
        return f"\nEl texto encriptado es: {cipher_vigenere_text}\nCifrado Vigénere\nLlave: {vigenere_key}\n"
    elif modo == "D":
        return f"\nEl texto desencriptado es: {cipher_vigenere_text}\nCifrado Vigénere\nLlave: {vigenere_key}\n"


# Admite los inputs y genera las respuestas llamando a la funcion vigenere_cipher_process, y los imprime en la terminal
def vigenere_cipher():

    print("=====Cifrado Vigénere=====")
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    # Hace un check y valida que la opción elegida es correcta
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()

    # El cifrado vigénere no acepta mayúsculas
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
    # El plaintext solo acepta minúsculas
    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
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
    with open(filename, 'wb') as key_file:
        key_file.write(key)


def cargar_llave_de_archivo(filename):
    with open(filename, 'rb') as key_file:
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
            f"\nEl texto encriptado es: \n{encrypted_text}\n\nCifrado RSA\nLlave pública: \n\n{RSA_public_key.export_key().decode()}\n")

    else:
        RSA_private_key = cargar_llave_de_archivo('private_key.pem')
        decrypted_text = RSA_cipher_process(plaintext, RSA_private_key, "D")
        print(
            f"\nEl texto desencriptado es: \n{decrypted_text}\n\nCifrado RSA\nLlave privada: \n\n{RSA_private_key.export_key().decode()}\n")
    input("Pulsa enter para continuar.")


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


def display_datos_encriptados(ECC_public_key, ECC_private_key, nonce, tag, ciphertext):
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

    print("===== Guarda esta información para desencriptar el mensaje posteriormente =====\n")
    print(f"Llave pública ECC (PEM):\n{ECC_public_key}\n")
    print(f"Llave privada ECC (PEM):\n{ECC_private_key}\n")
    print(f"Nonce (Base64):\n{nonce_b64}\n")
    print(f"Tag (Base64):\n{tag_b64}\n")
    print(f"Texto encriptado (Base64):\n{ciphertext_b64}\n")
    print("=============================================================")


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
        display_datos_encriptados(
            ECC_public_key, ECC_private_key, nonce, tag, ciphertext)

    else:
        ciphertext_b64 = input("Introduce el texto encriptado: ")
        while len(ciphertext_b64) < 1:
            print("Error. Introduce un texto válido.")
            ciphertext_b64 = input("Introduce el texto encriptado: ")
        try:
            ECC_public_key_encoded = (
                input("Introduce la llave pública usada durante la encripción: "))
            ECC_private_key_encoded = (
                input("Introduce la llave privada usada durante la encripción: "))
            nonce_b64 = (
                input("Introduce el nonce usado durante la encripción: "))
            tag_b64 = (input("Introduce el tag usado durante la encripción: "))
            ECC_public_key = ECC.import_key(
                base64.b64decode(ECC_public_key_encoded))
            ECC_private_key = ECC.import_key(
                base64.b64decode(ECC_private_key_encoded))
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            decrypted_message = desencriptar_ECC(
                ECC_public_key, nonce, tag, ciphertext, ECC_private_key)
            print(
                f"\nEl texto desencriptado es: \n{decrypted_message.decode()}\nCifrado ECC\n")
        except:
            print("Has introducido algún dato de forma incorrecta.")

    input("Pulsa enter para continuar.")
    clear_terminal()
    title()


def main_menu():
    while True:
        clear_terminal()
        title()
        main_menu_choice = (input(
            "==== Menú ====\n1. Lecciones\n2. Retos\n3. Máquinas\n4. Salir\n\nIntroduce tu opción: "))
        clear_terminal()
        title()
        if main_menu_choice == "1":
            lecciones_menu()
        elif main_menu_choice == "2":
            retos_menu()
        elif main_menu_choice == "3":
            maquinas_menu()
        elif main_menu_choice == "4":
            exit_programa()
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_menu():
    while True:
        clear_terminal()
        title()
        lecciones_choice = input(
            "===== Lecciones =====\n1. Introducción\n2. Cifrados Clásicos\n3. Cifrados Simétricos\n4. Cifrados Asimétricos\n5. Hashes\n6. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
        if lecciones_choice == "1":
            lecciones_introduccion()
        elif lecciones_choice == "2":
            lecciones_cifrados_clasicos()
        elif lecciones_choice == "3":
            lecciones_cifrados_simetricos()
        elif lecciones_choice == "4":
            lecciones_cifrados_asimetricos()
        elif lecciones_choice == "5":
            pass
        elif lecciones_choice == "6":
            return


def lecciones_introduccion():
    print("¡Bienvenido A La Lección Introductoria De EncryptEd!")
    name = get_name()
    input(f"\nPerfecto, {name}! Vamos a empezar con una introducción de como funciona el programa. Después, veremos los conocimientos básicos de la criptografía que debes saber.")
    clear_terminal()
    title()
    print("""Estructura del programa:\n
    1. Lecciones: Aquí podrás aprender todo sobre los cifrados más comunes e importantes desde una perspectiva más accesible, en vez de matemática.
                  En las lecciones encontrarás un poco de historia, teoría con una demostración práctica y un reto final para porerlo en práctica.
    2. Retos: En este apartado, hay retos que puedes intentar usando lo que has aprendido en el apartado de Lecciones.
    3. Máquina: En la máquina se encuentran todos los cifrados para poder encriptar o desencriptar mensajes si se conocen los datos necesarios.\n""")
    input("Pulsa enter para continuar.")
    clear_terminal()
    title()
    print("¿Qué Es La Criptografía?:\n\n  Definición formal: La criptografía es el arte y la ciencia de cifrar mensajes para proteger su contenido.\n")
    print("""Historia De La Criptografía\n
    La criptografía es tan antigua como la necesidad de comunicación en secreto. 
    Desde los tiempos de Julio César, quien usaba un sistema de cifrado por sustitución para proteger sus mensajes, 
    hasta los jeroglíficos del Egipto faraónico que ocultaban significados solo conocidos por unos pocos, la criptografía ha tenido un papel fundamental en la historia.

    Durante la Segunda Guerra Mundial, la criptografía alcanzó un punto crucial. 
    La máquina Enigma, utilizada por Alemania para enviar mensajes codificados, fue descifrada por los aliados (con Alan Turing), 
    lo que contribuyó significativamente al resultado de la guerra. 

    Hoy en día, la criptografía sigue evolucionando con la tecnología digital, asegurando que la comunicación privada,
    desde correos electrónicos hasta transacciones bancarias, permanezca segura y confidencial.\n""")
    input("Pulsa enter para continuar.")
    clear_terminal()
    title()
    print("""Recomendación:\n
    Empezar por los cifrados clásicos (en orden) para entender en que se basa la criptografía.
        
    Luego, ya entendidos los cifrados clásicos, ¡podrás adentrarte en el mundo de la criptografía simétrica y asimétrica!
          
    La criptografía es difícil de entender, pero es preciosa una vez entiendes diferentes partes de ella.
    Por ello, ¡¡¡no perdamos más tiempo en la introducción y a comenzar!!!\n""")
    input("Recuerda: deberías empezar por la clase del cifrado César. Pulsa enter para continuar.")


def lecciones_cifrados_clasicos():
    while True:
        clear_terminal()
        title()
        lecciones_cifrados_clasicos_choice = input(
            "========= Lecciones =========\n===== Cifrados Clásicos =====\n1. Cifrado César\n2. Cifrado Vigénere\n3. Cifrado Rail Fence\n4. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
        if lecciones_cifrados_clasicos_choice == "1":
            lecciones_caesar_cipher()
        elif lecciones_cifrados_clasicos_choice == "2":
            lecciones_vigenere_cipher()
        elif lecciones_cifrados_clasicos_choice == "3":
            lecciones_rail_fence_cipher()
        elif lecciones_cifrados_clasicos_choice == "4":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_caesar_cipher():
    print("¡Bienvenido A La Lección Del Cifrado César!")
    name = get_name()
    input(f"\n¡{name}, hoy te embarcas en tu primera lección de criptografía!\n")
    input("""Historia Del Cifrado César\n
    Aunque no es el primer cifrado de la historia, se considera uno de los cifrados más importantes historicamente.
          
    El cifrado se usaba para poder mandar mensajes entre divisiones del ejército de forma segura.""")
    clear_terminal()
    title()
    print("""Teoría\n
    Este cifrado es un cifrado de sustitución, es decir, sustituye (de forma constante) una letra por otra:
          
    Para encriptar y desencriptar el mensaje era necesaria una llave númerica, que shiftee el abecedario.
    Por ejemplo: key (llave) = 5

    key = 5
    abecedario original:  [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z]
    abecedario shifteado: [f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a,b,c,d,e]
          
    En este ejemplo: la "a" se encriptaría --> f
                     la "b" se encriptaría --> g
                     la "c" se encriptaría --> h
                     ...
                     la "z" se encriptaría --> e""")
    input()
    print(f"""\n{"="*100}\n\nEjemplo: vamos a encriptar "Hola Mundo!" con key (llave) = 5.
          
        Nota: las mayúsculas se transforman en minúsculas para encriptar, y cualquier símbolo fuera del abecedario se mantiene en la posición en la que está en el texto original.

        "Hola Mundo!" --> "mtqf rzsit!" (llave = 5)
          
    Para desencriptar el mensaje con llave 5: 
    
        Cogemos el abecedario original: [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z]
        y shifteamos el abecedario:     [f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a,b,c,d,e]
          
        Ahora, en vez de coger las letras del abecedario original y pasarlas al abecedario shifteado, como se hace en la encripción,
        metemos el texto encriptado en el abecedario shifteado y sacamos las letras correspondientes del abecedario original.
        
        "m" --> "h"
        "t" --> "o"
        "q" --> "l"
        "f" --> "a"
        ...
        "t" --> "o" 
        "!" --> "!"

        "mtqf rzsit!" --> "hola mundo!"\n""")
    input(f"{name} debes entender esto muy bien para seguir con los retos. Pulsa enter para ir a los retos.")

    print("""Reto Manual:\n
    Texto encriptado: "¡pxb elhq!"
    Llave: (el segundo número primo)\n
    Intenta desencriptarlo de forma manual, con una hoja y un boli.\n""")
    respuesta_1 = input("Introduce el texto desencriptado: ")
    while respuesta_1 != "¡muy bien!":
        print("El mensaje no ha sido desencriptado.\n")
        respuesta_1 = input("Introduce el texto desencriptado: ")
    print(f"\n¡Genial, {name} has aprendido el funcionamiento del Cifrado César!\n")
    input("El siguiente reto es un reto automático, haciendo uso de la máquina del Cifrado César implementada en el programa.")
    clear_terminal()
    title()
    input(f"""Reto Con Máquina:\n
    {name}, imagina que estás en la época romana, el aire está impregnado con el polvo y el clamor de la batalla. 
    Eres un soldado leal al gran general Pompeyo. 
    En medio del caos, interceptas un mensaje de tu adversario, Julio César, destinado a sus legiones. 
    Sabes que descifrar su contenido podría cambiar el curso de la guerra y potencialmente llevar a tu lado a la victoria. 
    El mensaje está codificado con un método desconocido para muchos, pero tú has oído rumores sobre este tipo de cifrado: 
    El cifrado César, un ingenioso sistema de desplazamiento que el propio César utiliza para comunicarse con sus generales. 
    Descifrarlo podría ser la clave para anticipar sus movimientos y asegurar la gloria para Pompeyo y para Roma.
          
    Junto al mensaje encriptado encuentras una nota, en la que pone: VIII
          
    El mensaje encriptado: 
    "tmoqwv bzma, uwdquqmvbw qvumlqibw pikqi tia kwtqvia lm xpizaitca. zmncmzhw vmkmaizqw mv mt ntivkw lmzmkpw xizi mvdwtdmz it mvmuqow. uivbmvoiv ti nwzuikqwv lm bmabclw piabi ti amvit lm ibiycm. dqkbwzqi maxmzi."
          
    ¿Usando la máquina del Cifrado César crees que puedes interceptar el mensaje?
          
    Pulsa enter para continuar.""")

    caesar_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "legion tres, movimiento inmediato hacia las colinas de pharsalus. refuerzo necesario en el flanco derecho para envolver al enemigo. mantengan la formacion de testudo hasta la senal de ataque. victoria espera.":
        print("El mensaje no ha sido desencriptado.\n")
        caesar_cipher()
        respuesta = input("Introduce el mensaje desencriptado: ")
        print()
    print(f"\n¡Correcto! ¡Ahora ya sabes los siguientes movimientos del ejército de Julio César!\n¡{name}, prepara una ofensiva para vencerles!\n")

    input("Pulsa enter para continuar.")
    clear_terminal()
    title()
    input(f"¡{name}, ya has aprendido como funciona el Cifrado César!\n\n¿Ves qué fácil?\n\n¡Ahora continua con el resto de lecciones y aprende todo sobre la criptografía!")


def lecciones_vigenere_cipher():
    print("¡Bienvenido A La Lección Del Cifrado Vigénere!")
    name = get_name()
    input(f"\n¡{name}, esta es la segunda lección! Aprenderás sobre el llamado \"cifrado indescifrable\".\n")
    input("""Historia Del Cifrado Vigénere\n
    El cifrado Vigenère, atribuido al francés Blaise de Vigenère en el siglo XVI, representa una evolución del cifrado por sustitución. 
          
    A pesar de su complejidad, que le valió el título de "cifrado indescifrable",
    fue finalmente descifrado en el siglo XIX gracias a los avances en el análisis de frecuencias.
          
    Breve explicación: el análisis de frecuencias permite, con gran complejidad matemática,
    asociar ciertas letras encriptadas a letras del abecedario original para desencriptar el mensaje.""")
    clear_terminal()
    title()
    print("""Teoría\n
    Este cifrado es un cifrado de sustitución más avanzado que el Cifrado César.
    
    A diferencia del cifrado César que utiliza un desplazamiento fijo,
    el cifrado Vigenère emplea una clave de palabra que corresponde a múltiples desplazamientos a lo largo del mensaje. 
    Esto significa que la letra a ser sustituida en el mensaje depende de la letra correspondiente de la clave.
          
    Para encriptar/desencriptar el mensaje, se necesita una contraseña:
    Por ejemplo: key (llave) = KEY
    
    Primero se repite la llave hasta que tenga la misma longitud que el texto que se va a encriptar/desencriptar:
    
    Clave repetida:       keykeykeykeykeykey
    Mensaje original:     atacar al amanecer
    Abecedario original: [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z]
          
    Para encriptar el mensaje:
    Desplazamos cada letra del mensaje un número de posiciones en el alfabeto igual al valor (índice) de la letra correspondiente de la clave en el alfabeto. 

    Así que, con nuestra clave 'KEY' y mensaje: "atacar al amanecer":
                                                                    _                                     _
                                             abecedario original:  [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z]
                                                                    _
            K --> 11 posiciones adelante --> abecedario shifteado: [k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a,b,c,d,e,f,g,h,i,j] --> k
                                                                                                          _
            E --> 5 posiciones adelante  --> abecedario shifteado: [e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,a,b,c,d] --> x
                                                                    _
            Y --> 25 posiciones adelante --> abecedario shifteado: [y,z,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x] --> y
                                             
    Mensaje encriptado: kxymep kp ywelogcb""")
    input()
    clear_terminal()
    title()
    print("""También se puede usar la matriz del Cifrado Vigénere:
                                                            
                                                              TEXTO
                a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z |
            -----------------------------------------------------------------------------------------------------------
            a : a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z |
            b : b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a |
            c : c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b |
            d : d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c |
            e : e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d |
            f : f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e |
            g : g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f |
            h : h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g |
            i : i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h |
            j : j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i |
            k : k | l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j |
            l : l | m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k |
   LLAVE    m : m | n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l |
            n : n | o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m |
            o : o | p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n |
            p : p | q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o |
            q : q | r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p |
            r : r | s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q |
            s : s | t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r |
            t : t | u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s |
            u : u | v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t |
            v : v | w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u |
            w : w | x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v |
            x : x | y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w |
            y : y | z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x |
            z : z | a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p | q | r | s | t | u | v | w | x | y |

    Para usar la matriz tienes que ir letra por letra mirando primero la fila de la LLAVE y cogiendo la columna de TEXTO, sacas la letra encriptada.
    Con el ejemplo anterior:
    
    Llave =   keykeykeykeykeykey
    Mensaje = atacar al amanecer
    
    fila k, columna a --> k
    fila e, columna t --> x
    fila y, columna a --> y
    ...
    fila y, columna r --> p
    
    Mensaje encriptado: kxymep ej ekkrcmip""")
    input()
    clear_terminal()
    title()
    print("""Para no tener que crear una matriz cada vez que vayamos a encriptar/desencriptar, podemos usar un truco:\n
        El truco consiste en sumar (restar si se desencripta) los índices de la letra del texto y de la letra de la llave, hacer su módulo 26 y eso dará un número entre 0 y 25.
        Este número será el índice de la letra encriptada/desencriptada.
        Los índices de todas las letras (incluyendo llave) se cogerán respecto al abecedario.
          
        Usando el ejemplo anterior:
        
        Llave =   keykeykeykeykeykey
        Mensaje = atacar al amanecer
        
        indíce texto + índice llave --> índice encriptado
           (a) 0      +   (k) 10     -->   (k) 10
           (t) 19     +   (e) 4     -->    (x) 23
           (a) 0      +   (y) 24     -->   (y) 24
           (c) 2      +   (k) 10     -->   (m) 12
           (a) 0      +   (e) 4      -->   (e) 4
           ...
           (r) 17     +   (y) 24     -->   (k) 41 (hacemos el módulo 26) --> (p) 15
        
        Mensaje encriptado: kxymep ej ekkrcmip
        
        Ahora vamos a desencriptarlo:
          
          índice encriptado - índice llave --> índice texto
              (k) 10        -    (k) 10    -->    (a) 0 
              (x) 23        -    (e) 4     -->    (t) 19
              (y) 24        -    (y) 24    -->    (a) 0
              (m) 12        -    (k) 10    -->    (c) 2
              (e) 4         -    (e) 4     -->    (a) 0
              ...       
              (p) 41        -    (y) 24    -->    (r) 17      o bien     (p) 15 - (y) 24 --> (r) -9  (se cuenta desde atrás)""")
    input()
    clear_terminal()
    title()
    print(f"""\n{"="*100}Ahora vamos a ver un ejemplo:\n
    Mensaje: "Hola Mundo!"
    Llave: "hola"

    Primero vamos a encriptar el mensaje usando el truco:
        llave + letra --> letra encriptada
          h   +   h   -->   o
          o   +   o   -->   c
          l   +   l   -->   w
          a   +   a   -->   a
          h   +       -->   
          o   +   m   -->   a
          l   +   u   -->   f
          a   +   m   -->   n
          h   +   d   -->   k
          o   +   o   -->   c   
          l   +   !   -->   !   
             
        Mensaje encriptado: ocwa afnkc!
    
    Ahora vamos a desencriptarlo sabiendo la llave: "hola" (también veremos que da igual el orden de la resta ya que el índice puede ser negativo también)
          letra encriptada   -   llave  --> letra desencriptada
              o (14)         -   h (7)  -->         h (7) 
              c (2)          -   o (14) -->         o (-12)
              w (22)         -   l (11) -->         l (11)
              a (0)          -   a (0)  -->         a (0)
                             -   h (7)  -->        
              a (0)          -   o (14) -->         m (-14)       
              f (5)          -   l (11) -->         u (-3)
              n (13)         -   a (0)  -->         n (13)
              k (10)         -   h (7)  -->         d (3)
              c (2)          -   o (14) -->         o (-12)
              !              -   l (11) -->         !
              
        Mensaje desencriptado: hola mundo!\n""")
    input("¡Antes de pasar al reto con máquina, intenta hacer este ejemplo tú mismo!")
    clear_terminal()
    title()
    print("""Reto Con Máquina:\n
    Imagina que has interceptado un mensaje cifrado durante una misión de espionaje. Sabes que el mensaje ha sido cifrado usando la clave "VIGENERE". 
    Sin embargo, el mensaje es confuso y necesitas descifrarlo para completar tu misión con éxito.\n 
    Aquí está el texto cifrado:

    "xqze wvgmmze ec vugrrgvv mt bpu wzohti. zavieie hiy vrjxmcigvsein."

    ¿Puedes descifrar el mensaje completo?""")
    vigenere_cipher()
    respuesta = input("Introduce el mensaje desencriptado: ")
    while respuesta != "cita secreta al amanecer en old bridge. esperen mas instrucciones.":
        print("El mensaje no ha sido desencriptado.\n")
        respuesta = input("Introduce el texto desencriptado: ")
    
    print(f"\n¡Enhorabuena, {name}! !Ya sabes cómo funciona el cifrado Vigénere!")
    print(f"\n!Queda un último cifrado clásico por aprender! ¡A por ello, {name}!")


def lecciones_rail_fence_cipher():
    pass


def lecciones_cifrados_simetricos():
    while True:
        clear_terminal()
        title()
        lecciones_cifrados_simetricos_choice = input(
            "========== Lecciones ==========\n===== Cifrados Simétricos =====\n1. Cifrado AES-56\n2. Cifrado DES\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
        if lecciones_cifrados_simetricos_choice == "1":
            lecciones_AES_cipher()
        elif lecciones_cifrados_simetricos_choice == "2":
            lecciones_DES_cipher()
        elif lecciones_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_AES_cipher():
    pass


def lecciones_DES_cipher():
    pass


def lecciones_cifrados_asimetricos():
    while True:
        clear_terminal()
        title()
        maquinas_cifrados_simetricos_choice = input(
            "========== Lecciones ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
        if maquinas_cifrados_simetricos_choice == "1":
            lecciones_RSA_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            lecciones_ECC_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_RSA_cipher():
    pass


def lecciones_ECC_cipher():
    pass


def retos_menu():
    while True:
        clear_terminal()
        title()
        retos_choice = input("===== Retos =====\n1. ")
        clear_terminal()
        title()
        # opciones = ...


def maquinas_menu():
    while True:
        clear_terminal()
        title()
        maquinas_choice = input(
            "===== Máquinas =====\n1. Cifrados Clásicos\n2. Cifrado Simétricos\n3. Cifrados Asimétricos\n4. Hashes\n5. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
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
        title()
        maquinas_cifrados_clasicos_choice = input(
            "========= Máquinas ==========\n===== Cifrados Clásicos =====\n1. Cifrado César\n2. Cifrado Vigénere\n3. Cifrado Rail Fence\n4. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
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
        title()
        maquinas_cifrados_simetricos_choice = input(
            "========== Máquinas ===========\n===== Cifrados Simétricos =====\n1. Cifrado AES-56\n2. Cifrado DES\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
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
        title()
        maquinas_cifrados_simetricos_choice = input(
            "=========== Máquinas ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        title()
        if maquinas_cifrados_simetricos_choice == "1":
            RSA_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            ECC_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def exit_programa():
    print("Saliendo del programa...")
    exit(0)


if __name__ == "__main__":
    main_menu()
