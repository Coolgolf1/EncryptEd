# Lecciones
from funciones_maquinas import *
from funciones_ct_gn import *


def lecciones_menu():
    while True:
        clear_terminal()
        lecciones_choice = input(
            "===== Lecciones =====\n1. Introducción\n2. Cifrados Clásicos\n3. Cifrados Simétricos\n4. Cifrados Asimétricos\n5. Hashes\n6. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
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
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print("¡Bienvenido A La Lección Introductoria De EncryptEd!")
    input(f"\nPerfecto, {name}! Vamos a empezar con una introducción de como funciona el programa. Después, veremos los conocimientos básicos de la criptografía que debes saber.")
    clear_terminal()
    f = open(".\Lecciones\intro\estructura_intro.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input("\nPulsa enter para continuar.")
    clear_terminal()
    print("""¿Qué Es La Criptografía?:\n\nDefinición formal: La criptografía es el arte y la ciencia de cifrar mensajes para proteger su contenido.\n""")
    f = open(".\Lecciones\intro\historia_intro.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input("\nPulsa enter para continuar.")
    clear_terminal()
    f = open(".\Lecciones\intro\\recomendacion_intro.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    input("\nRecuerda: deberías empezar por la clase del cifrado César. Pulsa enter para continuar.")


def lecciones_cifrados_clasicos():
    while True:
        clear_terminal()
        lecciones_cifrados_clasicos_choice = input(
            "========= Lecciones =========\n===== Cifrados Clásicos =====\n1. Cifrado César\n2. Cifrado Vigènere\n3. Cifrado Rail Fence\n4. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
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
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print("¡Bienvenido A La Lección Del Cifrado César!")
    input(f"\n¡{name}, hoy te embarcas en tu primera lección de criptografía!\n")
    f = open(".\Lecciones\caesar\historia_caesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\caesar\\teoria_caesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    print(f"""\n{"="*100}""")
    f = open(".\Lecciones\caesar\\ejemplo_caesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input(f"{name}, debes entender esto muy bien para seguir con los retos. Pulsa enter para ir a los retos.")
    print("""Reto Manual:\n
    Texto encriptado: "¡pxb elhq!"
    Llave: (el segundo número primo)\n
    Intenta desencriptarlo de forma manual, con una hoja y un boli.\n""")
    respuesta_1 = input("Introduce el texto desencriptado: ")
    while respuesta_1 != "¡muy bien!":
        print("El mensaje no ha sido desencriptado.\n")
        respuesta_1 = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡Genial, {name} has aprendido el funcionamiento del Cifrado César!\n")
    print("El siguiente reto es un reto automático, haciendo uso de la máquina del Cifrado César implementada en el programa.")
    input()
    clear_terminal()
    f = open(".\Lecciones\caesar\\reto_caesar.txt", "r", encoding="utf-8")
    print(f"""Reto Con Máquina:\n\n{name}, {f.read()}""")
    f.close()
    input("Pulsa enter para continuar.")
    caesar_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "legion tres, movimiento inmediato hacia las colinas de pharsalus. refuerzo necesario en el flanco derecho para envolver al enemigo. mantengan la formacion de testudo hasta la senal de ataque. victoria espera.":
        print("El mensaje no ha sido desencriptado.\n")
        caesar_cipher()
        respuesta = input("Introduce el mensaje desencriptado: ")
        print()
    print(
        f"\n¡Correcto! ¡Ahora ya sabes los siguientes movimientos del ejército de Julio César!\n¡{name}, prepara una ofensiva para vencerles!\n")

    input("Pulsa enter para continuar.")
    clear_terminal()
    print(f"¡{name}, ya has aprendido como funciona el Cifrado César!\n\n¿Ves qué fácil?\n\n¡Ahora continua con el resto de lecciones y aprende todo sobre la criptografía!")
    input()


def lecciones_vigenere_cipher():
    print("¡Bienvenido A La Lección Del Cifrado Vigènere!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    input(f"\n¡{name}, esta es la segunda lección! Aprenderás sobre el llamado \"cifrado indescifrable\".\n")
    f = open(".\Lecciones\\vigenere\\historia_vigenere.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    clear_terminal()
    f = open(".\Lecciones\\vigenere\\teoria_1_vigenere.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\vigenere\\teoria_2_vigenere.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\vigenere\\teoria_3_vigenere.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    print(f"""\n{"="*100}\nAhora vamos a ver un ejemplo:\n""")
    f = open(".\Lecciones\\vigenere\\ejemplo_vigenere.txt",
             "r", encoding="utf-8")
    print(f.read())
    f.close()
    input("\n¡Antes de pasar al reto con máquina, intenta hacer este ejemplo tú mismo!")
    clear_terminal()
    f = open(".\Lecciones\\vigenere\\reto_vigenere.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    vigenere_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "cita secreta al amanecer en old bridge. esperen mas instrucciones.":
        print("El mensaje no ha sido desencriptado.\n")
        respuesta = input("Introduce el texto desencriptado: ")

    print(
        f"\n¡Enhorabuena, {name}! !Ya sabes cómo funciona el cifrado Vigènere!")
    print(
        f"\n!Queda un último cifrado clásico por aprender! ¡A por ello, {name}!")
    input()


def lecciones_rail_fence_cipher():
    print("¡Bienvenido A La Lección Del Cifrado Rail Fence!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print(f"""\n¡{name}, esta es la tercera y última lección de los cifrados clásicos!\n\nAprenderás sobre un cifrado de trasposición, el Rail Fence, en vez de cifrados de sustitución cómo los anteriores.\n""")
    input()
    clear_terminal()
    f = open(".\Lecciones\\rail_fence\\historia_rf.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\rail_fence\\teoria_rf.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\rail_fence\\ejemplo_rf.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input(f"\n¡{name} si entiendes este ejemplo, pulsa entera para ir a los retos!")
    clear_terminal()
    f = open(".\Lecciones\\rail_fence\\reto_rf.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    rail_fence_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "encuentro secreto en el muelle al amanecer":
        print("El mensaje no ha sido desencriptado.\n")
        respuesta = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡Enhorabuena {name}! ¡Has terminado las tres lecciones de los cifrados clásicos!\n")
    print(f"Ahora, {name}, empieza lo interesante... !Prepárate para los cifrados simétricos y asimétricos! Empieza lo bueno ;)")
    input()


def lecciones_cifrados_simetricos():
    while True:
        clear_terminal()
        lecciones_cifrados_simetricos_choice = input(
            "========== Lecciones ==========\n===== Cifrados Simétricos =====\n1. Cifrado AES-256\n2. Cifrado DES\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if lecciones_cifrados_simetricos_choice == "1":
            lecciones_AES_cipher()
        elif lecciones_cifrados_simetricos_choice == "2":
            lecciones_DES_cipher()
        elif lecciones_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_AES_cipher():
    print("¡Bienvenido A La Lección Del Cifrado AES!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, ahora empieza lo interesante! Vas a aprender mucho sobre el cifrado más importante del mundo, usado en todo tipo de sistemas digitales y de comunicación, como WhatsApp.\n
Bienvenido al corazón de la seguridad en internet.""")
    input()
    clear_terminal()
    f = open(".\Lecciones\\aes\historia_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\aes\\teoria_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print(f"\n{name}, es bastante abstracto, por lo que es normal si no lo entiendes de primeras.\n\nVuelve a leerlo hasta que entiendas la estructura.")
    input()
    clear_terminal()
    f = open(".\Lecciones\\aes\ejemplo_encrypt_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    print(f"""{"="*100}""")
    f = open(".\Lecciones\\aes\ejemplo_decrypt_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\aes\\reto_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print(
        f"\n¡Buena suerte agente {name}! Necesitamos que desencriptes el texto para poder avanzar en la misión.\n")
    caesar_cipher()
    AES_cipher()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "reunión en la cafetería de la esquina a las 10 p.m. trae los documentos.":
        print("El mensaje no ha sido desencriptado.\n")
        print("Pista: mira la longitud de la clave... puede ser el número de shifts")
        caesar_cipher()
        AES_cipher()
        respuesta = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡Muy bien, agente {name}! Hemos conseguido adelantarnos al espía y hemos podido capturarle.")
    input()
    clear_terminal()
    print(
        f"\n¡¡¡{name} has aprendido sobre el cifrado más importante del mundo!!!\n\n¡Enhorabuena!")
    input()
    print(f"\nEn el siguiente cifrado vamos a volver algo atrás en el tiempo... al sistema de cifrado anterior al AES. El DES.")
    input()


def lecciones_DES_cipher():
    print("¡Bienvenido A La Lección Del Cifrado DES!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, prepárate para explorar el Data Encryption Standard (DES), el precursor de la criptografía moderna!\n 
Aunque hoy ha sido superado por tecnologías más avanzadas, DES jugó un papel crucial en la historia del cifrado digital.\n 
Fue el estándar de oro para la seguridad de datos durante décadas y sentó las bases para los sistemas de cifrado que usamos hoy en día.\n 
¡Descubramos juntos cómo este algoritmo clásico transformó el mundo de la seguridad digital!""")
    input()
    clear_terminal()
    f = open(".\Lecciones\des\historia_des.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\des\\teoria_des.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print(f"\n{name}, como puedes observar, es un cifrado más simple que el AES. Por ello, dejó de usarse, ya que no era lo suficientemente seguro.")
    input()
    clear_terminal()
    f = open(".\Lecciones\\des\ejemplo_encrypt_des.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    print(f"""{"="*100}""")
    f = open(".\Lecciones\\des\ejemplo_decrypt_des.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\des\\reto_des.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    DES_cipher()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "en la base del viejo roble, donde la sombra toca el río al amanecer, encontrarás lo que buscas.":
        print("El mensaje no ha sido desencriptado.\n")
        DES_cipher()
        respuesta = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡Enhorabuena, {name}! ¡¡¡Es hora de ir a por el oro!!!.")
    input()
    clear_terminal()
    print(
        f"\n¡{name}, ya lo sabes todo sobre los cifrados simétricos!\n\n¡Enhorabuena!")
    input()
    print(f"\nSiguiente: cifrados asimétricos, hmmm.... ¿como serán?\n¡Vamos a descubrirlo!")
    input()


def lecciones_cifrados_asimetricos():
    while True:
        clear_terminal()
        maquinas_cifrados_simetricos_choice = input(
            "========== Lecciones ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_simetricos_choice == "1":
            lecciones_RSA_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            lecciones_ECC_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def RSA_cipher_process_lecciones(plaintext, RSA_key, modo):
    if modo == "E":
        RSA_cipher = PKCS1_OAEP.new(RSA_key)
        encrypted_message = RSA_cipher.encrypt(plaintext.encode())
        return binascii.hexlify(encrypted_message).decode()
    else:
        RSA_cipher = PKCS1_OAEP.new(RSA_key)
        decrypted_message = RSA_cipher.decrypt(binascii.unhexlify(plaintext))
        return decrypted_message.decode()


def RSA_cipher_lecciones():
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
            RSA_public_key = cargar_llave_de_archivo("public_key_leccion.pem")
            encrypted_text = RSA_cipher_process(plaintext, RSA_public_key, "E")
            print(
                f"\nEl texto encriptado es: \n{encrypted_text}\n\nCifrado RSA\n\n")

        else:
            RSA_private_key = cargar_llave_de_archivo(
                'private_key_leccion.pem')
            decrypted_text = RSA_cipher_process(
                plaintext, RSA_private_key, "D")
            print(
                f"\nEl texto desencriptado es: \n{decrypted_text}\n\nCifrado RSA\n\n")
        input("Pulsa enter para continuar.")
    except:
        print("Has introducido algún dato de forma incorrecta.")


def lecciones_RSA_cipher():
    print("¡Bienvenido A La Lección Del Cifrado RSA!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, explora el mundo de RSA, el pilar de la criptografía asimétrica que protege las comunicaciones digitales!\n 
Descubre cómo este algoritmo esencial asegura la privacidad y la autenticidad en el vasto mundo de Internet.""")
    input()
    clear_terminal()
    f = open(".\Lecciones\\rsa\historia_rsa.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\rsa\\teoria_rsa.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print(f"\n{name}, como se puede observar, el cifrado RSA requiere un cierto nivel matemático, aunque podemos entender la parte teórica del cifrado.")
    input()
    clear_terminal()
    f = open(".\Lecciones\\rsa\ejemplo_encrypt_rsa.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    print(f"""{"="*100}""")
    f = open(".\Lecciones\\rsa\ejemplo_decrypt_rsa.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\\rsa\\reto_rsa.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    RSA_cipher_lecciones()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "descubierto: un método innovador para fortalecer rsa contra futuros ataques cuánticos.":
        print("El mensaje no ha sido desencriptado.\n")
        RSA_cipher_lecciones()
        respuesta = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡{name}, vamos a buscar por el resto de su laboratorio a ver si encontramos el gran descubrimiento!")
    input()
    clear_terminal()
    print(
        f"\n¡{name}, ya has aprendido sobre el cifrado RSA, uno de los más importantes en todo el mundo!\n\n¡Enhorabuena!")
    input()
    print(f"\n!A por el cifrado de Curva Elíptica! Suena raro, pero sí, existe un cifrado con ese nombre...")
    input()


def ECC_cipher_lecciones():
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
            ECC_public_key_pem = leer_de_archivo("public_key_lecciones.pem")
            ECC_private_key_pem = leer_de_archivo("private_key_lecciones.pem")
            nonce_b64 = leer_de_archivo("nonce_lecciones.txt")
            tag_b64 = leer_de_archivo("tag_lecciones.txt")
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


def lecciones_ECC_cipher():
    print("¡Bienvenido A La Lección Del Cifrado ECC!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, sumérgete en el elegante mundo de ECC, la criptografía basada en curvas elípticas!\n 
Esta tecnología moderna ofrece seguridad robusta con claves más cortas, siendo esencial para proteger comunicaciones móviles y transacciones en línea.\n 
Descubre cómo ECC combina matemáticas avanzadas con seguridad digital para crear un sistema criptográfico eficiente y poderoso.""")
    input()
    clear_terminal()
    f = open(".\Lecciones\ecc\historia_ecc.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\ecc\\teoria_ecc.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print(f"\n{name}, al igual que RSA, requiere un cierto nivel en matemáticas, pero la teoría se puede seguir para entender el cifrado.")
    input()
    clear_terminal()
    f = open(".\Lecciones\ecc\ejemplo_encrypt_ecc.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    print(f"""{"="*100}""")
    f = open(".\Lecciones\ecc\ejemplo_decrypt_ecc.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    clear_terminal()
    f = open(".\Lecciones\ecc\\reto_ecc.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    ECC_cipher_lecciones()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "revelado: las coordenadas secretas del antiguo templo oculto en la selva amazónica.":
        print("El mensaje no ha sido desencriptado.\n")
        ECC_cipher_lecciones()
        respuesta = input("Introduce el texto desencriptado: ")
    print(
        f"\n¡{name}, vamos al templo! ¡Pero cuidado con las trampas que puede haber!")
    input()
    clear_terminal()
    print(
        f"\n¡{name}, ya sabes todo lo básico sobre cifrados asimétricos!\n\n¡Enhorabuena!")
    input()
    print(
        f"\n¿Por qué no pruebas los retos, {name}? Puede que sean interesantes ;)")
    input()
