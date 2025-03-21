# Lecciones
from funciones_maquinas import *
from funciones_misc import *
import json


def lecciones_menu():
    """En este menú imprimo las lecciones y doy la opción al usuario para elegir cuál quiere hacer.
    """
    lecciones_choice = ""
    while lecciones_choice != "5":
        clear_terminal()
        lecciones_choice = input(
            "===== Lecciones =====\n1. Introducción\n2. Cifrados Clásicos\n3. Cifrados Simétricos\n4. Cifrados Asimétricos\n5. Atrás\n\nIntroduce tu opción: ")
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
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def lecciones_introduccion():
    """LLamo a los archivos json de la introducción, la primera lección.
    """
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print("¡Bienvenido A La Lección Introductoria De EncryptEd!")
    input(f"\nPerfecto, {name}! Vamos a empezar con una introducción de como funciona el programa. Después, veremos los conocimientos básicos de la criptografía que debes saber.")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['intro']['estructura'])
    input("\nPulsa enter para continuar.")
    clear_terminal()
    print("""¿Qué Es La Criptografía?:\n\nDefinición formal: La criptografía es el arte y la ciencia de cifrar mensajes para proteger su contenido.\n""")
    print(data['lecciones']['intro']['historia'])
    input("\nPulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['intro']['recomendacion'])
    input("\nRecuerda: deberías empezar por la clase del cifrado César. Pulsa enter para continuar.")


def lecciones_cifrados_clasicos():
    """En este menú imprimo las lecciones en la categoría de los cifrados clásicos y doy la opción al usuario para elegir cuál quiere hacer.
    """
    lecciones_cifrados_clasicos_choice = ""
    while lecciones_cifrados_clasicos_choice != "4":
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
    """LLamo a los archivos json de la lección del cifrado césar y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print("¡Bienvenido A La Lección Del Cifrado César!")
    input(f"\n¡{name}, hoy te embarcas en tu primera lección de criptografía!\n")
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['clasicos']['cesar']['historia'])
    input("\nPulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['clasicos']['cesar']['teoria'])
    input("\nPulsa entera para continuar.")
    print(f"""\n{"="*100}""")
    print(data['lecciones']['clasicos']['cesar']['ejemplo'])
    input(f"\n{name}, debes entender esto muy bien para seguir con los retos. Pulsa enter para ir a los retos.")
    print("""Reto Manual:\n
    Texto encriptado: "¡pxb elhq!"
    Llave: (el segundo número primo)\n
    Intenta desencriptarlo de forma manual, con una hoja y un boli.\n""")
    respuesta_1 = input("Introduce el texto desencriptado: ")
    while respuesta_1 != "¡muy bien!" and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        respuesta_1 = input("Introduce el texto desencriptado: ")
        cansado = funcion_cansado()
        print()
    if not cansado:
        print(
            f"\n¡Genial, {name} has aprendido el funcionamiento del Cifrado César!\n")
        print("El siguiente reto es un reto automático, haciendo uso de la máquina del Cifrado César implementada en el programa.")
        input("Pulsa enter para continuar")
        clear_terminal()
        print()
        print(
            f"""Reto Con Máquina:\n\n{name}, {data['lecciones']['clasicos']['cesar']['reto']}""")
        input("Pulsa enter para continuar.")
        caesar_cipher()
        respuesta = input("\nIntroduce el mensaje desencriptado: ")
        while respuesta != "legion tres, movimiento inmediato hacia las colinas de pharsalus. refuerzo necesario en el flanco derecho para envolver al enemigo. mantengan la formacion de testudo hasta la senal de ataque. victoria espera." and not cansado:
            print("El mensaje no ha sido desencriptado.\n")
            caesar_cipher()
            respuesta = input("Introduce el mensaje desencriptado: ")
            if respuesta != "legion tres, movimiento inmediato hacia las colinas de pharsalus. refuerzo necesario en el flanco derecho para envolver al enemigo. mantengan la formacion de testudo hasta la senal de ataque. victoria espera.":
                cansado = funcion_cansado()
            print()
        if not cansado:
            print(
                f"\n¡Correcto! ¡Ahora ya sabes los siguientes movimientos del ejército de Julio César!\n¡{name}, prepara una ofensiva para vencerles!\n")
        else:
            input("¡Inténtalo de nuevo en otro momento!")

        input("Pulsa enter para continuar.")
        clear_terminal()
        print(f"¡{name}, ya has aprendido como funciona el Cifrado César!\n\n¿Ves qué fácil?\n\n¡Ahora continua con el resto de lecciones y aprende todo sobre la criptografía!")
        input("Pulsa enter para continuar.")
    else:
        input("¡Inténtalo de nuevo en otro momento!")


def lecciones_vigenere_cipher():
    """LLamo a los archivos json de la lección del cifrado vigènere y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado Vigènere!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    input(f"\n¡{name}, esta es la segunda lección! Aprenderás sobre el llamado \"cifrado indescifrable\".\n")
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['clasicos']['vigenere']['historia'])
    clear_terminal()
    print(data['lecciones']['clasicos']['vigenere']['teoria_1'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['clasicos']['vigenere']['teoria_2'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['clasicos']['vigenere']['teoria_3'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(f"""\n{"="*100}\nAhora vamos a ver un ejemplo:\n""")
    print(data['lecciones']['clasicos']['vigenere']['ejemplo'])
    input("\n¡Antes de pasar al reto con máquina, intenta hacer este ejemplo tú mismo!")
    clear_terminal()
    print(data['lecciones']['clasicos']['vigenere']['reto'])
    vigenere_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "cita secreta al amanecer en old bridge. esperen mas instrucciones." and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "cita secreta al amanecer en old bridge. esperen mas instrucciones.":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡Enhorabuena, {name}! !Ya sabes cómo funciona el cifrado Vigènere!")
        print(
            f"\n!Queda un último cifrado clásico por aprender! ¡A por ello, {name}!")
        input("Pulsa enter para continuar.")
    else:
        input("¡Inténtalo de nuevo en otro momento!")


def lecciones_rail_fence_cipher():
    """LLamo a los archivos json de la lección del cifrado rail fence y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado Rail Fence!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    print(f"""\n¡{name}, esta es la tercera y última lección de los cifrados clásicos!\n\nAprenderás sobre un cifrado de trasposición, el Rail Fence, en vez de cifrados de sustitución cómo los anteriores.\n""")
    input("Pulsa enter para continuar.")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['clasicos']['rail_fence']['historia'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['clasicos']['rail_fence']['teoria'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['clasicos']['rail_fence']['ejemplo'])
    input(f"\n¡{name} si entiendes este ejemplo, pulsa entera para ir a los retos!")
    clear_terminal()
    print(data['lecciones']['clasicos']['rail_fence']['reto'])
    input("Pulsa enter para continuar.")
    rail_fence_cipher()
    respuesta = input("\nIntroduce el mensaje desencriptado: ")
    while respuesta != "encuentro secreto en el muelle al amanecer" and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "encuentro secreto en el muelle al amanecer":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡Enhorabuena {name}! ¡Has terminado las tres lecciones de los cifrados clásicos!\n")
        print(
            f"Ahora, {name}, empieza lo interesante... !Prepárate para los cifrados simétricos y asimétricos! Empieza lo bueno ;)")
        input("Pulsa enter para continuar")
    else:
        input("¡Inténtalo de nuevo en otro momento!")


def lecciones_cifrados_simetricos():
    """En este menú imprimo las lecciones en la categoría de los cifrados simétricos y doy la opción al usuario para elegir cuál quiere hacer.
    """
    lecciones_cifrados_simetricos_choice = ""
    while lecciones_cifrados_simetricos_choice != "3":
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
    """LLamo a los archivos json de la lección del cifrado AES y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado AES!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, ahora empieza lo interesante! Vas a aprender mucho sobre el cifrado más importante del mundo, usado en todo tipo de sistemas digitales y de comunicación, como WhatsApp.\n
Bienvenido al corazón de la seguridad en internet.""")
    input("Pulsa entera para continuar.")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['simetricos']['aes']['historia'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['simetricos']['aes']['teoria'])
    print(f"\n{name}, es bastante abstracto, por lo que es normal si no lo entiendes de primeras.\n\nVuelve a leerlo hasta que entiendas la estructura.")
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['simetricos']['aes']['ejemplo_encrypt'])
    input("Pulsa enter para continuar.")
    print(f"""{"="*100}""")
    print(data['lecciones']['simetricos']['aes']['ejemplo_decrypt'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['simetricos']['aes']['reto'])
    print(
        f"\n¡Buena suerte agente {name}! Necesitamos que desencriptes el texto para poder avanzar en la misión.\n")
    caesar_cipher()
    AES_cipher()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "reunión en la cafetería de la esquina a las 10 p.m. trae los documentos." and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        print("Pista: mira la longitud de la clave... puede ser el número de shifts")
        caesar_cipher()
        AES_cipher()
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "reunión en la cafetería de la esquina a las 10 p.m. trae los documentos.":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡Muy bien, agente {name}! Hemos conseguido adelantarnos al espía y hemos podido capturarle.")
        input("Pulsa enter para continuar")
        clear_terminal()
        print(
            f"\n¡¡¡{name} has aprendido sobre el cifrado más importante del mundo!!!\n\n¡Enhorabuena!")
        input("Pulsa enter para continuar")
        print(f"\nEn el siguiente cifrado vamos a volver algo atrás en el tiempo... al sistema de cifrado anterior al AES. El DES.")
        input("Pulsa enter para continuar")
    else:
        input("Inténtalo de nuevo en otro momento!")


def lecciones_DES_cipher():
    """LLamo a los archivos json de la lección del cifrado DES y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado DES!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, prepárate para explorar el Data Encryption Standard (DES), el precursor de la criptografía moderna!\n
Aunque hoy ha sido superado por tecnologías más avanzadas, DES jugó un papel crucial en la historia del cifrado digital.\n
Fue el estándar de oro para la seguridad de datos durante décadas y sentó las bases para los sistemas de cifrado que usamos hoy en día.\n
¡Descubramos juntos cómo este algoritmo clásico transformó el mundo de la seguridad digital!""")
    input("Pulsa enter para continuar")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['simetricos']['des']['historia'])
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['simetricos']['des']['teoria'])
    print(f"\n{name}, como puedes observar, es un cifrado más simple que el AES. Por ello, dejó de usarse, ya que no era lo suficientemente seguro.")
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['simetricos']['des']['ejemplo_encrypt'])
    input("Pulsa enter para continuar")
    print(f"""{"="*100}""")
    print(data['lecciones']['simetricos']['des']['ejemplo_decrypt'])
    input("Pulsa enter para continuar.")
    clear_terminal()
    print(data['lecciones']['simetricos']['des']['reto'])
    print("Pulsa enter para continuar.")
    DES_cipher()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "en la base del viejo roble, donde la sombra toca el río al amanecer, encontrarás lo que buscas." and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        DES_cipher()
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "en la base del viejo roble, donde la sombra toca el río al amanecer, encontrarás lo que buscas.":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡Enhorabuena, {name}! ¡¡¡Es hora de ir a por el oro!!!.")
        input("Pulsa enter para continuar")
        clear_terminal()
        print(
            f"\n¡{name}, ya lo sabes todo sobre los cifrados simétricos!\n\n¡Enhorabuena!")
        input("Pulsa enter para continuar")
        print(f"\nSiguiente: cifrados asimétricos, hmmm.... ¿como serán?\n¡Vamos a descubrirlo!")
        input("Pulsa enter para continuar")
    else:
        input("¡Inténtalo de nuevo en otro momento!")


def lecciones_cifrados_asimetricos():
    """En este menú imprimo las lecciones en la categoría de los cifrados asimétricos y doy la opción al usuario para elegir cuál quiere hacer.
    """
    lecciones_cifrados_asimetricos_choice = ""
    while lecciones_cifrados_asimetricos_choice != "3":
        clear_terminal()
        lecciones_cifrados_asimetricos_choice = input(
            "========== Lecciones ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if lecciones_cifrados_asimetricos_choice == "1":
            lecciones_RSA_cipher()
        elif lecciones_cifrados_asimetricos_choice == "2":
            lecciones_ECC_cipher()
        elif lecciones_cifrados_asimetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def RSA_cipher_lecciones():
    """Aquí está la lógica del cifrado RSA y las llaves guardadas en archivos para poder descifrar correctamente el mensaje que se le da al usuario por pantalla.
    Esto es necesario ya que cada vez que se genera un mensaje va ligado a sus llaves, y si las llaves cambian, este reto no se podría completar, por lo que,
    esas llaves están guardadas en un archivo diferente al que usa la máquina de encriptar RSA.
    """
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
    """LLamo a los archivos json de la lección del cifrado RSA y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado RSA!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, explora el mundo de RSA, el pilar de la criptografía asimétrica que protege las comunicaciones digitales!\n
Descubre cómo este algoritmo esencial asegura la privacidad y la autenticidad en el vasto mundo de Internet.""")
    input("Pulsa enter para continuar")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['asimetricos']['rsa']['historia'])
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['rsa']['teoria'])
    print(f"\n{name}, como se puede observar, el cifrado RSA requiere un cierto nivel matemático, aunque podemos entender la parte teórica del cifrado.")
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['rsa']['ejemplo_encrypt'])
    input("Pulsa enter para continuar")
    print(f"""{"="*100}""")
    print(data['lecciones']['asimetricos']['rsa']['ejemplo_decrypt'])
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['rsa']['reto'])
    print()
    RSA_cipher_lecciones()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "descubierto: un método innovador para fortalecer rsa contra futuros ataques cuánticos." and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        RSA_cipher_lecciones()
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "descubierto: un método innovador para fortalecer rsa contra futuros ataques cuánticos.":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡{name}, vamos a buscar por el resto de su laboratorio a ver si encontramos el gran descubrimiento!")
        input("Pulsa enter para continuar")
        clear_terminal()
        print(
            f"\n¡{name}, ya has aprendido sobre el cifrado RSA, uno de los más importantes en todo el mundo!\n\n¡Enhorabuena!")
        input("Pulsa enter para continuar")
        print(f"\n!A por el cifrado de Curva Elíptica! Suena raro, pero sí, existe un cifrado con ese nombre...")
        input("Pulsa enter para continuar")
    else:
        input("¡Inténtalo de nuevo en otro momento!")


def ECC_cipher_lecciones():
    """Aquí está la lógica del cifrado ECC y las llaves guardadas en archivos para poder descifrar correctamente el mensaje que se le da al usuario por pantalla.
    Esto es necesario ya que cada vez que se genera un mensaje va ligado a sus llaves, y si las llaves cambian, este reto no se podría completar, por lo que,
    esas llaves están guardadas en un archivo diferente al que usa la máquina de encriptar ECC.
    """
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
    """LLamo a los archivos json de la lección del cifrado de curva elíptica y en la parte de los retos hago un check del input para ver si el mensaje ha sido descifrado correctamente.
    """
    cansado = False
    print("¡Bienvenido A La Lección Del Cifrado ECC!")
    f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
    name = f.read()
    f.close()
    print(f"""\n¡{name}, sumérgete en el elegante mundo de ECC, la criptografía basada en curvas elípticas!\n
Esta tecnología moderna ofrece seguridad robusta con claves más cortas, siendo esencial para proteger comunicaciones móviles y transacciones en línea.\n
Descubre cómo ECC combina matemáticas avanzadas con seguridad digital para crear un sistema criptográfico eficiente y poderoso.""")
    input("Pulsa enter para continuar")
    clear_terminal()
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['lecciones']['asimetricos']['ecc']['historia'])
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['ecc']['teoria'])
    print(f"\n{name}, al igual que RSA, requiere un cierto nivel en matemáticas, pero la teoría se puede seguir para entender el cifrado.")
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['ecc']['ejemplo_encrypt'])
    input("Pulsa enter para continuar")
    print(f"""{"="*100}""")
    print(data['lecciones']['asimetricos']['ecc']['ejemplo_decrypt'])
    input("Pulsa enter para continuar")
    clear_terminal()
    print(data['lecciones']['asimetricos']['ecc']['reto'], "\n")
    ECC_cipher_lecciones()
    respuesta = input("\nIntroduce el texto desencriptado: ")
    while respuesta != "revelado: las coordenadas secretas del antiguo templo oculto en la selva amazónica." and not cansado:
        print("El mensaje no ha sido desencriptado.\n")
        ECC_cipher_lecciones()
        respuesta = input("Introduce el texto desencriptado: ")
        if respuesta != "revelado: las coordenadas secretas del antiguo templo oculto en la selva amazónica.":
            cansado = funcion_cansado()
    if not cansado:
        print(
            f"\n¡{name}, vamos al templo! ¡Pero cuidado con las trampas que puede haber!")
        input("Pulsa enter para continuar")
        clear_terminal()
        print(
            f"\n¡{name}, ya sabes todo lo básico sobre cifrados asimétricos!\n\n¡Enhorabuena!")
        input("Pulsa enter para continuar")
        print(
            f"\n¿Por qué no pruebas los retos, {name}? Puede que sean interesantes ;)")
        input("Pulsa enter para continuar")
    else:
        input("¡Inténtalo de nuevo en otro momento!")
