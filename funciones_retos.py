from funciones_misc import *
from funciones_maquinas import *
import json


def retos_menu():
    """En este menú imprimo el nombre de los retos y le doy la opción al usuario de elegir cuál quiere hacer.
    """
    retos_choice = ""
    while retos_choice != "11":
        clear_terminal()
        retos_choice = input(
            """===== Retos =====
1. El Código de César
2. El Secreto de la Relatividad
3. Mensajes Ocultos en la Vía Férrea
4. El Misterio del Cifrado AES 
5. Descifrando el Código Bancario
6. La Misión Diplomática Cifrada
7. El Código Estelar
8. El Legado de Turing
9. El Enigma de la Esfinge
10. El Secreto de la Atlántida 
11. Atrás\n\nIntroduce tu opción: """)
        clear_terminal()
        if retos_choice == "1":
            el_codigo_del_cesar()
        elif retos_choice == "2":
            el_secreto_de_la_relatividad()
        elif retos_choice == "3":
            mensajes_ocultos_en_la_via_ferrea()
        elif retos_choice == "4":
            el_misterio_del_cifrado_aes()
        elif retos_choice == "5":
            descifrando_el_codigo_bancario()
        elif retos_choice == "6":
            la_mision_diplomatica_cifrada()
        elif retos_choice == "7":
            el_codigo_estelar()
        elif retos_choice == "8":
            el_legado_de_turing()
        elif retos_choice == "9":
            el_enigma_de_la_esfinge()
        elif retos_choice == "10":
            el_secreto_de_la_atlantida()
        elif retos_choice == "11":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")
        clear_terminal()


def el_codigo_del_cesar():
    """Imprime mediante las diferentes partes del json el reto del código del césar y chequea que el input sea el mensaje descifrado correctamente.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_codigo_del_cesar'])
    input()
    caesar_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "veni, vidi, vici":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        caesar_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Excelente trabajo! Has descifrado el código de César y revelado un pedazo de historia. 
Al igual que Julio César conquistó territorios, tú has conquistado este reto criptográfico. 
Prepárate para más desafíos en el mundo de los códigos secretos.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_secreto_de_la_relatividad():
    """Imprime mediante las diferentes partes del json el reto del secreto de la relatividad y chequea que el input sea el mensaje descifrado correctamente.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_secreto_de_la_relatividad'])
    input()
    vigenere_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "la imaginacion es mas importante que el conocimiento.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        vigenere_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Has revelado con éxito el mensaje oculto! 
Al igual que Einstein revolucionó nuestra comprensión del universo, tú has desentrañado un misterio de la criptografía. 
Sigue adelante para descubrir más secretos encriptados.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def mensajes_ocultos_en_la_via_ferrea():
    """Imprime mediante las diferentes partes del json el reto de los mensajes ocultos en la vía férrea y chequea que el input sea el mensaje descifrado correctamente.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['mensajes_ocultos_en_la_via_ferrea'])
    input()
    rail_fence_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "la solucion esta en los detalles mas insignificantes.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        rail_fence_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Brillante! Has descifrado con éxito el mensaje oculto en la vía férrea
y encontrado las pistas que incluso el mejor detective del siglo XIX pasó por alto. 
Tu agudeza para descifrar códigos te llevará lejos en el mundo de la criptografía.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_misterio_del_cifrado_aes():
    """Imprime mediante las diferentes partes del json el reto del misterio del cifrado aes y chequea que el input sea el mensaje descifrado correctamente.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_misterio_del_cifrado_aes'])
    input()
    AES_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "en el corazón de la criptografía moderna yace un secreto bien guardado, la llave para el futuro de la seguridad digital.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        AES_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Enhorabuena! Has descifrado el mensaje secreto y descubierto los planes ocultos. 
Tus habilidades en descifrar el complejo cifrado AES demuestran que eres un maestro de la criptografía moderna.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def descifrando_el_codigo_bancario():
    """Imprime mediante las diferentes partes del json el reto descifrando el código bancario y chequea que el input sea el mensaje descifrado correctamente.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['descifrando_el_codigo_bancario'])
    input()
    DES_cipher()
    respuesta = input("\nIntroduce el código de confirmación: ")
    while respuesta != "deltaechosierra":
        input("Ese no es el código de confirmación correcto.")
        cansado = funcion_cansado()
        if cansado:
            break
        DES_cipher()
        respuesta = input("\nIntroduce el código de confirmación: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Increíble! Has demostrado ser un auténtico criptoanalista al descifrar el secreto del banquero. 
Tu habilidad para conectar los puntos y descubrir la clave oculta en los detalles te ha llevado a revelar una operación bancaria encubierta.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def RSA_cipher_reto_mision_diplomatica():
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
            RSA_public_key = cargar_llave_de_archivo(
                "public_key_reto_diplomatica.pem")
            encrypted_text = RSA_cipher_process(plaintext, RSA_public_key, "E")
            print(
                f"\nEl texto encriptado es: \n{encrypted_text}\n\nCifrado RSA\n\n")
        else:
            RSA_private_key = cargar_llave_de_archivo(
                'private_key_reto_diplomatica.pem')
            decrypted_text = RSA_cipher_process(
                plaintext, RSA_private_key, "D")
            print(
                f"\nEl texto desencriptado es: \n{decrypted_text}\n\nCifrado RSA\n\n")
        input("Pulsa enter para continuar.")
    except:
        print("Has introducido algún dato de forma incorrecta.")
    input("Pulsa enter para continuar.")


def la_mision_diplomatica_cifrada():
    """Imprime mediante las diferentes partes del json el reto de la misión diplomática cifrada y chequea que el input sea el mensaje descifrado correctamente.
    Este reto incluye un menú para elegir que cifrado usar, por si tiene que usarlos en un orden concreto.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['la_mision_diplomatica_cifrada'])
    print()
    count = 0
    while count < 2:
        opcion = input(
            "1. Rail Fence\n2. RSA\n3. Ninguno\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            rail_fence_cipher()
        elif opcion == "2":
            RSA_cipher_reto_mision_diplomatica()
        elif opcion == "3":
            break
        else:
            print("Opción Incorrecta.")
            count -= 1
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "urgente: reunión de embajadores programada para discutir la paz mundial. la clave está en la colaboración.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        print(data['retos']['la_mision_diplomatica_cifrada'])
        print()
        count = 0
        while count < 2:
            opcion = input(
                "1. Rail Fence\n2. RSA\n3. Ninguno\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                rail_fence_cipher()
            elif opcion == "2":
                RSA_cipher_reto_mision_diplomatica()
            elif opcion == "3":
                break
            else:
                print("Opción Incorrecta.")
                count -= 1
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Felicidades! Has descifrado con éxito el mensaje cifrado y contribuido a la paz internacional. 
Tu destreza criptográfica ha demostrado ser esencial para el éxito de misiones diplomáticas críticas.""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def ECC_cipher_reto_estelar():
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
            ECC_public_key_pem = leer_de_archivo("public_key_reto_estelar.pem")
            ECC_private_key_pem = leer_de_archivo(
                "private_key_reto_estelar.pem")
            nonce_b64 = leer_de_archivo("nonce_reto_estelar.txt")
            tag_b64 = leer_de_archivo("tag_reto_estelar.txt")
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


def el_codigo_estelar():
    """Imprime mediante las diferentes partes del json el reto del código estelar y chequea que el input sea el mensaje descifrado correctamente.
    Este reto incluye un menú para elegir que cifrado usar, por si tiene que usarlos en un orden concreto.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_codigo_estelar'])
    print()
    count = 0
    while count < 2:
        opcion = input(
            "1. Vigènere\n2. ECC\n3. Ninguno\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            vigenere_cipher()
        elif opcion == "2":
            ECC_cipher_reto_estelar()
        elif opcion == "3":
            break
        else:
            print("Opción Incorrecta.")
            count -= 1
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "revelación astronómica: en el cúmulo de nebulosas de orión se ha detectado una secuencia de exoplanetas potencialmente habitables.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        print(data['retos']['el_codigo_estelar'])
        print()
        count = 0
        while count < 2:
            opcion = input(
                "1. Vigènere\n2. ECC\n3. Ninguno\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                vigenere_cipher()
            elif opcion == "2":
                ECC_cipher_reto_estelar()
            elif opcion == "3":
                break
            else:
                print("Opción Incorrecta.")
                count -= 1
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Impresionante! Has descifrado con éxito el mensaje cifrado utilizando la criptografía de curva elíptica y el cifrado Vigenère. 
Al igual que los astrónomos desentrañan los misterios del cosmos, tú has revelado los secretos ocultos en este complejo código. 
Tu habilidad para navegar por estas sofisticadas técnicas criptográficas te coloca entre los expertos del campo. 
¡Sigue así y sigue explorando los límites del universo criptográfico!""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_legado_de_turing():
    """Imprime mediante las diferentes partes del json el reto del legado de Turing y chequea que el input sea el mensaje descifrado correctamente.
    Este reto incluye un menú para elegir que cifrado usar, por si tiene que usarlos en un orden concreto.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_legado_de_turing'])
    print()
    count = 0
    while count < 2:
        opcion = input(
            "1. César\n2. AES\n3. Ninguno\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            caesar_cipher()
        elif opcion == "2":
            AES_cipher()
        elif opcion == "3":
            break
        else:
            print("Opción Incorrecta.")
            count -= 1
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "podemos ver solo un poco del futuro, pero lo suficiente para darnos cuenta de que hay mucho por hacer.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        print(data['retos']['el_legado_de_turing'])
        print()
        count = 0
        while count < 2:
            opcion = input(
                "1. César\n2. AES\n3. Ninguno\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                caesar_cipher()
            elif opcion == "2":
                AES_cipher()
            elif opcion == "3":
                break
            else:
                print("Opción Incorrecta.")
                count -= 1
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Has descubierto con éxito el legado oculto de Turing! 
Tu habilidad para combinar la historia de la criptografía con técnicas modernas demuestra que estás en el camino correcto para convertirte en un gran criptoanalista""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_enigma_de_la_esfinge():
    """Imprime mediante las diferentes partes del json el reto del enigma de la esfinge y chequea que el input sea el mensaje descifrado correctamente.
    Este reto incluye un menú para elegir que cifrado usar, por si tiene que usarlos en un orden concreto.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_enigma_de_la_esfinge'])
    print()
    count = 0
    while count < 2:
        opcion = input(
            "1. DES\n2. Vigènere\n3. Ninguno\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            DES_cipher()
        elif opcion == "2":
            vigenere_cipher()
        elif opcion == "3":
            break
        else:
            print("Opción Incorrecta.")
            count -= 1
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "la sabiduría es hablar y escuchar como los dioses.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        print(data['retos']['el_enigma_de_la_esfinge'])
        print()
        count = 0
        while count < 2:
            opcion = input(
                "1. DES\n2. Vigènere\n3. Ninguno\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                DES_cipher()
            elif opcion == "2":
                vigenere_cipher()
            elif opcion == "3":
                break
            else:
                print("Opción Incorrecta.")
                count -= 1
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")

    if not cansado:
        print("""\nHas resuelto el enigma de la Esfinge y descifrado el mensaje oculto. 
Al igual que los antiguos sabios, tu conocimiento y habilidad criptográfica te han llevado a la verdad.\n""")
    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_secreto_de_la_atlantida():
    """Imprime mediante las diferentes partes del json el reto del secreto de la Atlantida y chequea que el input sea el mensaje descifrado correctamente.
    Este reto incluye un menú para elegir que cifrado usar, por si tiene que usarlos en un orden concreto.
    También tiene una variable "cansado" en la que si el usuario quiere dejar de hacer el reto puede elegirlo y el reto se terminará.
    """
    cansado = False
    with open("textos.json", "r", encoding="utf-8") as file:
        data = json.load(file)
    print(data['retos']['el_secreto_de_la_atlantida']['reto'])
    print()
    count = 0
    while count < 5:
        opcion = input(
            "1. Rail Fence\n2. Vigènere\n3. César\n4. DES\n5. AES\n6. Ninguno\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            rail_fence_cipher()
        elif opcion == "2":
            vigenere_cipher()
        elif opcion == "3":
            caesar_cipher()
        elif opcion == "4":
            DES_cipher()
        elif opcion == "5":
            AES_cipher()
        elif opcion == "6":
            break
        else:
            print("Opción Incorrecta.")
            count -= 1
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "en las profundidades del océano, las ruinas de la atlántida esperan ser descubiertas, ocultando sabiduría de un pasado remoto.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        print(data['retos']['el_secreto_de_la_atlantida']['reto'])
        print()
        count = 0
        while count < 6:
            opcion = input(
                "1. Rail Fence\n2. Vigènere\n3. César\n4. DES\n5. AES\n6. Atrás\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                rail_fence_cipher()
            elif opcion == "2":
                vigenere_cipher()
            elif opcion == "3":
                caesar_cipher()
            elif opcion == "4":
                DES_cipher()
            elif opcion == "5":
                AES_cipher()
            elif opcion == "6":
                break
            else:
                print("Opción Incorrecta.")
                count -= 1
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")

    if not cansado:
        f = open(".\\temp\\nombre.txt", "r", encoding="utf-8")
        name = f.read()
        f.close()
        print(f"""¡Felicidades, {name}! Has revelado el Secreto de la Atlántida, combinando tu pasión por la historia antigua con una maestría en criptografía.
Tu viaje a través de los misterios del pasado te ha llevado a un descubrimiento que ha permanecido oculto durante milenios.\n\n""")
        print(data['retos']['el_secreto_de_la_atlantida']['enhorabuena'])

    else:
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")
