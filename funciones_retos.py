from funciones_misc import *
from funciones_maquinas import *


def retos_menu():
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
10. Códigos Del Espacio 
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
    f = open(".\\retos\el_codigo_del_cesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
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
    f = open(".\\retos\el_secreto_de_la_relatividad.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
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
    f = open(".\\retos\mensajes_ocultos_en_la_via_ferrea.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
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
    f = open(".\\retos\el_misterio_del_cifrado_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
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
    f = open(".\\retos\descifrando_el_codigo_bancario.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
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
            RSA_public_key = cargar_llave_de_archivo("public_key_reto_diplomatica.pem")
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
    f = open(".\\retos\la_mision_diplomatica_cifrada.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 2:
        opcion = input("1. Rail Fence\n2. RSA\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
        f = open(".\\retos\la_mision_diplomatica_cifrada.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 2:
            opcion = input("1. Rail Fence\n2. RSA\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
            ECC_private_key_pem = leer_de_archivo("private_key_reto_estelar.pem")
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
    f = open(".\\retos\el_codigo_estelar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 2:
        opcion = input("1. Vigènere\n2. ECC\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
        f = open(".\\retos\la_mision_diplomatica_cifrada.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 2:
            opcion = input("1. Vigènere\n2. ECC\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
    f = open(".\\retos\el_legado_de_turing.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 2:
        opcion = input("1. César\n2. AES\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
        f = open(".\\retos\el_legado_de_turing.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 2:
            opcion = input("1. César\n2. AES\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
    f = open(".\\retos\el_enigma_de_la_esfinge.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 2:
        opcion = input("1. DES\n2. Vigènere\n3. Ninguno\n\nElige que cifrado quieres usar: ")
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
        f = open(".\\retos\el_enigma_de_la_esfinge.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 2:
            opcion = input("1. DES\n2. Vigènere3. Ninguno\n\nElige que cifrado quieres usar: ")
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
        print("""Has resuelto el enigma de la Esfinge y descifrado el mensaje oculto. 
Al igual que los antiguos sabios, tu conocimiento y habilidad criptográfica te han llevado a la verdad.""")
    else: 
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")


def el_secreto_de_la_atlantida():
    f = open(".\\retos\el_secreto_de_la_atlantida.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 5:
        opcion = input("1. Rail Fence\n2. Vigènere\n3. César\n4. DES\n5. AES\n6. Atrás\n\nElige que cifrado quieres usar: ")
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
    while respuesta != "en las profundidades del oceano, las ruinas de la atlantida esperan ser descubiertas, ocultando sabiduria de un pasado remoto.":
        input("El mensaje no ha sido descifrado correctamente.")
        cansado = funcion_cansado()
        if cansado:
            break
        clear_terminal()
        f = open(".\\retos\el_secreto_de_la_atlantida.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 5:
            opcion = input("1. Rail Fence\n2. Vigènere\n3. César\n4. DES\n5. AES\n6. Atrás\n\nElige que cifrado quieres usar: ")
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
        print("""¡Felicidades! Has revelado el Secreto de la Atlántida, combinando tu pasión por la historia antigua con una maestría en criptografía. 
Tu viaje a través de los misterios del pasado te ha llevado a un descubrimiento que ha permanecido oculto durante milenios.\n\n""")
        
        print("""¡Extraordinario! Has completado el último y más desafiante reto de 'EncryptEd'. 
Tu viaje a través de los laberintos de la criptografía te ha llevado desde los códigos clásicos hasta los misterios de la criptografía moderna. 
Has demostrado no solo habilidad y agudeza en el arte del cifrado y descifrado, sino también perseverancia y curiosidad intelectual. 
Este no es solo un logro en el juego, sino un paso significativo en tu camino como criptoanalista. 
¡Felicidades por desbloquear todos los secretos y gracias por embarcarte en esta aventura criptográfica!\n""")
        
    else: 
        print("¡Inténtalo en otro momento!")
    input("Pulsa enter para continuar.")