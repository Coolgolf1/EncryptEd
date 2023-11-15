from funciones_misc import *
from funciones_maquinas import *


def retos_menu():
    retos_choice = ""
    while retos_choice != "3":
        clear_terminal()
        retos_choice = input(
            "===== Retos =====\n1. Retos Básicos\n2. Retos Avanzados\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if retos_choice == "1":
            retos_basicos_menu()
        elif retos_choice == "2":
            retos_avanzados_menu()
        elif retos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def retos_basicos_menu():
    retos_basicos_choice = ""
    while retos_basicos_choice != "11":
        clear_terminal()
        retos_basicos_choice = input(
            """===== Retos Básicos =====
1. El Código de César
2. El Secreto de la Relatividad
3. Mensajes Ocultos en la Vía Férrea
4. El Misterio del Cifrado AES 
5. Descifrando el Código Bancario
6. La Misión Diplomática Cifrada
7. 
8. 
9. 
10. 
11. Atrás\n\nIntroduce tu opción: """)
        clear_terminal()
        if retos_basicos_choice == "1":
            el_codigo_del_cesar()
        elif retos_basicos_choice == "2":
            el_secreto_de_la_relatividad()
        elif retos_basicos_choice == "3":
            mensajes_ocultos_en_la_via_ferrea()
        elif retos_basicos_choice == "4":
            el_misterio_del_cifrado_aes()
        elif retos_basicos_choice == "5":
            descifrando_el_codigo_bancario()
        elif retos_basicos_choice == "6":
            la_mision_diplomatica_cifrada()
        elif retos_basicos_choice == "7":
            pass
        elif retos_basicos_choice == "8":
            pass
        elif retos_basicos_choice == "9":
            pass
        elif retos_basicos_choice == "10":
            pass
        elif retos_basicos_choice == "11":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")
        clear_terminal()


def retos_avanzados_menu():
    while True:
        clear_terminal()
        retos_avanzados_choice = input(
            "===== Retos Avanzados =====\n1. Retos Básicos\n2. Retos Avanzados\n\nIntroduce tu opción: ")
        clear_terminal()


def el_codigo_del_cesar():
    f = open(".\Retos\el_codigo_del_cesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    caesar_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    cansado = False
    while respuesta != "veni, vidi, vici" and not cansado:
        input("El mensaje no ha sido descifrado correctamente.")
        caesar_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Excelente trabajo! Has descifrado el código de César y revelado un pedazo de historia. 
Al igual que Julio César conquistó territorios, tú has conquistado este reto criptográfico. 
Prepárate para más desafíos en el mundo de los códigos secretos.""")
    else: 
        print("¡Inténtalo en otro momento!")
    input()
    

def el_secreto_de_la_relatividad():
    f = open(".\Retos\el_secreto_de_la_relatividad.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    vigenere_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    cansado = False
    while respuesta != "la imaginacion es mas importante que el conocimiento." and not cansado:
        input("El mensaje no ha sido descifrado correctamente.")
        vigenere_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Has revelado con éxito el mensaje oculto! 
Al igual que Einstein revolucionó nuestra comprensión del universo, tú has desentrañado un misterio de la criptografía. 
Sigue adelante para descubrir más secretos encriptados.""")
    else:
        print("¡Inténtalo en otro momento!")
    input()
    

def mensajes_ocultos_en_la_via_ferrea():
    f = open(".\Retos\mensajes_ocultos_en_la_via_ferrea.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    rail_fence_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    cansado = False
    while respuesta != "la solucion esta en los detalles mas insignificantes." and not cansado:
        input("El mensaje no ha sido descifrado correctamente.")
        rail_fence_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Brillante! Has descifrado con éxito el mensaje oculto en la vía férrea
y encontrado las pistas que incluso el mejor detective del siglo XIX pasó por alto. 
Tu agudeza para descifrar códigos te llevará lejos en el mundo de la criptografía.""")
    else: 
        print("¡Inténtalo en otro momento!")
    input()


def el_misterio_del_cifrado_aes():
    f = open(".\Retos\el_misterio_del_cifrado_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    AES_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    cansado = False
    while respuesta != "en el corazón de la criptografía moderna yace un secreto bien guardado, la llave para el futuro de la seguridad digital." and not cansado:
        input("El mensaje no ha sido descifrado correctamente.")
        AES_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Enhorabuena! Has descifrado el mensaje secreto y descubierto los planes ocultos. 
Tus habilidades en descifrar el complejo cifrado AES demuestran que eres un maestro de la criptografía moderna.""")
    else:
        print("¡Inténtalo en otro momento!")
    input()


def descifrando_el_codigo_bancario():
    f = open(".\Retos\descifrando_el_codigo_bancario.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    DES_cipher()
    respuesta = input("\nIntroduce el código de confirmación: ")
    cansado = False
    while respuesta != "deltaechosierra" and not cansado:
        input("Ese no es el código de confirmación correcto.")
        DES_cipher()
        respuesta = input("\nIntroduce el código de confirmación: ")
        cansado = funcion_cansado()
    if not cansado: 
        print("""¡Increíble! Has demostrado ser un auténtico criptoanalista al descifrar el secreto del banquero. 
Tu habilidad para conectar los puntos y descubrir la clave oculta en los detalles te ha llevado a revelar una operación bancaria encubierta.""")
    else: 
        print("¡Inténtalo en otro momento!")
    input()



def RSA_cipher_reto_mision_diplomatica():
    print("=====Cifrado RSA =====")
    modo = input("Elige encriptar o desencriptar (E/D): ").upper()
    while modo not in "ED" or modo == "" or modo in " " or modo == "ED":
        print("Error")
        modo = input("Elige encriptar o desencriptar (E/D): ").upper()

    plaintext = input("Introduce un texto: ").lower()
    while len(plaintext) < 1:
        print("Error. Introduce un texto válido.")
        plaintext = input("Introduce un texto: ").lower()
    #try:
    if modo == "E":
        RSA_public_key = cargar_llave_de_archivo("public_key_reto_diplomatica.pem")
        encrypted_text = RSA_cipher_process(plaintext, RSA_public_key, "E")
        print(
            f"\nEl texto encriptado es: \n{encrypted_text}\n\nCifrado RSA\n\n")

    else:
        RSA_private_key = input("Introduce la llave privada: ")
        decrypted_text = RSA_cipher_process(
            plaintext, RSA_private_key, "D")
        print(
            f"\nEl texto desencriptado es: \n{decrypted_text}\n\nCifrado RSA\n\n")
    input("Pulsa enter para continuar.")
    #except:        
       # print("Has introducido algún dato de forma incorrecta.")


def la_mision_diplomatica_cifrada(): 
    f = open(".\Retos\la_mision_diplomatica_cifrada.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    print()
    count = 0
    while count < 2:
        opcion = input("1. Rail Fence\n2. RSA\n\nElige que cifrado quieres usar: ")
        if opcion == "1":
            rail_fence_cipher()
        elif opcion == "2":
            RSA_cipher_reto_mision_diplomatica()
        count += 1
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    cansado = False
    while respuesta != "urgente: reunión de embajadores programada para discutir la paz mundial. la clave está en la colaboración." and not cansado:
        input("El mensaje no ha sido descifrado correctamente.")
        clear_terminal()
        f = open(".\Retos\la_mision_diplomatica_cifrada.txt", "r", encoding="utf-8")
        print(f.read())
        f.close()
        print()
        count = 0
        while count < 2:
            opcion = input("1. Rail Fence\n2. RSA\n\nElige que cifrado quieres usar: ")
            if opcion == "1":
                rail_fence_cipher()
            elif opcion == "2":
                RSA_cipher_reto_mision_diplomatica()
            count += 1
        respuesta = input("\nIntroduce el mensaje descifrado: ")
        cansado = funcion_cansado()
    if not cansado:
        print("""¡Felicidades! Has descifrado con éxito el mensaje cifrado y contribuido a la paz internacional. 
Tu destreza criptográfica ha demostrado ser esencial para el éxito de misiones diplomáticas críticas.""")
    else: 
        print("¡Inténtalo en otro momento!")


def sdfsd():
    pass

