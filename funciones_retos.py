from funciones_ct_gn import *
from funciones_maquinas import *


def retos_menu():
    while True:
        clear_terminal()
        retos_choice = input(
            "===== Retos =====\n1Retos Básicos\n2.Retos Avanzados\n\nIntroduce tu opción: ")
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
    while True:
        clear_terminal()
        retos_basicos_choice = input(
            """===== Retos =====
            1. El Código de César
            2. El Secreto de la Relatividad
            3. Mensajes Ocultos en la Vía Férrea
            4. El Misterio del Cifrado AES 
            5. Descifrando el Código Bancario
            6. El Desafio RSA de César
            7. 
            8. 
            9. 
            10. 
            11. Atrás\n\nIntroduce tu opción: """)
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
            pass
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
        clear_terminal()


def retos_avanzados_menu():
    while True:
        clear_terminal()
        retos_avanzados_choice = input(
            "===== Retos =====\n1Retos Básicos\n2.Retos Avanzados\n\nIntroduce tu opción: ")
        clear_terminal()


def el_codigo_del_cesar():
    f = open(".\Retos\el_codigo_del_cesar.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    caesar_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "veni, vidi, vici":
        input("El mensaje no ha sido descifrado correctamente.")
        caesar_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
    print("""¡Excelente trabajo! Has descifrado el código de César y revelado un pedazo de historia. 
Al igual que Julio César conquistó territorios, tú has conquistado este reto criptográfico. 
Prepárate para más desafíos en el mundo de los códigos secretos.""")
    

def el_secreto_de_la_relatividad():
    f = open(".\Retos\el_secreto_de_la_relatividad.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    vigenere_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "la imaginacion es mas importante que el conocimiento.":
        input("El mensaje no ha sido descifrado correctamente.")
        vigenere_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
    print("""¡Has revelado con éxito el mensaje oculto! 
Al igual que Einstein revolucionó nuestra comprensión del universo, tú has desentrañado un misterio de la criptografía. 
Sigue adelante para descubrir más secretos encriptados.""")
    

def mensajes_ocultos_en_la_via_ferrea():
    f = open(".\Retos\mensajes_ocultos_en_la_via_ferrea.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    rail_fence_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "la solucion esta en los detalles mas insignificantes.":
        input("El mensaje no ha sido descifrado correctamente.")
        rail_fence_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
    print("""¡Brillante! Has descifrado con éxito el mensaje oculto en la vía férrea
y encontrado las pistas que incluso el mejor detective del siglo XIX pasó por alto. 
Tu agudeza para descifrar códigos te llevará lejos en el mundo de la criptografía.""")


def el_misterio_del_cifrado_aes():
    f = open(".\Retos\el_misterio_del_cifrado_aes.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    AES_cipher()
    respuesta = input("\nIntroduce el mensaje descifrado: ")
    while respuesta != "en el corazón de la criptografía moderna yace un secreto bien guardado, la llave para el futuro de la seguridad digital.":
        input("El mensaje no ha sido descifrado correctamente.")
        AES_cipher()
        respuesta = input("\nIntroduce el mensaje descifrado: ")
    print("""¡Enhorabuena! Has descifrado el mensaje secreto y descubierto los planes ocultos. 
Tus habilidades en descifrar el complejo cifrado AES demuestran que eres un maestro de la criptografía moderna.""")


def descifrando_el_codigo_bancario():
    f = open(".\Retos\descifrando_el_codigo_bancario.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    DES_cipher()
    respuesta = input("\nIntroduce el código de confirmación: ")
    while respuesta != "deltaechosierra":
        input("Ese no es el código de confirmación correcto.")
        DES_cipher()
        respuesta = input("\nIntroduce el código de confirmación: ")
    print("""¡Increíble! Has demostrado ser un auténtico criptoanalista al descifrar el secreto del banquero. 
Tu habilidad para conectar los puntos y descubrir la clave oculta en los detalles te ha llevado a revelar una operación bancaria encubierta.""")


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
    try:
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
    except:
        print("Has introducido algún dato de forma incorrecta.")



def la_mision_diplomatica_cifrada(): 
    f = open(".\Retos\descifrando_el_codigo_bancario.txt", "r", encoding="utf-8")
    print(f.read())
    f.close()
    input()
    DES_cipher()
    respuesta = input("\nIntroduce el código de confirmación: ")
    while respuesta != "deltaechosierra":
        input("Ese no es el código de confirmación correcto.")
        DES_cipher()
        respuesta = input("\nIntroduce el código de confirmación: ")
    print("""¡Has descifrado con éxito el doble cifrado! Tu habilidad para navegar por las complejidades de RSA y César demuestra que eres un estratega criptográfico astuto, digno de los grandes líderes de la historia.""")

def la_mision_diplomatica_cifrada():

