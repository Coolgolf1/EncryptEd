# Lecciones
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
    print(f"\n\nEn el siguiente cifrado vamos a volver algo atrás en el tiempo... al sistema de cifrado anterior al AES. El DES.")
    input()


def lecciones_DES_cipher():
    pass


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


def lecciones_RSA_cipher():
    pass


def lecciones_ECC_cipher():
    pass
