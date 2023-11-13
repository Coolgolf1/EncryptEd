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
            "===== Retos =====\n1. El Código de César\n2. El Secreto de la Relatividad\n3. \n\nIntroduce tu opción: ")
        if retos_basicos_choice == "1":
            el_codigo_del_cesar()
        elif retos_basicos_choice == "2":
            el_secreto_de_la_relatividad()
        elif retos_basicos_choice == "3":
            mensajes_ocultos_en_la_via_ferrea()
        elif retos_basicos_choice == "4":
            pass
        elif retos_basicos_choice == "5":
            pass
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



