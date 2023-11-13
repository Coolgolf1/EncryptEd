from funciones_ct_gn import *
from funciones_maquinas import *
from funciones_lecciones import *
from funciones_retos import *


def main_menu():
    while True:
        clear_terminal()
        main_menu_choice = (input(
            "==== Menú ====\n1. Lecciones\n2. Retos\n3. Máquinas\n4. Sigue Aprendiendo\n5. Salir\n\nIntroduce tu opción: "))
        clear_terminal()
        if main_menu_choice == "1":
            lecciones_menu()
        elif main_menu_choice == "2":
            retos_menu()
        elif main_menu_choice == "3":
            maquinas_menu()
        elif main_menu_choice == "4":
            sigue_aprendiendo()
        elif main_menu_choice == "5":
            exit_programa()
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def sigue_aprendiendo():
    clear_terminal()
    print("""Las lecciones de los cifrados avanzados en este juego son bastante simples
Por ello, recomiendo, que si quieres aprender el funcionamiento completo de cada cifrado, que uses estos links.""")
    links_choice = input("¿Qué cifrado quieres mirar?\n1. AES\n2. DES\n3. RSA\n4. ECC\n5. Atrás\n\nIntroduce tu opción: ")
    clear_terminal()
    if links_choice == "1":
        print("\nCryptoHack AES (INTERMEDIO): https://cryptohack.org/courses/symmetric/")
        input()
    elif links_choice == "2":
        print("\nGeeksForGeeks DES (ANTIGUO): https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/")
        input()
    elif links_choice == "3":
        print("\nCryptoHack RSA (INTERMEDIO): https://cryptohack.org/courses/public-key/")
        input()
    elif links_choice == "4":
        print("\CryptoHack ECC (DIFÍCIL): https://cryptohack.org/courses/elliptic/")
        input()
    elif links_choice == "5":
        return
    else:
        input("Error. No es una opción correcta. Pulsa enter para continuar.")


def exit_programa():
    os.remove(".\\temp\\nombre.txt")
    print("Saliendo del programa...")
    print("\n¡Esperamos verte pronto!\n")
    exit(0)


if __name__ == "__main__":
    clear_terminal()
    name = get_name()
    with open(".\\temp\\nombre.txt", "w", encoding="utf-8") as f:
        f.write(name)
    main_menu()
