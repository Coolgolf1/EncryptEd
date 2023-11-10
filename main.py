from funciones_ct_gn import *
from funciones_maquinas import *
from funciones_lecciones import *


def main_menu():
    while True:
        clear_terminal()
        main_menu_choice = (input(
            "==== Menú ====\n1. Lecciones\n2. Retos\n3. Máquinas\n4. Salir\n\nIntroduce tu opción: "))
        clear_terminal()
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


def retos_menu():
    while True:
        clear_terminal()
        retos_choice = input("===== Retos =====\n1. ")
        clear_terminal()
        # opciones = ...


def maquinas_menu():
    while True:
        clear_terminal()
        maquinas_choice = input(
            "===== Máquinas =====\n1. Cifrados Clásicos\n2. Cifrado Simétricos\n3. Cifrados Asimétricos\n4. Hashes\n5. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_choice == "1":
            maquinas_cifrados_clasicos()
        elif maquinas_choice == "2":
            maquinas_cifrados_simetricos()
        elif maquinas_choice == "3":
            maquinas_cifrados_asimetricos()
        elif maquinas_choice == "5":
            return


def exit_programa():
    print("Saliendo del programa...")
    exit(0)


if __name__ == "__main__":
    clear_terminal()
    name = get_name()
    with open(".\\temp\\nombre.txt", "w", encoding="utf-8") as f:
        f.write(name)
    main_menu()
