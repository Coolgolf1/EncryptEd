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
    pass


def retos_avanzados_menu():
    pass
