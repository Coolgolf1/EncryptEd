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


def maquinas_cifrados_clasicos():
    while True:
        clear_terminal()
        maquinas_cifrados_clasicos_choice = input(
            "========= Máquinas ==========\n===== Cifrados Clásicos =====\n1. Cifrado César\n2. Cifrado Vigènere\n3. Cifrado Rail Fence\n4. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_clasicos_choice == "1":
            caesar_cipher()
        elif maquinas_cifrados_clasicos_choice == "2":
            vigenere_cipher()
        elif maquinas_cifrados_clasicos_choice == "3":
            rail_fence_cipher()
        elif maquinas_cifrados_clasicos_choice == "4":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def maquinas_cifrados_simetricos():
    while True:
        clear_terminal()
        maquinas_cifrados_simetricos_choice = input(
            "========== Máquinas ===========\n===== Cifrados Simétricos =====\n1. Cifrado AES-56\n2. Cifrado DES\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_simetricos_choice == "1":
            AES_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            DES_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def maquinas_cifrados_asimetricos():
    while True:
        clear_terminal()
        maquinas_cifrados_simetricos_choice = input(
            "=========== Máquinas ===========\n===== Cifrados Asimétricos =====\n1. Cifrado RSA\n2. Cifrado Curva Elíptica\n3. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if maquinas_cifrados_simetricos_choice == "1":
            RSA_cipher()
        elif maquinas_cifrados_simetricos_choice == "2":
            ECC_cipher()
        elif maquinas_cifrados_simetricos_choice == "3":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def exit_programa():
    print("Saliendo del programa...")
    exit(0)


if __name__ == "__main__":
    main_menu()
