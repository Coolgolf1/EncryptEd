import os

# Esta función limpia la terminal por estética


def clear_terminal():
    os.system("cls")
    print("""\n\n             _|_|_|_|                                                      _|      _|_|_|_|        _|  
             _|        _|_|_|      _|_|_|  _|  _|_|  _|    _|  _|_|_|    _|_|_|_|  _|          _|_|_|  
             _|_|_|    _|    _|  _|        _|_|      _|    _|  _|    _|    _|      _|_|_|    _|    _|  
             _|        _|    _|  _|        _|        _|    _|  _|    _|    _|      _|        _|    _|  
             _|_|_|_|  _|    _|    _|_|_|  _|          _|_|_|  _|_|_|        _|_|  _|_|_|_|    _|_|_|  
                                                           _|  _|                                      
                                                         _|_|  _|   \n""")


def get_name():
    name = str(input("¡Bienvenido a EncryptEd!\n\n¿Cómo te llamas? "))
    while len(name) > 12:
        print("Error. Nombre demasiado largo.")
        name = str(input("¿Cómo te llamas? "))
    if name == "" or name in (" "*12):
        name = "User"
    return (name.capitalize())


def sigue_aprendiendo():
    links_choice = 0
    while links_choice != "6":
        clear_terminal()
        print("""Las lecciones de los cifrados avanzados en este juego son bastante simples
    Por ello, recomiendo, que si quieres aprender el funcionamiento completo de cada cifrado, que uses estos links.""")
        links_choice = input("¿Qué cifrado quieres mirar?\n1. Animaciones\n2. AES\n3. DES\n4. RSA\n5. ECC\n6. Atrás\n\nIntroduce tu opción: ")
        clear_terminal()
        if links_choice == "1":
            print("CrypTool (Aprende Visualmente): https://www.cryptool.org/en/")
            input()
        elif links_choice == "2":
            print("\nCryptoHack AES (INTERMEDIO): https://cryptohack.org/courses/symmetric/")
            input()
        elif links_choice == "3":
            print("\nGeeksForGeeks DES (ANTIGUO): https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/")
            input()
        elif links_choice == "4":
            print("\nCryptoHack RSA (INTERMEDIO): https://cryptohack.org/courses/public-key/")
            input()
        elif links_choice == "5":
            print("\CryptoHack ECC (DIFÍCIL): https://cryptohack.org/courses/elliptic/")
            input()
        elif links_choice == "6":
            return
        else:
            input("Error. No es una opción correcta. Pulsa enter para continuar.")


def exit_programa():
    os.remove(".\\temp\\nombre.txt")
    print("Saliendo del programa...")
    print("\n¡Esperamos verte pronto!\n")
    exit(0)


def funcion_cansado():
    cansado = False
    cansado_input = input("¿Quieres continuar? (S/N) ").upper()
    if cansado_input == "N":
        cansado = True
    return cansado
