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
    name = str(input("¿Cómo te llamas? "))
    while len(name) > 12:
        print("Error. Nombre demasiado largo.")
        name = str(input("¿Cómo te llamas? "))
    if name == "" or name in (" "*12):
        name = "User"
    return (name.capitalize())
