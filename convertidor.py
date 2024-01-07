import os


def convertidor(carpeta1: str, archivo: str):
    """Convertir un document .txt a una sola línea para ctrl+c/ctrl+v en el .json.
    Lo use ya que tenía todo guardado en archivos de texto y, para facilitarme la vida, escribía el archivo de texto y esta función me devolvía el texto clavado para el json.

    Args:
        carpeta1 (str): La primera carpeta usada.
        # carpeta2 (str): En el caso de necesitar acceder dos carpetas, se usa.
        archivo (str): El nombre del archivo que se quiere leer.
    """
    os.system("cls")
    with open(f".\\{carpeta1}\\{archivo}.txt", "r", encoding="utf-8") as file:
        text = file.readlines()
        for i in text:
            i = i.replace("\n", "\\n")
            print(f"{i}", end="")


if __name__ == "__main__":
    carpeta1 = input("Introduce la primera carpeta: ")
    # carpeta2 = input("Introduce la segunda carpeta: ")
    archivo = input("Introduce el nombre del archivo: ")
    convertidor(carpeta1, archivo)
