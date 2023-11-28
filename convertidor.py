import os

# Convertir un document .txt a una sola línea para pasar a .json

def convertidor(carpeta1, carpeta2 ,archivo):
    os.system("cls")
    with open(f".\\{carpeta1}\\{carpeta2}\\{archivo}.txt", "r", encoding="utf-8") as file:
            text = file.readlines()
            for i in text:
                i = i.replace("\n","\\n")
                print(f"{i}",end="")

if __name__ == "__main__":
    carpeta1 = input("Introduce la primera carpeta: ")
    carpeta2 = input("Introduce la segunda carpeta: ")
    archivo = input("Introduce el nombre del archivo: ")
    convertidor(carpeta1,carpeta2,archivo)
