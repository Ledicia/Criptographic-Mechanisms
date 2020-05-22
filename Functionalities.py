## SCRIP DE PYTHON PARA LEER LOS ARCHIVOS DADOS AL EJECUTAR EL PROGRAMA Y ESCRIBIR LOS RESULTADOS ##

# 1. Lee el archivo que se ubica en path como una cadena
def read_file(path):
    with open(path, 'r') as f:
        text = f.read()
    return text


# 2. Crea o sobre-escribe los resultados en un documento de texto
def write_file(path, text):
    with open(path, 'w+') as f:
        f.write(text)
    print('Fichero %s generado' % path)


# 3. Lee el archivo binario que se ubica en path como una cadena
def read_binary_file(path):
    with open(path, 'rb') as f:
        text = f.read()
    return text


# 4. Crea o sobre-escribe los resultados en codificacion binaria en un documento de texto
def write_binary_file(path, text):
    with open(path, 'wb+') as f:
        f.write(text)
    print('Fichero %s generado' % path)
