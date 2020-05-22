from Crypto.Hash import SHA256


# Clase: permite la creacion y posterior verificacion de un hash creado con la funcion suma SHA256
class Hasher:

    # Constructor de clase: crea un nuevo hasher del tipo SHA256 cada vez que se quiere crear un hash de un mensaje
    def __init__(self):
        self.hash = SHA256.new()

    # Funcion: permite obtener la funcion resumen de la concatenacion de las cadenas utilizando codificacion hexadecimal
    def get_hash_hex(self, text):
        self.hash.update(text.encode('utf-8'))  # Actualiza el contenido del hash con los datos procedentes de text
        return self.hash.hexdigest()            # Devolver el resultado del hash del texto codificado en hexadecimal

    # Funcion: calcula el hash del texto
    def get_hash(self, text):
        self.hash.update(text.encode('utf-8'))  # Actualiza el contenido del hash con los datos procedentes de text
        return self.hash                        # Devuelve un objeto de tipo Crypto.Hash.SHA256.SHA256Hash

    # Funcion: permite verificar si el hash del texto y el hash que le hagamos al texto son iguales
    def check_hash(self, text, shasum):
        shasum_text = self.get_hash_hex(text)
        # print('shasum', shasum)
        # print('text hash', shasum_text)
        if shasum_text == shasum:
            print("Hash verificado")
        else:
            print("Hash incorrecto, el hash del texto no coincide con el hash proporcionado")


