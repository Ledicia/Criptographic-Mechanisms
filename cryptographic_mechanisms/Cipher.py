from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib


# Clase: permite cifrar y descifrar
class Cipher:

    # Constructor de clase: genera la clave a partir de una passphrase (secuencia de texto usada para controlar acceso)
    def __init__(self, key):
        self.block_size = 32                              # El tamaño de la clave es de 32 bytes
        self.key = hashlib.sha256(key.encode()).digest()  # Passphrase a partir de la clave usada para cifrar y descifrar

    # Funcion: permite cifrar la informacion usando la passphrase seleccionada
    def encrypt(self, raw):
        raw = self._pad(raw)                                        # Texto que se va a cifrar
        iv = Random.new().read(AES.block_size)                      # Vector de inicializacion
        cipher = AES.new(self.key, AES.MODE_CBC, iv)                # Cifrado con clave key (Cipher Block Chaining)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))  # Bloque aleatorio + resultado binario encriptacion

    # Funcion: permite descifrar la informacion con la passphrase seleccionada
    def decrypt(self, enc):
        enc = base64.b64decode(enc)                                               # Decodificar el texto encriptado
        iv = enc[:AES.block_size]                                                 # Seleccion de un bloque de 16 bytes
        cipher = AES.new(self.key, AES.MODE_CBC, iv)                              # Descifrado del bloque
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')  # Resultado de decodificar

    # Modo de operacion
    def _pad(self, string):
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size)

    @staticmethod
    def _unpad(string):
        return string[:-ord(string[len(string) - 1:])]
