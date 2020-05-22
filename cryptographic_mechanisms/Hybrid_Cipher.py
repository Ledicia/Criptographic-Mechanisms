import os
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Clase: permite cifrar y descifrar
class Hybrid_Cipher:

    # Constructor de clase: genera la clave a partir de una passphrase (secuencia de texto usada para controlar acceso)
    def __init__(self, key, PathPrivKey, PathPubKey):
        self.block_size = 32
        self.key = hashlib.sha256(key.encode()).digest()  # Passphrase a partir de la clave usada para cifrar y descifrar
        self.public_key = open(PathPubKey).read()
        self.private_key = open(PathPrivKey).read()
        # En caso de que le pasasemos como argumento solo la clave privada
        #private_key = RSA.importKey(self.private_key)
        #self.public_key = private_key.publickey().exportKey('OpenSSH')

    # Funcion: cifra la informacion usando un cifrado hibrido -> se cifra la clave simetrica con cifrado asimetrico
    def encrypt(self, text):
        recipient_key = RSA.importKey(self.public_key)     # Clave publica para cifrar la clave simetrica
        session_key = self.key                             # Clave simétrica
        #session_key = Random.new().read(AES.block_size)   # Clave simetrica para cifrar el documento (aleatoriamente)
        #print(session_key)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)          # Cifrado de la clave simetrica para compartirla
        enc_session_key = cipher_rsa.encrypt(session_key)   #

        text = self._pad(text)                               # Texto que se va a cifrar
        iv = Random.new().read(AES.block_size)               # Vector de inicializacion
        cipher = AES.new(session_key, AES.MODE_CBC, iv)      # Cifrado con clave key (Cipher Block Chaining)

        # Save the simetric key encodad
        with open("./DataFiles/simetric_key_enconded.txt", "wb") as f:
            f.write(enc_session_key)
            f.close()

        return base64.b64encode(iv + cipher.encrypt(text.encode()))

    # Funcion: descifra la informacion con la passphrase seleccionada
    def decrypt(self, enc_text, enc_session_key):
        private_key = RSA.importKey(self.private_key)      # Clave privada para descifrar la clave simetrica

        cipher_rsa = PKCS1_OAEP.new(private_key)            # Descifrando la clave simetrica
        session_key = cipher_rsa.decrypt(enc_session_key)

        enc = base64.b64decode(enc_text)                    # Decodificar el texto encriptado
        iv = enc[:AES.block_size]                           # Seleccion de un bloque de 16 bytes
        cipher = AES.new(session_key, AES.MODE_CBC, iv)     # Descifrado del bloque

        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')  # Resultado de decodificar

    # Modo de operacion
    def _pad(self, string):
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size)

    @staticmethod
    def _unpad(string):
        return string[:-ord(string[len(string) - 1:])]


