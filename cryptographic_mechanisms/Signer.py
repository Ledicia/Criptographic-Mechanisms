import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from cryptographic_mechanisms.Hasher import Hasher

# Funcion para leer las claves publica y privada:
def get_keys():
    private_key = None
    public_key = None

    # Leer los archivos de clave publica y privada
    for file in os.listdir("./DataFiles"):
        if file.endswith("private_key.pem") and private_key is None:
            private_key = os.path.join("./DataFiles", file)
        if file.endswith("public_key.pem") and public_key is None:
            public_key = os.path.join("./DataFiles", file)

    # Lanzar un error en caso de que no haya calve privada o clave publica
    if private_key is None or public_key is None:
        raise FileNotFoundError

    return private_key, public_key


# Clase: permite firmar el documento y verificar la firma
class Signer:

    # Constructor de clase:
    def __init__(self):
        self.hasher = Hasher()                          # Se crea un objeto te tipo Hasher
        self.private_key, self.public_key = get_keys()  # Se obtienen las claves publica y privada

    # Funcion: permite firmar el texto (text)
    def sign(self, text):
        key = RSA.importKey(open(self.private_key).read())  # Se lee la clave privada
        shasum = self.hasher.get_hash(text)                 # Se calcula el hash del texto mediante la clase Hasher
        signer = PKCS1_v1_5.new(key)                        # Se firma el hash con la clave privada
        return signer.sign(shasum)

    # Funcion: permite verificar la suma
    def check_sign(self, text, signature):
        key = RSA.importKey(open(self.public_key).read())  # Se lee la clave publica
        shasum = self.hasher.get_hash(text)            # Se calcula el hash del texto usando SHA256
        verifier = PKCS1_v1_5.new(key)  # Se verifica que el hash del texto coincide con el hash firmado con la clave privada
        if verifier.verify(shasum, signature):
            print("Firma verificada")
        else:
            print("Firma incorrecta, el hash del texto no coincide con el hash del texto descifrado con la clave publica")


