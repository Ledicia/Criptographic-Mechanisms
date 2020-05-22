import logging  # For logs
from Parser import *
from Functionalities import *
from cryptographic_mechanisms.Signer import *
from cryptographic_mechanisms.Cipher import *
from cryptographic_mechanisms.Hasher import *
from cryptographic_mechanisms.Hybrid_Cipher import *
from cryptographic_mechanisms.CertificateX509 import *


# Funcion que lee el contenido del archivo de entrada y lo cifrar utilizando la clase Cipher
def encrypt(args):
    cipher = Cipher(args.password)        # Lee la contraseña con la que cifra
    text = read_file(args.input)          # Lee el texto a cifrar
    cryp = cipher.encrypt(text)           # Cifra el texto usando la funcion cipher de la clase Cipher
    write_binary_file(args.output, cryp)  # Escribe el texto cifrado


# Funcion que lee el archivo cifrado y lo descifra utilizando la clase Cipher
def decrypt(args):
    cipher = Cipher(args.password)
    cryp = read_binary_file(args.input)
    text = cipher.decrypt(cryp)
    write_file(args.output, text)


# Funcion que lee el contenido del archivo de entrada y crea un hash utilizando la clase Hasher
def get_hash_bin(args):
    hasher = Hasher()                       # Instancia la clase para crear un objeto de tipo Hasher
    text = read_file(args.input)            # Lee el texto para el que se quiere calcular el hash
    shasumhex = hasher.get_hash_hex(text)   # Calcula la uncion de hash en codificacion hexadecimal
    write_file(args.output, shasumhex)      # Escribe el resultado en un archivo binario


# Funcion que lee el hash del archivo y lo verifica contra el contenido del archivo de entrada utilizando la clase Hasher
def check_hash(args):
    hasher = Hasher()
    text = read_file(args.input)                      # Lee el archivo de texto
    shasumhex = read_file(args.additional_input)      # Lee el archivo contra el que se verifica el hash del input
    hasher.check_hash(text, shasumhex)                # Se verifica el hash del archivo mediante la funcion check_hass


# Funcion que lee el contenido del archivo de entrada y firma un hash con la clave privada utilizando la clase Signer
def sign(args):
    signer = Signer()
    text = read_file(args.input)               # Lee el archivo de entrada
    signature = signer.sign(text)              # Firma el archivo
    write_binary_file(args.output, signature)  # Escribe la firma en un archivo de texto binario


# Funcion que lee el archivo y lo verifica contra la firma proporcionada utilizando la clase Signer
def check_sign(args):
    signer = Signer()
    text = read_file(args.input)                         # Lee el archivo de entrada
    signature = read_binary_file(args.additional_input)  # Lee la firma
    signer.check_sign(text, signature)                   # Verifica la firma


# Funcion que genera un certificado segun el estandar X509
def certificate_X509(args):
    # Si no se le pasa una clave privada la genera y la guarda junto con su clave publica asociada
    if args.password is None:
        cert = Certificate(True)
        Cert = cert.create_self_signed_cert()
        print('Creación de un par de claves pública/privada y del certificado.'+
        'Las claves se guardan en los ficheros cert_publicKey.pem, cert_privateKey.pem')
        write_binary_file(args.output, Cert)
    else:
        cert = Certificate(False, args.password)
        Cert = cert.create_self_signed_cert()
        print('Creación del certificado a partir de una clave privada')
        write_binary_file(args.output, Cert)
        # Guardar la clave pública leida del certificado
        cert.get_pubKey_from_cert(pathLoad=args.output, pathSave='./DataFiles/Cert_PubKey_from_PrivKey.pem')

# Paths de las claves pública y privada para encriptar y desencriptar la clave simetrica
PathPrivKey = './DataFiles/private_key.pem'
PathPubKey = './DataFiles/public_key.pem'

# Funcion que cifra utilizando RSA y EAS
def hybrid_encrypt(args):
    h_cipher = Hybrid_Cipher(args.password, PathPrivKey, PathPubKey)
    text = read_file(args.input)                        # Lee el texto a cifrar
    cryp = h_cipher.encrypt(text)                       # Cifra el texto usando la funcion cipher de la clase Cipher
    write_binary_file(args.output, cryp)                # Escribe el texto cifrado


# Funcion que lee el archivo cifrado y lo descifra utilizando la clase Hybrid_Cipher
def hybrid_decrypt(args):
    h_cipher = Hybrid_Cipher(args.password, PathPrivKey, PathPubKey)
    cryp = read_binary_file(args.additional_input)                               # Fichero que ha sido encriptado
    enc_session_key = read_binary_file('./DataFiles/simetric_key_enconded.txt')
    text = h_cipher.decrypt(cryp, enc_session_key)                               # Descifrado de clave simetrica y fichero
    write_file(args.output, text)


# Mecanismos criptograficos implementados
#choose_mode = {'cs': encrypt, 'ds': decrypt, 'h': get_hash_bin, 'vh': check_hash, 'ca': sign, 'da': check_sign,
#               'cert': certificate_X509, 'ch': hybrid_encrypt, 'dh': hybrid_decrypt}

choose_mode = {'cs': encrypt, 'ds': decrypt, 'h': get_hash_bin, 'vh': check_hash, 's': sign, 'vs': check_sign,
               'cert': certificate_X509, 'ca': hybrid_encrypt, 'da': hybrid_decrypt}

def main():
    # Se lanza el programa en la terminal:
    args = parse_args()

    try:
        check_args(args)                  # Comprueba los argumentos introducidos al lanzar el programa
        choose_mode.get(args.mode)(args)  # Ejecutar el programa segun el error
    except (UnsupportedOperationError, ArgumentError) as e:
        logging.warning(e)

if __name__=="__main__":
    main()