import datetime
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Clase para
class Certificate:

    # Constructor de clase:
    def __init__(self, Create_PrivKey = True, Path2Key = None):
        '''
        :param Create_PrivKey: True if we want to generate a private key, False if we dont want to.
        :param Path2Key: If it is provided reads the private key
        '''
        self.cert = x509.CertificateBuilder()  # Creamos el objeto certificado
        # Si nos proporcionan una clave privada no hace falta crearla
        self.Path = Path2Key
        self.Create_Priv_Key = Create_PrivKey
        if self.Create_Priv_Key == True:
            self.key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend())
        # En caso de que se llame al constructor con la ruta a la clave privada
        else:
            if self.Path != None:
                self.key = serialization.load_pem_private_key(str.encode(open(self.Path).read()),
                                                          password = None, backend = default_backend())

    # Funcion: permite crear el certificado autofrimado en el estandar X509 que contiene mi clave publica y mas info
    def create_self_signed_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Coruña"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Oleiros"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])

        cert = self.cert.subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Certificado valido durante 20 dias
            datetime.datetime.utcnow() + datetime.timedelta(days=20)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Por ultimo, se firma el certificado con la clave privada
        ).sign(self.key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        # Mejor guardar el certificado con el nombre que le de la persona que lo crea
        # with open("/Users/HP/Documents/Master_FinTech/BlockChain/Tema3/Practica2Python/" +
        #         "/DataFiles/cert1.pem", "wb") as f:
        #     f.write(cert_pem)
        #     f.close()

        # Guardamos la clave privada y la pública en caso de que no se proporcione para crear el certificado
        if self.Create_Priv_Key == True:
            key_pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open("/Users/HP/Documents/Master_FinTech/BlockChain/Tema3/Practica2Python/" +
                    "/DataFiles/cert_privateKey.pem", "wb") as f:
                f.write(key_pem)
                f.close()

            public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            with open("/Users/HP/Documents/Master_FinTech/BlockChain/Tema3/Practica2Python/" +
                      "/DataFiles/cert_publicKey.pem", "wb") as f:
                f.write(public_key)
                f.close()

        print('Certificate type x509 created')
        return cert_pem

    # Funcion: Lee la clave publica del certificado y la guarda en formato OpenSHH
    def get_pubKey_from_cert(self, pathLoad = './DataFiles/cert.cert',
                             pathSave = "./DataFiles/Cert_PubKey.pem"):
        # Se carga el certificado generado
        cert_obj = load_pem_x509_certificate(str.encode(open(pathLoad).read()), default_backend())
        public_key = cert_obj.public_key()
        # Se guarda la clave en formato OpenSSH
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        with open(pathSave, "wb") as f:
            f.write(public_key)
            f.close()




