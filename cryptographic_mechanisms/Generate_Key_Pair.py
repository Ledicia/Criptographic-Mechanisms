from Crypto.PublicKey import RSA

#key = RSA.generate(1024)
# Se generar un par de claves publica-privada usando 4096 bits (512 bytes)
key = RSA.generate(4096, e=65537)

f = open("/Users/HP/Documents/Master_FinTech/BlockChain/Tema3/Practica2Python/" +
         "/DataFiles/private_key.pem", "wb")
f.write(key.exportKey('PEM'))
f.close()

pubkey = key.publickey()
f = open("/Users/HP/Documents/Master_FinTech/BlockChain/Tema3/Practica2Python/" +
         "/DataFiles/public_key.pem", "wb")
f.write(pubkey.exportKey('OpenSSH'))
f.close()