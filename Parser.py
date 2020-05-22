import os
import argparse


# En caso de que algún argumento no este presete ignorarlo
class ArgumentError(BaseException):
    pass


# En el casode que una funcion aun no este implementada ignorarlo
class UnsupportedOperationError(BaseException):
    pass


# Para poder lanzar el programa desde la terminal:
def parse_args():
    description = 'Cifra y descifra información utilizando el algoritmo de clave simétrica AES.\n' \
                  'Calcula y verifica su función resumen SHA256.\n' \
                  'Firmaresta información mediante RSA y verifica la firma'
    parser = argparse.ArgumentParser(description=description)

    help = 'Modo: ' \
           '[cs/ds] cifrado/descifrado simétrico. La contraseña se establecerá con -p, el fichero cifrado -o' \
           '[h/vh] función resumen y su verificación. El hash se pasara con -ad ' \
           '[ca/da] cifrado/descifrado asimétrico. El par de claves publica-privada se ' \
           'guardara en ./DataFiles/, bajo el nombre de private_key.pem y public_key.pem ' \
           '[cert] Creación de un certificado X.509, cuyo nombre se especificará con -o ' \
           '[ts/tsv] Sellado de tiempo y su verificación. La autoridad de sellado de tiempo podrá ' \
           'establecerse directamente en el código fuente.'

    parser.add_argument('-m', '--mode', choices=['cs', 'ds', 'h', 'vh', 's', 'vs', 'cert', 'ca', 'da', 'ts', 'tsv'],
                        type=str, required=True, help=help, metavar='mode')
    parser.add_argument('-p', '--password', type=str, required=False, help="Contraseña utilizada para cifrar/descifrar")
    parser.add_argument('-i', '--input', type=str, required=False, help="Ruta del archivo de entrada")
    parser.add_argument('-ad', '--additional_input', type=str, required=False, help="Ruta del fichero adicional")
    parser.add_argument('-o', '--output', type=str, required=False, help="Ruta del archivo de salida")
    return parser.parse_args()


# Determinar el modo de operacion
def check_args(args):
    # Levantar un error en caso de que el archivo de entrada no se incluya
    # if not os.path.isfile(args.input):
    #     raise FileNotFoundError

    # Modo escogido para las diferentes funcionalidades
    mode = args.mode
    if mode in ['cs', 'ds']:
        if args.password is None or args.output is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
    elif mode == 'h':
        if args.output is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
    elif mode == 's':
        if args.output is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
    elif mode in ['vh', 'vs']:
        if args.additional_input is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
        if not os.path.isfile(args.additional_input):
            raise FileNotFoundError
    elif mode == 'cert':
        if args.output is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
    if mode in ['ca', 'da']:
        # El additional_input es el certificado usado para extraer la clave pública
        if args.password is None or args.output is None:
            raise ArgumentError('Argumentos erroneos. Utiliza la bandera -h para ayuda')
    # TODO: Ejercicios extra
    elif mode == 'ts':
        raise UnsupportedOperationError('Operacion no implementada')
    elif mode == 'tsv':
        raise UnsupportedOperationError('Operacion no implementada')
