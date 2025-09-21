from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
from cryptography.fernet import Fernet
from keys import cargar_clave  # Asegúrate de que esta línea esté presente

def cifrar_archivo(ruta_archivo, ruta_clave_publica):
    """Cifra un archivo usando cifrado híbrido (AES y RSA)."""
    try:
        # Generar una clave AES aleatoria para cifrar los datos
        clave_aes = Fernet.generate_key()
        fernet = Fernet(clave_aes)
        
        # Cargar la clave pública o el certificado para cifrar la clave AES
        clave_publica_rsa = cargar_clave('publica', ruta_clave_publica)
        if clave_publica_rsa is None:
            return False, "No se pudo cargar la clave pública."
            
        # Cifrar la clave AES con la clave pública RSA
        clave_aes_cifrada = clave_publica_rsa.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
            
        # Leer y cifrar el archivo con AES
        with open(ruta_archivo, "rb") as archivo:
            datos_cifrados = fernet.encrypt(archivo.read())
            
        # Escribir la clave AES cifrada y los datos cifrados en el archivo de salida
        nombre_salida = ruta_archivo + ".cifrado"
        with open(nombre_salida, "wb") as f_salida:
            f_salida.write(len(clave_aes_cifrada).to_bytes(4, 'big'))
            f_salida.write(clave_aes_cifrada)
            f_salida.write(datos_cifrados)
            
        return True, "Archivo cifrado correctamente."
    except Exception as e:
        return False, f"Ocurrió un error: {e}"

def descifrar_archivo(ruta_archivo, ruta_clave_privada):
    """Descifra un archivo usando cifrado híbrido (AES y RSA)."""
    try:
        # Cargar la clave privada RSA para descifrar la clave AES
        clave_privada_rsa = cargar_clave('privada', ruta_clave_privada)
        if clave_privada_rsa is None:
            return False, "No se pudo cargar la clave privada."
            
        # Leer la clave AES cifrada y los datos cifrados del archivo de entrada
        with open(ruta_archivo, "rb") as f_entrada:
            tamano_clave_cifrada = int.from_bytes(f_entrada.read(4), 'big')
            clave_aes_cifrada = f_entrada.read(tamano_clave_cifrada)
            datos_cifrados = f_entrada.read()
            
        # Descifrar la clave AES con la clave privada RSA
        clave_aes = clave_privada_rsa.decrypt(
            clave_aes_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
            
        # Descifrar los datos con la clave AES
        fernet = Fernet(clave_aes)
        datos_descifrados = fernet.decrypt(datos_cifrados)
            
        # Escribir los datos descifrados en el archivo original
        nombre_original = os.path.splitext(ruta_archivo)[0]
        with open(nombre_original, "wb") as f_salida:
            f_salida.write(datos_descifrados)
            
        return True, "Archivo descifrado correctamente."
    except Exception as e:
        return False, f"Ocurrió un error: {e}"