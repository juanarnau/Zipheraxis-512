from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import os
import keys


def cifrar_archivo_desde_vault(ruta_archivo, nombre_clave_publica, password_vault):
    """Cifra un archivo obteniendo la clave pública del vault."""
    try:
        clave_aes = Fernet.generate_key()
        fernet = Fernet(clave_aes)
        
        # Cargar la clave pública desde el vault
        clave_publica_rsa = keys.cargar_clave_de_vault(nombre_clave_publica, password_vault)
        if clave_publica_rsa is None:
            return False, "No se pudo cargar la clave pública."
            
        clave_aes_cifrada = clave_publica_rsa.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(ruta_archivo, "rb") as archivo:
            datos_cifrados = fernet.encrypt(archivo.read())
            
        nombre_salida = ruta_archivo + ".cifrado"
        with open(nombre_salida, "wb") as f_salida:
            f_salida.write(len(clave_aes_cifrada).to_bytes(4, 'big'))
            f_salida.write(clave_aes_cifrada)
            f_salida.write(datos_cifrados)
            
        return True, "Archivo cifrado correctamente."
    except Exception as e:
        return False, f"Ocurrió un error: {e}"

def descifrar_archivo_desde_vault(nombre_clave_privada, password_clave_privada, ruta_archivo, password_vault):
    """Descifra un archivo obteniendo la clave privada del vault."""
    try:
        # Cargar la clave privada desde el vault
        clave_privada_rsa = keys.cargar_clave_de_vault(nombre_clave_privada, password_vault)
        if clave_privada_rsa is None:
            return False, "No se pudo cargar la clave privada."
            
        with open(ruta_archivo, "rb") as f_entrada:
            tamano_clave_cifrada = int.from_bytes(f_entrada.read(4), 'big')
            clave_aes_cifrada = f_entrada.read(tamano_clave_cifrada)
            datos_cifrados = f_entrada.read()
            
        clave_aes = clave_privada_rsa.decrypt(
            clave_aes_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        fernet = Fernet(clave_aes)
        datos_descifrados = fernet.decrypt(datos_cifrados)
        
        nombre_original = os.path.splitext(ruta_archivo)[0]
        with open(nombre_original, "wb") as f_salida:
            f_salida.write(datos_descifrados)
            
        return True, "Archivo descifrado correctamente."
    except Exception as e:
        return False, f"Ocurrió un error: {e}"