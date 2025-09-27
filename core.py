import keys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding # Renombrado para evitar conflictos
from cryptography.hazmat.primitives import padding # Importacin correcta para PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json

def cifrar_archivo(ruta_archivo, clave_publica_pem):
  """Cifra un archivo usando una clave pblica RSA."""
  try:
    # Cargar la clave pblica desde el formato PEM
    clave_publica = serialization.load_pem_public_key(
      clave_publica_pem.encode('utf-8'),
      backend=default_backend()
    )

    # Generar una clave de sesin AES aleatoria
    clave_sesion = os.urandom(32) # Clave de 256-bit para AES

    # Cifrar la clave de sesin con la clave pblica RSA
    clave_sesion_cifrada = clave_publica.encrypt(
      clave_sesion,
      asymmetric_padding.OAEP( # Usar el padding de RSA
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
    )

    # Cifrar el archivo con la clave de sesin AES
    iv = os.urandom(16)
    cifrador = Cipher(algorithms.AES(clave_sesion), modes.CBC(iv), backend=default_backend()).encryptor()

    with open(ruta_archivo, 'rb') as f_entrada:
      datos_brutos = f_entrada.read()
      # Aadir padding a los datos antes de cifrar
      padder = padding.PKCS7(algorithms.AES.block_size).padder()
      datos_padded = padder.update(datos_brutos) + padder.finalize()
      datos_cifrados = cifrador.update(datos_padded) + cifrador.finalize()

    # Guardar la clave de sesin cifrada, el IV y los datos cifrados
    ruta_salida = ruta_archivo + ".enc"
    with open(ruta_salida, 'wb') as f_salida:
      f_salida.write(clave_sesion_cifrada)
      f_salida.write(iv)
      f_salida.write(datos_cifrados)
    
    return True, f"Archivo cifrado y guardado como '{ruta_salida}'"

  except Exception as e:
    return False, f"Error durante el cifrado: {e}"

def descifrar_archivo(ruta_archivo, clave_privada_pem):
  """Descifra un archivo usando una clave privada RSA."""
  try:
    # Cargar la clave privada desde el formato PEM
    clave_privada = serialization.load_pem_private_key(
      clave_privada_pem.encode('utf-8'),
      password=None, # La clave no tiene contrasea
      backend=default_backend()
    )

    with open(ruta_archivo, 'rb') as f_entrada:
      datos_completos = f_entrada.read()
      # La longitud de la clave RSA es 2048 bits, que son 256 bytes
      # La longitud de la clave de sesin cifrada es igual al tamao de la clave RSA
      tamanio_clave_rsa = clave_privada.key_size // 8 # Convertir a bytes
      
      clave_sesion_cifrada = datos_completos[:tamanio_clave_rsa]
      iv = datos_completos[tamanio_clave_rsa:tamanio_clave_rsa + 16]
      datos_cifrados = datos_completos[tamanio_clave_rsa + 16:]
    
    # Descifrar la clave de sesin con la clave privada RSA
    clave_sesion = clave_privada.decrypt(
      clave_sesion_cifrada,
      asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
    )
    
    # Descifrar el archivo con la clave de sesin AES
    descifrador = Cipher(algorithms.AES(clave_sesion), modes.CBC(iv), backend=default_backend()).decryptor()
    datos_padded = descifrador.update(datos_cifrados) + descifrador.finalize()

    # Quitar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    datos_descifrados = unpadder.update(datos_padded) + unpadder.finalize()

    # Guardar el archivo descifrado
    ruta_salida = os.path.splitext(ruta_archivo)[0]
    with open(ruta_salida, 'wb') as f_salida:
      f_salida.write(datos_descifrados)

    return True, f"Archivo descifrado y guardado como '{ruta_salida}'"

  except Exception as e:
    return False, f"Error durante el descifrado: {e}"

def cifrar_archivo_con_vault(ruta_archivo, nombre_clave_destino, contrasena_vault):
  """Cifra un archivo usando una clave pblica del vault."""
  vault, _, mensaje_error = keys.cargar_vault(contrasena_vault)
  if not vault:
    return False, f"Error al cargar el vault: {mensaje_error}"
  
  clave_publica_pem_str = None
  for clave_completa in vault['claves_publicas']:
    # La estructura es: {'nombre': 'alias', 'clave': {'nombre': 'alias', 'clave_publica_pem_str': '...'} }
    datos_clave = clave_completa.get('clave', clave_completa)
    
    if datos_clave.get('nombre') == nombre_clave_destino:
      #  CORRECCIN CLAVE: Acceder al string PEM anidado 
      clave_publica_pem_str = datos_clave.get('clave_publica_pem_str')
      break
      
  if not clave_publica_pem_str:
    return False, "Clave pblica de destino no encontrada en el vault o falta el contenido PEM."
    
  # Ahora pasamos la cadena de texto (string) al cifrador
  return cifrar_archivo(ruta_archivo, clave_publica_pem_str)

def descifrar_archivo_con_vault(ruta_archivo, nombre_clave_privada, contrasena_vault):
  """Descifra un archivo usando una clave privada del vault."""
  vault, _, mensaje_error = keys.cargar_vault(contrasena_vault)
  if not vault:
    return False, f"Error al cargar el vault: {mensaje_error}"

  clave_privada_pem_str = None
  for clave_completa in vault['claves_privadas']:
    # La estructura es: {'nombre': 'alias', 'clave': {'nombre': 'alias', 'clave_privada_pem_str': '...'} }
    datos_clave = clave_completa.get('clave', clave_completa)
    
    if datos_clave.get('nombre') == nombre_clave_privada:
      #  CORRECCIN CLAVE: Acceder al string PEM privado anidado
      clave_privada_pem_str = datos_clave.get('clave_privada_pem_str')
      break
      
  if not clave_privada_pem_str:
    return False, "Clave privada no encontrada en el vault o falta el contenido PEM."
    
  # Ahora pasamos la cadena de texto (string) al descifrador
  return descifrar_archivo(ruta_archivo, clave_privada_pem_str)

