import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding # <--- IMPORTACIÓN AÑADIDA
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# ----------------------------------------------------------------------
# LÓGICA DE PERSISTENCIA PARA EJECUTABLE (PYINSTALLER)
# Se asegura que el vault y el salt se guarden en una ubicación estable.
# ----------------------------------------------------------------------
# 1. Definir la carpeta de la aplicación en AppData/Roaming de Windows.
APP_FOLDER_NAME = "Zipheraxis-512"
APP_DATA_PATH = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', APP_FOLDER_NAME)

# 2. Asegurar que la carpeta exista antes de guardar archivos.
if not os.path.exists(APP_DATA_PATH):
    try:
        os.makedirs(APP_DATA_PATH)
    except Exception as e:
        # En caso de error de permisos, revertir a la carpeta de Documentos
        print(f"Advertencia: No se pudo crear AppData. Usando Documentos. Error: {e}")
        APP_DATA_PATH = os.path.join(os.path.expanduser('~'), 'Documents', APP_FOLDER_NAME)
        if not os.path.exists(APP_DATA_PATH):
             os.makedirs(APP_DATA_PATH)

# 3. Definir las rutas persistentes de los archivos del vault y el salt.
# Apuntan a la ruta AppData, y VAULT_FILE usa .dat (binario).
VAULT_FILE = os.path.join(APP_DATA_PATH, "vault.dat")
SALT_FILE = os.path.join(APP_DATA_PATH, "salt.bin")
# ----------------------------------------------------------------------

def obtener_clave_aes(contrasena, sal):
    """Deriva una clave AES de la contraseña y la sal."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=600000, # Aumentado a 480k iteraciones para mejor seguridad
        backend=default_backend()
    )
    return kdf.derive(contrasena.encode('utf-8'))

def guardar_vault(contrasena, datos):
    """Cifra y guarda el diccionario de claves en un archivo vault.dat."""
    # --- GESTIÓN DE SALT ---
    if not os.path.exists(SALT_FILE):
        sal = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(sal)
    else:
        with open(SALT_FILE, "rb") as f:
            sal = f.read()
    # -----------------------

    clave_aes = obtener_clave_aes(contrasena, sal)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    try:
        # Convertir datos a JSON y luego a bytes
        datos_json = json.dumps(datos).encode('utf-8')
        
        # Asegurarse de que los datos tengan padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_datos = padder.update(datos_json) + padder.finalize()
        
        datos_cifrados = encryptor.update(padded_datos) + encryptor.finalize()

        # Guardar IV + Datos cifrados en el VAULT_FILE persistente
        with open(VAULT_FILE, "wb") as f:
            f.write(iv + datos_cifrados)
            
        return True, "Vault guardado con éxito."

    except Exception as e:
        return False, f"Error al guardar el vault en '{VAULT_FILE}': {e}"

def cargar_vault(contrasena):
    """Carga y descifra el diccionario de claves desde el archivo vault.dat."""
    # Verificar existencia en la ruta persistente
    if not os.path.exists(VAULT_FILE) or not os.path.exists(SALT_FILE):
        return None, None, "El vault o el archivo de sal no existen."

    with open(SALT_FILE, "rb") as f:
        sal = f.read()
    
    clave_aes = obtener_clave_aes(contrasena, sal)
    
    with open(VAULT_FILE, "rb") as f:
        datos_completos = f.read()
        iv = datos_completos[:16]
        datos_cifrados = datos_completos[16:]

    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_datos = decryptor.update(datos_cifrados) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        datos_descifrados = unpadder.update(padded_datos) + unpadder.finalize()

        # Cargar los datos JSON descifrados
        datos = json.loads(datos_descifrados.decode('utf-8'))
        return datos, None, None
    
    except Exception:
        # Esto captura errores de padding incorrecto (debido a contraseña errónea) o errores de JSON inválido
        return None, None, "Contraseña incorrecta o error en la derivación de clave."

def generar_par_de_claves(nombre):
    """Genera un par de claves RSA."""
    clave_privada_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_obj = clave_privada_obj.public_key()
    
    # Serializar claves a formato PEM (SIEMPRE usar .decode('utf-8'))
    clave_privada_pem_str = clave_privada_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    clave_publica_pem_str = clave_publica_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Lógica de fecha de caducidad
    fecha_expiracion = datetime.now() + timedelta(days=365 * 1)
    fecha_caducidad_str = fecha_expiracion.strftime('%Y-%m-%d')
    
    # PASO CRÍTICO: Crear los diccionarios de claves con nombres de campo EXPLICITOS
    
    # Este diccionario contiene la CLAVE PÚBLICA PEM
    datos_clave_publica = {
        "nombre": nombre,
        # CAMBIO CLAVE: Usamos nombre de campo explícito
        "clave_publica_pem_str": clave_publica_pem_str, 
        "expiration_date": fecha_caducidad_str 
    }
    
    # Este diccionario contiene la CLAVE PRIVADA PEM
    datos_clave_privada = {
        "nombre": nombre,
        # CAMBIO CLAVE: Usamos nombre de campo explícito
        "clave_privada_pem_str": clave_privada_pem_str, 
        "expiration_date": fecha_caducidad_str
    }
    
    return datos_clave_publica, datos_clave_privada 

def agregar_par_claves_a_vault(contrasena, nombre):
    """Genera un par de claves y lo añade al vault."""
    vault, _, mensaje_error = cargar_vault(contrasena)
    if not vault:
        # En lugar de fallar, verifica si el mensaje de error es 'El vault o el archivo de sal no existen.'
        # Si es así, crea la estructura inicial.
        if "no existen" in mensaje_error:
            # Crea la estructura inicial del vault
            vault = {'claves_privadas': [], 'claves_publicas': [], 'metadatos': {'version': '1.0'}}
        else:
            return None, mensaje_error

    try:
        # Renombramos las variables para ser más claros
        datos_clave_publica, datos_clave_privada = generar_par_de_claves(nombre)
        
        # Guardamos el diccionario completo de la clave privada
        vault['claves_privadas'].append({"nombre": nombre, "clave": datos_clave_privada})
        
        # Guardamos el diccionario completo de la clave pública
        vault['claves_publicas'].append({"nombre": nombre, "clave": datos_clave_publica})

        success, mensaje = guardar_vault(contrasena, vault)
        if success:
            return vault, "Par de claves generado y guardado con éxito."
        else:
            return None, mensaje
            
    except Exception as e:
        return None, f"Error al generar y guardar las claves: {e}"

def importar_clave_a_vault(contrasena, nombre, ruta_archivo): # Se agregó 'contrasena' para guardar
    """Importa una clave pública desde un archivo y la añade al vault."""
    vault_data, _, mensaje_error = cargar_vault(contrasena)
    if not vault_data:
        return None, mensaje_error
        
    try:
        with open(ruta_archivo, 'rb') as f:
            clave_pem_bin = f.read()

        # Cargar la clave para validar su formato (lanzará error si es privada o inválida)
        serialization.load_pem_public_key(clave_pem_bin)

        clave_pem_str = clave_pem_bin.decode('utf-8')
        
        # Al importar, usamos el nombre estandarizado y 'N/A' como fecha de caducidad
        datos_clave_publica_importada = {
            "nombre": nombre,
            "clave_publica_pem_str": clave_pem_str,
            # CORRECTO: Usamos "N/A" para indicar que no hay fecha de caducidad conocida.
            "expiration_date": "N/A" 
        }
        
        # Guardamos la clave importada, usando la misma estructura anidada del vault
        vault_data['claves_publicas'].append({"nombre": nombre, "clave": datos_clave_publica_importada})

        # Guardar el vault actualizado
        success, mensaje = guardar_vault(contrasena, vault_data)
        if success:
             return vault_data, "Clave pública importada con éxito."
        else:
             return None, f"Error al guardar el vault: {mensaje}"
             
    except Exception as e:
        # Mejora en el manejo de errores
        return None, f"Error al importar clave: El formato PEM no es válido o la clave es privada. Detalle: {e}"


def eliminar_clave_de_vault(contrasena, nombre): # Se agregó 'contrasena' para cargar y guardar
    """Elimina un par de claves por su nombre del vault y guarda."""
    vault_data, _, mensaje_error = cargar_vault(contrasena)
    if not vault_data:
        return None, mensaje_error
        
    vault_data['claves_privadas'] = [c for c in vault_data['claves_privadas'] if c['nombre'] != nombre]
    vault_data['claves_publicas'] = [c for c in vault_data['claves_publicas'] if c['nombre'] != nombre]

    success, mensaje = guardar_vault(contrasena, vault_data)
    if success:
         return vault_data, "Clave eliminada con éxito."
    else:
         return None, f"Error al guardar el vault después de la eliminación: {mensaje}"

def obtener_clave_publica(vault_data, nombre):
    """Obtiene un objeto de clave pública a partir de su nombre."""
    for c in vault_data.get('claves_publicas', []):
        if c.get('nombre') == nombre:
            # Accede al campo estandarizado
            clave_pem_str = c['clave'].get('clave_publica_pem_str')
            if clave_pem_str:
                return serialization.load_pem_public_key(clave_pem_str.encode('utf-8'))
    return None

def obtener_clave_privada(vault_data, nombre):
    """Obtiene un objeto de clave privada a partir de su nombre."""
    for c in vault_data.get('claves_privadas', []):
        if c.get('nombre') == nombre:
            # Accede al campo estandarizado
            clave_pem_str = c['clave'].get('clave_privada_pem_str')
            if clave_pem_str:
                return serialization.load_pem_private_key(
                    clave_pem_str.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
    return None

def obtener_clave_publica_por_nombre(vault_data, nombre):
    """Obtiene el PEM de una clave pública a partir de su nombre."""
    for c in vault_data.get('claves_publicas', []):
        if c.get('nombre') == nombre:
            # Devuelve directamente la cadena PEM pública estandarizada
            return c['clave'].get('clave_publica_pem_str')
    return None