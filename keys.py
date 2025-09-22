import os
import datetime
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet

# Directorio donde se guardará el almacén de claves
CLAVES_DIR = "claves"
VAULT_FILE = os.path.join(CLAVES_DIR, "key_vault.dat")

def generar_llave_de_vault(password, salt=None):
    """Genera una clave de encriptación para el vault a partir de la contraseña."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = b64encode(kdf.derive(password.encode()))
    return key, salt

def crear_vault(password):
    """Crea un nuevo vault de claves encriptado."""
    if not os.path.exists(CLAVES_DIR):
        os.makedirs(CLAVES_DIR)

    key, salt = generar_llave_de_vault(password)
    fernet = Fernet(key)
    
    vault_data = {
        "keys": []
    }
    
    try:
        # Encriptamos el vault y guardamos el salt junto con los datos encriptados
        encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode('utf-8'))
        
        with open(VAULT_FILE, "wb") as f:
            f.write(b64encode(salt) + b"|" + encrypted_vault)
        return True
    except Exception as e:
        print(f"Error al crear el vault: {e}")
        return False

def cargar_vault(password):
    """Carga y desencripta el vault de claves."""
    if not os.path.exists(VAULT_FILE):
        return None, "Vault no encontrado."
    
    try:
        with open(VAULT_FILE, "rb") as f:
            full_data = f.read()
        
        # Separamos el salt de los datos encriptados
        salt_encoded, encrypted_data = full_data.split(b"|", 1)
        salt = b64decode(salt_encoded)
        
        # Generamos la clave usando la contraseña y el salt recuperado
        key, _ = generar_llave_de_vault(password, salt)
        fernet = Fernet(key)
        
        decrypted_data = fernet.decrypt(encrypted_data)
        vault_data = json.loads(decrypted_data)
        
        return vault_data, None
        
    except Exception as e:
        return None, f"Contraseña incorrecta: {e}"

def obtener_claves_de_vault(vault_data):
    """Extrae las claves del vault y las organiza."""
    certificados_publicos = []
    claves_privadas = []
    for k in vault_data["keys"]:
        if k["tipo"] == "publica":
            certificados_publicos.append(k)
        elif k["tipo"] == "privada":
            claves_privadas.append(k)
    return certificados_publicos, claves_privadas

def agregar_clave_a_vault(nombre, password_vault):
    """Genera un nuevo par de claves y lo añade al vault."""
    vault_data, _ = cargar_vault(password_vault)
    if not vault_data:
        return False, "No se pudo cargar el vault."
    
    # Prevenir duplicados
    if any(k["nombre"] == f"{nombre}_privada.pem" for k in vault_data["keys"]):
        return False, "Ya existe un par de claves con este nombre."

    clave_privada = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
    certificado = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(clave_publica).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).sign(clave_privada, hashes.SHA256(), default_backend())

    nueva_clave_privada = {
        "nombre": f"{nombre}_privada.pem",
        "tipo": "privada",
        "caducidad": "N/A",
        "data": b64encode(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')
    }

    nueva_clave_publica = {
        "nombre": f"{nombre}_publica.crt",
        "tipo": "publica",
        "caducidad": certificado.not_valid_after.strftime("%Y-%m-%d"),
        "data": b64encode(certificado.public_bytes(serialization.Encoding.PEM)).decode('utf-8')
    }

    vault_data["keys"].append(nueva_clave_privada)
    vault_data["keys"].append(nueva_clave_publica)
    
    if guardar_vault(password_vault, vault_data):
        return True, "Claves añadidas correctamente."
    else:
        return False, "Error al guardar los cambios en el vault."

def eliminar_clave_de_vault(nombre_clave, password_vault):
    """Elimina una clave del vault y guarda los cambios."""
    vault_data, _ = cargar_vault(password_vault)
    if not vault_data:
        return False

    vault_data["keys"] = [k for k in vault_data["keys"] if k["nombre"] != nombre_clave]
    
    if nombre_clave.endswith("_privada.pem"):
        nombre_publica = nombre_clave.replace("_privada.pem", "_publica.crt")
        vault_data["keys"] = [k for k in vault_data["keys"] if k["nombre"] != nombre_publica]
    elif nombre_clave.endswith("_publica.crt"):
        nombre_privada = nombre_clave.replace("_publica.crt", "_privada.pem")
        vault_data["keys"] = [k for k in vault_data["keys"] if k["nombre"] != nombre_privada]

    return guardar_vault(password_vault, vault_data)

def guardar_vault(password, vault_data):
    """Encripta y guarda el vault en el disco."""
    key, salt = generar_llave_de_vault(password)
    fernet = Fernet(key)
    
    try:
        encrypted_vault = fernet.encrypt(json.dumps(vault_data).encode('utf-8'))
        
        with open(VAULT_FILE, "wb") as f:
            f.write(b64encode(salt) + b"|" + encrypted_vault)
        return True
    except Exception as e:
        print(f"Error al guardar el vault: {e}")
        return False

def cargar_clave_de_vault(nombre_clave, password_vault):
    """Carga una clave específica del vault."""
    vault_data, _ = cargar_vault(password_vault)
    if not vault_data:
        return None

    for k in vault_data["keys"]:
        if k["nombre"] == nombre_clave:
            data_bytes = b64decode(k["data"])
            if k["tipo"] == "privada":
                return serialization.load_pem_private_key(data_bytes, password=None, backend=default_backend())
            elif k["tipo"] == "publica":
                try:
                    cert = x509.load_pem_x509_certificate(data_bytes, default_backend())
                    return cert.public_key()
                except ValueError:
                    try:
                        return serialization.load_pem_public_key(data_bytes, backend=default_backend())
                    except Exception as e:
                        print(f"Error al cargar clave pública {nombre_clave}: {e}")
                        return None
    return None