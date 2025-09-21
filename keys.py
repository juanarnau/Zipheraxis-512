from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import datetime

# --- Importaciones adicionales para Certificados ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Directorio donde se guardarán las claves
CLAVES_DIR = "claves"

def generar_par_de_claves_con_cert(nombre_usuario):
    """Genera un par de claves RSA y un certificado con el nombre del usuario y caducidad."""
    # Asegurarse de que el directorio de claves exista
    if not os.path.exists(CLAVES_DIR):
        os.makedirs(CLAVES_DIR)

    # 1. Generar la clave privada
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    
    # 2. Crear el certificado X.509 con metadatos
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_usuario),
    ])
    
    certificado = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        clave_publica
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # El certificado será válido por 365 días
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(clave_privada, hashes.SHA256(), default_backend())
    
    # 3. Guardar la clave privada y el certificado público en el directorio CLAVES_DIR
    nombre_base = nombre_usuario.replace(" ", "_").lower()
    
    ruta_privada = os.path.join(CLAVES_DIR, f"{nombre_base}_privada.pem")
    with open(ruta_privada, "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    ruta_publica = os.path.join(CLAVES_DIR, f"{nombre_base}_publica.crt")
    with open(ruta_publica, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))
        
    return True

def obtener_claves():
    """Devuelve una lista de las rutas de todas las claves y certificados con sus metadatos."""
    # Asegurarse de que el directorio de claves exista antes de listar
    if not os.path.exists(CLAVES_DIR):
        return [], []
        
    archivos = os.listdir(CLAVES_DIR)
    
    certificados_publicos = []
    claves_privadas = []
    
    for f in archivos:
        ruta_completa = os.path.join(CLAVES_DIR, f)
        if f.endswith('.crt'):
            try:
                with open(ruta_completa, "rb") as key_file:
                    certificado = x509.load_pem_x509_certificate(key_file.read(), default_backend())
                    nombre = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    caducidad = certificado.not_valid_after.strftime("%Y-%m-%d")
                    certificados_publicos.append({
                        "nombre": nombre,
                        "tipo": "pública",
                        "caducidad": caducidad,
                        "ruta": ruta_completa
                    })
            except Exception as e:
                # Manejar archivos que no son certificados válidos
                print(f"Error al leer el certificado {f}: {e}")
                
        elif f.endswith('_privada.pem'):
            # Las claves privadas no tienen metadatos de caducidad
            claves_privadas.append({
                "nombre": os.path.basename(ruta_completa),
                "tipo": "privada",
                "caducidad": "N/A",
                "ruta": ruta_completa
            })
            
    return certificados_publicos, claves_privadas

def cargar_clave(tipo_clave, ruta):
    """Carga una clave (privada o pública) desde un archivo."""
    try:
        with open(ruta, "rb") as key_file:
            if tipo_clave == 'publica':
                # Intentar cargar como certificado primero
                try:
                    cert = x509.load_pem_x509_certificate(key_file.read(), default_backend())
                    return cert.public_key()
                except ValueError:
                    # Si no es un certificado, intentar cargar como clave pública normal
                    key_file.seek(0)  # Volver al inicio del archivo
                    return serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            else:
                return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        return None
        
def eliminar_clave(ruta_clave):
    """Elimina una clave del sistema de archivos."""
    try:
        os.remove(ruta_clave)
        return True
    except OSError as e:
        print(f"Error al eliminar el archivo: {e}")
        return False