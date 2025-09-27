import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image
import os
import keys
import core

# Obtener la ruta del directorio actual donde se encuentra ui.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Rutas de los archivos de imagen (MODIFICADAS A ABSOLUTAS) ---
# Usamos os.path.join para crear rutas robustas que funcionen en cualquier SO.
LOGO_PATH = os.path.join(BASE_DIR, "assets", "logo.png")  
ICON_ICO_PATH = os.path.join(BASE_DIR, "assets", "icon.ico") 
ICON_PNG_PATH = os.path.join(BASE_DIR, "assets", "icon.png") 
# ------------------------------------------------------------------

# Configuracin de la ventana principal
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# ==========================================================
# CLASE DE VENTANA DE AYUDA (VERSIN CON SCROLLABLE FRAME)
# ==========================================================

class AyudaWindow(ctk.CTkToplevel):
  """Ventana de ayuda robusta usando un CTkScrollableFrame."""
  def __init__(self, master=None, **kwargs): 
    super().__init__(master, **kwargs)
    self.title("Ayuda: Cifrado Asimtrico")
    self.geometry("550x500") # Un poco ms grande para el frame
    self.transient(master) 
    self.grab_set() 
    self.update() 
    
    self.grid_columnconfigure(0, weight=1)
    self.grid_rowconfigure(0, weight=1)
    
    # Contenedor principal con scroll
    self.scrollable_frame = ctk.CTkScrollableFrame(self, label_text="Flujo de Cifrado Asimtrico")
    self.scrollable_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
    self.scrollable_frame.grid_columnconfigure(0, weight=1)

    # Contenido de la ayuda
    pasos_ayuda = [
      "Paso 1: Genera un par de claves con un nombre (ej: \"MiClaveSecreta\"). Esto guarda la clave pblica y la privada en tu vault.",
      "Paso 2: Exporta la clave pblica (botn \"Exportar Clave Pblica\") y dsela a la persona que te envi el archivo.",
      "Paso 3: La otra persona cifra el archivo usando tu clave pblica.",
      "Paso 4: Cuando recibes el archivo cifrado y usas el nombre \"MiClaveSecreta\" para descifrar, tu programa encuentra la clave privada y descifra el archivo.",
      
      # ADVERTENCIA AYUDA
      "---> : *****************************************************************\nINFORMACIN SOBRE CLAVES IMPORTADAS\nLas claves pblicas importadas de archivos externos (formato PEM) no contienen metadatos de caducidad.\nClaves generadas: Tienen la fecha de caducidad controlada por el Vault.\nClaves importadas: Muestran 'Caduca: N/A' porque esta informacin se pierde al exportarse al formato PEM estndar.\nSe recomienda contactar al remitente de la clave para confirmar su periodo de validez."
    ]
    
    # 1. Configuracin de fuentes y tags
    try:
      font_name = ctk.ThemeManager.theme["CTkFont"]["family"] 
    except:
      font_name = "Arial" 
      
    font_size = 14
    
    font_regular = ctk.CTkFont(family=font_name, size=font_size)
    font_bold = ctk.CTkFont(family=font_name, size=font_size, weight="bold")
    
    # 2. Insertar cada paso como un CTkLabel separado dentro del frame scrollable
    for i, paso in enumerate(pasos_ayuda):
      partes = paso.split(":", 1)
      titulo = partes[0] + ":"
      contenido = partes[1].strip()
      
      # Crear un frame para contener el ttulo y el contenido 
      paso_frame = ctk.CTkFrame(self.scrollable_frame, fg_color="transparent")
      paso_frame.grid(row=i, column=0, sticky="ew", pady=(10, 0))
      paso_frame.grid_columnconfigure(0, weight=0) # Ttulo fijo
      paso_frame.grid_columnconfigure(1, weight=1) # Contenido expansible
      
      # Label para el ttulo (en negrita)
      label_titulo = ctk.CTkLabel(paso_frame, text=titulo, font=font_bold, anchor="nw")
      label_titulo.grid(row=0, column=0, sticky="w")
      
      # Label para el contenido (regular)
      # Usamos wraplength para que el texto se ajuste a la ventana
      label_contenido = ctk.CTkLabel(paso_frame, text=contenido, font=font_regular, anchor="nw", justify="left", wraplength=400)
      label_contenido.grid(row=0, column=1, sticky="ew")
    
    # Intenta copiar el icono de la ventana principal
    self.after(1, self.aplicar_icono_forzado) 


  def aplicar_icono_forzado(self):
    """Intenta aplicar el icono con un pequeo retraso para evitar el parpadeo."""
    try:
      # Intenta usar el mismo icono ICO de la ventana principal
      self.iconbitmap(ICON_ICO_PATH)
    except Exception as e:
      # print(f"Error al configurar el icono en la ventana de ayuda: {e}")
      pass
    


# ==========================================================
# CLASE DE LA APLICACIN PRINCIPAL
# ==========================================================
class App(ctk.CTk):
  def __init__(self):
    super().__init__()

    self.title("Zipheraxis")
    self.geometry("700x500")
    # ==========================================================
    # 1. ESTABLECER EL ICONO DE LA VENTANA Y LA BARRA DE TAREAS
    # ==========================================================
    
    # 1.1 Cargar el ICO (para el marco de la ventana principal y messagebox)
    try:
      self.iconbitmap(ICON_ICO_PATH)
    except Exception as e_ico:
      print(f"Advertencia: No se pudo cargar el icono ICO: {e_ico}.")
      
    # 1.2 Cargar el PNG (Necesario para la barra de tareas en muchos SOs)
    self.icon_png = None 
    try:
      # Usamos tk.PhotoImage ya que ctk.CTkImage no es compatible con wm_iconphoto
      self.icon_png = tk.PhotoImage(file=ICON_PNG_PATH) 
      
      # 1.3 Aplicar el PNG al icono de la barra de tareas.
      # wm_iconphoto es el mtodo estndar para establecer el icono de la barra de tareas
      self.wm_iconphoto(True, self.icon_png)
      
    except Exception as e_png:
      print(f"Advertencia: No se pudo cargar ni aplicar el logo PNG para la barra de tareas: {e_png}")
      
    self.update_idletasks() 
    
    # ==========================================================
    # 2. CONFIGURACIN DEL GRID PRINCIPAL (Asegurar pesos de columnas)
    # ==========================================================
    # Fila 0 (Header) | Fila 1 (Contenido)
    self.grid_rowconfigure(0, weight=0) 
    self.grid_rowconfigure(1, weight=1) 
    
    # Columna 0 (Logo) | Columna 1 (Botones de Vault)
    # Damos peso al logo, pero permitimos que los botones se ajusten bien a la derecha.
    self.grid_columnconfigure(0, weight=1) 
    self.grid_columnconfigure(1, weight=0) 
    
    # ==========================================================
    # SECCIN DEL HEADER (Logo, Ttulo, Contrasea y Botones Principales)
    # ==========================================================
    
    # --- Contenedor para el Logo y el Ttulo (columna 0 del header) ---
    self.logo_title_frame = ctk.CTkFrame(self, fg_color="transparent")
    self.logo_title_frame.grid(row=0, column=0, padx=20, pady=(20, 0), sticky="nw")
    self.logo_title_frame.grid_columnconfigure(0, weight=1)
    
    try:
      # Cargar la imagen del logo
      logo_image_pil = Image.open(LOGO_PATH)
      LOGO_SIZE = (80, 80) 
      logo_image = ctk.CTkImage(light_image=logo_image_pil,
             dark_image=logo_image_pil,
             size=LOGO_SIZE) 
      
      self.logo_label = ctk.CTkLabel(self.logo_title_frame, image=logo_image, text="", anchor="w")
      self.logo_label.grid(row=0, column=0, sticky="w")
      
    except FileNotFoundError:
      print(f"ERROR: No se encontr el logo en {LOGO_PATH}.")
    except Exception as e:
      print(f"Error inesperado al cargar el logo: {e}")

    self.suite_name_label = ctk.CTkLabel(self.logo_title_frame, 
                 text="Zipheraxis-512", 
                 font=ctk.CTkFont(size=14, weight="bold"))
    self.suite_name_label.grid(row=1, column=0, sticky="w", pady=(5,0))

    # --- Contenedor para Contrasea y Botones de Vault (columna 1 del header) ---
    self.header_vault_frame = ctk.CTkFrame(self, fg_color="transparent")
    # NOTA: Usamos sticky="ne" para asegurar que se ancla a la esquina superior derecha
    self.header_vault_frame.grid(row=0, column=1, padx=20, pady=(20, 0), sticky="ne") 
    
    # Configurar filas y columnas para los widgets dentro de este frame
    self.header_vault_frame.grid_columnconfigure(0, weight=1) 
    self.header_vault_frame.grid_columnconfigure(1, weight=1) 
    
    # Etiqueta de Contrasea (Fila 0)
    self.label_pass_header = ctk.CTkLabel(self.header_vault_frame, text="Contrasea del Cofre:")
    self.label_pass_header.grid(row=0, column=0, columnspan=2, padx=5, pady=(0, 0), sticky="w")

    # Entrada de Contrasea (Fila 1)
    self.entry_pass_header = ctk.CTkEntry(self.header_vault_frame, show="*")
    self.entry_pass_header.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

    # Botones de Vault (Fila 2)
    self.boton_crear_vault_header = ctk.CTkButton(self.header_vault_frame, text="Crear Cofre", command=self.crear_vault)
    self.boton_crear_vault_header.grid(row=2, column=0, padx=5, pady=(5, 0), sticky="ew")

    self.boton_cargar_vault_header = ctk.CTkButton(self.header_vault_frame, text="Cargar Cofre", command=self.cargar_vault)
    self.boton_cargar_vault_header.grid(row=2, column=1, padx=5, pady=(5, 0), sticky="ew")
    
    # Botones de Ayuda y Salir (Fila 3)
    self.boton_ayuda = ctk.CTkButton(self.header_vault_frame, text="Ayuda", command=self.mostrar_ventana_ayuda)
    self.boton_ayuda.grid(row=3, column=0, padx=5, pady=(5, 0), sticky="ew")
    
    self.boton_salir = ctk.CTkButton(self.header_vault_frame, text="Salir", command=self.destroy, fg_color="red")
    self.boton_salir.grid(row=3, column=1, padx=5, pady=(5, 0), sticky="ew")


    # ==========================================================
    # RESTO DE LA INTERFAZ (Pestaas)
    # ==========================================================
    
    self.main_frame = ctk.CTkFrame(self)
    self.main_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=20, sticky="nsew")
    self.main_frame.grid_rowconfigure(0, weight=1)
    self.main_frame.grid_columnconfigure(0, weight=1)

    self.tabview = ctk.CTkTabview(self.main_frame)
    self.tabview.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")
    self.tabview.add("Gestin de Claves")
    self.tabview.add("Cifrar/Descifrar")

    self.tabview.tab("Gestin de Claves").grid_columnconfigure(0, weight=1)
    self.tabview.tab("Gestin de Claves").grid_columnconfigure(1, weight=1)
    self.tabview.tab("Cifrar/Descifrar").grid_columnconfigure(0, weight=1)
    self.tabview.tab("Cifrar/Descifrar").grid_columnconfigure(1, weight=1)

    self.vault_data = None
    self.crear_ui_gestion_claves()
    self.crear_ui_cifrar_descifrar()

  def mostrar_mensaje(self, titulo, mensaje):
    """
    Muestra un cuadro de diálogo informativo.
    🚨 CORRECCIÓN: Usar title=titulo para forzar la correcta codificación del título 
    en plataformas problemáticas con messagebox.
    """
    # Usamos la función original de Tkinter/CustomTkinter.
    # Tkinter maneja el primer argumento como el título y el segundo como el mensaje,
    # pero lo hacemos explícito para asegurar la compatibilidad de encoding en el título.
    try:
      messagebox.showinfo(title=titulo, message=mensaje)
    except UnicodeEncodeError:
      # Fallback si el título tiene caracteres especiales y falla la codificación
      messagebox.showinfo(title="Resultado", message=f"({titulo}): {mensaje}")
    '''
      def mostrar_mensaje(self, titulo, mensaje):
        messagebox.showinfo(titulo, mensaje)
    ''' 
  def mostrar_ventana_ayuda(self):
    """Muestra la ventana de ayuda personalizada con formato de negrita."""
    self.help_window = AyudaWindow(self) 


  # -----------------------------------------------------------------
  # MTODOS DE LA UI Y LGICA 
  # -----------------------------------------------------------------
  def crear_ui_gestion_claves(self):
    # Entrada de contrasea (Oculta, solo existe para compatibilidad interna)
    self.entry_pass = ctk.CTkEntry(self.tabview.tab("Gestin de Claves"), show="*", width=1, height=1)
    
    # Lista de claves 
    self.lista_claves = ctk.CTkTextbox(self.tabview.tab("Gestin de Claves"))
    self.lista_claves.grid(row=1, column=0, rowspan=5, padx=10, pady=5, sticky="nsew") 

    # Entrada de nombre de clave
    self.label_nombre_clave = ctk.CTkLabel(self.tabview.tab("Gestin de Claves"), text="Nombre de la Clave:")
    self.label_nombre_clave.grid(row=0, column=1, padx=10, pady=(20, 0), sticky="w")
    self.entry_nombre_clave = ctk.CTkEntry(self.tabview.tab("Gestin de Claves"))
    self.entry_nombre_clave.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    # Botones de gestin de claves
    self.boton_generar_claves = ctk.CTkButton(self.tabview.tab("Gestin de Claves"), text="Generar Par de Claves", command=self.generar_claves)
    self.boton_generar_claves.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

    self.boton_importar_clave = ctk.CTkButton(self.tabview.tab("Gestin de Claves"), text="Importar Clave Pblica", command=self.manejar_importar_clave)
    self.boton_importar_clave.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    self.boton_exportar_clave = ctk.CTkButton(self.tabview.tab("Gestin de Claves"), text="Exportar Clave Pblica", command=self.exportar_clave_publica)
    self.boton_exportar_clave.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

    self.boton_eliminar_clave = ctk.CTkButton(self.tabview.tab("Gestin de Claves"), text="Eliminar Clave", command=self.eliminar_clave)
    self.boton_eliminar_clave.grid(row=5, column=1, padx=10, pady=5, sticky="ew")

    # Area de texto para mostrar las claves y el estado
    self.text_area = ctk.CTkTextbox(self.tabview.tab("Gestin de Claves"), wrap="word")
    self.text_area.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")


  def crear_ui_cifrar_descifrar(self):
    # Seleccin de archivo
    self.label_ruta_archivo = ctk.CTkLabel(self.tabview.tab("Cifrar/Descifrar"), text="Ruta del Archivo:")
    self.label_ruta_archivo.grid(row=0, column=0, padx=10, pady=(20, 0), sticky="w")
    self.entry_ruta_archivo = ctk.CTkEntry(self.tabview.tab("Cifrar/Descifrar"))
    self.entry_ruta_archivo.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

    self.boton_seleccionar_archivo = ctk.CTkButton(self.tabview.tab("Cifrar/Descifrar"), text="Seleccionar Archivo", command=self.seleccionar_archivo)
    self.boton_seleccionar_archivo.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    # Seleccin de clave (ComboBox)
    self.label_clave_destino = ctk.CTkLabel(self.tabview.tab("Cifrar/Descifrar"), text="Clave de Destino:")
    self.label_clave_destino.grid(row=2, column=0, padx=10, pady=(20, 0), sticky="w")
    self.combo_clave_destino = ctk.CTkComboBox(self.tabview.tab("Cifrar/Descifrar"), values=[""])
    self.combo_clave_destino.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

    # Botones de cifrar/descifrar
    self.boton_cifrar = ctk.CTkButton(self.tabview.tab("Cifrar/Descifrar"), text="Cifrar Archivo", command=self.cifrar_archivo)
    self.boton_cifrar.grid(row=4, column=0, padx=10, pady=5, sticky="ew")
    self.boton_descifrar = ctk.CTkButton(self.tabview.tab("Cifrar/Descifrar"), text="Descifrar Archivo", command=self.descifrar_archivo)
    self.boton_descifrar.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

  # -----------------------------------------------------------------
  # MTODOS DE LGICA (Usan self.entry_pass_header)
  # -----------------------------------------------------------------
  
  def get_vault_password(self):
    """Funcin auxiliar para obtener la contrasea del Entry del header."""
    return self.entry_pass_header.get()

  def crear_vault(self):
    password = self.get_vault_password()
    if not password:
      messagebox.showerror("Error", "La contrasea no puede estar vacia.")
      return

    if os.path.exists(keys.VAULT_FILE):
      messagebox.showerror("Error", "Ya existe un Cofre de claves. Brralo para crear uno nuevo.")
      return
      
    success, mensaje = keys.guardar_vault(password, {"claves_publicas": [], "claves_privadas": []})
    
    if success:
      self.mostrar_mensaje("Exito", mensaje)
    else:
      self.mostrar_mensaje("Error", mensaje)

  def cargar_vault(self):
    password = self.get_vault_password()
    vault_data, _, mensaje_error = keys.cargar_vault(password)
    if vault_data:
      self.vault_data = vault_data
      self.mostrar_mensaje("Exito", "Cofre cargado con Exito.")
      self.actualizar_ui()
      # Copiar la contrasea del header al entry oculto para las otras funciones
      self.entry_pass.delete(0, tk.END)
      self.entry_pass.insert(0, password)
    else:
      self.mostrar_mensaje("Error", f"Error al cargar el Cofre: {mensaje_error}")

  def generar_claves(self):
    nombre = self.entry_nombre_clave.get()
    password = self.get_vault_password() 
    if not nombre or not password:
      messagebox.showerror("Error", "El nombre de la clave y la contrasea del Cofre no pueden estar vacios.")
      return

    if not hasattr(self, 'vault_data'):
      messagebox.showerror("Error", "Debes cargar el Cofre primero.")
      return

    vault_actualizado, mensaje = keys.agregar_par_claves_a_vault(password, nombre)
    if vault_actualizado:
      self.vault_data = vault_actualizado
      self.mostrar_mensaje("Exito", mensaje)
      self.actualizar_ui()
    else:
      self.mostrar_mensaje("Error", mensaje)

  def manejar_importar_clave(self):
    nombre = self.entry_nombre_clave.get()
    if not nombre:
      messagebox.showerror("Error", "El nombre de la clave no puede estar vacio.")
      return

    if not hasattr(self, 'vault_data'):
      messagebox.showerror("Error", "Debes cargar el Cofre primero.")
      return

    ruta_archivo = filedialog.askopenfilename(
      filetypes=[("Archivos de clave", "*.pem *.pub *.cer")]
    )
    if not ruta_archivo:
      return

    vault_actualizado, mensaje = keys.importar_clave_a_vault(self.vault_data, nombre, ruta_archivo)
    if vault_actualizado:
      self.vault_data = vault_actualizado
      self.mostrar_mensaje("Exito", mensaje)
      self.actualizar_ui()
      password = self.get_vault_password()
      keys.guardar_vault(password, self.vault_data)
    else:
      self.mostrar_mensaje("Error", mensaje)

  def exportar_clave_publica(self):
    """Maneja la lgica para exportar la clave pblica seleccionada."""
    from tkinter import filedialog 

    nombre_clave = self.entry_nombre_clave.get().strip() 
    clave_publica_pem_str = None
    
    if not nombre_clave:
      self.mostrar_mensaje("Error", "Por favor, introduce el nombre de la clave a exportar.")
      return

    try:
      # 1. Buscar el diccionario de la clave.
      clave_completa = self.obtener_clave_por_nombre(nombre_clave, 'publicas') 
      
      if not clave_completa:
        self.mostrar_mensaje("Error", f"Clave pblica '{nombre_clave}' no encontrada en el Cofre.")
        return

      # 2. Obtener el diccionario de datos anidado
      datos_clave = clave_completa.get('clave', clave_completa)
      clave_publica_pem_str = None
      
      # Intentamos encontrar el campo de clave pblica
      if 'clave_publica_pem_str' in datos_clave:
        clave_publica_pem_str = datos_clave['clave_publica_pem_str']
      # Fallback por si la estructura de clave['clave'] se ha aplanado
      elif 'clave_pem' in datos_clave:
        clave_publica_pem_str = datos_clave['clave_pem']
      
      
      # 3. Verificacin Estricta (Bloquea la exportacin de la privada)
      if not clave_publica_pem_str:
        self.mostrar_mensaje("Error", "No se encontr el campo PEM para la clave pblica.")
        return
        
      # La verificacin ms importante
      if "PRIVATE KEY" in clave_publica_pem_str:
        self.mostrar_mensaje("Error", "ALERTA DE SEGURIDAD! El formato de clave es privado. Se detuvo la exportacin.")
        return
      
      # 4. Abrir dilogo de guardado y escribir
      file_path = filedialog.asksaveasfilename(
        defaultextension=".pub",
        filetypes=[("Clave Pblica", "*.pub"), ("Todos los archivos", "*.*")],
        initialfile=f"{nombre_clave}.pub"
      )

      if file_path:
        with open(file_path, "w") as f:
          f.write(clave_publica_pem_str) 
        self.mostrar_mensaje("Exito", f"Clave pblica exportada a:\n{file_path}")

    except Exception as e:
      self.mostrar_mensaje("Error", f"Error al exportar la clave: {e}")

  def eliminar_clave(self):
    nombre = self.entry_nombre_clave.get()
    if not nombre:
      messagebox.showerror("Error", "El nombre de la clave no puede estar vacio.")
      return

    if not hasattr(self, 'vault_data'):
      messagebox.showerror("Error", "Debes cargar el vault primero.")
      return

    self.vault_data = keys.eliminar_clave_de_vault(self.vault_data, nombre)
    password = self.get_vault_password()
    success, mensaje = keys.guardar_vault(password, self.vault_data)
    
    if success:
      self.mostrar_mensaje("Exito", f"Clave '{nombre}' eliminada del Cofre.")
      self.actualizar_ui()
    else:
      self.mostrar_mensaje("Error", mensaje)

  def seleccionar_archivo(self):
    ruta_archivo = filedialog.askopenfilename()
    if ruta_archivo:
      self.entry_ruta_archivo.delete(0, tk.END)
      self.entry_ruta_archivo.insert(0, ruta_archivo)

  def cifrar_archivo(self):
    if not hasattr(self, 'vault_data'):
      messagebox.showerror("Error", "Debes cargar el Cofre primero.")
      return

    ruta_archivo = self.entry_ruta_archivo.get()
    nombre_clave = self.combo_clave_destino.get()
    contrasena = self.get_vault_password()

    if not ruta_archivo or not nombre_clave or not contrasena:
      messagebox.showerror("Error", "Todos los campos son obligatorios.")
      return

    success, mensaje = core.cifrar_archivo_con_vault(ruta_archivo, nombre_clave, contrasena)
    self.mostrar_mensaje("Resultado de Cifrado", mensaje)

  def descifrar_archivo(self):
    if not hasattr(self, 'vault_data'):
      messagebox.showerror("Error", "Debes cargar el Cofre primero.")
      return
    
    nombre_clave = self.combo_clave_destino.get()
    ruta_archivo = self.entry_ruta_archivo.get()
    contrasena = self.get_vault_password()

    if not ruta_archivo or not nombre_clave or not contrasena:
      messagebox.showerror("Error", "Todos los campos son obligatorios.")
      return

    success, mensaje = core.descifrar_archivo_con_vault(ruta_archivo, nombre_clave, contrasena)
    self.mostrar_mensaje("Resultado de Descifrado", mensaje)

  def actualizar_ui(self):
    self.lista_claves.delete("1.0", tk.END)
    self.text_area.delete("1.0", tk.END)
    
    if hasattr(self, 'vault_data') and self.vault_data:
      
      nombres_claves_publicas = [] # Lista para el Combobox de Cifrado/Descifrado

      # --- CLAVES PBLICAS ---
      self.lista_claves.insert(tk.END, "--- CLAVES PBLICAS ---\n")
      publicas = self.vault_data.get("claves_publicas", [])
      for clave_completa in publicas:
        
        # Accedemos al diccionario anidado 'clave' o usamos el diccionario completo
        datos_clave = clave_completa.get('clave', clave_completa)
        
        nombre = datos_clave.get('nombre', 'Nombre Desconocido')
        fecha_caducidad = datos_clave.get('expiration_date', 'N/A')
        
        # AñADIMOS EL NOMBRE PARA EL COMBOBOX 
        nombres_claves_publicas.append(nombre) 
        
        self.lista_claves.insert(tk.END, 
              f"- {nombre} (Caduca: {fecha_caducidad})\n")
      
      # ACTUALIZAR COMBOBOX DE CIFRADO/DESCIFRADO 
      if nombres_claves_publicas:
        self.combo_clave_destino.configure(values=nombres_claves_publicas)
        # Seleccionar la primera clave como valor por defecto
        self.combo_clave_destino.set(nombres_claves_publicas[0]) 
      else:
        self.combo_clave_destino.configure(values=[""])
        self.combo_clave_destino.set("Ninguna clave pblica disponible")


      # --- CLAVES PRIVADAS ---
      self.lista_claves.insert(tk.END, "\n--- CLAVES PRIVADAS ---\n")
      privadas = self.vault_data.get("claves_privadas", [])
      for clave_completa in privadas:
        
        # 1. Intentamos acceder al diccionario anidado:
        datos_clave = clave_completa.get('clave', clave_completa)
        
        # 2. Leemos la fecha desde ese nivel:
        nombre = datos_clave.get('nombre', 'Nombre Desconocido')
        fecha_caducidad = datos_clave.get('expiration_date', 'N/A')
        
        self.lista_claves.insert(tk.END, 
              f"- {nombre} (Caduca: {fecha_caducidad})\n")

  def obtener_clave_por_nombre(self, nombre_clave, tipo='publicas'):
    """Busca y devuelve el diccionario completo de una clave por su nombre."""
    
    if not hasattr(self, 'vault_data') or not self.vault_data:
      return None

    if tipo == 'publicas':
      lista_claves = self.vault_data.get("claves_publicas", [])
    elif tipo == 'privadas':
      lista_claves = self.vault_data.get("claves_privadas", [])
    else:
      return None 

    for clave_completa in lista_claves:
      datos_clave = clave_completa.get('clave', clave_completa)
      
      # Compara el nombre
      if datos_clave.get('nombre') == nombre_clave:
        return clave_completa # Devuelve el diccionario COMPLETO
    
    return None

if __name__ == "__main__":
  app = App()
  app.mainloop()
