import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import core
import keys
import os

# Configuración del tema y el color
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Zipheraxis")
        self.geometry("800x650")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.password = None
        self.vault_data = None
        
        # Intentar cargar las imágenes de inicio
        try:
            self.iconbitmap(os.path.join("assets", "icon.ico"))
        except tk.TclError:
            try:
                icon_image = Image.open(os.path.join("assets", "icon.png"))
                icon_photo = ImageTk.PhotoImage(icon_image)
                self.iconphoto(False, icon_photo)
            except Exception:
                pass
        
        # Configurar la pantalla de inicio de sesión
        self.login_frame = ctk.CTkFrame(self, corner_radius=10)
        self.login_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.login_frame.grid_columnconfigure(0, weight=1)
        
        try:
            logo_path = os.path.join("assets", "logo.png")
            self.logo_image = ctk.CTkImage(Image.open(logo_path), size=(100, 100))
            self.logo_label = ctk.CTkLabel(self.login_frame, image=self.logo_image, text="")
            self.logo_label.pack(pady=(100, 5))
        except FileNotFoundError:
            pass # Si no hay logo, no se muestra
            
        ctk.CTkLabel(self.login_frame, text="Zipheraxis", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(5, 10))
        
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Contraseña Maestra", show="*", width=250)
        self.password_entry.pack(pady=10)
        self.password_entry.bind("<Return>", self.autenticar)
        
        self.btn_login = ctk.CTkButton(self.login_frame, text="Desbloquear Vault", command=self.autenticar, width=250)
        self.btn_login.pack(pady=5)
        
        self.btn_crear_vault = ctk.CTkButton(self.login_frame, text="Crear Nuevo Vault", command=self.crear_vault, width=250)
        self.btn_crear_vault.pack(pady=5)

    def autenticar(self, event=None):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Debes ingresar una contraseña.")
            return

        self.vault_data, error = keys.cargar_vault(password)
        if self.vault_data:
            self.password = password
            self.login_frame.destroy()
            self.main_app()
        else:
            messagebox.showerror("Error", error)

    def crear_vault(self):
        password = simpledialog.askstring("Crear Vault", "Ingresa una nueva contraseña maestra:", show="*")
        if not password:
            messagebox.showerror("Error", "La contraseña no puede estar vacía.")
            return
        
        if os.path.exists(keys.VAULT_FILE):
            messagebox.showerror("Error", "Ya existe un vault de claves. Bórralo para crear uno nuevo.")
            return
            
        if keys.crear_vault(password):
            messagebox.showinfo("Éxito", "Vault creado correctamente. Por favor, inicia sesión.")
        else:
            messagebox.showerror("Error", "No se pudo crear el vault.")

    def main_app(self):
        # --- Configuración de la ventana principal ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)

        try:
            logo_path = os.path.join("assets", "logo.png")
            self.logo_image = ctk.CTkImage(Image.open(logo_path), size=(100, 100))
            self.logo_label = ctk.CTkLabel(self.main_frame, image=self.logo_image, text="")
            self.logo_label.pack(pady=(10, 5))
        except FileNotFoundError:
            pass
        except Exception as e:
            messagebox.showwarning("Advertencia", f"Error al cargar el logo: {e}")

        self.title_label = ctk.CTkLabel(self.main_frame, text="Zipheraxis", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.pack(pady=(5, 10))
        
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(pady=10, padx=20, fill="both", expand=True)

        self.tab_operaciones = self.tabview.add("Operaciones de Cifrado")
        self.tab_claves = self.tabview.add("Gestión de Claves")

        self.tab_operaciones.grid_columnconfigure(0, weight=1)
        self.tab_claves.grid_columnconfigure(0, weight=1)

        self.label_publica = ctk.CTkLabel(self.tab_operaciones, text="Certificados Públicos Disponibles:")
        self.label_publica.pack(pady=(10, 0))
        self.combo_publica = ctk.CTkComboBox(self.tab_operaciones, state="readonly", values=[])
        self.combo_publica.pack(pady=5, padx=30, fill="x")

        self.btn_cifrar = ctk.CTkButton(self.tab_operaciones, text="Cifrar Archivo", command=self.manejar_cifrar, fg_color="#28a745", hover_color="#218838", font=ctk.CTkFont(size=14, weight="bold"))
        self.btn_cifrar.pack(pady=(20, 10), padx=30, fill="x")

        self.label_privada = ctk.CTkLabel(self.tab_operaciones, text="Claves Privadas Disponibles:")
        self.label_privada.pack(pady=(10, 0))
        self.combo_privada = ctk.CTkComboBox(self.tab_operaciones, state="readonly", values=[])
        self.combo_privada.pack(pady=5, padx=30, fill="x")

        self.btn_descifrar = ctk.CTkButton(self.tab_operaciones, text="Descifrar Archivo", command=self.manejar_descifrar, fg_color="#dc3545", hover_color="#c82333", font=ctk.CTkFont(size=14, weight="bold"))
        self.btn_descifrar.pack(pady=10, padx=30, fill="x")
        
        self.btn_generar_claves = ctk.CTkButton(self.tab_claves, text="Generar Nuevo Par de Claves", command=self.manejar_generar_claves, font=ctk.CTkFont(size=14))
        self.btn_generar_claves.pack(pady=10, padx=30, fill="x")

        self.claves_frame = ctk.CTkScrollableFrame(self.tab_claves, label_text="Claves Disponibles")
        self.claves_frame.pack(pady=10, padx=20, fill="both", expand=True)
        self.claves_frame.grid_columnconfigure(0, weight=1)
        self.claves_frame.grid_columnconfigure(1, weight=1)
        self.claves_frame.grid_columnconfigure(2, weight=1)

        self.btn_salir = ctk.CTkButton(self.main_frame, text="Salir", command=self.salir_app, fg_color="gray", hover_color="dim gray", font=ctk.CTkFont(size=14, weight="bold"))
        self.btn_salir.pack(pady=(20, 10), padx=30, fill="x")

        self.actualizar_listas_de_claves()

    def actualizar_listas_de_claves(self):
        if self.vault_data is None:
            return

        datos_publicos, datos_privadas = keys.obtener_claves_de_vault(self.vault_data)
        
        for widget in self.claves_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.claves_frame, text="Nombre", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Tipo", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Caducidad", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Acción", font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, padx=10, pady=5)

        row_index = 1
        for clave in datos_publicos:
            ctk.CTkLabel(self.claves_frame, text=clave["nombre"]).grid(row=row_index, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text="Pública (Cert)").grid(row=row_index, column=1, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text=clave["caducidad"]).grid(row=row_index, column=2, padx=10, pady=5, sticky="w")
            btn_eliminar = ctk.CTkButton(self.claves_frame, text="Eliminar", command=lambda r=clave["nombre"]: self.manejar_eliminar_clave(r), width=80, fg_color="red")
            btn_eliminar.grid(row=row_index, column=3, padx=10, pady=5)
            row_index += 1

        for clave in datos_privadas:
            ctk.CTkLabel(self.claves_frame, text=clave["nombre"]).grid(row=row_index, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text="Privada").grid(row=row_index, column=1, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text=clave["caducidad"]).grid(row=row_index, column=2, padx=10, pady=5, sticky="w")
            btn_eliminar = ctk.CTkButton(self.claves_frame, text="Eliminar", command=lambda r=clave["nombre"]: self.manejar_eliminar_clave(r), width=80, fg_color="red")
            btn_eliminar.grid(row=row_index, column=3, padx=10, pady=5)
            row_index += 1

        nombres_publicos = [d["nombre"] for d in datos_publicos]
        nombres_privados = [d["nombre"] for d in datos_privadas]
        
        self.combo_publica.configure(values=nombres_publicos)
        self.combo_privada.configure(values=nombres_privados)
        
        if nombres_publicos:
            self.combo_publica.set(nombres_publicos[0])
        else:
            self.combo_publica.set("No hay certificados")

        if nombres_privados:
            self.combo_privada.set(nombres_privados[0])
        else:
            self.combo_privada.set("No hay claves")

    def manejar_generar_claves(self):
        nombre_usuario = simpledialog.askstring("Nombre de Usuario", "Ingresa tu nombre para el certificado:")
        if not nombre_usuario:
            return

        exito, mensaje = keys.agregar_clave_a_vault(nombre_usuario, self.password)
        if exito:
            messagebox.showinfo("Claves Generadas", f"Se ha generado un nuevo par de claves para {nombre_usuario}.")
            self.vault_data, _ = keys.cargar_vault(self.password) # Volver a cargar el vault después de añadir claves
            self.actualizar_listas_de_claves()
            self.tabview.set("Operaciones de Cifrado")
        else:
            messagebox.showerror("Error", mensaje)

    def manejar_eliminar_clave(self, nombre_clave):
        respuesta = messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que quieres eliminar la clave '{nombre_clave}'?")
        if respuesta:
            if keys.eliminar_clave_de_vault(nombre_clave, self.password):
                messagebox.showinfo("Clave Eliminada", "La clave ha sido eliminada correctamente.")
                self.vault_data, _ = keys.cargar_vault(self.password) # Volver a cargar el vault después de eliminar claves
                self.actualizar_listas_de_claves()
            else:
                messagebox.showerror("Error", "No se pudo eliminar la clave.")

    def manejar_cifrar(self):
        nombre_seleccionado = self.combo_publica.get()
        if not nombre_seleccionado or nombre_seleccionado == "No hay certificados":
            messagebox.showerror("Error", "Selecciona un certificado público para cifrar.")
            return

        ruta_archivo = filedialog.askopenfilename(title="Selecciona el archivo a cifrar")
        if not ruta_archivo:
            return

        exito, mensaje = core.cifrar_archivo_desde_vault(ruta_archivo, nombre_seleccionado, self.password)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
        else:
            messagebox.showerror("Error de Cifrado", mensaje)

    def manejar_descifrar(self):
        nombre_seleccionado = self.combo_privada.get()
        if not nombre_seleccionado or nombre_seleccionado == "No hay claves":
            messagebox.showerror("Error", "Selecciona una clave privada para descifrar.")
            return
            
        ruta_archivo = filedialog.askopenfilename(title="Selecciona el archivo a descifrar", filetypes=[("Archivos cifrados", "*.cifrado")])
        if not ruta_archivo:
            return

        # La clave privada en el vault no tiene contraseña adicional
        # Así que pasamos None
        exito, mensaje = core.descifrar_archivo_desde_vault(nombre_seleccionado, None, ruta_archivo, self.password)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
        else:
            messagebox.showerror("Error de Descifrado", mensaje)
            
    def salir_app(self):
        self.destroy()