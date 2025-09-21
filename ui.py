import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import core
import keys
import os

# Configuración del tema y el color
ctk.set_appearance_mode("Dark")  # Temas: "Light", "Dark", "System"
ctk.set_default_color_theme("blue") # Colores: "blue", "green", "dark-blue"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuración de la ventana principal ---
        self.title("Zipheraxis")
        self.geometry("800x650") # Aumentamos el tamaño para la nueva tabla
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Cargar el icono de la aplicación ---
        try:
            self.iconbitmap(os.path.join("assets", "icon.ico"))
        except tk.TclError:
            try:
                icon_image = Image.open(os.path.join("assets", "icon.png"))
                icon_photo = ImageTk.PhotoImage(icon_image)
                self.iconphoto(False, icon_photo)
            except Exception:
                pass

        # Crear el frame principal
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)

        # --- Cargar y colocar el logo dentro de la interfaz ---
        try:
            logo_path = os.path.join("assets", "logo.png")
            self.logo_image = ctk.CTkImage(Image.open(logo_path), size=(100, 100))
            self.logo_label = ctk.CTkLabel(self.main_frame, image=self.logo_image, text="")
            self.logo_label.pack(pady=(10, 5))
        except FileNotFoundError:
            messagebox.showwarning("Advertencia", "No se encontró 'logo.png' en la carpeta 'assets'.")
        except Exception as e:
            messagebox.showwarning("Advertencia", f"Error al cargar el logo: {e}")

        # Título de la aplicación
        self.title_label = ctk.CTkLabel(self.main_frame, text="Zipheraxis", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.pack(pady=(5, 10))
        
        # --- Crear las pestañas ---
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(pady=10, padx=20, fill="both", expand=True)

        # Cambiamos el orden. Añadimos primero la pestaña de Operaciones de Cifrado
        self.tab_operaciones = self.tabview.add("Operaciones de Cifrado")
        self.tab_claves = self.tabview.add("Gestión de Claves")

        # Esto asegura que la pestaña de operaciones sea la que se muestre al inicio
        self.tabview.set("Operaciones de Cifrado")

        # Configurar las pestañas
        self.tab_claves.grid_columnconfigure(0, weight=1)
        self.tab_operaciones.grid_columnconfigure(0, weight=1)

        # --- Widgets de la Pestaña "Operaciones de Cifrado" ---
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
        
        # --- Widgets de la Pestaña "Gestión de Claves" ---
        self.btn_generar_claves = ctk.CTkButton(self.tab_claves, text="Generar Nuevo Par de Claves", command=self.manejar_generar_claves, font=ctk.CTkFont(size=14))
        self.btn_generar_claves.pack(pady=10, padx=30, fill="x")

        self.claves_frame = ctk.CTkScrollableFrame(self.tab_claves, label_text="Claves Disponibles")
        self.claves_frame.pack(pady=10, padx=20, fill="both", expand=True)
        self.claves_frame.grid_columnconfigure(0, weight=1)
        self.claves_frame.grid_columnconfigure(1, weight=1)
        self.claves_frame.grid_columnconfigure(2, weight=1)

        # --- Botón de Salida ---
        self.btn_salir = ctk.CTkButton(self.main_frame, text="Salir", command=self.salir_app, fg_color="gray", hover_color="dim gray", font=ctk.CTkFont(size=14, weight="bold"))
        self.btn_salir.pack(pady=(20, 10), padx=30, fill="x")

        # Inicializar la lista de claves
        self.actualizar_listas_de_claves()

    def actualizar_listas_de_claves(self):
        self.datos_publicos, self.datos_privados = keys.obtener_claves()
        
        # Limpiar el frame de claves antes de actualizar
        for widget in self.claves_frame.winfo_children():
            widget.destroy()

        # Encabezados de la tabla
        ctk.CTkLabel(self.claves_frame, text="Nombre", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Tipo", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Caducidad", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, padx=10, pady=5)
        ctk.CTkLabel(self.claves_frame, text="Acción", font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, padx=10, pady=5)

        row_index = 1
        # Mostrar claves públicas
        for clave in self.datos_publicos:
            ctk.CTkLabel(self.claves_frame, text=clave["nombre"]).grid(row=row_index, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text="Pública (Cert)").grid(row=row_index, column=1, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text=clave["caducidad"]).grid(row=row_index, column=2, padx=10, pady=5, sticky="w")
            btn_eliminar = ctk.CTkButton(self.claves_frame, text="Eliminar", command=lambda r=clave["ruta"]: self.manejar_eliminar_clave(r), width=80, fg_color="red")
            btn_eliminar.grid(row=row_index, column=3, padx=10, pady=5)
            row_index += 1

        # Mostrar claves privadas
        for clave in self.datos_privados:
            ctk.CTkLabel(self.claves_frame, text=clave["nombre"]).grid(row=row_index, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text="Privada").grid(row=row_index, column=1, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.claves_frame, text=clave["caducidad"]).grid(row=row_index, column=2, padx=10, pady=5, sticky="w")
            btn_eliminar = ctk.CTkButton(self.claves_frame, text="Eliminar", command=lambda r=clave["ruta"]: self.manejar_eliminar_clave(r), width=80, fg_color="red")
            btn_eliminar.grid(row=row_index, column=3, padx=10, pady=5)
            row_index += 1

        # Actualizar los ComboBox en la pestaña de operaciones
        self.paths_publicas = [d["ruta"] for d in self.datos_publicos]
        self.paths_privadas = [d["ruta"] for d in self.datos_privados]
        nombres_publicos = [os.path.basename(p) for p in self.paths_publicas]
        nombres_privados = [os.path.basename(p) for p in self.paths_privadas]
        
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
        if nombre_usuario:
            if keys.generar_par_de_claves_con_cert(nombre_usuario):
                messagebox.showinfo("Claves Generadas", f"Se ha generado un nuevo par de claves para {nombre_usuario}.")
                self.actualizar_listas_de_claves()
                self.tabview.set("Operaciones de Cifrado") # Volver a la pestaña de operaciones

    def manejar_eliminar_clave(self, ruta_clave):
        respuesta = messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que quieres eliminar la clave '{os.path.basename(ruta_clave)}'?")
        if respuesta:
            if keys.eliminar_clave(ruta_clave):
                messagebox.showinfo("Clave Eliminada", "La clave ha sido eliminada correctamente.")
                self.actualizar_listas_de_claves()

    def manejar_cifrar(self):
        nombre_seleccionado = self.combo_publica.get()
        if not self.paths_publicas:
            messagebox.showerror("Error", "No hay certificados para cifrar.")
            return

        try:
            nombres_publicos = [os.path.basename(p) for p in self.paths_publicas]
            index_seleccionado = nombres_publicos.index(nombre_seleccionado)
            ruta_clave_publica = self.paths_publicas[index_seleccionado]
        except (ValueError, IndexError):
            messagebox.showerror("Error", "El certificado seleccionado no es válido.")
            return

        ruta_archivo = filedialog.askopenfilename(title="Selecciona el archivo a cifrar")
        if not ruta_archivo:
            return

        exito, mensaje = core.cifrar_archivo(ruta_archivo, ruta_clave_publica)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
        else:
            messagebox.showerror("Error de Cifrado", mensaje)

    def manejar_descifrar(self):
        nombre_seleccionado = self.combo_privada.get()
        if not self.paths_privadas:
            messagebox.showerror("Error", "No hay claves privadas para descifrar.")
            return
            
        try:
            nombres_privados = [os.path.basename(p) for p in self.paths_privadas]
            index_seleccionado = nombres_privados.index(nombre_seleccionado)
            ruta_clave_privada = self.paths_privadas[index_seleccionado]
        except (ValueError, IndexError):
            messagebox.showerror("Error", "La clave privada seleccionada no es válida.")
            return

        ruta_archivo = filedialog.askopenfilename(title="Selecciona el archivo a descifrar", filetypes=[("Archivos cifrados", "*.cifrado")])
        if not ruta_archivo:
            return

        exito, mensaje = core.descifrar_archivo(ruta_archivo, ruta_clave_privada)
        if exito:
            messagebox.showinfo("Éxito", mensaje)
        else:
            messagebox.showerror("Error de Descifrado", mensaje)
            
    def salir_app(self):
        self.destroy() # Cierra la ventana principal