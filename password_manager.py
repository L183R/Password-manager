import os
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox

from pm_core.crypto import CryptoError
from pm_core.passwords import generate_password
from pm_core.storage import StorageError, load_credentials, save_credentials

CAMPOS = ["nombre", "link", "cuenta", "contrasena", "observaciones"]
ARCHIVO_DEFECTO = os.path.join(os.path.dirname(__file__), "credenciales.json")


def pedir_clave(titulo="Clave de acceso", mensaje="🔐 Ingresá la clave maestra:"):
    clave = tk.StringVar()
    mostrar = tk.BooleanVar(value=False)
    resultado = {"clave": None}

    def toggle():
        mostrar.set(not mostrar.get())
        entry.config(show="" if mostrar.get() else "*")
        btn_ojo.config(text="🙈" if mostrar.get() else "👁")

    def confirmar(event=None):
        resultado["clave"] = clave.get()
        top.destroy()

    def cancelar(event=None):
        top.destroy()

    top = tk.Toplevel()
    top.title(titulo)
    top.geometry("420x155")
    top.configure(bg="white")
    top.resizable(False, False)
    top.grab_set()
    top.protocol("WM_DELETE_WINDOW", cancelar)
    top.bind("<Return>", confirmar)
    top.bind("<Escape>", cancelar)

    tk.Label(top, text=mensaje, bg="white", font=("Segoe UI", 10)).pack(padx=10, pady=(15, 0))

    frame = tk.Frame(top, bg="white")
    frame.pack(pady=10)

    entry = tk.Entry(frame, textvariable=clave, show="*", width=32, font=("Segoe UI", 10))
    entry.pack(side=tk.LEFT, padx=(0, 5))

    btn_ojo = tk.Button(frame, text="👁", width=3, command=toggle, bg="#2e4a1c", fg="white", relief="flat")
    btn_ojo.pack(side=tk.LEFT)

    botones = tk.Frame(top, bg="white")
    botones.pack(pady=(0, 10))
    tk.Button(botones, text="✅ Confirmar", command=confirmar, bg="#2e4a1c", fg="white", relief="flat", width=14, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)
    tk.Button(botones, text="Cancelar", command=cancelar, relief="flat", width=10, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=4)

    entry.focus()
    top.wait_window()
    return resultado["clave"]


class GestorCredenciales:
    def __init__(self, root):
        self.root = root
        self.datos = []
        self.clave = ""
        self.entries = []
        self.archivo_actual = ARCHIVO_DEFECTO
        self.build_ui()
        self.cargar_archivo_por_defecto()

    def build_ui(self):
        self.root.title("Gestor de Credenciales")
        self.root.geometry("1100x520")

        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=8, pady=8)
        tk.Button(toolbar, text="📂 Abrir archivo", command=self.cargar_archivo).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="📄 Nuevo archivo", bg="#2e4a1c", fg="white", command=self.crear_nuevo_archivo).pack(side=tk.LEFT, padx=3)
        self.btn_agregar = tk.Button(toolbar, text="➕ Agregar fila", command=self.agregar_fila, state="disabled")
        self.btn_agregar.pack(side=tk.LEFT, padx=3)
        self.btn_guardar = tk.Button(toolbar, text="💾 Guardar", command=self.guardar_archivo, state="disabled")
        self.btn_guardar.pack(side=tk.LEFT, padx=3)

        self.lbl_archivo = tk.Label(self.root, text="Sin archivo abierto", anchor="w")
        self.lbl_archivo.pack(fill=tk.X, padx=10)

        container = tk.Frame(self.root)
        container.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.canvas = tk.Canvas(container, highlightthickness=0)
        scroll_y = tk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        scroll_x = tk.Scrollbar(container, orient="horizontal", command=self.canvas.xview)
        self.frame_tabla = tk.Frame(self.canvas)
        self.frame_tabla.bind("<Configure>", lambda _event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.frame_tabla, anchor="nw")
        self.canvas.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

    def set_estado_archivo(self):
        self.lbl_archivo.config(text=f"Archivo: {self.archivo_actual}")

    def crear_nuevo_archivo(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], title="Guardar nuevo archivo")
        if not ruta:
            return
        clave = pedir_clave("Nueva clave", "🔐 Elegí la clave maestra para este archivo:")
        if not clave:
            return
        self.datos = []
        self.entries = []
        self.archivo_actual = ruta
        self.clave = clave
        self.render_tabla()
        self.set_estado_archivo()

    def cargar_archivo_por_defecto(self):
        if os.path.exists(self.archivo_actual):
            clave = pedir_clave(mensaje="🔐 Ingresá la clave para descifrar el archivo por defecto:")
            if clave:
                self.abrir_con_clave(self.archivo_actual, clave)

    def cargar_archivo(self):
        ruta = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not ruta:
            return
        clave = pedir_clave(mensaje="🔐 Ingresá la clave para descifrar el archivo:")
        if clave:
            self.abrir_con_clave(ruta, clave)

    def abrir_con_clave(self, ruta, clave):
        try:
            self.datos = load_credentials(ruta, clave)
        except (CryptoError, StorageError) as exc:
            messagebox.showerror("Error", f"❌ No se pudo abrir el archivo: {exc}")
            return
        self.archivo_actual = ruta
        self.clave = clave
        self.render_tabla()
        self.set_estado_archivo()

    def render_tabla(self):
        for widget in self.frame_tabla.winfo_children():
            widget.destroy()

        headers = ["Nombre", "Link", "Cuenta", "Contraseña", "Observaciones", "Acciones"]
        for j, header in enumerate(headers):
            lbl = tk.Label(self.frame_tabla, text=header, bg="#2e4a1c", fg="white", font=("Segoe UI", 9, "bold"), padx=6, pady=4)
            lbl.grid(row=0, column=j, sticky="nsew", padx=1, pady=1)

        self.entries = []
        for i, fila in enumerate(self.datos, start=1):
            fila_entries = []
            for j, campo in enumerate(CAMPOS):
                if campo == "contrasena":
                    frame_pass = tk.Frame(self.frame_tabla, bg="#f5f5f5")
                    entry = tk.Entry(frame_pass, show="*", width=20, font=("Segoe UI", 9))
                    entry.insert(0, fila.get(campo, ""))
                    entry.pack(side=tk.LEFT)
                    tk.Button(frame_pass, text="👁", command=lambda e=entry: self.toggle_password(e), bg="#2e4a1c", fg="white", relief="flat", width=2).pack(side=tk.LEFT, padx=2)
                    tk.Button(frame_pass, text="✨", command=lambda e=entry: self.sugerir_password(e), bg="#2e4a1c", fg="white", relief="flat", width=2).pack(side=tk.LEFT, padx=2)
                    frame_pass.grid(row=i, column=j, sticky="w", padx=1, pady=1)
                    fila_entries.append((campo, entry))
                else:
                    width = 45 if campo in {"link", "observaciones"} else 26
                    entry = tk.Entry(self.frame_tabla, width=width, font=("Segoe UI", 9))
                    entry.insert(0, fila.get(campo, ""))
                    entry.grid(row=i, column=j, sticky="w", padx=1, pady=1)
                    fila_entries.append((campo, entry))

            acciones = tk.Frame(self.frame_tabla)
            acciones.grid(row=i, column=5, padx=5, pady=1)
            tk.Button(acciones, text="Ir y copiar", bg="#2e4a1c", fg="white", relief="flat", font=("Segoe UI", 9), command=lambda idx=i - 1: self.ir_y_copiar(idx)).pack(side=tk.LEFT, padx=2)
            tk.Button(acciones, text="Eliminar", relief="flat", font=("Segoe UI", 9), command=lambda idx=i - 1: self.eliminar_fila(idx)).pack(side=tk.LEFT, padx=2)
            self.entries.append(fila_entries)

        self.btn_agregar["state"] = "normal"
        self.btn_guardar["state"] = "normal"

    def sincronizar_datos_desde_ui(self):
        datos = []
        for fila in self.entries:
            fila_dict = {campo: entry.get().strip() for campo, entry in fila}
            datos.append(fila_dict)
        self.datos = datos

    def agregar_fila(self):
        self.sincronizar_datos_desde_ui()
        self.datos.append({campo: "" for campo in CAMPOS})
        self.render_tabla()

    def eliminar_fila(self, index):
        self.sincronizar_datos_desde_ui()
        if 0 <= index < len(self.datos):
            del self.datos[index]
            self.render_tabla()

    def toggle_password(self, entry):
        entry.config(show="" if entry.cget("show") == "*" else "*")

    def sugerir_password(self, entry):
        entry.delete(0, tk.END)
        entry.insert(0, generate_password())

    def ir_y_copiar(self, index):
        self.sincronizar_datos_desde_ui()
        if not 0 <= index < len(self.datos):
            return
        fila = self.datos[index]
        cuenta = fila.get("cuenta", "")
        contrasena = fila.get("contrasena", "")
        link = fila.get("link", "")
        texto = contrasena or cuenta
        if texto:
            self.root.clipboard_clear()
            self.root.clipboard_append(texto)
        if link:
            webbrowser.open(link)
        messagebox.showinfo("Listo", "✅ Se copió la contraseña al portapapeles." if contrasena else "✅ Se copió la cuenta al portapapeles.")

    def guardar_archivo(self):
        self.sincronizar_datos_desde_ui()
        try:
            save_credentials(self.archivo_actual, self.datos, self.clave)
        except (CryptoError, StorageError) as exc:
            messagebox.showerror("Error", f"❌ No se pudo guardar: {exc}")
            return
        messagebox.showinfo("OK", "✅ Archivo guardado correctamente.")


if __name__ == "__main__":
    root = tk.Tk()
    app = GestorCredenciales(root)
    root.mainloop()
