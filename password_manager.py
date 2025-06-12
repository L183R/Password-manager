import tkinter as tk
from tkinter import simpledialog, messagebox
import json
import base64
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pedir_clave():
    clave = tk.StringVar()
    mostrar = tk.BooleanVar(value=False)
    resultado = {"clave": None}

    def toggle():
        mostrar.set(not mostrar.get())
        entry.config(show="" if mostrar.get() else "*")
        btn_ojo.config(text="🙈" if mostrar.get() else "👁")

    def confirmar():
        resultado["clave"] = clave.get()
        top.destroy()

    top = tk.Toplevel()
    top.title("Clave de acceso")
    top.geometry("400x140")
    top.configure(bg="white")
    top.resizable(False, False)
    top.grab_set()

    tk.Label(top, text="🔐 Ingresá la clave para descifrar el archivo:", bg="white", font=("Segoe UI", 10)).pack(padx=10, pady=(15, 0))

    frame = tk.Frame(top, bg="white")
    frame.pack(pady=10)

    entry = tk.Entry(frame, textvariable=clave, show="*", width=30, font=("Segoe UI", 10))
    entry.pack(side=tk.LEFT, padx=(0, 5))

    btn_ojo = tk.Button(frame, text="👁", width=3, command=toggle, bg="#2e4a1c", fg="white", relief="flat")
    btn_ojo.pack(side=tk.LEFT)

    btn_confirmar = tk.Button(top, text="✅ Confirmar", command=confirmar, bg="#2e4a1c", fg="white", relief="flat", width=15, font=("Segoe UI", 9, "bold"))
    btn_confirmar.pack(pady=(0, 10))

    entry.focus()
    top.wait_window()
    return resultado["clave"]

class GestorCredenciales:
    def __init__(self, root):
        self.root = root
        self.datos = []
        self.clave = ""
        self.entries = []
        self.archivo_defecto = os.path.join(os.path.dirname(__file__), "credenciales.json")
        self.build_ui()
        self.cargar_archivo_por_defecto()

    def crear_nuevo_archivo(self):
        from tkinter import filedialog
        self.datos = []
        self.entries = []
        self.archivo_defecto = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Guardar nuevo archivo"
        )
        if not self.archivo_defecto:
            return
        self.clave = pedir_clave()
        if self.clave:
            self.render_tabla()

    def build_ui(self):
        self.root.title("Gestor de Credenciales")
        tk.Button(self.root, text="📂 Abrir otro archivo", command=self.cargar_archivo).pack()
        tk.Button(self.root, text="📄 Nuevo archivo", bg="#2e4a1c", fg="white", command=self.crear_nuevo_archivo).pack(pady=5)
        self.frame_tabla = tk.Frame(self.root)
        self.frame_tabla.pack()
        self.btn_agregar = tk.Button(self.root, text="➕ Agregar fila", command=self.agregar_fila, state="disabled")
        self.btn_agregar.pack()
        self.btn_guardar = tk.Button(self.root, text="💾 Guardar", command=self.guardar_archivo, state="disabled")
        self.btn_guardar.pack()

    def cargar_archivo_por_defecto(self):
        if os.path.exists(self.archivo_defecto):
            self.clave = pedir_clave()
            if self.clave:
                self.descifrar_archivo(self.archivo_defecto)

    def cargar_archivo(self):
        from tkinter import filedialog
        ruta = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not ruta:
            return
        self.archivo_defecto = ruta
        self.clave = simpledialog.askstring("Clave", "🔐 Ingresá la clave para descifrar el archivo:", show='*')
        if self.clave:
            self.descifrar_archivo(ruta)

    def descifrar_archivo(self, ruta):
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                contenido = json.load(f)
            iv = base64.b64decode(contenido["iv"])
            key = hashlib.sha256(self.clave.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(base64.b64decode(contenido["data"]))
            pad = decrypted[-1]
            texto = decrypted[:-pad].decode("utf-8")
            self.datos = json.loads(texto)
            self.render_tabla()
        except Exception as e:
            messagebox.showerror("Error", f"❌ No se pudo descifrar el archivo: {e}")

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
            for j, campo in enumerate(["nombre", "link", "cuenta", "contrasena", "observaciones"]):
                if campo == "contrasena":
                    frame_pass = tk.Frame(self.frame_tabla, bg="#f5f5f5")
                    entry = tk.Entry(frame_pass, show="*", width=20, font=("Segoe UI", 9))
                    entry.insert(0, fila.get(campo, ""))
                    entry.pack(side=tk.LEFT)
                    btn_ver = tk.Button(frame_pass, text="👁", command=lambda e=entry: self.toggle_password(e), bg="#2e4a1c", fg="white", relief="flat", width=2)
                    btn_ver.pack(side=tk.LEFT, padx=2)
                    btn_sug = tk.Button(frame_pass, text="✨", command=lambda e=entry: self.sugerir_password(e), bg="#2e4a1c", fg="white", relief="flat", width=2)
                    btn_sug.pack(side=tk.LEFT, padx=2)
                    frame_pass.grid(row=i, column=j, sticky="w", padx=1, pady=1)
                    fila_entries.append((campo, entry))
                else:
                    entry = tk.Entry(self.frame_tabla, width=30, font=("Segoe UI", 9))
                    entry.insert(0, fila.get(campo, ""))
                    entry.grid(row=i, column=j, sticky="w", padx=1, pady=1)
                    fila_entries.append((campo, entry))

            btn = tk.Button(self.frame_tabla, text="Ir y copiar", bg="#2e4a1c", fg="white", relief="flat", font=("Segoe UI", 9), command=lambda f=fila: self.ir_y_copiar(f))
            btn.grid(row=i, column=5, padx=5, pady=1)
            self.entries.append(fila_entries)

        self.btn_agregar["state"] = "normal"
        self.btn_guardar["state"] = "normal"

    def agregar_fila(self):
        self.datos.append({"nombre": "", "link": "", "cuenta": "", "contrasena": "", "observaciones": ""})
        self.render_tabla()

    def toggle_password(self, entry):
        entry.config(show="" if entry.cget("show") == "*" else "*")

    def sugerir_password(self, entry):
        import random, string
        caracteres = string.ascii_letters + string.digits + '!@#$%^&*()-_=+[]{}<>?'
        while True:
            pwd = ''.join(random.choices(caracteres, k=20))
            if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in '!@#$%^&*()-_=+[]{}<>?' for c in pwd)):
                break
        entry.delete(0, tk.END)
        entry.insert(0, pwd)

    def guardar_archivo(self):
        self.datos = []
        for fila in self.entries:
            fila_dict = {}
            for campo, e in fila:
                fila_dict[campo] = e.get()
            self.datos.append(fila_dict)
        try:
            texto = json.dumps(self.datos, ensure_ascii=False).encode("utf-8")
            pad_len = 16 - (len(texto) % 16)
            texto += bytes([pad_len] * pad_len)
            key = hashlib.sha256(self.clave.encode()).digest()
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(texto)
            with open(self.archivo_defecto, "w", encoding="utf-8") as f:
                json.dump({
                    "iv": base64.b64encode(iv).decode(),
                    "data": base64.b64encode(encrypted).decode()
                }, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("OK", "✅ Archivo guardado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"❌ No se pudo guardar: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = GestorCredenciales(root)
    root.mainloop()
