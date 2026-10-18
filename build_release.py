"""
Script d'automatisation des Releases GitHub pour Vibe Audit.
Genere :
1. VibeAudit.exe (binaire autonome avec icone)
2. VibeAudit-Setup-v1.0.0.exe (installeur Inno Setup)
3. VibeAudit-v1.0.0-Windows-x64-Portable.zip (archive portable)
4. checksums-sha256.txt (empreintes cryptographiques de securite)
5. RELEASE_NOTES.md (notes de version pretes pour GitHub)
"""
import os
import sys
import subprocess
import shutil
import zipfile
import hashlib

VERSION = "1.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASE_DIR = os.path.join(BASE_DIR, "dist", "release")
ISCC_PATHS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"),
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]

def find_iscc():
    for p in ISCC_PATHS:
        if os.path.isfile(p):
            return p
    return shutil.which("iscc")

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def make_portable_zip(zip_path, exe_path):
    print(f"[+] Creation de l'archive portable : {zip_path}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(exe_path, arcname="VibeAudit.exe")
        for f in ["README.md", "LICENSE"]:
            p = os.path.join(BASE_DIR, f)
            if os.path.isfile(p):
                zf.write(p, arcname=f)
        ico = os.path.join(BASE_DIR, "assets", "icon.ico")
        if os.path.isfile(ico):
            zf.write(ico, arcname="icon.ico")

def generate_release_notes(release_dir, setup_exe, portable_zip, setup_hash, zip_hash):
    notes_path = os.path.join(release_dir, "RELEASE_NOTES.md")
    content = f"""# Vibe Audit v{VERSION} 🚀

Bienvenue sur la version officielle **v{VERSION}** de **Vibe Audit** !

Vibe Audit est un analyseur de viabilité, de sécurité et d'architecture conçu spécialement pour auditer les projets conçus avec de l'IA et en *vibe coding*.

---

### ✨ Téléchargements Windows (64-bit)

| Type | Fichier | Taille | Empreinte SHA-256 |
|---|---|---|---|
| **Installeur recommandé** | [`VibeAudit-Setup-v{VERSION}.exe`](https://github.com/gotenash/VibeAudit/releases/download/v{VERSION}/VibeAudit-Setup-v{VERSION}.exe) | {os.path.getsize(setup_exe)/(1024*1024):.1f} Mo | `{setup_hash}` |
| **Version Portable (.zip)** | [`VibeAudit-v{VERSION}-Windows-x64-Portable.zip`](https://github.com/gotenash/VibeAudit/releases/download/v{VERSION}/VibeAudit-v{VERSION}-Windows-x64-Portable.zip) | {os.path.getsize(portable_zip)/(1024*1024):.1f} Mo | `{zip_hash}` |

---

### 🌟 Fonctionnalités incluses

- **Analyse Statique Complète** : Détection de clés d'API et secrets codés en dur, imports fantômes (packages hallucinés par les LLMs), gestion paresseuse des exceptions (`except: pass`), et failles de sécurité.
- **Audit Réseau Dynamique en Temps Réel** : Surveillance des processus, sockets sortantes et interception d'appels HTTP sortants.
- **Dashboard Sombre Glassmorphism** : Interface interactive avec jauge de score, répartition des risques et plan d'action correctif généré automatiquement.
- **Port Dédié Sécurisé** : Tourne sur `http://127.0.0.1:8765`, évitant tout conflit avec vos serveurs de développement (Vite, Next, etc.).
- **Zéro Prérequis** : Aucune installation de Python ou de runtime requise.

---

### 🛠️ Installation

- **Option 1 (Installeur)** : Téléchargez et lancez `VibeAudit-Setup-v{VERSION}.exe`. Il configure automatiquement les raccourcis Bureau et Menu Démarrer avec désinstallation propre.
- **Option 2 (Portable)** : Téléchargez et décompressez `VibeAudit-v{VERSION}-Windows-x64-Portable.zip`, puis double-cliquez sur `VibeAudit.exe`.
"""
    with open(notes_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Notes de version generees : {notes_path}")

def build_release():
    print("=" * 65)
    print(f"       PREPARATION DU PACK DE RELEASE VIBE AUDIT v{VERSION}")
    print("=" * 65)

    os.makedirs(RELEASE_DIR, exist_ok=True)
    exe_path = os.path.join(BASE_DIR, "dist", "VibeAudit.exe")

    if not os.path.isfile(exe_path):
        print("[*] VibeAudit.exe non trouve, compilation initiale via build_exe.py...")
        subprocess.check_call([sys.executable, "build_exe.py", "--mode", "onefile"], cwd=BASE_DIR)

    iscc_bin = find_iscc()
    if not iscc_bin:
        print("[!] Erreur: Inno Setup (ISCC.exe) n'a pas ete trouve sur le systeme.")
        sys.exit(1)

    iss_file = os.path.join(BASE_DIR, "installer.iss")
    print(f"[+] Compilation de l'installeur via Inno Setup ({iscc_bin})...")
    subprocess.check_call([iscc_bin, iss_file], cwd=BASE_DIR)

    setup_exe = os.path.join(RELEASE_DIR, f"VibeAudit-Setup-v{VERSION}.exe")
    portable_zip = os.path.join(RELEASE_DIR, f"VibeAudit-v{VERSION}-Windows-x64-Portable.zip")
    make_portable_zip(portable_zip, exe_path)

    print("[+] Calcul des empreintes SHA-256...")
    setup_hash = sha256_file(setup_exe)
    zip_hash = sha256_file(portable_zip)

    checksums_path = os.path.join(RELEASE_DIR, "checksums-sha256.txt")
    with open(checksums_path, "w", encoding="utf-8") as f:
        f.write(f"{setup_hash}  VibeAudit-Setup-v{VERSION}.exe\n")
        f.write(f"{zip_hash}  VibeAudit-v{VERSION}-Windows-x64-Portable.zip\n")
    print(f"[+] Fichier de somme de controle genere : {checksums_path}")

    generate_release_notes(RELEASE_DIR, setup_exe, portable_zip, setup_hash, zip_hash)

    print("\n" + "=" * 65)
    print("          PACK DE RELEASE GITHUB TERMINE AVEC SUCCES !")
    print("=" * 65)
    print(f" Dossier : {RELEASE_DIR}")
    print(f" 1. Installeur   : {setup_exe}")
    print(f" 2. Portable Zip : {portable_zip}")
    print(f" 3. Checksums    : {checksums_path}")
    print(f" 4. Notes GitHub : {os.path.join(RELEASE_DIR, 'RELEASE_NOTES.md')}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    build_release()
