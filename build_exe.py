"""
Script de compilation automatique de Vibe Audit en exécutable autonome Windows (.EXE).
Utilise PyInstaller pour générer un fichier .exe tout-en-un intégrant le serveur Web,
le moteur d'analyse statique, l'auditeur réseau et le frontend (HTML/CSS/JS).
"""
import os
import sys
import subprocess
import shutil
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def check_pyinstaller():
    try:
        import PyInstaller
        print(f"[+] PyInstaller version {PyInstaller.__version__} détecté.")
    except ImportError:
        print("[!] PyInstaller n'est pas installé. Installation en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def kill_running_instances():
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            name = (p.info["name"] or "").lower()
            if name in ["vibeaudit.exe", "audit_exe.exe"]:
                try:
                    p.kill()
                    p.wait(timeout=2)
                except (psutil.Error, OSError):
                    pass
    except (ImportError, psutil.Error, OSError):
        pass

def build_vibe_audit(mode="onefile"):
    print("=" * 65)
    mode_desc = "FICHIER UNIQUE AUTONOME (--onefile)" if mode == "onefile" else "MODE DOSSIER (--onedir)"
    print(f"       COMPILATION VIBE AUDIT : {mode_desc}")
    print("=" * 65)

    kill_running_instances()
    check_pyinstaller()

    app_entry = os.path.join(BASE_DIR, "app.py")
    static_folder = os.path.join(BASE_DIR, "static")
    samples_folder = os.path.join(BASE_DIR, "samples")

    mode_flag = "--onefile" if mode == "onefile" else "--onedir"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=VibeAudit",
        mode_flag,
        "--noconsole",  # Supprime complètement la fenêtre d'invite de commande
        "--noconfirm",
        "--clean",
        f"--add-data={static_folder};static",
        f"--add-data={samples_folder};samples",
        "--hidden-import=psutil",
        "--hidden-import=engine",
        "--hidden-import=engine.rules",
        "--hidden-import=engine.rules.base",
        "--hidden-import=engine.rules.architecture",
        "--hidden-import=engine.rules.ghost_deps",
        "--hidden-import=engine.rules.lazy_errors",
        "--hidden-import=engine.rules.secrets",
        "--hidden-import=engine.rules.security",
        "--hidden-import=engine.rules.dep_vulnerabilities",
        "--hidden-import=engine.rules.testing_docs",
        "--hidden-import=engine.scanner",
        "--hidden-import=engine.tech_detector",
        "--hidden-import=engine.report_generator",
        "--hidden-import=engine.dynamic_network_audit",
        app_entry
    ]

    print(f"\n[+] Lancement de la compilation ({mode_flag})...")
    print("    Commande :", " ".join(cmd))
    ret = subprocess.call(cmd, cwd=BASE_DIR)

    if ret != 0:
        print("\n[!] Échec de la compilation de VibeAudit.")
        sys.exit(ret)

    if mode == "onefile":
        dist_exe = os.path.join(BASE_DIR, "dist", "VibeAudit.exe")
        if os.path.isfile(dist_exe):
            size_mb = os.path.getsize(dist_exe) / (1024 * 1024)
            print("\n" + "=" * 65)
            print("     COMPILATION TERMINÉE AVEC SUCCÈS (FICHIER UNIQUE) !")
            print("=" * 65)
            print(f"  Exécutable généré : {dist_exe}")
            print(f"  Taille du binaire : {size_mb:.2f} Mo")
            print("  Avantage          : 100% portable ! Vous pouvez déplacer ce fichier")
            print("                      unique n'importe où (bureau, clé USB, autre PC).")
            print("  Utilisation       : Double-cliquez sur VibeAudit.exe pour démarrer.")
            print("=" * 65 + "\n")
        else:
            print("\n[!] Erreur: Le fichier 'dist/VibeAudit.exe' est introuvable après compilation.")
    else:
        dist_dir = os.path.join(BASE_DIR, "dist", "VibeAudit")
        dist_exe = os.path.join(dist_dir, "VibeAudit.exe")

        # Copie de sécurité de static et samples directement dans dist_dir si nécessaire
        static_dest = os.path.join(dist_dir, "static")
        if not os.path.exists(static_dest):
            shutil.copytree(static_folder, static_dest)

        samples_dest = os.path.join(dist_dir, "samples")
        if not os.path.exists(samples_dest):
            shutil.copytree(samples_folder, samples_dest)

        if os.path.isfile(dist_exe):
            print("\n" + "=" * 65)
            print("          COMPILATION TERMINÉE AVEC SUCCÈS (MODE DOSSIER) !")
            print("=" * 65)
            print(f"  Dossier généré : {dist_dir}")
            print(f"  Exécutable     : {dist_exe}")
            print("  Avantage       : Démarrage instantané.")
            print("=" * 65 + "\n")
        else:
            print("\n[!] Erreur: Le fichier compilé est introuvable dans 'dist/VibeAudit/'.")

def build_cli_audit():
    print("\n" + "=" * 65)
    print("       COMPILATION DE L'OUTIL CLI : AUDIT_EXE.EXE")
    print("=" * 65)
    cli_entry = os.path.join(BASE_DIR, "audit_exe.py")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=audit_exe",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--hidden-import=psutil",
        "--hidden-import=engine",
        "--hidden-import=engine.dynamic_network_audit",
        cli_entry
    ]
    subprocess.call(cmd, cwd=BASE_DIR)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compiler Vibe Audit en exécutable autonome.")
    parser.add_argument(
        "--mode",
        choices=["onefile", "onedir"],
        default="onefile",
        help="Type de compilation : 'onefile' (fichier unique portable, défaut) ou 'onedir' (dossier d'application)."
    )
    parser.add_argument(
        "--with-cli",
        action="store_true",
        help="Compiler également l'outil CLI d'audit dynamique (dist/audit_exe.exe)."
    )

    args = parser.parse_args()
    build_vibe_audit(mode=args.mode)

    if args.with_cli:
        build_cli_audit()
