import os
import sys
import json
import argparse
import re

import io

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, io.UnsupportedOperation):
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError, io.UnsupportedOperation):
            pass

from engine.dynamic_network_audit import DynamicNetworkAuditor

def extract_static_domains(exe_path):
    """Extraction statique des domaines et URLs présents dans les binaires."""
    domains = set()
    try:
        with open(exe_path, "rb") as f:
            data = f.read()

        # Regex pour repérer les URLs valides
        pattern = rb"https?://[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,6}(?:/[a-zA-Z0-9\.\-_~%]*)*"
        matches = re.findall(pattern, data)
        for m in matches:
            s = m.decode("latin1", errors="ignore")
            # Filtrer les faux positifs
            if "." in s and not s.endswith(".") and len(s) < 80 and not s.startswith("http://www.w3.org"):
                domains.add(s)
    except Exception as e:
        print(f"[WARN] Impossible d'effectuer l'analyse statique : {e}")

    return sorted(list(domains))


def print_formatted_report(report, static_urls):
    print("\n" + "=" * 70)
    print("           RAPPORT D'AUDIT RÉSEAU DYNAMIQUE - VIBE AUDIT")
    print("=" * 70)
    print(f"  Fichier audité       : {os.path.basename(report['exe_path'])}")
    print(f"  Chemin complet       : {report['exe_path']}")
    print(f"  Score de Transparence: {report['score']} / 100")
    print(f"  Verdict              : {report['verdict']}")
    print(f"  Détail               : {report['verdict_description']}")
    print(f"  Total connexions     : {report['total_connections']}")
    print("-" * 70)

    print("\n[+] RÉPARTITION DU TRAFIC PAR CATÉGORIE :")
    if not report['categories_summary']:
        print("  ✓ Aucun trafic réseau externe enregistré.")
    else:
        for cat, count in report['categories_summary'].items():
            print(f"  • {cat:20} : {count} trame(s)")

    print("\n[+] DESTINATIONS EXTERNES CONTACTÉES EN COURS D'EXÉCUTION :")
    if not report['unique_destinations']:
        print("  ✓ Aucune connexion sortante (100% offline).")
    else:
        for dest in report['unique_destinations']:
            print(f"  ⚡ [{dest['process_name']}] {dest['protocol']} -> {dest['ip']}:{dest['port']}")
            print(f"     Nom d'hôte   : {dest['hostname']}")
            if dest.get('org'):
                print(f"     Organisation : {dest['org']} ({dest.get('country', 'N/A')})")
            print(f"     Catégorie    : {dest['category']}")
            print(f"     Première vue : {dest['first_seen']} | Dernière : {dest['last_seen']}\n")

    if static_urls:
        print("[+] URLs & ENDPOINTS DÉTECTÉS STATIQUEMENT DANS LE BINAIRE :")
        for u in static_urls[:10]:
            print(f"  🔍 {u}")
        if len(static_urls) > 10:
            print(f"  ... et {len(static_urls) - 10} autre(s) URL(s).")

    print("\n[+] PROCESSUS DE L'ARBRE SURVEILLÉS :")
    for proc in report['processes_monitored']:
        r_kb = proc['read_bytes'] / 1024
        w_kb = proc['write_bytes'] / 1024
        print(f"  • {proc['name']} - Lecture: {r_kb:.1f} KB | Écriture: {w_kb:.1f} KB")

    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Audit dynamique de flux réseau pour exécutable .exe")
    parser.add_argument("exe", nargs="?", default=None, help="Chemin vers le fichier .exe à auditer (optionnel si --pid est utilisé)")
    parser.add_argument("--pid", type=int, default=None, help="PID d'un processus déjà en cours d'exécution à surveiller")
    parser.add_argument("--args", dest="exe_args", default="", help="Arguments à transmettre au .exe (ex: '--verbose --check')")
    parser.add_argument("--timeout", type=int, default=15, help="Durée maximale de l'audit en secondes (défaut: 15, 0 = illimité jusqu'à fermeture)")
    parser.add_argument("--json", action="store_true", help="Afficher le rapport au format JSON brut")
    args = parser.parse_args()

    if not args.exe and not args.pid:
        print("[ERREUR] Vous devez spécifier soit le chemin du .exe, soit l'option --pid <PID>.")
        sys.exit(1)

    if args.exe and not os.path.exists(args.exe):
        print(f"[ERREUR] Le fichier '{args.exe}' n'existe pas.")
        sys.exit(1)

    custom_args = args.exe_args.split() if args.exe_args else []

    static_urls = []
    if args.exe:
        print(f"🔍 [1/3] Analyse statique du binaire {os.path.basename(args.exe)}...")
        static_urls = extract_static_domains(args.exe)
        print(f"    Trouvé {len(static_urls)} URL/endpoint(s) dans le binaire.")

    timeout_val = None if args.timeout == 0 else args.timeout
    timeout_msg = f"{args.timeout}s d'observation" if timeout_val else "en continu (Ctrl+C pour terminer)"
    print(f"\n🚀 [2/3] Démarrage du test dynamique ({timeout_msg})...")
    auditor = DynamicNetworkAuditor(exe_path=args.exe, pid=args.pid, args=custom_args)
    auditor.start()

    auditor.wait_or_interactive(timeout=args.timeout)

    print(f"\n📊 [3/3] Analyse des traces et génération du rapport...")
    report = auditor.generate_report()

    if args.json:
        report["static_detected_urls"] = static_urls
        print(json.dumps(report, indent=2))
    else:
        print_formatted_report(report, static_urls)

    # Sauvegarde automatique du rapport JSON
    output_file = "dynamic_network_audit_report.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[INFO] Rapport complet sauvegardé dans '{output_file}'.")


if __name__ == "__main__":
    main()
