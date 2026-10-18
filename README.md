# ⚡ Vibe Audit

> **Plateforme d'analyse d'intégrité, de sécurité et d'audit réseau comportemental pour les applications générées par IA et projets "Vibe-Codés".**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078d6.svg)](https://microsoft.com/windows)
[![UI: Dark Glassmorphism](https://img.shields.io/badge/UI-Cyberpunk%20Glassmorphism-6366f1.svg)](#-interface-web-dashboard)

---

## 🌟 Présentation

Le **vibe coding** permet de concevoir des applications et des prototypes à une vitesse spectaculaire. Cependant, le code généré par de grands modèles de langage (LLM) dissimule fréquemment des défauts critiques :
- **Secrets et jetons d'API codés en dur** dans le code source.
- **Dépendances fantômes** inventées ou hallucinées par l'IA.
- **Gestion paresseuse des erreurs** (`except: pass` avalant les bugs).
- **Télémétrie clandestine ou appels réseau dissimulés** dans les exécutables finaux.

**Vibe Audit** offre une solution à 360° combinant :
1. 📂 **Un moteur d'audit statique (AST & Heuristiques)** pour diagnostiquer les référentiels de code source.
2. ⚡ **Un moteur d'audit dynamique réseau (.EXE)** pour surveiller le comportement réel des binaires Windows en temps réel (arbre de processus, WebView2, sockets TCP/UDP, DNS et télémétrie).

---

## 🚀 Fonctionnalités Principales

### 1. 📂 Audit Statique du Code Source
- **Détection de Secrets & Clés d'API** : Reconnaissance de signatures pour clés OpenAI, Anthropic, GitHub PAT, clés privées RSA/SSH, jetons d'accès et mots de passe.
- **Packages & Dépendances Fantômes** : Détection des packages importés absents de `requirements.txt` ou `pyproject.toml` (hallucinations LLM).
- **📦 Failles de Dépendances & CVEs (OSV.dev)** : Détection des vulnérabilités connues (CVE/GHSA) et versions obsolètes injectées par l'IA dans `requirements.txt` et `package.json` (requête batch en ligne et base locale de signatures hors-ligne).
- **Hygiène d'Erreur & Dette Technique** : Repérage des clauses `except: pass`, fonctions démesurées et fichiers monolithiques ("God objects").
- **Failles de Sécurité** : Injections SQL par concaténation, utilisation d'évaluations dynamiques arbitraires (`eval()`, `exec()`, `os.system()`).
- **🛠️ Stack Technologique & Répartition des Langages** : Identification automatique des langages de programmation (avec volumétrie en lignes de code et pourcentages de répartition façon GitHub) et cartographie catégorisée des frameworks, bibliothèques, SDKs IA (OpenAI, Anthropic, LangChain...), bases de données, ORMs et outils de build.
- **Score Vibe Readiness (0 à 100)** : Algorithme pondérant la dette technique et la sévérité des vulnérabilités.

### 2. ⚡ Audit Réseau Dynamique (.EXE)
- **Traçage récursif de l'arbre de processus** : Détecte l'exécutable racine ainsi que tous ses processus enfants (indispensable pour les applications **Tauri**, **Electron** et les sous-processus `msedgewebview2.exe` ou `ffmpeg.exe`).
- **Interception haute fréquence des sockets (TCP / UDP)** : Capture les handshakes réseau à la milliseconde près.
- **Enrichissement des données en temps réel** : Résolution DNS inverse et identification de l'organisation/ASN propriétaire (ex: *GitHub, Inc.*, *Microsoft*, *Cloudflare*, *OpenAI*).
- **Classification automatique des flux** : Catégorise le trafic en *Télémétrie & Trackers*, *APIs Cloud / LLM*, *CDN*, *Distribution de Code* ou *Adresses Inconnues*.
- **Score Réseau & Badge de Posture** :
  - `🛡️ 100% OFFLINE` : Zéro flux externe émis.
  - `⚠️ TÉLÉMÉTRIE DÉTECTÉE` : Envoi de statistiques à des plateformes connues (Sentry, Google Analytics, telemetry Microsoft).
  - `🚨 TRAFIC NON VÉRIFIÉ` : Communications sortantes non répertoriées.
- **Inspection statique PE complémentaire** : Recherche des URLs et endpoints embarqués dans le binaire compilé.

---

## 🖥️ Interface Web Dashboard

Vibe Audit intègre un serveur Web moderne accessible sur le navigateur (`http://127.0.0.1:8765`) avec une interface sombre de type **glassmorphism** :

- **Double onglet** : Basculez instantanément entre l'audit statique et l'audit dynamique d'exécutables.
- **Visualiseur radar animé** : Suivi visuel des paquets capturés au fil de l'eau.
- **Arbre des processus** : Cartographie des PIDs parents et enfants avec volumétrie I/O (lecture / écriture).
- **Timeline des événements** : Journal chronologique interactif des connexions réseau.
- **Export en un clic** : Téléchargement des rapports au format Markdown ou JSON structuré.

---

## 📦 Installation

### Prérequis
- **Système d'exploitation** : Windows 10 ou 11 (pour le module dynamique d'audit `.exe`).
- **Python** : Version 3.10 ou supérieure.

### 1. Cloner le dépôt
```bash
git clone https://github.com/votre-compte/vibe-audit.git
cd "vibe audit"
```

### 2. Installer les dépendances
```bash
pip install psutil requests
```

---

## 🎮 Guide d'Utilisation

### Option 1 : Lancer l'Interface Web (Recommandé)
Démarrez le serveur applicatif local :
```bash
python app.py
```
Ouvrez ensuite votre navigateur sur :
👉 **`http://127.0.0.1:8765`**

---

### Option 2 : Audit Statique en Ligne de Commande (CLI)
Analysez un dossier de code source directement depuis votre terminal :

```bash
# Exemple sur le projet de démonstration
python vibe_audit.py samples/vibe_chaos_saas

# Analyser votre propre projet
python vibe_audit.py C:\Chemin\Vers\MonProjet
```

---

### Option 3 : Audit Réseau Dynamique .EXE en Ligne de Commande (CLI)
Surveillez un binaire Windows pendant une période définie ou en continu :

```bash
# Lancer un exécutable et l'observer pendant 15 secondes
python audit_exe.py "C:\Users\ash\AppData\Local\OpenPeek\openpeek.exe" --timeout 15

# Transmettre des arguments CLI à l'exécutable
python audit_exe.py "C:\Python314\python.exe" --args "samples/network_test_app.py" --timeout 10

# S'attacher à un processus déjà en cours d'exécution sur votre machine (PID)
python audit_exe.py --pid 17072 --timeout 0

# Exporter le rapport directement au format JSON
python audit_exe.py "C:\Chemin\vers\outil.exe" --json
```

---

## 📦 Exécutables Autonomes Windows (.EXE)

Vibe Audit est disponible sous la forme d'un **exécutable unique et autonome (`.exe` portable)** intégrant l'interface Web complète, les assets statiques, les scénarios de démonstration et le moteur d'analyse :

### 1. Démarrage en 1 clic :
- **Double-cliquez sur `Lancer_Vibe_Audit.bat`** à la racine du projet.
- Ou lancez directement : **`dist\VibeAudit.exe`**.
- L'exécutable démarre le serveur local et ouvre automatiquement votre navigateur sur le Dashboard (`http://127.0.0.1:8765`).
- **100% portable** : Vous pouvez copier le fichier `dist\VibeAudit.exe` sur votre bureau, une clé USB ou une autre machine Windows sans avoir besoin d'installer Python.

### 2. Outil CLI autonome :
- **`dist/audit_exe.exe`** : L'outil d'audit dynamique réseau en ligne de commande (sans besoin de Python).
  ```powershell
  .\dist\audit_exe.exe "C:\Chemin\Application.exe" --timeout 15
  ```

### 3. Recompiler en 1 clic :
- Double-cliquez sur **`Compiler_Vibe_Audit.bat`** à la racine du projet.
- Ou via le terminal :
  ```bash
  # Compiler le fichier unique autonome (.exe portable)
  python build_exe.py --mode onefile

  # Ou compiler en mode dossier classique
  python build_exe.py --mode onedir
  ```

---

## 📂 Architecture du Projet

```text
vibe audit/
│
├── app.py                         # Serveur Web HTTP & API REST (port 8765)
├── vibe_audit.py                  # Point d'entrée CLI pour l'audit statique
├── audit_exe.py                   # Point d'entrée CLI pour l'audit dynamique d'exécutables
├── build_exe.py                   # Script de compilation PyInstaller (.exe)
│
├── dist/                          # Exécutables compilés autonomes
│   ├── VibeAudit/                 # Application Web complète tout-en-un (--onedir)
│   │   ├── VibeAudit.exe          # Binaire principal Windows
│   │   └── _internal/             # Bibliothèques et assets embarqués
│   └── audit_exe.exe              # Outil CLI d'audit dynamique réseau
│
├── engine/                        # Cœur du moteur d'audit
│   ├── dynamic_network_audit.py   # Moteur de traçage réseau, sockets & arbre des processus
│   ├── tech_detector.py           # Analyseur de stack technologique, frameworks et langages
│   ├── report_generator.py        # Génération des synthèses et exports Markdown/JSON
│   ├── scanner.py                 # Analyseur statique de fichiers de code et AST
│   └── rules/                     # Règles d'inspection statique modulaires
│       ├── base.py                # Classes de base, sévérités, catégories et types
│       ├── architecture.py        # Détection de la dette technique & god objects
│       ├── ghost_deps.py          # Détection des packages fantômes (hallucinations IA)
│       ├── dep_vulnerabilities.py # Scan des vulnérabilités CVE / GHSA (OSV.dev + hors-ligne)
│       ├── lazy_errors.py         # Erreurs avalées (except: pass), clauses trop larges
│       ├── secrets.py             # Détection de tokens, clés d'API et clés privées
│       ├── security.py            # Failles XSS, injections SQL et code dynamique (eval/exec)
│       └── testing_docs.py        # Vérification de la présence de tests unitaires et README
│
├── samples/                       # Projets et scénarios de test
│   ├── network_test_app.py        # Script de test de flux réseau sortant (GitHub API)
│   ├── hardened_app/              # Projet modèle propre (bonne architecture)
│   └── vibe_chaos_saas/           # Projet modèle vibe-codé avec pièges typiques & CVE requests
│
└── static/                        # Frontend moderne (Single Page App)
    ├── index.html                 # Structure du dashboard avec onglets statique/dynamique
    ├── css/
    │   └── style.css              # Design system Dark Glassmorphism, animations radar
    └── js/
        └── app.js                 # Logique applicative, polling temps réel et visualisations
```

---

## 🧪 Scénarios de Démonstration Inclus

| Scénario | Type | Objectif |
| :--- | :--- | :--- |
| **OpenPeek (`openpeek.exe`)** | Dynamique | Validation d'une application de bureau desktop basée sur Tauri & WebView2. Démontre un fonctionnement **100% offline** (Score 100/100). |
| **GitHub Test App (`network_test_app.py`)** | Dynamique | Validation de la capture en direct d'un appel HTTPS vers l'API GitHub avec reverse DNS et classification ASN. |
| **Vibe Chaos SaaS (`vibe_chaos_saas`)** | Statique | Cas d'école d'un projet généré à la hâte par IA : clés OpenAI en clair, injections SQL, `except: pass` et dépendance vulnérable (`requests==2.20.0` avec CVE-2023-32681). |
| **Hardened App (`hardened_app`)** | Statique | Projet de référence configuré selon les standards de production logicielle. |

---

## 🛡️ Confidentialité & Sécurité

- **Analyse 100% Locale** : Vibe Audit s'exécute intégralement sur votre machine hôte. Aucun fragment de votre code source n'est envoyé à des serveurs tiers.
- **Audit passif des sockets** : Le moteur dynamique s'appuie sur les compteurs du sous-système Windows et ne modifie pas les binaires audités.

---

## 📄 Licence

Ce projet est distribué sous licence MIT. Consultez le fichier [LICENSE](LICENSE) pour plus d'informations.
