@echo off
title Vibe Audit
cd /d "%~dp0"

echo =======================================================
echo               LANCEMENT DE VIBE AUDIT
echo =======================================================

if exist "dist\VibeAudit.exe" (
    echo [OK] Executable autonome detecte : dist\VibeAudit.exe
    echo Demarrage du serveur et ouverture automatique du navigateur...
    start "" "dist\VibeAudit.exe"
    exit /b 0
)

if exist "VibeAudit.exe" (
    echo [OK] Executable autonome detecte : VibeAudit.exe
    echo Demarrage du serveur et ouverture automatique du navigateur...
    start "" "VibeAudit.exe"
    exit /b 0
)

if exist "dist\VibeAudit\VibeAudit.exe" (
    echo [OK] Application detectee : dist\VibeAudit\VibeAudit.exe
    echo Demarrage du serveur et ouverture automatique du navigateur...
    start "" "dist\VibeAudit\VibeAudit.exe"
    exit /b 0
)

echo [ERREUR] Aucun executable VibeAudit.exe n'a ete trouve.
echo.
echo Voulez-vous generer l'executable portable maintenant ? (O/N)
set /p REP="> "
if /i "%REP%"=="O" (
    echo.
    python build_exe.py --mode onefile
    if exist "dist\VibeAudit.exe" (
        echo.
        echo Demarrage de Vibe Audit...
        start "" "dist\VibeAudit.exe"
    )
) else (
    echo Lancement annule.
    pause
)
