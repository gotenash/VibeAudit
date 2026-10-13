@echo off
title Compilation Vibe Audit
cd /d "%~dp0"

echo =======================================================
echo        COMPILATION DE VIBE AUDIT (.EXE UNIQUE)
echo =======================================================
echo.
echo Ce script va generer un fichier VibeAudit.exe 100%% autonome
echo dans le dossier dist\ que vous pourrez deplacer n'importe ou.
echo.
python build_exe.py --mode onefile
echo.
echo =======================================================
pause
