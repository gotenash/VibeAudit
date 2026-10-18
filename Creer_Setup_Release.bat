@echo off
title Preparation Release Vibe Audit
cd /d "%~dp0"

echo =======================================================
echo     GENERATION DU PACK DE RELEASE GITHUB VIBE AUDIT
echo =======================================================
echo.
echo Ce script compile le binaire autonome, l'installeur Windows (.exe)
echo et l'archive portable (.zip) dans le dossier dist\release\
echo.
python build_release.py
echo.
echo =======================================================
pause
