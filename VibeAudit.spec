# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/ash/Documents/GitHub/vibe audit/VibeAudit/app.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/ash/Documents/GitHub/vibe audit/VibeAudit/static', 'static'), ('C:/Users/ash/Documents/GitHub/vibe audit/VibeAudit/samples', 'samples')],
    hiddenimports=['psutil', 'engine', 'engine.rules', 'engine.rules.base', 'engine.rules.architecture', 'engine.rules.ghost_deps', 'engine.rules.lazy_errors', 'engine.rules.secrets', 'engine.rules.security', 'engine.rules.dep_vulnerabilities', 'engine.rules.testing_docs', 'engine.scanner', 'engine.tech_detector', 'engine.report_generator', 'engine.dynamic_network_audit'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VibeAudit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:/Users/ash/Documents/GitHub/vibe audit/VibeAudit/assets/icon.ico'],
)
