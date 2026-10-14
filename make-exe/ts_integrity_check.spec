# -*- mode: python ; coding: utf-8 -*-
"""
ts_integrity_check.spec - PyInstaller build spec для Windows 7.

Собирает ОДИН .exe со встроенным ffmpeg из ./bin/.

ВАЖНО для Windows 7:
  - Python 3.8.x (последняя версия для Win7).
  - PyInstaller 4.x или 5.x (6.x может работать нестабильно).
  - Включены DLL Universal CRT (ucrtbase.dll и др.).

Сборка:
    pyinstaller ts_integrity_check.spec --clean --noconfirm

Готовый файл:
    dist/ts_integrity_check.exe
"""

import os
import sys

# ------------------------------------------------------------------
# Проверка версии Python — рекомендуется 3.8.x для Windows 7
# ------------------------------------------------------------------
if sys.version_info[:2] != (3, 8):
    print("=" * 60)
    print("  ВНИМАНИЕ: для сборки под Windows 7 рекомендуется Python 3.8.x")
    print("  Текущая версия: %d.%d.%d" % sys.version_info[:3])
    print("=" * 60)

# ------------------------------------------------------------------
# Внешние бинарники из ./bin/
# ts_integrity_check использует только ffmpeg.
# ffprobe — опционально (на случай, если понадобится).
# exiftool — НЕ используется.
# ------------------------------------------------------------------
binaries = []
for _name in ('ffmpeg', 'ffprobe'):
    _win = _name + ('.exe' if os.name == 'nt' else '')
    for _dir in ('bin', '.'):
        _src = os.path.join(_dir, _win)
        if os.path.isfile(_src):
            binaries.append((_src, 'bin'))
            break

# ------------------------------------------------------------------
# DLL Universal CRT для Windows 7
# ------------------------------------------------------------------
_ucrt_dlls = [
    'ucrtbase.dll',
    'api-ms-win-crt-runtime-l1-1-0.dll',
    'api-ms-win-crt-stdio-l1-1-0.dll',
    'api-ms-win-crt-math-l1-1-0.dll',
    'api-ms-win-crt-locale-l1-1-0.dll',
    'api-ms-win-crt-heap-l1-1-0.dll',
    'api-ms-win-crt-string-l1-1-0.dll',
    'api-ms-win-crt-convert-l1-1-0.dll',
    'api-ms-win-crt-environment-l1-1-0.dll',
    'api-ms-win-crt-filesystem-l1-1-0.dll',
    'api-ms-win-crt-time-l1-1-0.dll',
    'api-ms-win-crt-utility-l1-1-0.dll',
    'api-ms-win-crt-process-l1-1-0.dll',
]

_search_dirs = [
    os.path.join(sys.prefix, 'DLLs'),
    os.path.join(sys.prefix, 'Lib', 'site-packages'),
    os.path.dirname(sys.executable),
    os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
]

for _dll in _ucrt_dlls:
    for _dir in _search_dirs:
        _src = os.path.join(_dir, _dll)
        if os.path.isfile(_src):
            binaries.append((_src, '.'))
            break

# ------------------------------------------------------------------
# Скрытые импорты — специфично для ts_integrity_check
# ------------------------------------------------------------------
hiddenimports = [
    'numpy',
    'numpy.core',
    'numpy.core._multiarray_umath',
    'matplotlib',
    'matplotlib.pyplot',
    'matplotlib.backends.backend_agg',
    'scipy',
    'scipy.signal',
    'scipy.signal.spectral',
    'PIL',
    'PIL.Image',
]

# ------------------------------------------------------------------
# Исключения — не тянуть лишнее
# tkinter не нужен: ts_integrity_check — консольный скрипт.
# ------------------------------------------------------------------
excludes = [
    'tkinter',
    'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
    'IPython', 'jupyter', 'notebook', 'nbformat',
    'pytest', 'sphinx', 'docutils',
]

# ------------------------------------------------------------------
# Analysis
# ------------------------------------------------------------------
a = Analysis(
    ['ts_integrity_check.py'],
    pathex=['.'],
    binaries=binaries,
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ts_integrity_check',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,                # консольный скрипт
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    embed_manifest=True,
)