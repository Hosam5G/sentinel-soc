# PyInstaller spec for Sentinel SOC Windows executable
# Usage: pyinstaller sentinel.spec
# Output: dist/Sentinel_SOC.exe (~80-120 MB)

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[
        # All dashboard static files (UI, fonts, media/ backgrounds)
        ('dashboard', 'dashboard'),
    ]
    # Self-hosted Thmanyah fonts + their CSS live in the PROJECT ROOT (not under
    # dashboard/). Bundle them too, otherwise the .exe loads with a fallback font.
    # Each entry is added only if the file/folder actually exists, so the build
    # never fails when an optional asset is missing.
    + [(src, dst) for (src, dst) in [
        ('fonts', 'fonts'),                       # fonts/*.woff2
        ('colors_and_type.css', '.'),             # @font-face declarations
        ('styles.css', '.'),                      # main stylesheet (may @import the font)
        ('i18n.js', '.'),
        ('icons.jsx', '.'),
        ('premium-icons.jsx', '.'),
        ('motion.jsx', '.'),
        ('laptop-core.jsx', '.'),
      ] if os.path.exists(src)]
    + collect_data_files('flask'),
    hiddenimports=[
        'flask',
        'werkzeug',
        'jinja2',
        'markupsafe',
        'cryptography',
        'sqlite3',
        'psutil',
        'urllib3',
        'urllib',
        # Optional: only include if installed
        'pystray',
        'PIL',
        'yara',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Sentinel_SOC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window on startup
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Set to a .ico file if you have one
)
