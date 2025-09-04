# -*- mode: python -*-
import os
import re
import sys
from sys import platform

import importlib
from PyInstaller.utils.hooks import copy_metadata

sys.modules['FixTk'] = None

with open("gyb.py") as f:
    version_file = f.read()
version = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M).group(1)
version_list = [int(i) for i in version.split('.')]
while len(version_list) < 4:
  version_list.append(0)
version_tuple = tuple(version_list)
version_str = str(version_tuple)
with open("version_info.txt.in") as f:
    version_info = f.read()
version_info = version_info.replace("{VERSION}", version).replace(
    "{VERSION_TUPLE}", version_str
)
with open("version_info.txt", "w") as f:
    f.write(version_info)
print(version_info)

# dynamically determine where httplib2/cacerts.txt lives
proot = os.path.dirname(importlib.import_module('httplib2').__file__)
extra_files = [(os.path.join(proot, 'cacerts.txt'), 'httplib2')]

excludes = [
    'pkg_resources',
    'FixTk',
    'tcl',
    'tk',
    '_tkinter',
    'tkinter',
    'Tkinter',
]
#extra_files += copy_metadata('google-api-python-client')

a = Analysis(['gyb.py'],
             excludes=excludes,
             datas=extra_files,
             hiddenimports=[],
             hooksconfig={},
             hookspath=None,
             runtime_hooks=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=None,
             noarchive=False,
             )

for d in a.datas:
    if 'pyconfig' in d[0]:
        print(f' manually removing {d[0]}')
        a.datas.remove(d)
    elif 'googleapiclient/discovery_cache/documents/' in d[0]:
        print(f' manually removing discovery JSON {d[0]}')
        a.datas.remove(d)
    else:
        print(f' LEAVING {d}')

pyz = PYZ(a.pure)

# requires Python 3.10+ but no one should be compiling
# GYB with older versions anyway
target_arch = None
codesign_identity = None
entitlements_file = None
manifest = None
version = 'version_info.txt'
match platform:
    case "darwin":
        codesign_identity = os.getenv('codesign_identity')
        if codesign_identity:
            entitlements_file = '.github/actions/entitlements.plist'
        strip = True
    case "win32":
        target_arch = None
        strip = False
        manifest = 'gyb.exe.manifest'
    case _:
        target_arch = None
        strip = True
name = 'gyb'
debug = False
bootloader_ignore_signals = False
upx = False
console = True
disable_windowed_traceback = False
argv_emulation = False
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name=name,
          debug=debug,
          bootloader_ignore_signals=bootloader_ignore_signals,
          strip=strip,
          manifest=manifest,
          upx=upx,
          console=console,
          argv_emulation=argv_emulation,
          target_arch=target_arch,
          codesign_identity=codesign_identity,
          entitlements_file=entitlements_file,
          version=version,
          )
