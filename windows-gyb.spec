# -*- mode: python -*-
a = Analysis(['gyb.py'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break
a.datas += [('httplib2/cacerts.txt', 'httplib2\cacerts.txt', 'DATA')]
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='gyb.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True )
