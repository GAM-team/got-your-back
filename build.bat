rmdir /q /s gyb
rmdir /q /s gyb-64
rmdir /q /s build
rmdir /q /s dist
del /q /f gyb-%1-windows.zip
del /q /f gyb-%1-windows-x64.zip

c:\python27-32\scripts\pyinstaller --distpath=gyb gyb.spec
xcopy LICENSE gyb\
xcopy cacert.pem gyb\
xcopy client_secrets.json gyb\
del gyb\w9xpopen.exe
"%ProgramFiles(x86)%\7-Zip\7z.exe" a -tzip gyb-%1-windows.zip gyb\ -xr!.svn

c:\python27\scripts\pyinstaller --distpath=gyb-64 gyb.spec
xcopy LICENSE gyb-64\
xcopy cacert.pem gyb-64\
xcopy client_secrets.json gyb-64\
"%ProgramFiles(x86)%\7-Zip\7z.exe" a -tzip gyb-%1-windows-x64.zip gyb-64\ -xr!.svn