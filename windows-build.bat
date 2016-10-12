rmdir /q /s gyb
rmdir /q /s build
rmdir /q /s dist
del /q /f gyb-%1-windows.zip

c:\python3\scripts\pyinstaller --distpath=gyb windows-gyb.spec
xcopy LICENSE gyb\
xcopy client_secrets.json gyb\
"%ProgramFiles%\7-Zip\7z.exe" a -tzip gyb-%1-windows.zip gyb\ -xr!.svn
