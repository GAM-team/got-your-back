rmdir /q /s gyb
rmdir /q /s gyb-64
rmdir /q /s build
rmdir /q /s dist
del /q /f gyb-%1-windows.zip
del /q /f gyb-%1-windows-x64.zip

\python27-32\python.exe setup.py py2exe
xcopy LICENSE.txt gyb\
xcopy whatsnew.txt gyb\
xcopy cacert.pem gyb\
xcopy client_secrets.json gyb\
del gyb\w9xpopen.exe
"%ProgramFiles(x86)%\7-Zip\7z.exe" a -tzip gyb-%1-windows.zip gyb\ -xr!.svn

\python27\python.exe setup-64.py py2exe
xcopy LICENSE.txt gyb-64\
xcopy whatsnew.txt gyb-64\
xcopy cacert.pem gyb-64\
xcopy client_secrets.json gyb-64\
"%ProgramFiles(x86)%\7-Zip\7z.exe" a -tzip gyb-%1-windows-x64.zip gyb-64\ -xr!.svn
