rmdir /q /s gyb
rmdir /q /s build
rmdir /q /s dist
del /q /f gyb-%1-windows.zip
del /q /f gyb-%1-windows.msi
del /q /f windows-gyb.wixobj
del /q /f windows-gyb.wixpdb

c:\python37\scripts\pyinstaller --clean -F --distpath=gyb windows-gyb.spec
copy LICENSE gyb\
copy license.rtf gyb\
copy gyb-setup.bat gyb\

"%ProgramFiles%\7-Zip\7z.exe" a -tzip gyb-%1-windows.zip gyb\ -xr!.svn

set GYBVERSION=%1
"%ProgramFiles(x86)%\WiX Toolset v3.11\bin\candle.exe" -arch x64 windows-gyb.wxs
"%ProgramFiles(x86)%\WiX Toolset v3.11\bin\light.exe" -ext "%ProgramFiles(x86)%\WiX Toolset v3.11\bin\WixUIExtension.dll" windows-gyb.wixobj -o gyb-%1-windows.msi
