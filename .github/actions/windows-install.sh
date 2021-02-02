echo "compiling GYB with pyinstaller..."
pyinstaller --clean --noupx -F --distpath=gyb gyb.spec
export gyb="gyb/gyb"
export gybpath=$(readlink -e gyb)
echo "running compiled GYB..."
$gyb --version
export GYBVERSION=`$gyb --short-version`
cp LICENSE gyb
cp gyb-setup.bat gyb
GYB_ARCHIVE=gyb-$GYBVERSION-windows-$ARCH.zip
/c/Program\ Files/7-Zip/7z.exe a -tzip $GYB_ARCHIVE gyb -xr!.svn
mkdir gyb-64
cp -rf gyb/* gyb-64/;
/c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/candle.exe -arch x64 windows-gyb.wxs
/c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/light.exe -ext /c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/WixUIExtension.dll windows-gyb.wixobj -o gyb-$GYBVERSION-windows-$ARCH.msi || true;
rm *.wixpdb
