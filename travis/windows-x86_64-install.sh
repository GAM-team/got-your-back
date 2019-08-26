$python -m PyInstaller --clean -F --distpath=gyb $TRAVIS_OS_NAME-gyb.spec
gyb/gyb --version
export GYBVERSION=`gyb/gyb --short-version`
cp LICENSE gyb
cp gyb-setup.bat gyb
cp license.rtf gyb
GYB_ARCHIVE=gyb-$GYBVERSION-windows-$ARCH.zip
/c/Program\ Files/7-Zip/7z.exe a -tzip $GYB_ARCHIVE gyb -xr!.svn
/c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/candle.exe -arch $WIX_ARCH windows-gyb.wxs
/c/Program\ Files\ \(x86\)/Wix\ Toolset\ v3.11/bin/light.exe -ext /c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/WixUIExtension.dll windows-gyb.wixobj -o gyb-$GYBVERSION-windows-$ARCH.msi || true
rm *.wixpdb
export gybpath=$(readlink -e gyb)
export gyb="$gybpath/gyb"
