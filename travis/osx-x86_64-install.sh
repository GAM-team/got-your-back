cd src
echo "MacOS Version Info According to Python:"
python -c "import platform; print(platform.mac_ver())"
$python -OO -m PyInstaller --clean --noupx --strip -F --distpath=gyb osx-gyb.spec
export gyb="gyb/gyb"
$gyb --version
export GYBVERSION=`$gyb --simple-version`
cp LICENSE gyb
MACOSVERSION=$(defaults read loginwindow SystemVersionStampAsString)
GYB_ARCHIVE=gyb-$GYBVERSION-macos-$PLATFORM-MacOS$MACOSVERSION.tar.xz
tar cfJ $GYB_ARCHIVE gyb/
