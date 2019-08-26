$python -m PyInstaller --clean -F --distpath=gyb $TRAVIS_OS_NAME-gyb.spec
gyb/gyb --version
export GYBVERSION=`gyb/gyb --short-version`
cp LICENSE gyb
GYB_ARCHIVE=gyb-$GYBVERSION-$TRAVIS_OS_NAME-$ARCH.tar.xz
tar cfJ $GYB_ARCHIVE gyb/
export gybpath=gyb
export gyb="$gybpath/gyb"
