if [ "$VMTYPE" == "test" ]; then
  export gyb="$python gyb.py"
  export gybpath=$(readlink -e .)
else
  $python -m PyInstaller --clean -F --distpath=gyb $TRAVIS_OS_NAME-gyb.spec
  gyb/gyb --version
  export GYBVERSION=`gyb/gyb --short-version`
  cp LICENSE gyb
  this_glibc_ver=$(ldd --version | awk '/ldd/{print $NF}')
  GYB_ARCHIVE=gyb-$GYBVERSION-$TRAVIS_OS_NAME-$ARCH-glibc$this_glibc_ver.tar.xz
  tar cfJ $GYB_ARCHIVE gyb/
  if [[ "$dist" == "precise" ]]; then
    GYB_LEGACY_ARCHIVE=gyb-$GYBVERSION-$TRAVIS_OS_NAME-$ARCH-legacy.tar.xz
    $python -OO -m staticx gyb/gyb gyb/gyb-staticx
    strip gyb/gyb-staticx
    rm gyb/gyb
    mv gyb/gyb-staticx gyb/gyb
    tar cfJ $GYB_LEGACY_ARCHIVE gyb/
    echo "Legacy StaticX GYB info:"
    du -h gyb/gyb
    time gyb/gyb --version
  fi
  mkdir gyb-test
  cp -rf gyb/* gyb-test/
  export gybpath=$(readlink -e gyb-test)
  export gyb="$gybpath/gyb"
fi
