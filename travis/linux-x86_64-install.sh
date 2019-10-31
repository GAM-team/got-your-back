cd src
if [ "$VMTYPE" == "test" ]; then
  export gyb="$python gyb.py"
else
  $python -OO -m PyInstaller --clean --noupx --strip -F --distpath=gyb $GAMOS-gyb.spec
  export gyb="gyb/gyb"
  export GYBVERSION=`$gyb --simple-versio`
  cp LICENSE gyb
  this_glibc_ver=$(ldd --version | awk '/ldd/{print $NF}')
  GYB_ARCHIVE=gyb-$GYBVERSION-linux-$PLATFORM-glibc$this_glibc_ver.tar.xz
  tar cfJ $GYB_ARCHIVE gyb/
  echo "PyInstaller GYB info:"
  du -h gyb/gyb
  time $gyb --version

  if [[ "$dist" == "precise" ]]; then
    GYB_LEGACY_ARCHIVE=gyb-$GYBVERSION-linux-$PLATFORM-legacy.tar.xz
    $python -OO -m staticx gyb/gyb gyb/gyb-staticx
    strip gyb/gyb-staticx
    rm gyb/gyb
    mv gyb/gyb-staticx gyb/gyb
    tar cfJ $GYB_LEGACY_ARCHIVE gyb/
    echo "Legacy StaticX GYB info:"
    du -h gyb/gyb
    time $gyb --version
  fi
fi
