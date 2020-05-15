if [ "$VMTYPE" == "test" ]; then
  export gyb="$python gyb.py"
  export gybpath=$(readlink -e .)
else
  $python -OO -m PyInstaller --clean --noupx --strip -F --distpath=gyb gyb.spec
  export gyb="gyb/gyb"
  export gybpath=$(readlink -e gyb)
  export GYBVERSION=`$gyb --short-version`
  cp LICENSE gyb
  this_glibc_ver=$(ldd --version | awk '/ldd/{print $NF}')
  GYB_ARCHIVE=gyb-$GYBVERSION-linux-$ARCH-glibc$this_glibc_ver.tar.xz
  tar cfJ $GYB_ARCHIVE gyb/
  echo "PyInstaller GYB info:"
  du -h gyb/gyb
  time $gyb --version

  if [[ "$dist" == "xenial" ]]; then
    GYB_LEGACY_ARCHIVE=gyb-$GYBVERSION-linux-$ARCH-legacy.tar.xz
    $python -OO -m staticx gyb/gyb gyb/gyb-staticx
    strip gyb/gyb-staticx
    rm gyb/gyb
    mv gyb/gyb-staticx gyb/gyb
    chmod 755 gyb/gyb
    tar cfJ $GYB_LEGACY_ARCHIVE gyb/
    echo "Legacy StaticX GYB info:"
    du -h gyb/gyb
    time $gyb --version
  fi
fi
