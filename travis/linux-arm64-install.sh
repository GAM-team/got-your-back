cd src
if [ "$VMTYPE" == "test" ]; then
  export gyb="$python gyb.py"
else
  $python -OO -m PyInstaller --clean --noupx --strip -F --distpath=gyb linux-gyb.spec
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
fi
