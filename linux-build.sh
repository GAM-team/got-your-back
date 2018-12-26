rm -rf gyb
rm -rf build
rm -rf dist
rm -rf gyb-$1-linux-$(arch).tar.xz

export LD_LIBRARY_PATH=/usr/local/lib
python3.7 /usr/local/bin/pyinstaller -F --clean --distpath=gyb linux-gyb.spec
cp LICENSE gyb/
tar cJf gyb-$1-linux-$(arch).tar.xz gyb/
