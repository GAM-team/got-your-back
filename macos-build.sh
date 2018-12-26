rm -rf gyb
rm -rf build
rm -rf dist
rm -rf gyb-$1-macos.tar.xz

/Library/Frameworks/Python.framework/Versions/3.7/bin/pyinstaller -F --clean --distpath=gyb macos-gyb.spec
cp LICENSE gyb/
tar cJf gyb-$1-macos.tar.xz gyb/
