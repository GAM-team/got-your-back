mypath=$HOME
whereibelong=$(pwd)
brew install xz > /dev/null

# Compile latest OpenSSL
wget --quiet https://www.openssl.org/source/openssl-$BUILD_OPENSSL_VERSION.tar.gz
echo "Extracting OpenSSL..."
tar xf openssl-$BUILD_OPENSSL_VERSION.tar.gz
cd openssl-$BUILD_OPENSSL_VERSION
echo "Compiling OpenSSL $BUILD_OPENSSL_VERSION..."
./config shared --prefix=$mypath/ssl
echo "Running make for OpenSSL..."
make -j$cpucount -s
echo "Running make install for OpenSSL..."
make install > /dev/null
export LD_LIBRARY_PATH=~/ssl/lib
cd ~

# Compile latest Python
wget --quiet https://www.python.org/ftp/python/$BUILD_PYTHON_VERSION/Python-$BUILD_PYTHON_VERSION.tar.xz
echo "Extracting Python..."
tar xf Python-$BUILD_PYTHON_VERSION.tar.xz
cd Python-$BUILD_PYTHON_VERSION
echo "Compiling Python $BUILD_PYTHON_VERSION..."
safe_flags="--with-openssl=$mypath/ssl --enable-shared --prefix=$mypath/python --with-ensurepip=upgrade"
unsafe_flags="--enable-optimizations --with-lto"
./configure $safe_flags $unsafe_flags > /dev/null
make -j$cpucount -s
if [ $? != 0 ]; then
  echo "Trying Python $BUILD_PYTHON_VERSION compile again without unsafe flags..."
  ./configure $safe_flags > /dev/null
  make -j$cpucount -s
fi
echo "Installing Python..."
make install > /dev/null
cd ~

export LD_LIBRARY_PATH=~/ssl/lib:~/python/lib
export python=~/python/bin/python3
export pip=~/python/bin/pip3

$python -V

cd $whereibelong

export PATH=/usr/local/opt/python/libexec/bin:$PATH
$pip install --upgrade pip
$pip freeze > upgrades.txt
$pip install --upgrade -r upgrades.txt
$pip install -r src/requirements.txt
$pip install pyinstaller
