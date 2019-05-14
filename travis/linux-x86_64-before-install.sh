export whereibelong=$(pwd)
export dist=$(lsb_release --codename --short)
echo "We are running on Ubuntu $dist"
echo "RUNNING: apt update..."
sudo apt-get -qq --yes update > /dev/null
echo "RUNNING: apt dist-upgrade..."
sudo apt-get -qq --yes dist-upgrade > /dev/null
echo "Installing build tools..."
sudo apt-get -qq --yes install build-essential > /dev/null

echo "Installing deps for python3"
sudo cp -v /etc/apt/sources.list /tmp
chmod a+rwx /tmp/sources.list
echo "deb-src http://archive.ubuntu.com/ubuntu/ $dist main" >> /tmp/sources.list
sudo cp -v /tmp/sources.list /etc/apt
sudo apt-get --yes update > /dev/null
sudo apt-get --yes build-dep python3

mypath=$HOME
echo "My Path is $mypath"
cpucount=$(nproc --all)
echo "This device has $cpucount CPUs for compiling..."

cd build
# Compile latest OpenSSL
if [ ! -d openssl-$BUILD_OPENSSL_VERSION ]; then
  wget --quiet https://www.openssl.org/source/openssl-$BUILD_OPENSSL_VERSION.tar.gz
  echo "Extracting OpenSSL $BUILD_OPENSSL_VERSION..."
  tar xf openssl-$BUILD_OPENSSL_VERSION.tar.gz
fi
cd openssl-$BUILD_OPENSSL_VERSION
echo "Compiling OpenSSL $BUILD_OPENSSL_VERSION..."
./config shared --prefix=$mypath/ssl
echo "Running make for OpenSSL..."
make -j$cpucount -s
echo "Running make install for OpenSSL..."
make install > /dev/null
export LD_LIBRARY_PATH=~/ssl/lib
cd ~/build

# Compile latest Python
if [ ! -d Python-$BUILD_PYTHON_VERSION ]; then
  wget --quiet https://www.python.org/ftp/python/$BUILD_PYTHON_VERSION/Python-$BUILD_PYTHON_VERSION.tar.xz
  echo "Extracting Python..."
  tar xf Python-$BUILD_PYTHON_VERSION.tar.xz
fi
cd Python-$BUILD_PYTHON_VERSION
echo "Compiling Python $BUILD_PYTHON_VERSION..."
safe_flags="--with-openssl=$mypath/ssl --enable-shared --prefix=$mypath/python --with-ensurepip=upgrade"
unsafe_flags="--enable-optimizations --with-lto"
if [ ! -e Makefile ]; then
  ./configure $safe_flags $unsafe_flags > /dev/null
fi
make -j$cpucount -s
RESULT=$?
echo "First make exited with $RESULT"
if [ $RESULT != 0 ]; then
  echo "Trying Python $BUILD_PYTHON_VERSION compile again without unsafe flags"
  make clean
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

if [[ "$dist" == "xenial" ]]; then
  echo "Installing deps for StaticX..."
  sudo apt-get install --yes patchelf scons musl
  $pip install git+https://github.com/JonathonReinhart/staticx.git@master
fi

cd $whereibelong

echo "Upgrading pip packages..."
$pip freeze > upgrades.txt
$pip install --upgrade -r upgrades.txt
$pip install -r src/requirements.txt
$pip install pyinstaller

cd $whereibelong
