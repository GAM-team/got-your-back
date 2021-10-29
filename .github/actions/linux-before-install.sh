if [[ "$TRAVIS_JOB_NAME" == *"Testing" ]]; then
  export python="python"
  export pip="pip"
  echo "Travis setup Python $TRAVIS_PYTHON_VERSION"
  echo "running tests with this version"
else
  export whereibelong=$(pwd)
  export openssl=/usr/local/bin/openssl
  export python=/usr/local/bin/python3
  export pip=/usr/local/bin/pip3
  export LD_LIBRARY_PATH=/usr/local/lib
  echo "We are running on Ubuntu $TRAVIS_DIST $PLATFORM"
  cpucount=$(nproc --all)
  echo "This device has $cpucount CPUs for compiling..."
  SSLVER=$($openssl version)
  SSLRESULT=$?
  PYVER=$($python -V)
  PYRESULT=$?
  if [ $SSLRESULT -ne 0 ] || [[ "$SSLVER" != "OpenSSL $BUILD_OPENSSL_VERSION "* ]] || [ $PYRESULT -ne 0 ] || [[ "$PYVER" != "Python $BUILD_PYTHON_VERSION"* ]]; then
    echo "SSL Result: $SSLRESULT - SSL Ver: $SSLVER - Py Result: $PYRESULT - Py Ver: $PYVER"
    if [ $SSLRESULT -ne 0 ]; then
      echo "sslresult -ne 0"
    fi
    if [[ "$SSLVER" != "OpenSSL $BUILD_OPENSSL_VERSION "* ]]; then
      echo "sslver not equal to..."
    fi
    if [ $PYRESULT -ne 0 ]; then
      echo "pyresult -ne 0"
    fi
    if [[ "$PYVER" != "Python $BUILD_PYTHON_VERSION" ]]; then
      echo "pyver not equal to..."
    fi
    cd ~
    echo "RUNNING: apt update..."
    sudo apt-get -qq --yes update > /dev/null
    #echo "RUNNING: apt dist-upgrade..."
    #sudo apt-get -qq --yes dist-upgrade > /dev/null
    echo "Installing build tools..."
    sudo apt-get -qq --yes install build-essential
    echo "Installing deps for python3"
    sudo apt-get -qq --yes build-dep python3 > /dev/null

    # Compile latest OpenSSL
    curl -O -L https://www.openssl.org/source/openssl-$BUILD_OPENSSL_VERSION.tar.gz
    echo "Extracting OpenSSL..."
    tar xf openssl-$BUILD_OPENSSL_VERSION.tar.gz
    cd openssl-$BUILD_OPENSSL_VERSION
    echo "Compiling OpenSSL $BUILD_OPENSSL_VERSION..."
    ./Configure --libdir=lib
    echo "Running make for OpenSSL..."
    make -j$cpucount -s
    echo "Running make install for OpenSSL..."
    sudo make install > /dev/null
    cd ~
    $openssl version
    
    # Compile latest Python
    echo "Downloading Python $BUILD_PYTHON_VERSION..."
    curl -O https://www.python.org/ftp/python/$BUILD_PYTHON_VERSION/Python-$BUILD_PYTHON_VERSION.tar.xz
    echo "Extracting Python..."
    tar xf Python-$BUILD_PYTHON_VERSION.tar.xz
    cd Python-$BUILD_PYTHON_VERSION
    echo "Compiling Python $BUILD_PYTHON_VERSION..."
    safe_flags="--enable-shared --with-ensurepip=upgrade --with-openssl=/usr/local --with-openssl-rpath=/usr/local/lib"
    unsafe_flags="--enable-optimizations --with-lto"
    if [ ! -e Makefile ]; then
      echo "running configure with safe and unsafe"
      ./configure $safe_flags $unsafe_flags
    fi
    make -j$cpucount
    RESULT=$?
    echo "First make exited with $RESULT"
    if [ $RESULT != 0 ]; then
      echo "Trying Python compile again without unsafe flags..."
      make clean
      ./configure $safe_flags > /dev/null
      make -j$cpucount -s
      echo "Sticking with safe Python for now..."
    fi
    echo "Installing Python..."
    sudo make install > /dev/null
    cd ~
    $python -V
  fi

  if ([ "${ImageOS}" == "ubuntu20" ]) && [ "${HOSTTYPE}" == "x86_64" ]; then
    echo "Installing deps for StaticX..."
    if [ ! -d patchelf-$PATCHELF_VERSION ]; then
      echo "Downloading PatchELF $PATCHELF_VERSION"
      wget https://nixos.org/releases/patchelf/patchelf-$PATCHELF_VERSION/patchelf-$PATCHELF_VERSION.tar.bz2
      tar xf patchelf-$PATCHELF_VERSION.tar.bz2
      cd patchelf-$PATCHELF_VERSION
      ./configure
      make
      sudo make install
    fi
    $pip install staticx
  fi

  $pip install --upgrade git+git://github.com/pyinstaller/pyinstaller.git@$PYINSTALLER_COMMIT

  cd $whereibelong
fi

echo "Upgrading pip packages..."
$pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 $pip install -U
$pip install --upgrade -r requirements.txt
