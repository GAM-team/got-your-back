until powershell Install-WindowsFeature Net-Framework-Core; do echo "trying again..."; done
#export exefile=Win32OpenSSL_Light-${BUILD_OPENSSL_VERSION//./_}.exe
#if [ ! -e $exefile ]; then
#  echo "Downloading $exefile..."
#  wget --quiet https://slproweb.com/download/$exefile
#fi
#echo "Installing $exefile..."
#powershell ".\\${exefile} /silent /sp- /suppressmsgboxes /DIR=C:\\ssl"
cinst -y $CINST_ARGS python3
#cp -v /c/Program\ Files/OpenSSL/bin/*.dll /c/Python37/DLLs
export PATH=$PATH:/c/Python37/scripts
cinst -y wixtoolset
#until cp -v /c/ssl/*.dll /c/Python37/DLLs; do echo "trying again..."; done
export python=/c/Python37/python
export pip=/c/Python37/scripts/pip
