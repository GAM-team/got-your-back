powershell Install-WindowsFeature Net-Framework-Core
cinst $CINST_ARGS python3
cinst -y openssl.light
cp -v /c/Program\ Files/OpenSSL/bin/*.dll /c/Python37/DLLs
export PATH=$PATH:/c/Python37/scripts
cinst -y wixtoolset

export python=/c/Python37/python
export pip=/c/Python37/script/pip
