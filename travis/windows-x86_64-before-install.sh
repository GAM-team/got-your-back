cinst $CINST_ARGS python3
powershell Install-WindowsFeature Net-Framework-Core
export PATH=$PATH:/c/Python37/scripts
cinst -y wixtoolset
