powershell Install-WindowsFeature Net-Framework-Core
cinst $CINST_ARGS python3
export PATH=$PATH:/c/Python37/scripts
cinst -y wixtoolset
