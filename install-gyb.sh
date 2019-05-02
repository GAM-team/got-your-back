#!/usr/bin/env bash

usage()
{
cat << EOF
GYB installation script.

OPTIONS:
   -h      show help.
   -d      Directory where gyb folder will be installed. Default is \$HOME/bin/
   -a      Architecture to install (i686, x86_64, armv7l, aarch64). Default is to detect your arch with "uname -m".
   -o      OS we are running (linux, osx). Default is to detect your OS with "uname -s".
   -l      Just upgrade GYB to latest version. Skips project creation and auth.
   -p      Profile update (true, false). Should script add gyb command to environment. Default is true.
   -u      Admin user email address to use with GYB. Default is to prompt.
   -r      Regular user email address. Used to test service account access to user data. Default is to prompt.
   -v      Version to install (latest, prerelease, draft, 3.8, etc). Default is latest.
EOF
}


target_dir="$HOME/bin"
myarch=$(uname -m)
myos=$(uname -s)
update_profile=true
upgrade_only=false
gybversion="latest"
adminuser=""
regularuser=""
glibc_vers="2.23 2.19 2.15"

while getopts "hd:a:o:lp:u:r:v:" OPTION
do
     case $OPTION in
         h) usage; exit;;
         d) target_dir="$OPTARG";;
         a) myarch="$OPTARG";;
         o) myos="$OPTARG";;
         l) upgrade_only=true;;
         p) update_profile="$OPTARG";;
         u) adminuser="$OPTARG";;
         r) regularuser="$OPTARG";;
         v) gybversion="$OPTARG";;
         ?) usage; exit;;
     esac
done

# remove possible / from end of target_dir
target_dir=${target_dir%/}

update_profile() {
	[ -f "$1" ] || return 1

	grep -F "$alias_line" "$1" > /dev/null 2>&1
	if [ $? -ne 0 ]; then
                echo_yellow "Adding gam alias to profile file $1."
		echo -e "\n$alias_line" >> "$1"
        else
          echo_yellow "gyb alias already exists in profile file $1. Skipping add."
	fi
}

echo_red()
{
echo -e "\x1B[1;31m$1"
echo -e '\x1B[0m'
}

echo_green()
{
echo -e "\x1B[1;32m$1"
echo -e '\x1B[0m'
}

echo_yellow()
{
echo -e "\x1B[1;33m$1"
echo -e '\x1B[0m'
}

version_gt()
{
test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

case $myos in
  [lL]inux)
    myos="linux"
    this_glibc_ver=$(ldd --version | awk '/ldd/{print $NF}')
    echo "This Linux distribution uses glibc $this_glibc_ver"
    useglibc="legacy"
    for glibc_ver in $glibc_vers; do
      if version_gt $this_glibc_ver $glibc_ver; then
        useglibc="glibc$glibc_ver"
        echo_green "Using GYB compiled against $useglibc"
        break
      fi
    done
    case $myarch in
      x86_64) gybfile="linux-x86_64-$useglibc.tar.xz";;
      i?86) gybfile="linux-i686.tar.xz";;
      arm|armv7l) gybfile="linux-armv7l.tar.xz";;
      arm64|aarch64) gybfile="linux-aarch64.tar.xz";;
      *)
        echo_red "ERROR: this installer currently only supports x86_64, i686, armv7l and aarch64. Looks like you're running on $gybarch. You'll need to try the Python source. Exiting."
        exit
    esac
    ;;
  [Mm]ac[Oo][sS]|[Dd]arwin)
    osver=$(sw_vers -productVersion | awk -F'.' '{print $2}')
    if (( $osver < 14 )); then
      echo_red "ERROR: GYB currently requires MacOS 10.14 or newer. You are running MacOS 10.$osver. Please upgrade." 
      exit
    else
      echo_green "Good, you're running MacOS 10.$osver..."
    fi
    myos="osx"
    gybfile="osx-x86_64.tar.xz"
    ;;
  *)
    echo_red "Sorry, this installer currently only supports Linux and MacOS. Looks like you're runnning on $myos. Exiting."
    exit
    ;;
esac

if [ "$gybversion" == "latest" -o "$gybversion" == "prerelease" -o "$gybversion" == "draft" ]; then
  release_url="https://api.github.com/repos/jay0lee/got-your-back/releases"
else
  release_url="https://api.github.com/repos/jay0lee/got-your-back/releases/tags/v$gybversion"
fi

echo_yellow "Checking GitHub URL $release_url for $gamversion GYB release..."
release_json=$(curl -s $release_url 2>&1 /dev/null)

echo_yellow "Getting file and download URL..."
# Python is sadly the nearest to universal way to safely handle JSON with Bash
# At least this code should be compatible with just about any Python version ever
# unlike GYB itself. If some users don't have Python we can try grep / sed / etc
# but that gets really ugly
pycode="import json
import sys

attrib = sys.argv[1]
gybversion = sys.argv[2]

release = json.load(sys.stdin)
if type(release) is list:
  for a_release in release:
    if a_release['prerelease'] and gybversion != 'prerelease':
      continue
    elif a_release['draft'] and gybversion != 'draft':
      continue
    release = a_release
    break
try:
  for asset in release['assets']:
    if asset[attrib].endswith('$gybfile'):
      print(asset[attrib])
      break
  else:
    print('ERROR: Attribute: {0} for $gybfile version {1} not found'.format(attrib, gybversion))
except KeyError:
  print('ERROR: assets value not found in JSON value of:\n\n%s' % release)"

pycmd="python"
$pycmd -V >/dev/null 2>&1
rc=$?
if (( $rc != 0 )); then
  pycmd="python3"
fi
$pycmd -V >/dev/null 2>&1
rc=$?
if (( $rc != 0 )); then
  echo_red "ERROR: No version of python installed."
  exit
fi

browser_download_url=$(echo "$release_json" | $pycmd -c "$pycode" browser_download_url $gybversion)
if [[ ${browser_download_url:0:5} = "ERROR" ]]; then
  echo_red "${browser_download_url}"
  exit
fi
name=$(echo "$release_json" | $pycmd -c "$pycode" name $gybversion)
if [[ ${name:0:5} = "ERROR" ]]; then
  echo_red "${name}"
  exit
fi
# Temp dir for archive
temp_archive_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')
echo_yellow "Downloading file $name from $browser_download_url to $temp_archive_dir."
# Save archive to temp w/o losing our path
(cd $temp_archive_dir && curl -O -L $browser_download_url)

mkdir -p "$target_dir"

echo_yellow "Extracting archive to $target_dir"
tar xf $temp_archive_dir/$name -C "$target_dir"
rc=$?
if (( $rc != 0 )); then
  echo_red "ERROR: extracting the GYB archive with tar failed with error $rc. Exiting."
  exit
else
  echo_green "Finished extracting GYB archive."
fi

if [ "$upgrade_only" = true ]; then
  echo_green "Here's information about your GYB upgrade:"
  "$target_dir/gyb/gyb" --version
  rc=$?
  if (( $rc != 0 )); then
    echo_red "ERROR: Failed running GYB for the first time with $rc. Please report this error to GYB mailing list. Exiting."
    exit
  fi

  echo_green "GYB upgrade complete!"
  exit
fi

# Update profile to add gyb command
if [ "$update_profile" = true ]; then
  alias_line="export PATH=$PATH:$target_dir/gyb"
  if [ "$myos" == "linux" ]; then
    update_profile "$HOME/.bashrc" || update_profile "$HOME/.bash_profile"
  elif [ "$myos" == "osx" ]; then
    update_profile "$HOME/.profile" || update_profile "$HOME/.bash_profile"
  fi
else
  echo_yellow "skipping profile update."
fi

while [ ! -f "$target_dir/gyb/nobrowser.txt" ]; do
  read -p "Can you run a full browser on this machine? (usually Y for MacOS, N for Linux if you SSH into this machine) " yn
  case $yn in
    [Yy]*)
      break
      ;;
    [Nn]*)
      touch "$target_dir/gyb/nobrowser.txt" > /dev/null 2>&1
      break
      ;;
    *)
      echo_red "Please answer yes or no."
      ;;
  esac
done
echo

if [ "$adminuser" == "" ]; then
  read -p "Please enter your email address: " adminuser
fi

project_created=false
while true; do
  "$target_dir/gyb/gyb" --action create-project --email $adminuser
  rc=$?
  if (( $rc == 0 )); then
    echo_green "Project creation complete."
    project_created=true
    break
  else
    echo_red "Project creation failed. Trying again."
  fi
done

admin_authorized=false
while true; do
  read -p "Do you want to authorize GYB to backup email for $adminuser? (yes or no) " yn
  case $yn in
    [Yy]*)
      "$target_dir/gyb/gyb" --action quota --email $adminuser
      rc=$?
      if (( $rc == 0 )); then
        echo_green "User authorization complete."
        admin_authorized=true
        break
      else
        echo_red "User authorization failed. Trying again. Say N to skip user authorization."
      fi
      ;;
     [Nn]*)
       echo -e "\nYou can authorize a user later by running:\n\ngyb --action quota --email $adminuser\n"
       break
       ;;
     *)
       echo_red "Please answer yes or no."
       ;;
  esac
done

service_account_authorized=false
while $project_created; do
  read -p "Are you ready to authorize GYB to backup and restore G Suite user email? (yes or no) " yn
  case $yn in
    [Yy]*)
      if [ "$regularuser" == "" ]; then
        read -p "Please enter the email address of a regular G Suite user: " regularuser
      fi
      echo_yellow "Great! Checking service account scopes.This will fail the first time. Follow the steps to authorize and retry. It can take a few minutes for scopes to PASS after they've been authorized in the admin console."
      "$target_dir/gyb/gyb" --email $regularuser --action check-service-account
      rc=$?
      if (( $rc == 0 )); then
        echo_green "Service account authorization complete."
        service_account_authorized=true
        break
      else
        echo_red "Service account authorization failed. Confirm you entered the scopes correctly in the admin console. It can take a few minutes for scopes to PASS after they are entered in the admin console so if you're sure you entered them correctly, go grab a coffee and then hit Y to try again. Say N to skip admin authorization."
      fi
      ;;
     [Nn]*)
       echo -e "\nYou can authorize a service account later by running:\n\ngyb --email $regularuser --action check-service-account\n"
       break
       ;;
     *)
       echo_red "Please answer yes or no."
       ;;
  esac
done

echo_green "Here's information about your new GYB installation:"
"$target_dir/gyb/gyb" --version
rc=$?
if (( $rc != 0 )); then
  echo_red "ERROR: Failed running GYB for the first time with $rc. Please report this error to GYB mailing list. Exiting."
  exit
fi

echo_green "GYB installation and setup complete!"
if [ "$update_profile" = true ]; then
  echo_green "Please restart your terminal shell or to get started right away run:\n\n$target_dir/gyb/gyb"
fi

# Clean up after ourselves even if we are killed with CTRL-C
trap "rm -rf $temp_archive_dir" EXIT
