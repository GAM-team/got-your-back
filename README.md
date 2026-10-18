GYB
============================
Got Your Back (GYB) is a command line tool for backing up your Gmail messages to your local computer. It uses Gmail's API over HTTPS.

[![Build Status](https://travis-ci.org/jay0lee/got-your-back.svg?branch=master)](https://travis-ci.org/jay0lee/got-your-back)
# Quick Start
## Linux / MacOS
Open a terminal and run:
```
bash <(curl -s -S -L https://gyb-shortn.jaylee.us/gyb-install)
```
this will download GYB, install it and start setup.
## Windows
Download the MSI Installer from the [GitHub Releases] page. Install the MSI and you'll be prompted to setup GYB.

# Downloads
You can download the current GYB release from the [GitHub Releases] page.

# Documentation
The GYB documentation is hosted in the [GitHub Wiki]

## Gmail API rate limits
GYB limits Gmail requests to 40 quota units per second, or about two message
downloads per second. This leaves headroom below the 6,000 units per minute per
user limit for new Google Cloud projects. Each message download costs 20 units.
The limiter also applies to other Gmail operations, including restores, and
accounts for every request within a batch. Changing `--batch-size` does not
change this quota budget. See [Google's current Gmail API quotas](https://developers.google.com/workspace/gmail/api/reference/quota).

To run the quota regression tests without Google credentials:
```
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

# Mailing List / Discussion group
The GYB mailing list / discussion group is hosted on [Google Groups].  You can join the list and interact via email, or just post from the web itself.

# Author
GYB is maintained by <a href="mailto:jay0lee@gmail.com">Jay Lee</a>. Please direct "how do I?" questions to [Google Groups].

[GitHub Releases]: https://github.com/jay0lee/got-your-back/releases
[GitHub]: https://github.com/jay0lee/got-your-back/tree/master
[GitHub Wiki]: https://github.com/jay0lee/got-your-back/wiki
[Google Groups]: http://groups.google.com/group/got-your-back
