#!/usr/bin/env python3
#
# Got Your Back
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""\n%s\n\nGot Your Back (GYB) is a command line tool which allows users to
backup and restore their Gmail.

For more information, see http://git.io/gyb/
"""

global __name__, __author__, __email__, __version__, __license__
__program_name__ = 'Got Your Back: Gmail Backup'
__author__ = 'Jay Lee'
__email__ = 'jay0lee@gmail.com'
__version__ = '0.45'
__license__ = 'Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)'
__website__ = 'http://git.io/gyb'
__db_schema_version__ = '6'
__db_schema_min_version__ = '6'        #Minimum for restore

global extra_args, options, allLabelIds, allLabels, gmail, chunksize
extra_args = {'prettyPrint': False}
allLabelIds = dict()
allLabels = dict()
chunksize = 1024 * 1024 * 30
reserved_labels = ['chat', 'chats', 'migrated', 'todo', 'todos', 'buzz', 'bin', 'allmail', 'drafts']

import argparse
import sys
import os
import os.path
import time
import random
import struct
import platform
import datetime
import sqlite3
import email
import hashlib
import mailbox
import re
from itertools import islice, chain
import base64
import json
import httplib2
import oauth2client.client
import oauth2client.file
from oauth2client.service_account import ServiceAccountCredentials
import oauth2client.tools
import googleapiclient
import googleapiclient.discovery
import googleapiclient.errors

def SetupOptionParser(argv):
  parser = argparse.ArgumentParser(add_help=False)
  #parser.usage = parser.print_help()
  parser.add_argument('--email',
    dest='email',
    help='Full email address of user or group to act against')
  action_choices = ['backup','restore', 'restore-group', 'restore-mbox',
    'count', 'purge', 'purge-labels', 'estimate', 'quota', 'reindex', 'revoke']
  parser.add_argument('--action',
    choices=action_choices,
    dest='action',
    default='backup',
    help='Action to perform. Default is backup.')
  parser.add_argument('--search',
    dest='gmail_search',
    default=None,
    help='Optional: On backup, estimate, count and purge, Gmail search to \
scope operation against')
  parser.add_argument('--local-folder',
    dest='local_folder',
    help='Optional: On backup, restore, estimate, local folder to use. \
Default is GYB-GMail-Backup-<email>',
    default='XXXuse-email-addressXXX')
  parser.add_argument('--label-restored',
    action='append',
    dest='label_restored',
    help='Optional: On restore, all messages will additionally receive \
this label. For example, "--label_restored gyb-restored" will label all \
uploaded messages with a gyb-restored label.')
  parser.add_argument('--strip-labels',
    dest='strip_labels',
    action='store_true',
    default=False,
    help='Optional: On restore and restore-mbox, strip existing labels from \
messages except for those explicitly declared with the --label-restored \
parameter.')
  parser.add_argument('--vault',
    action='store_true',
    default=None,
    dest='vault',
    help='Optional: On restore and restore-mbox, restored messages will not be\
visible in user\'s Gmail but are subject to Vault discovery/retention.')
  parser.add_argument('--service-account',
    action='store_true',
    dest='service_account',
    help='Google Apps Business and Education only. Use OAuth 2.0 Service \
Account to authenticate.')
  parser.add_argument('--use-admin',
    dest='use_admin',
    help='Optional: On restore-group, authenticate as this admin user.')
  parser.add_argument('--spam-trash',
    dest='spamtrash',
    action='store_true',
    help='Optional: Include Spam and Trash folders in backup, estimate and count actions. This is always enabled for purge.')
  parser.add_argument('--batch-size',
    dest='batch_size',
    metavar='{1 - 100}',
    type=int,
    choices=list(range(1,101)),
    default=0, # default of 0 means use per action default
    help='Optional: Sets the number of operations to perform at once.')
  parser.add_argument('--noresume', 
    action='store_true',
    help='Optional: On restores, start from beginning. Default is to resume \
where last restore left off.')
  parser.add_argument('--fast-restore',
    action='store_true',
    dest='fast_restore',
    help='Optional: On restores, use the fast method. WARNING: using this \
method breaks Gmail deduplication and threading.')
  parser.add_argument('--fast-incremental',
    dest='refresh',
    action='store_false',
    default=True,
    help='Optional: On backup, skips refreshing labels for existing message')
  parser.add_argument('--debug',
    action='store_true',
    dest='debug',
    help='Turn on verbose debugging and connection information \
(troubleshooting)')
  parser.add_argument('--version',
    action='store_true',
    dest='version',
    help='print GYB version and quit')
  parser.add_argument('--help',
    action='help',
    help='Display this message.')
  return parser.parse_args(argv)

def getProgPath():
  if os.path.abspath('/') != -1:
    divider = '/'
  else:
    divider = '\\'
  return os.path.dirname(os.path.realpath(sys.argv[0]))+divider

class cmd_flags(object):
  def __init__(self):
    self.short_url = True
    self.noauth_local_webserver = False
    self.logging_level = 'ERROR'
    self.auth_host_name = 'localhost'
    self.auth_host_port = [8080, 9090]

def requestOAuthAccess():
  if options.use_admin:
    auth_as = options.use_admin
  else:
    auth_as = options.email
  CLIENT_SECRETS = getProgPath()+'client_secrets.json'
  MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make GYB run you will need to populate the client_secrets.json file
found at:

   %s

with information from the APIs Console https://console.developers.google.com.

""" % (CLIENT_SECRETS)
  cfgFile = '%s%s.cfg' % (getProgPath(), auth_as)
  storage = oauth2client.file.Storage(cfgFile)
  credentials = storage.get()
  flags = cmd_flags()
  if os.path.isfile(getProgPath()+'nobrowser.txt'):
    flags.noauth_local_webserver = True
  if credentials is None or credentials.invalid:
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(
      disable_ssl_certificate_validation=disable_ssl_certificate_validation)
    possible_scopes = ['https://www.googleapis.com/auth/gmail.modify',
                       # Gmail modify

                       'https://www.googleapis.com/auth/gmail.readonly',
                       # Gmail readonly

                       'https://www.googleapis.com/auth/gmail.insert \
https://www.googleapis.com/auth/gmail.labels',
                       # insert and labels

                       'https://mail.google.com/',
                       # Gmail Full Access

                       '',
                       # No Gmail

                       'https://www.googleapis.com/auth/apps.groups.migration',
                       # Groups Archive Restore

                       'https://www.googleapis.com/auth/drive.appdata']
                       # Drive app config (used for quota)

    selected_scopes = ['*', ' ', ' ', ' ', ' ', ' ', '*']
    menu = '''Select the actions you wish GYB to be able to perform for %s

[%s]  0)  Gmail Backup And Restore - read/write mailbox access
[%s]  1)  Gmail Backup Only - read-only mailbox access
[%s]  2)  Gmail Restore Only - write-only mailbox access and label management
[%s]  3)  Gmail Full Access - read/write mailbox access and message purge
[%s]  4)  No Gmail Access

[%s]  5)  Groups Restore - write to Google Apps Groups Archive
[%s]  6)  Storage Quota - Drive app config scope used for --action quota

      7)  Continue
'''
    os.system(['clear', 'cls'][os.name == 'nt'])
    while True:
      selection = input(menu % tuple([auth_as]+selected_scopes))
      try:
        if int(selection) > -1 and int(selection) <= 6:
          if selected_scopes[int(selection)] == ' ':
            selected_scopes[int(selection)] = '*'
            if int(selection) > -1 and int(selection) <= 4:
              for i in range(0,5):
                if i == int(selection):
                  continue
                selected_scopes[i] = ' '
          else:
            selected_scopes[int(selection)] = ' '
        elif selection == '7':
          at_least_one = False
          for i in range(0, len(selected_scopes)):
            if selected_scopes[i] in ['*',]:
              if i == 4:
                continue
              at_least_one = True
          if at_least_one:
            break
          else:
            os.system(['clear', 'cls'][os.name == 'nt'])
            print("YOU MUST SELECT AT LEAST ONE SCOPE!\n")
            continue
        else:
          os.system(['clear', 'cls'][os.name == 'nt'])
          print('NOT A VALID SELECTION!\n')
          continue
        os.system(['clear', 'cls'][os.name == 'nt'])
      except ValueError:
        os.system(['clear', 'cls'][os.name == 'nt'])
        print('NOT A VALID SELECTION!\n')
        continue
    scopes = ['email',]
    for i in range(0, len(selected_scopes)):
      if selected_scopes[i] == '*':
        scopes.append(possible_scopes[i])
    FLOW = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS,
      scope=scopes, message=MISSING_CLIENT_SECRETS_MESSAGE, login_hint=auth_as)
    credentials = oauth2client.tools.run_flow(flow=FLOW, storage=storage,
      flags=flags, http=http)
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(
      disable_ssl_certificate_validation=disable_ssl_certificate_validation)

def doGYBCheckForUpdates():
  import urllib.request, urllib.error, urllib.parse, calendar
  no_update_check_file = getProgPath()+'noupdatecheck.txt'
  last_update_check_file = getProgPath()+'lastcheck.txt'
  if os.path.isfile(no_update_check_file): return
  try:
    current_version = float(__version__)
  except ValueError:
    return
  if os.path.isfile(last_update_check_file):
    f = open(last_update_check_file, 'r')
    last_check_time = int(f.readline())
    f.close()
  else:
    last_check_time = 0
  now_time = calendar.timegm(time.gmtime())
  one_week_ago_time = now_time - 604800
  if last_check_time > one_week_ago_time: return
  try:
    checkUrl = 'https://gyb-update.appspot.com/latest-version.txt?v=%s'
    c = urllib.request.urlopen(checkUrl % (__version__,))
    try:
      latest_version = float(c.read())
    except ValueError:
      return
    if latest_version <= current_version:
      f = open(last_update_check_file, 'w')
      f.write(str(now_time))
      f.close()
      return
    announceUrl = 'https://gyb-update.appspot.com/\
latest-version-announcement.txt?v=%s'
    a = urllib.request.urlopen(announceUrl % (__version__,))
    announcement = a.read()
    sys.stderr.write('\nThere\'s a new version of GYB!!!\n\n')
    sys.stderr.write(announcement)
    visit_gyb = input("\n\nHit Y to visit the GYB website and download \
the latest release. Hit Enter to just continue with this boring old version.\
 GYB won't bother you with this announcement for 1 week or you can create a \
file named %s and GYB won't ever check for updates: " % no_update_check_file)
    if visit_gyb.lower() == 'y':
      import webbrowser
      webbrowser.open(__website__)
      print('GYB is now exiting so that you can overwrite this old version \
with the latest release')
      sys.exit(0)
    f = open(last_update_check_file, 'w')
    f.write(str(now_time))
    f.close()
  except urllib.error.HTTPError:
    return
  except urllib.error.URLError:
    return

def getAPIVer(api):
  if api == 'oauth2':
    return 'v2'
  elif api == 'gmail':
    return 'v1'
  elif api == 'groupsmigration':
    return 'v1'
  elif api == 'drive':
    return 'v2'
  return 'v1'

def getAPIScope(api):
  if api == 'gmail':
    return ['https://mail.google.com/']
  elif api == 'groupsmigration':
    return ['https://www.googleapis.com/auth/apps.groups.migration']
  elif api == 'drive':
    return ['https://www.googleapis.com/auth/drive.appdata']

def buildGAPIObject(api):
  if options.use_admin:
    auth_as = options.use_admin
  else:
    auth_as = options.email
  oauth2file = '%s%s.cfg' % (getProgPath(), auth_as)
  storage = oauth2client.file.Storage(oauth2file)
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    doRequestOAuth()
    credentials = storage.get()
  credentials.user_agent = getGYBVersion(' | ') 
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(
    disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if options.debug:
    httplib2.debuglevel = 4
    extra_args['prettyPrint'] = True
  if os.path.isfile(getProgPath()+'extra-args.txt'):
    import configparser
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(getProgPath()+'extra-args.txt')
    extra_args.update(dict(config.items('extra-args')))
  http = credentials.authorize(http)
  version = getAPIVer(api)
  try:
    return googleapiclient.discovery.build(api, version, http=http, cache_discovery=False)
  except googleapiclient.errors.UnknownApiNameOrVersion:
    disc_file = getProgPath()+'%s-%s.json' % (api, version)
    if os.path.isfile(disc_file):
      f = file(disc_file, 'r')
      discovery = f.read()
      f.close()
      return googleapiclient.discovery.build_from_document(discovery,
        base='https://www.googleapis.com', http=http)
    else:
      print('No online discovery doc and %s does not exist locally'
        % disc_file)
      raise

def buildGAPIServiceObject(api, soft_errors=False):
  global extra_args
  if options.use_admin:
    auth_as = options.use_admin
  else:
    auth_as = options.email
  oauth2servicefilejson = getProgPath()+'oauth2service.json'
  scopes = getAPIScope(api)
  credentials = ServiceAccountCredentials.from_json_keyfile_name(
    oauth2servicefilejson, scopes)
  credentials = credentials.create_delegated(auth_as)
  credentials.user_agent = getGYBVersion(' | ')
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(
    disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if options.debug:
    httplib2.debuglevel = 4
    extra_args['prettyPrint'] = True
  if os.path.isfile(getProgPath()+'extra-args.txt'):
    import configparser
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(getGamPath()+'extra-args.txt')
    extra_args.update(dict(config.items('extra-args')))
  http = credentials.authorize(http)
  version = getAPIVer(api)
  try:
    return googleapiclient.discovery.build(api, version, http=http, cache_discovery=False)
  except oauth2client.client.AccessTokenRefreshError as e:
    if e.message in ['access_denied', 'unauthorized_client: Unauthorized \
client or scope in request.']:
      print('Error: Access Denied. Please make sure the Client Name:\
\n\n%s\n\nis authorized for the API Scope(s):\n\n%s\n\nThis can be \
configured in your Control Panel under:\n\nSecurity -->\nAdvanced \
Settings -->\nManage third party OAuth Client access'
% (SERVICE_ACCOUNT_CLIENT_ID, ','.join(scope)))
      sys.exit(5)
    else:
      print('Error: %s' % e)
      if soft_errors:
        return False
      sys.exit(4)

def callGAPI(service, function, soft_errors=False, throw_reasons=[], **kwargs):
  retries = 10
  parameters = kwargs.copy()
  parameters.update(extra_args)
  for n in range(1, retries+1):
    if function:
      method = getattr(service, function)(**parameters)
    else:
      method = service
    try:
      return method.execute()
    except googleapiclient.errors.HttpError as e:
      try:
        error = json.loads(e.content.decode('utf-8'))
        reason = error['error']['errors'][0]['reason']
        http_status = error['error']['code']
        message = error['error']['errors'][0]['message']
      except (KeyError, json.decoder.JSONDecodeError):
        http_status = int(e.resp['status'])
        reason = e.content
        message = e.content
      if reason in throw_reasons:
        raise
      if n != retries and (http_status >= 500 or
       reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'backendError']):
        wait_on_fail = (2 ** n) if (2 ** n) < 60 else 60
        randomness = float(random.randint(1,1000)) / 1000
        wait_on_fail += randomness
        if n > 3:
          sys.stderr.write('\nTemp error %s. Backing off %s seconds...'
            % (reason, int(wait_on_fail)))
        time.sleep(wait_on_fail)
        if n > 3:
          sys.stderr.write('attempt %s/%s\n' % (n+1, retries))
        continue
      sys.stderr.write('\n%s: %s - %s\n' % (http_status, message, reason))
      if soft_errors:
        sys.stderr.write(' - Giving up.\n')
        return
      else:
        sys.exit(int(http_status))
    except oauth2client.client.AccessTokenRefreshError as e:
      sys.stderr.write('Error: Authentication Token Error - %s' % e)
      sys.exit(403)

def callGAPIpages(service, function, items='items',
 nextPageToken='nextPageToken', page_message=None, message_attribute=None,
 **kwargs):
  pageToken = None
  all_pages = list()
  total_items = 0
  while True:
    this_page = callGAPI(service=service, function=function,
      pageToken=pageToken, **kwargs)
    if not this_page:
      this_page = {items: []}
    try:
      page_items = len(this_page[items])
    except KeyError:
      page_items = 0
    total_items += page_items
    if page_message:
      show_message = page_message
      try:
        show_message = show_message.replace('%%num_items%%', str(page_items))
      except (IndexError, KeyError):
        show_message = show_message.replace('%%num_items%%', '0')
      try:
        show_message = show_message.replace('%%total_items%%',
          str(total_items))
      except (IndexError, KeyError):
        show_message = show_message.replace('%%total_items%%', '0')
      if message_attribute:
        try:
          show_message = show_message.replace('%%first_item%%',
            str(this_page[items][0][message_attribute]))
          show_message = show_message.replace('%%last_item%%',
            str(this_page[items][-1][message_attribute]))
        except (IndexError, KeyError):
          show_message = show_message.replace('%%first_item%%', '')
          show_message = show_message.replace('%%last_item%%', '')
      rewrite_line(show_message)
    try:
      all_pages += this_page[items]
      pageToken = this_page[nextPageToken]
      if pageToken == '':
        return all_pages
    except (IndexError, KeyError):
      if page_message:
        sys.stderr.write('\n')
      return all_pages

def message_is_backed_up(message_num, sqlcur, sqlconn, backup_folder):
    try:
      sqlcur.execute('''
         SELECT message_filename FROM uids NATURAL JOIN messages
                where uid = ?''', ((message_num),))
    except sqlite3.OperationalError as e:
      if e.message == 'no such table: messages':
        print("\n\nError: your backup database file appears to be corrupted.")
      else:
        print("SQL error:%s" % e)
      sys.exit(8)
    sqlresults = sqlcur.fetchall()
    for x in sqlresults:
      filename = x[0]
      if os.path.isfile(os.path.join(backup_folder, filename)):
        return True
    return False

def get_db_settings(sqlcur):
  try:
    sqlcur.execute('SELECT name, value FROM settings')
    db_settings = dict(sqlcur) 
    return db_settings
  except sqlite3.OperationalError as e:
    if e.message == 'no such table: settings':
      print("\n\nSorry, this version of GYB requires version %s of the \
database schema. Your backup folder database does not have a version."
 % (__db_schema_version__))
      sys.exit(6)
    else: 
      print("%s" % e)

def check_db_settings(db_settings, action, user_email_address):
  if (db_settings['db_version'] < __db_schema_min_version__  or
      db_settings['db_version'] > __db_schema_version__):
    print("\n\nSorry, this backup folder was created with version %s of the \
database schema while GYB %s requires version %s - %s for restores"
% (db_settings['db_version'], __version__, __db_schema_min_version__,
__db_schema_version__))
    sys.exit(4)

  # Only restores are allowed to use a backup folder started with another
  # account (can't allow 2 Google Accounts to backup/estimate from same folder)
  if action not in ['restore', 'restore-group', 'restore-mbox']:
    if user_email_address.lower() != db_settings['email_address'].lower():
      print("\n\nSorry, this backup folder should only be used with the %s \
account that it was created with for incremental backups. You specified the\
 %s account" % (db_settings['email_address'], user_email_address))
      sys.exit(5)

def convertDB(sqlconn, uidvalidity, oldversion):
  print("Converting database")
  try:
    with sqlconn:
      if oldversion < '3':
        # Convert to schema 3
        sqlconn.executescript('''
          BEGIN;
          CREATE TABLE uids 
              (message_num INTEGER, uid INTEGER PRIMARY KEY); 
          INSERT INTO uids (uid, message_num) 
               SELECT message_num as uid, message_num FROM messages;
          CREATE INDEX labelidx ON labels (message_num);
          CREATE INDEX flagidx ON flags (message_num);
        ''')
      if oldversion < '4':
        # Convert to schema 4
        sqlconn.execute('''
          ALTER TABLE messages ADD COLUMN rfc822_msgid TEXT;
        ''')
      if oldversion < '5':
        # Convert to schema 5
        sqlconn.executescript('''
          DROP INDEX labelidx;
          DROP INDEX flagidx;
          CREATE UNIQUE INDEX labelidx ON labels (message_num, label);
          CREATE UNIQUE INDEX flagidx ON flags (message_num, flag);
        ''')
      if oldversion < '6':
        # Convert to schema 6
        getMessageIDs(sqlconn, options.local_folder)
        rebuildUIDTable(sqlconn)
      sqlconn.executemany('REPLACE INTO settings (name, value) VALUES (?,?)',
                        (('uidvalidity',uidvalidity), 
                         ('db_version', __db_schema_version__)) )   
      sqlconn.commit()
  except sqlite3.OperationalError as e:
      print("Conversion error: %s" % e.message)

  print("GYB database converted to version %s" % __db_schema_version__)

def getMessageIDs (sqlconn, backup_folder):   
  sqlcur = sqlconn.cursor()
  header_parser = email.parser.HeaderParser()
  for message_num, filename in sqlconn.execute('''
               SELECT message_num, message_filename FROM messages 
                      WHERE rfc822_msgid IS NULL'''):
    message_full_filename = os.path.join(backup_folder, filename)
    if os.path.isfile(message_full_filename):
      f = open(message_full_filename, 'r')
      msgid = header_parser.parse(f, True).get('message-id') or '<DummyMsgID>'
      f.close()
      sqlcur.execute(
          'UPDATE messages SET rfc822_msgid = ? WHERE message_num = ?',
                     (msgid, message_num))
  sqlconn.commit()
 
def rebuildUIDTable(sqlconn):
  pass

suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
def humansize(file_path):
  nbytes = os.stat(file_path).st_size
  if nbytes == 0: return '0 B'
  i = 0
  while nbytes >= 1024 and i < len(suffixes)-1:
    nbytes /= 1024.
    i += 1
  f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
  return '%s%s' % (f, suffixes[i])

def doesTokenMatchEmail():
  if options.use_admin:
    auth_as = options.use_admin
  else:
    auth_as = options.email
  oa2 = buildGAPIObject('oauth2')
  user_info = callGAPI(service=oa2.userinfo(), function='get',
    fields='email')
  if user_info['email'].lower() == auth_as.lower():
    return True
  print("Error: you did not authorize the OAuth token in the browser with the \
%s Google Account. Please make sure you are logged in to the correct account \
when authorizing the token in the browser." % auth_as)
  cfgFile = '%s%s.cfg' % (getProgPath(), auth_as)
  os.remove(cfgFile)
  return False

def rewrite_line(mystring):
  print(' ' * 80, end='\r')
  print(mystring, end='\r')

def initializeDB(sqlcur, sqlconn, email):
  sqlcur.executescript('''
   CREATE TABLE messages(message_num INTEGER PRIMARY KEY, 
                         message_filename TEXT, 
                         message_internaldate TIMESTAMP);
   CREATE TABLE labels (message_num INTEGER, label TEXT);
   CREATE TABLE uids (message_num INTEGER, uid TEXT PRIMARY KEY);
   CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT);
   CREATE UNIQUE INDEX labelidx ON labels (message_num, label);
  ''')
  sqlcur.executemany('INSERT INTO settings (name, value) VALUES (?, ?)', 
         (('email_address', email),
          ('db_version', __db_schema_version__)))
  sqlconn.commit()

def getGYBVersion(divider="\n"):
  return ('Got Your Back %s~DIV~%s~DIV~%s - %s~DIV~Python %s.%s.%s %s-bit \
%s~DIV~%s %s' % (__version__, __website__, __author__, __email__,
sys.version_info[0], sys.version_info[1], sys.version_info[2],
struct.calcsize('P')*8, sys.version_info[3], platform.platform(),
platform.machine())).replace('~DIV~', divider)

def labelIdsToLabels(labelIds):
  global allLabelIds, gmail
  labels = list()
  for labelId in labelIds:
    if labelId not in allLabelIds:
      # refresh allLabelIds from Google
      label_results = callGAPI(service=gmail.users().labels(), function='list',
        userId='me', fields='labels(name,id,type)')
      allLabelIds = dict()
      for a_label in label_results['labels']:
        if a_label['type'] == 'system':
          allLabelIds[a_label['id']] = a_label['id']
        else:
          allLabelIds[a_label['id']] = a_label['name']
    try:
      labels.append(allLabelIds[labelId])
    except KeyError:
      pass
  return labels

def labelsToLabelIds(labels):
  global allLabels
  if len(allLabels) < 1: # first fetch of all labels from Google
    label_results = callGAPI(service=gmail.users().labels(), function='list',
      userId='me', fields='labels(name,id,type)')
    allLabels = dict()
    for a_label in label_results['labels']:
      if a_label['type'] == 'system':
        allLabels[a_label['id']] = a_label['id']
      else:
        allLabels[a_label['name']] = a_label['id']
  labelIds = list()
  for label in labels:
    base_label = label.split('/')[0].lower()
    if base_label in reserved_labels:
      label = '_%s' % (label)
    if label not in allLabels:
      # create new label (or get it's id if it exists)
      label_results = callGAPI(service=gmail.users().labels(), function='create',
        body={'labelListVisibility': 'labelShow',
          'messageListVisibility': 'show', 'name': label},
        userId='me', fields='id')
      allLabels[label] = label_results['id']
    try:
      labelIds.append(allLabels[label])
    except KeyError:
      pass
    if label.find('/') != -1:
      # make sure to create parent labels for proper nesting
      parent_label = label[:label.rfind('/')]
      while True:
        if not parent_label in allLabels:
          label_result = callGAPI(service=gmail.users().labels(),
            function='create', userId='me', body={'name': parent_label})
          allLabels[parent_label] = label_result['id']
        if parent_label.find('/') == -1:
          break
        parent_label = parent_label[:parent_label.rfind('/')]
  return labelIds

def refresh_message(request_id, response, exception):
  if exception is not None:
    raise exception
  else:
    if 'labelIds' in response:
      labels = labelIdsToLabels(response['labelIds'])
      sqlcur.execute('DELETE FROM current_labels')
      sqlcur.executemany(
           'INSERT INTO current_labels (label) VALUES (?)',
              ((label,) for label in labels))
      sqlcur.execute("""DELETE FROM labels where message_num = 
                   (SELECT message_num from uids where uid = ?)
                    AND label NOT IN current_labels""", ((response['id']),))
      sqlcur.execute("""INSERT INTO labels (message_num, label) 
            SELECT message_num, label from uids, current_labels 
               WHERE uid = ? AND label NOT IN 
               (SELECT label FROM labels 
                  WHERE message_num = uids.message_num)""",
                  ((response['id']),))

def restored_message(request_id, response, exception):
  if exception is not None:
    try:
      error = json.loads(exception.content.decode('utf-8'))
      if error['error']['code'] == 400:
        print("\nERROR: %s: %s. Skipping message restore, you can retry later with --fast-restore"
          % (error['error']['code'], error['error']['errors'][0]['message']))
        return
    except:
      pass
    raise exception
  else:
    sqlconn.execute(
      '''INSERT OR IGNORE INTO restored_messages (message_num) VALUES (?)''',
      (request_id,))

def purged_message(request_id, response, exception):
  if exception is not None:
    raise exception

def estimate_message(request_id, response, exception):
  global message_size_estimate
  if exception is not None:
    raise exception
  else:
    this_message_size = int(response['sizeEstimate'])
    message_size_estimate += this_message_size

def backup_message(request_id, response, exception):
  if exception is not None:
    print(exception)
  else:
    if 'labelIds' in response:
      labelIds = response['labelIds']
    else:
      labelIds = list()
    labels = labelIdsToLabels(labelIds)
    message_file_name = "%s.eml" % (response['id'])
    message_time = int(response['internalDate'])/1000
    message_date = time.gmtime(message_time)
    time_for_sqlite = datetime.datetime.fromtimestamp(message_time)
    message_rel_path = os.path.join(str(message_date.tm_year),
                                    str(message_date.tm_mon),
                                    str(message_date.tm_mday))
    message_rel_filename = os.path.join(message_rel_path,
                                        message_file_name)
    message_full_path = os.path.join(options.local_folder,
                                     message_rel_path)
    message_full_filename = os.path.join(options.local_folder,
                                     message_rel_filename)
    if not os.path.isdir(message_full_path):
      os.makedirs(message_full_path)
    f = open(message_full_filename, 'wb')
    raw_message = str(response['raw'])
    full_message = base64.urlsafe_b64decode(raw_message)
    f.write(full_message)
    f.close()
    sqlcur.execute("""
             INSERT INTO messages (
                         message_filename, 
                         message_internaldate) VALUES (?, ?)""",
                        (message_rel_filename,
                         time_for_sqlite))
    message_num = sqlcur.lastrowid
    sqlcur.execute("""
             REPLACE INTO uids (message_num, uid) VALUES (?, ?)""",
                               (message_num, response['id']))
    for label in labels:
      sqlcur.execute("""
           INSERT INTO labels (message_num, label) VALUES (?, ?)""",
                              (message_num, label))

def bytes_to_larger(myval):
  myval = int(myval)
  mysize = 'b'
  if myval > 1024:
    myval = myval / 1024
    mysize = 'kb'
  if myval > 1024:
    myval = myval / 1024
    mysize = 'mb'
  if myval > 1024:
    myval = myval / 1024
    mysize = 'gb'
  if myval > 1024:
    myval = myval / 1024
    mysize = 'tb'
  return '%.2f%s' % (myval, mysize)

def main(argv):
  global options, gmail
  options = SetupOptionParser(argv)
  if options.version:
    print(getGYBVersion())
    sys.exit(0)
  if not options.email:
    print('ERROR: --email is required.')
    sys.exit(1)
  if options.local_folder == 'XXXuse-email-addressXXX':
    options.local_folder = "GYB-GMail-Backup-%s" % options.email
  if not options.service_account:  # 3-Legged OAuth
    requestOAuthAccess()
    if not doesTokenMatchEmail():
      sys.exit(9)
    gmail = buildGAPIObject('gmail')
  else:
    gmail = buildGAPIServiceObject('gmail')
  if not os.path.isdir(options.local_folder):
    if options.action in ['backup',]:
      os.mkdir(options.local_folder)
    elif options.action in ['restore', 'restore-group']:
      print('Error: Folder %s does not exist. Cannot restore.'
        % options.local_folder)
      sys.exit(3)

  sqldbfile = os.path.join(options.local_folder, 'msg-db.sqlite')
  # Do we need to initialize a new database?
  newDB = (not os.path.isfile(sqldbfile)) and \
    (options.action in ['backup', 'restore-mbox'])
  
  # If we're not doing a estimate or if the db file actually exists we open it
  # (creates db if it doesn't exist)
  if options.action not in ['count', 'purge', 'purge-labels',
    'quota', 'revoke']:
    if options.action not in ['estimate'] or os.path.isfile(sqldbfile):
      print("\nUsing backup folder %s" % options.local_folder)
      global sqlconn
      global sqlcur
      sqlconn = sqlite3.connect(sqldbfile,
        detect_types=sqlite3.PARSE_DECLTYPES)
      sqlconn.text_factory = str
      sqlcur = sqlconn.cursor()
      if newDB:
        initializeDB(sqlcur, sqlconn, options.email)
      db_settings = get_db_settings(sqlcur)
      check_db_settings(db_settings, options.action, options.email)
      if options.action not in ['restore', 'restore-group', 'restore-mbox']:
        if db_settings['db_version'] <  __db_schema_version__:
          convertDB(sqlconn, db_settings['db_version'])
          db_settings = get_db_settings(sqlcur)
        if options.action == 'reindex':
          getMessageIDs(sqlconn, options.local_folder)
          rebuildUIDTable(sqlconn)
          sqlconn.commit()
          sys.exit(0)

  # BACKUP #
  if options.action == 'backup':
    if options.batch_size == 0:
      options.batch_size = 100
    page_message = 'Got %%total_items%% Message IDs'
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', page_message=page_message,
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    backup_path = options.local_folder
    if not os.path.isdir(backup_path):
      os.mkdir(backup_path)
    messages_to_backup = []
    messages_to_refresh = []
    #Determine which messages from the search we haven't processed before.
    print("GYB needs to examine %s messages" % len(messages_to_process))
    for message_num in messages_to_process:
      if not newDB and message_is_backed_up(message_num['id'], sqlcur, sqlconn,
        options.local_folder):
        messages_to_refresh.append(message_num['id'])
      else:
        messages_to_backup.append(message_num['id'])
    print("GYB already has a backup of %s messages" %
      (len(messages_to_process) - len(messages_to_backup)))
    backup_count = len(messages_to_backup)
    print("GYB needs to backup %s messages" % backup_count)
    backed_up_messages = 0
    gbatch = googleapiclient.http.BatchHttpRequest()
    for a_message in messages_to_backup:
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='raw',
        fields='id,labelIds,internalDate,raw'),
        callback=backup_message)
      backed_up_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        sqlconn.commit()
        rewrite_line("backed up %s of %s messages" %
          (backed_up_messages, backup_count))
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None)
      sqlconn.commit()
      rewrite_line("backed up %s of %s messages" %
        (backed_up_messages, backup_count))
    print("\n")
 
    if not options.refresh:
      messages_to_refresh = []
    refreshed_messages = 0
    refresh_count = len(messages_to_refresh)
    print("GYB needs to refresh %s messages" % refresh_count)
    sqlcur.executescript("""
       CREATE TEMP TABLE current_labels (label TEXT);
    """)
    gbatch = googleapiclient.http.BatchHttpRequest()
    for a_message in messages_to_refresh:
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='minimal',
        fields='id,labelIds'),
        callback=refresh_message)
      refreshed_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        sqlconn.commit()
        rewrite_line("refreshed %s of %s messages" %
          (refreshed_messages, refresh_count))
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None)
      sqlconn.commit()
      rewrite_line("refreshed %s of %s messages" %
        (refreshed_messages, refresh_count))
    print("\n")

  # RESTORE #
  elif options.action == 'restore':
    if options.batch_size == 0:
      options.batch_size = 10
    resumedb = os.path.join(options.local_folder, 
                            "%s-restored.sqlite" % options.email)
    if options.noresume:
      try:
        os.remove(resumedb)
      except OSError:
        pass
      except IOError:
        pass
    sqlcur.execute('ATTACH ? as resume', (resumedb,))
    sqlcur.executescript('''CREATE TABLE IF NOT EXISTS resume.restored_messages 
                        (message_num INTEGER PRIMARY KEY); 
                        CREATE TEMP TABLE skip_messages (message_num INTEGER \
                          PRIMARY KEY);''')
    sqlcur.execute('''INSERT INTO skip_messages SELECT message_num from \
      restored_messages''')
    sqlcur.execute('''SELECT message_num, message_internaldate, \
      message_filename FROM messages
                      WHERE message_num NOT IN skip_messages ORDER BY \
                      message_internaldate DESC''') # All messages

    restore_serv = gmail.users().messages()
    if options.fast_restore:
      restore_func = 'insert'
      restore_params = {'internalDateSource': 'dateHeader'}
    else:
      restore_func = 'import_'
      restore_params = {'neverMarkSpam': True}
    restore_method = getattr(restore_serv, restore_func)
    messages_to_restore_results = sqlcur.fetchall()
    restore_count = len(messages_to_restore_results)
    current = 0
    gbatch = googleapiclient.http.BatchHttpRequest()
    max_batch_bytes = 8 * 1024 * 1024
    current_batch_bytes = 5000 # accounts for metadata
    largest_in_batch = 0
    for x in messages_to_restore_results:
      current += 1
      message_filename = x[2]
      message_num = x[0]
      if not os.path.isfile(os.path.join(options.local_folder,
        message_filename)):
        print('WARNING! file %s does not exist for message %s'
          % (os.path.join(options.local_folder, message_filename),
            message_num))
        print('  this message will be skipped.')
        continue
      f = open(os.path.join(options.local_folder, message_filename), 'rb')
      full_message = f.read()
      f.close()
      labels = []
      if not options.strip_labels:
        sqlcur.execute('SELECT DISTINCT label FROM labels WHERE message_num \
          = ?', (message_num,))
        labels_results = sqlcur.fetchall()
        for l in labels_results:
          labels.append(l[0])
      if options.label_restored:
        for restore_label in options.label_restored:
          labels.append(restore_label)
      labelIds = labelsToLabelIds(labels)
      body = {'labelIds': labelIds}
      b64_message_size = (len(full_message)/3) * 4
      if b64_message_size > 1 * 1024 * 1024 or options.batch_size == 1:
        # don't batch/raw >1mb messages, just do single
        rewrite_line('restoring single large message (%s/%s)' %
          (current, restore_count))
        # Note resumable=True is important here, it prevents errors on (bad)
        # messages that should be ASCII but contain extended chars.
        # What's that? No, no idea why
        media_body = googleapiclient.http.MediaInMemoryUpload(full_message,
          mimetype='message/rfc822', resumable=True, chunksize=chunksize)
        try:
          response = callGAPI(service=restore_serv, function=restore_func,
            userId='me', throw_reasons=['invalidArgument',], media_body=media_body, body=body,
            deleted=options.vault, **restore_params)
          exception = None
        except googleapiclient.errors.HttpError as e:
          response = None
          exception = e
        restored_message(request_id=str(message_num), response=response,
          exception=exception)
        rewrite_line('restored single large message (%s/%s)' % (current,
          restore_count))
        continue
      if b64_message_size > largest_in_batch:
        largest_in_batch = b64_message_size
      raw_message = base64.urlsafe_b64encode(full_message).decode('utf-8')
      body['raw'] = raw_message
      current_batch_bytes += len(raw_message)
      for labelId in labelIds:
        current_batch_bytes += len(labelId)
      if len(gbatch._order) > 0 and current_batch_bytes > max_batch_bytes:
        # this message would put us over max, execute current batch first
        rewrite_line("restoring %s messages (%s/%s)" % (len(gbatch._order),
          current, restore_count))
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        sqlconn.commit()
        current_batch_bytes = 5000
        largest_in_batch = 0
      gbatch.add(restore_method(userId='me',
        body=body, fields='id', deleted=options.vault,
        **restore_params), callback=restored_message,
          request_id=str(message_num))
      if len(gbatch._order) == options.batch_size:
        rewrite_line("restoring %s messages (%s/%s)" % (len(gbatch._order),
          current, restore_count))
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        sqlconn.commit()
        current_batch_bytes = 5000
        largest_in_batch = 0
    if len(gbatch._order) > 0:
      rewrite_line("restoring %s messages (%s/%s)" % (len(gbatch._order),
        current, restore_count))
      callGAPI(gbatch, None)
      sqlconn.commit()
    print("\n")
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

 # RESTORE-MBOX #
  elif options.action == 'restore-mbox':
    if options.batch_size == 0:
      options.batch_size = 10
    resumedb = os.path.join(options.local_folder,
                            "%s-restored.sqlite" % options.email)
    if options.noresume:
      try:
        os.remove(resumedb)
      except OSError:
        pass
      except IOError:
        pass
    sqlcur.execute('ATTACH ? as mbox_resume', (resumedb,))
    sqlcur.executescript('''CREATE TABLE
                        IF NOT EXISTS mbox_resume.restored_messages
                        (message_num TEXT PRIMARY KEY)''')
    sqlcur.execute('SELECT message_num FROM mbox_resume.restored_messages')
    messages_to_skip_results = sqlcur.fetchall()
    messages_to_skip = []
    for a_message in messages_to_skip_results:
      messages_to_skip.append(a_message[0])
    if os.name == 'windows' or os.name == 'nt':
      divider = '\\'
    else:
      divider = '/'
    current_batch_bytes = 5000
    gbatch = googleapiclient.http.BatchHttpRequest()
    restore_serv = gmail.users().messages()
    if options.fast_restore:
      restore_func = 'insert'
      restore_params = {'internalDateSource': 'dateHeader'}
    else:
      restore_func = 'import_'
      restore_params = {'neverMarkSpam': True}
    restore_method = getattr(restore_serv, restore_func)
    max_batch_bytes = 8 * 1024 * 1024
    for path, subdirs, files in os.walk(options.local_folder):
      for filename in files:
        if filename[-4:].lower() != '.mbx' and \
          filename[-5:].lower() != '.mbox':
          continue
        file_path = '%s%s%s' % (path, divider, filename)
        print("\nRestoring from %s file %s..." % (humansize(file_path), file_path))
        print("large files may take some time to open.")
        mbox = mailbox.mbox(file_path)
        restore_count = len(list(mbox.items()))
        current = 0
        for message in mbox:
          current += 1
          message_marker = '%s-%s' % (file_path, current)
          # shorten request_id to prevent content-id errors
          request_id = hashlib.md5(message_marker.encode('utf-8')).hexdigest()[:25]
          if request_id in messages_to_skip:
            continue
          labels = message['X-Gmail-Labels']
          if labels != None and labels != '' and not options.strip_labels:
            mybytes, encoding = email.header.decode_header(labels)[0]
            if encoding != None:
              try:
                labels = mybytes.decode(encoding)
              except UnicodeDecodeError:
                pass
            else:
              labels = labels.decode('string-escape')
            labels = labels.split(',')
          else:
            labels = []
          if options.label_restored:
            for restore_label in options.label_restored:
              labels.append(restore_label)
          labelIds = labelsToLabelIds(labels)
          del message['X-Gmail-Labels']
          del message['X-GM-THRID']
          rewrite_line(" message %s of %s" % (current, restore_count))
          full_message = message.as_bytes()
          body = {'labelIds': labelIds}
          b64_message_size = (len(full_message)/3) * 4
          if b64_message_size > 1 * 1024 * 1024:
            # don't batch/raw >1mb messages, just do single
            rewrite_line(' restoring single large message (%s/%s)' %
              (current, restore_count))
            media_body = googleapiclient.http.MediaInMemoryUpload(full_message,
              mimetype='message/rfc822', resumable=True, chunksize=chunksize)
            try:
              response = callGAPI(service=restore_serv, function=restore_func,
                userId='me', throw_reasons=['invalidArgument',], media_body=media_body, body=body,
                deleted=options.vault, **restore_params)
              exception = None
            except googleapiclient.errors.HttpError as e:
              response = None
              exception = e
            restored_message(request_id=request_id, response=response,
              exception=None)
            rewrite_line(' restored single large message (%s/%s)' %
              (current, restore_count))
            continue
          raw_message = base64.urlsafe_b64encode(full_message).decode('utf-8')
          body['raw'] = raw_message
          current_batch_bytes += len(raw_message)
          for labelId in labelIds:
            current_batch_bytes += len(labelId)
          if len(gbatch._order) > 0 and current_batch_bytes > max_batch_bytes:
            # this message would put us over max, execute current batch first
            rewrite_line("restoring %s messages (%s/%s)" %
              (len(gbatch._order), current, restore_count))
            callGAPI(gbatch, None)
            gbatch = googleapiclient.http.BatchHttpRequest()
            sqlconn.commit()
            current_batch_bytes = 5000
            largest_in_batch = 0
          gbatch.add(restore_method(userId='me',
            body=body, fields='id',
            deleted=options.vault, **restore_params),
            callback=restored_message,
            request_id=request_id)
          if len(gbatch._order) == options.batch_size:
            rewrite_line("restoring %s messages (%s/%s)" %
              (len(gbatch._order), current, restore_count))
            callGAPI(gbatch, None)
            gbatch = googleapiclient.http.BatchHttpRequest()
            sqlconn.commit()
            current_batch_bytes = 5000
            largest_in_batch = 0
        if len(gbatch._order) > 0:
          rewrite_line("restoring %s messages (%s/%s)" %
            (len(gbatch._order), current, restore_count))
          callGAPI(gbatch, None)
          sqlconn.commit()
    sqlconn.execute('DETACH mbox_resume')
    sqlconn.commit()

  # RESTORE-GROUP #
  elif options.action == 'restore-group':
    if not options.service_account:  # 3-Legged OAuth
      gmig = buildGAPIObject('groupsmigration')
    else:
      gmig = buildGAPIServiceObject('groupsmigration')
    resumedb = os.path.join(options.local_folder,
                            "%s-restored.sqlite" % options.email)
    if options.noresume:
      try:
        os.remove(resumedb)
      except OSError:
        pass
      except IOError:
        pass
    sqlcur.execute('ATTACH ? as resume', (resumedb,))
    sqlcur.executescript('''CREATE TABLE IF NOT EXISTS resume.restored_messages
                      (message_num INTEGER PRIMARY KEY);
       CREATE TEMP TABLE skip_messages (message_num INTEGER PRIMARY KEY);''')
    sqlcur.execute('''INSERT INTO skip_messages SELECT message_num
      FROM restored_messages''')
    sqlcur.execute('''SELECT message_num, message_internaldate,
      message_filename FROM messages
          WHERE message_num NOT IN skip_messages
            ORDER BY message_internaldate DESC''')
    messages_to_restore_results = sqlcur.fetchall()
    restore_count = len(messages_to_restore_results)
    current = 0
    for x in messages_to_restore_results:
      current += 1
      rewrite_line("restoring message %s of %s from %s" %
        (current, restore_count, x[1]))
      message_num = x[0]
      message_filename = x[2]
      if not os.path.isfile(os.path.join(options.local_folder,
        message_filename)):
        print('WARNING! file %s does not exist for message %s' %
          (os.path.join(options.local_folder, message_filename), message_num))
        print('  this message will be skipped.')
        continue
      f = open(os.path.join(options.local_folder, message_filename), 'rb')
      full_message = f.read()
      f.close()
      media = googleapiclient.http.MediaFileUpload(
        os.path.join(options.local_folder, message_filename),
        mimetype='message/rfc822', resumable=True, chunksize=chunksize)
      try:
        callGAPI(service=gmig.archive(), function='insert',
          groupId=options.email, media_body=media)
      except googleapiclient.errors.MediaUploadSizeError as e:
        print('\n ERROR: Message is to large for groups (16mb limit). \
          Skipping...')
        continue
      sqlconn.execute(
         'INSERT OR IGNORE INTO restored_messages (message_num) VALUES (?)',
           (message_num,))
      sqlconn.commit()
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

  # COUNT 
  elif options.action == 'count':
    if options.batch_size == 0:
      options.batch_size = 100
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages',
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    estimate_count = len(messages_to_process)
    print("%s,%s" % (options.email, estimate_count))

  # PURGE #
  elif options.action == 'purge':
    if options.batch_size == 0:
      options.batch_size = 20
    page_message = 'Got %%total_items%% Message IDs'
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', page_message=page_message,
      userId='me', includeSpamTrash=True, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    purge_count = len(messages_to_process)
    purged_messages = 0
    gbatch = googleapiclient.http.BatchHttpRequest()
    for a_message in messages_to_process:
      gbatch.add(gmail.users().messages().delete(userId='me',
        id=a_message['id']), callback=purged_message)
      purged_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        rewrite_line("purged %s of %s messages" %
          (purged_messages, purge_count))
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None)
      rewrite_line("purged %s of %s messages" % (purged_messages, purge_count))
    print("\n")

  # PURGE-LABELS #
  elif options.action == 'purge-labels':
    pattern = options.gmail_search
    if pattern == None:
      pattern = '.*'
    pattern = re.compile(pattern)
    existing_labels = callGAPI(service=gmail.users().labels(), function='list',
      userId='me', fields='labels(id,name,type)')
    for label_result in existing_labels['labels']:
      if label_result['type'] == 'system' or not \
        pattern.search(label_result['name']):
        continue
      rewrite_line('Deleting label %s' % label_result['name'])
      callGAPI(service=gmail.users().labels(), function='delete',
        userId='me', id=label_result['id'])
    print('\n')

  # QUOTA #
  elif options.action == 'quota':
    if not options.service_account:  # 3-Legged OAuth
      drive = buildGAPIObject('drive')
    else:
      drive = buildGAPIServiceObject('drive')
    quota_results = callGAPI(service=drive.about(), function='get',
      fields='quotaBytesTotal,quotaBytesUsedInTrash,quotaBytesUsedAggregate,qu\
otaBytesByService,quotaType')
    for key in quota_results:
      if key == 'quotaBytesByService':
        print('Service Usage:')
        for service in quota_results[key]:
          myval = int(service['bytesUsed'])
          myval = bytes_to_larger(myval)
          service_name = '%s%s' % (service['serviceName'][0],
            service['serviceName'][1:].lower())
          print(' %s: %s' % (service_name, myval))
        continue
      myval = quota_results[key]
      mysize = ''
      if myval.isdigit():
        myval = bytes_to_larger(myval)
      print('%s: %s' % (key, myval))

  # REVOKE
  elif options.action == 'revoke':
    if options.service_account:
      print('ERROR: --action revoke does not work with --service-account')
      sys.exit(5)
    oauth2file = getProgPath()+'%s.cfg' % options.email
    storage = oauth2client.file.Storage(oauth2file)
    credentials = storage.get()
    try:
      credentials.revoke_uri = oauth2client.GOOGLE_REVOKE_URI
    except AttributeError:
      print('Error: Authorization doesn\'t exist')
      sys.exit(1)
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(
      disable_ssl_certificate_validation=disable_ssl_certificate_validation)
    if os.path.isfile(getProgPath()+'debug.gam'):
      httplib2.debuglevel = 4
    sys.stdout.write('This authorizaton token will self-destruct in 3...')
    sys.stdout.flush()
    time.sleep(1)
    sys.stdout.write('2...')
    sys.stdout.flush()
    time.sleep(1)
    sys.stdout.write('1...')
    sys.stdout.flush()
    time.sleep(1)
    sys.stdout.write('boom!\n')
    sys.stdout.flush()
    try:
      credentials.revoke(http)
    except oauth2client.client.TokenRevokeError:
      print('Error')
      os.remove(oauth2file)

  # ESTIMATE #
  elif options.action == 'estimate':
    if options.batch_size == 0:
      options.batch_size = 100
    page_message = 'Got %%total_items%% Message IDs'
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', page_message=page_message,
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    estimate_path = options.local_folder
    if not os.path.isdir(estimate_path):
      os.mkdir(estimate_path)
    messages_to_estimate = []
    #Determine which messages from the search we haven't processed before.
    print("GYB needs to examine %s messages" % len(messages_to_process))
    for message_num in messages_to_process:
      if not newDB and os.path.isfile(sqldbfile) and message_is_backed_up(message_num['id'], sqlcur,
        sqlconn, options.local_folder):
        pass
      else:
        messages_to_estimate.append(message_num['id'])
    print("GYB already has a backup of %s messages" %
      (len(messages_to_process) - len(messages_to_estimate)))
    estimate_count = len(messages_to_estimate)
    print("GYB needs to estimate %s messages" % estimate_count)
    estimated_messages = 0
    gbatch = googleapiclient.http.BatchHttpRequest()
    global message_size_estimate
    message_size_estimate = 0
    for a_message in messages_to_estimate:
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='minimal',
        fields='sizeEstimate'),
        callback=estimate_message)
      estimated_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None)
        gbatch = googleapiclient.http.BatchHttpRequest()
        rewrite_line("Estimated size %s %s/%s messages" %
          (bytes_to_larger(message_size_estimate), estimated_messages,
          estimate_count))
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None)
      rewrite_line("Estimated size %s %s/%s messages" %
        (bytes_to_larger(message_size_estimate), estimated_messages,
        estimate_count))
    print('\n')

if __name__ == '__main__':
  doGYBCheckForUpdates()
  try:
    main(sys.argv[1:])
  except KeyboardInterrupt:
    try:
      sqlconn.commit()
      sqlconn.close()
      print()
    except NameError:
      pass
    sys.exit(4)