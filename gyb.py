#!/usr/bin/env python-
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

u"""\n%s\n\nGot Your Back (GYB) is a command line tool which allows users to backup and restore their Gmail.

For more information, see http://code.google.com/p/got-your-back/
"""

global __name__, __author__, __email__, __version__, __license__
__program_name__ = u'Got Your Back: Gmail Backup'
__author__ = u'Jay Lee'
__email__ = u'jay0lee@gmail.com'
__version__ = u'0.26'
__license__ = u'Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)'
__db_schema_version__ = u'5'
__db_schema_min_version__ = u'2'        #Minimum for restore

import imaplib
from optparse import OptionParser, SUPPRESS_HELP
import sys
import os
import os.path
import time
import random
import struct
import platform
import StringIO
import socket
import datetime
import sqlite3
import email
import mailbox
import mimetypes
import re
import shlex
from itertools import islice, chain
import math

try:
  import json as simplejson
except ImportError:
  import simplejson

import httplib2
import oauth2client.client
import oauth2client.file
import oauth2client.tools
import gflags
import apiclient
import apiclient.discovery
import apiclient.errors
import gimaplib

def SetupOptionParser():
  # Usage message is the module's docstring.
  parser = OptionParser(usage=__doc__ % getGYBVersion(), add_help_option=False)
  parser.add_option('--email',
    dest='email',
    help='Full email address of user or group to act against')
  action_choices = ['backup','restore', 'restore-group', 'restore-mbox', 'count', 'purge', 'purge-labels', 'estimate', 'reindex']
  parser.add_option('--action',
    type='choice',
    choices=action_choices,
    dest='action',
    default='backup',
    help='Action to perform - %s. Default is backup.' % ', '.join(action_choices))
  parser.add_option('--search',
    dest='gmail_search',
    default='in:anywhere',
    help='Optional: On backup, estimate, count and purge, Gmail search to scope operation against')
  parser.add_option('--local-folder',
    dest='local_folder',
    help='Optional: On backup, restore, estimate, local folder to use. Default is GYB-GMail-Backup-<email>',
    default='XXXuse-email-addressXXX')
  parser.add_option('--use-imap-folder',
    dest='use_folder',
    help='Optional: IMAP folder to act against. Default is "All Mail" label. You can run "--use_folder [Gmail]/Chats" to backup chat.')
  parser.add_option('--label-restored',
    dest='label_restored',
    help='Optional: On restore, all messages will additionally receive this label. For example, "--label_restored gyb-restored" will label all uploaded messages with a gyb-restored label.')
  parser.add_option('--strip-labels',
    dest='strip_labels',
    action='store_true',
    default=False,
    help='Optional: On restore and restore-mbox, strip existing labels from messages except for those explicitly declared with the --label-restored parameter.')
  parser.add_option('--service-account',
    dest='service_account',
    help='Google Apps Business and Education only. Use OAuth 2.0 Service Account to authenticate.')
  parser.add_option('--use-admin',
    dest='use_admin',
    help='Optional. On restore-group, authenticate as this admin user.')
  parser.add_option('--batch-size',
    dest='batch_size',
    type='int',
    default=100,
    help='Optional: On backup, sets the number of messages to batch download.')
  parser.add_option('--noresume', 
    action='store_true', 
    default=False,
    help='Optional: On restores, start from beginning. Default is to resume where last restore left off.')
  parser.add_option('--fast-incremental',
    dest='refresh',
    action='store_false',
    default=True,
    help='Optional: On backup, skips refreshing labels for existing message')
  parser.add_option('--debug',
    action='store_true',
    dest='debug',
    help='Turn on verbose debugging and connection information (troubleshooting)')
  parser.add_option('--version',
    action='store_true',
    dest='version',
    help='print GYB version and quit')
  parser.add_option('--help',
    action='help',
    help='Display this message.')
  return parser

def win32_unicode_argv():
  from ctypes import POINTER, byref, cdll, c_int, windll
  from ctypes.wintypes import LPCWSTR, LPWSTR

  GetCommandLineW = cdll.kernel32.GetCommandLineW
  GetCommandLineW.argtypes = []
  GetCommandLineW.restype = LPCWSTR

  CommandLineToArgvW = windll.shell32.CommandLineToArgvW
  CommandLineToArgvW.argtypes = [LPCWSTR, POINTER(c_int)]
  CommandLineToArgvW.restype = POINTER(LPWSTR)

  cmd = GetCommandLineW()
  argc = c_int(0)
  argv = CommandLineToArgvW(cmd, byref(argc))
  if argc.value > 0:
    # Remove Python executable and commands if present
    start = argc.value - len(sys.argv)
    return [argv[i] for i in xrange(start, argc.value)]

def getProgPath():
  if os.path.abspath('/') != -1:
    divider = '/'
  else:
    divider = '\\'
  return os.path.dirname(os.path.realpath(sys.argv[0]))+divider

def batch(iterable, size):
  sourceiter = iter(iterable)
  while True:
    batchiter = islice(sourceiter, size)
    yield chain([batchiter.next()], batchiter)

def getOAuthFromConfigFile(email):
  cfgFile = '%s%s.cfg' % (getProgPath(), email)
  if os.path.isfile(cfgFile):
    f = open(cfgFile, 'r')
    key = f.readline()[0:-1]
    secret = f.readline()
    f.close()
    return (key, secret)
  else:
    return (False, False)

def requestOAuthAccess(email, debug=False):
  scopes = ['https://mail.google.com/',                        # IMAP/SMTP client access
            'https://www.googleapis.com/auth/userinfo#email',
            'https://www.googleapis.com/auth/apps.groups.migration']
  CLIENT_SECRETS = getProgPath()+'client_secrets.json'
  MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make GYB run you will need to populate the client_secrets.json file
found at:

   %s

with information from the APIs Console <https://code.google.com/apis/console>.

""" % (CLIENT_SECRETS)
  FLOW = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, scope=scopes, message=MISSING_CLIENT_SECRETS_MESSAGE, login_hint=email)
  cfgFile = '%s%s.cfg' % (getProgPath(), email)
  storage = oauth2client.file.Storage(cfgFile)
  credentials = storage.get()
  if os.path.isfile(getProgPath()+'nobrowser.txt'):
    gflags.FLAGS.auth_local_webserver = False
  if credentials is None or credentials.invalid:
    certFile = getProgPath()+'cacert.pem'
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(ca_certs=certFile, disable_ssl_certificate_validation=disable_ssl_certificate_validation)
    credentials = oauth2client.tools.run(FLOW, storage, short_url=True, http=http)

def doGYBCheckForUpdates():
  import urllib2, calendar
  last_update_check_file = getProgPath()+'noupdatecheck.txt'
  if os.path.isfile(last_update_check_file): return
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
    c = urllib2.urlopen(u'https://gyb-update.appspot.com/latest-version.txt?v=%s' % __version__)
    try:
      latest_version = float(c.read())
    except ValueError:
      return
    if latest_version <= current_version:
      f = open(last_update_check_file, 'w')
      f.write(str(now_time))
      f.close()
      return
    a = urllib2.urlopen(u'https://gyb-update.appspot.com/latest-version-announcement.txt?v=%s')
    announcement = a.read()
    sys.stderr.write('\nThere\'s a new version of GYB!!!\n\n')
    sys.stderr.write(announcement)
    visit_gyb = raw_input(u"\n\nHit Y to visit the GYB website and download the latest release. Hit Enter to just continue with this boring old version. GYB won't bother you with this announcemnt for 1 week or you can create a file named noupdatecheck.txt in the same location as gyb.py or gyb.exe and GYB won't ever check for updates: ")
    if visit_gyb.lower() == u'y':
      import webbrowser
      webbrowser.open(u'http://git.io/gyb')
      print u'GYB is now exiting so that you can overwrite this old version with the latest release'
      sys.exit(0)
    f = open(last_update_check_file, 'w')
    f.write(str(now_time))
    f.close()
  except urllib2.HTTPError:
    return
  except urllib2.URLError:
    return

def generateXOAuthString(email, service_account=False, debug=False):
  if debug:
    httplib2.debuglevel = 4
  if service_account:
    f = file(getProgPath()+'privatekey.p12', 'rb')
    key = f.read()
    f.close()
    scope = 'https://mail.google.com/'
    credentials = oauth2client.client.SignedJwtAssertionCredentials(service_account_name=service_account, private_key=key, scope=scope, user_agent=getGYBVersion(' / '), prn=email)
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(ca_certs=getProgPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
    if debug:
      httplib2.debuglevel = 4
    http = credentials.authorize(http)
    service = apiclient.discovery.build('oauth2', 'v2', http=http)
  else:
    cfgFile = '%s%s.cfg' % (getProgPath(), email)
    storage = oauth2client.file.Storage(cfgFile)
    credentials = storage.get()
    if credentials is None or credentials.invalid:
      requestOAuthAccess(email, debug)
      credentials = storage.get()
  if credentials.access_token_expired:
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    credentials.refresh(httplib2.Http(ca_certs=getProgPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation))
  return "user=%s\001auth=OAuth %s\001\001" % (email, credentials.access_token)

def just_quote(self, arg):
        return '"%s"' % arg

def callGAPI(service, function, soft_errors=False, throw_reasons=[], **kwargs):
  method = getattr(service, function)
  retries = 3
  for n in range(1, retries+1):
    try:
      return method(**kwargs).execute()
    except apiclient.errors.HttpError, e:
      error = simplejson.loads(e.content)
      try:
        reason = error['error']['errors'][0]['reason']
        http_status = error['error']['code']
        message = error['error']['errors'][0]['message']
        if reason in throw_reasons:
          raise
        if n != retries and reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'backendError']:
          wait_on_fail = (2 ** n) if (2 ** n) < 60 else 60
          randomness = float(random.randint(1,1000)) / 1000
          wait_on_fail = wait_on_fail + randomness
          if n > 3: sys.stderr.write('\nTemp error %s. Backing off %s seconds...' % (reason, int(wait_on_fail)))
          time.sleep(wait_on_fail)
          if n > 3: sys.stderr.write('attempt %s/%s\n' % (n+1, retries))
          continue
        sys.stderr.write('\n%s: %s - %s\n' % (http_status, message, reason))
        if soft_errors:
          sys.stderr.write(' - Giving up.\n')
          return
        else:
          sys.exit(int(http_status))
      except KeyError:
        sys.stderr.write('Unknown Error: %s' % e)
        sys.exit(1)
    except oauth2client.client.AccessTokenRefreshError, e:
      sys.stderr.write('Error: Authentication Token Error - %s' % e)
      sys.exit(403)

def message_is_backed_up(message_num, sqlcur, sqlconn, backup_folder):
    try:
      sqlcur.execute('''
         SELECT message_filename FROM uids NATURAL JOIN messages
                where uid = ?''', ((message_num),))
    except sqlite3.OperationalError, e:
      if e.message == 'no such table: messages':
        print "\n\nError: your backup database file appears to be corrupted."
      else:
        print "SQL error:%s" % e
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
  except sqlite3.OperationalError, e:
    if e.message == 'no such table: settings':
      print "\n\nSorry, this version of GYB requires version %s of the database schema. Your backup folder database does not have a version." % (__db_schema_version__)
      sys.exit(6)
    else: 
      print "%s" % e

def check_db_settings(db_settings, action, user_email_address):
  if (db_settings['db_version'] < __db_schema_min_version__  or
      db_settings['db_version'] > __db_schema_version__):
    print "\n\nSorry, this backup folder was created with version %s of the database schema while GYB %s requires version %s - %s for restores" % (db_settings['db_version'], __version__, __db_schema_min_version__, __db_schema_version__)
    sys.exit(4)

  # Only restores are allowed to use a backup folder started with another account (can't allow 2 Google Accounts to backup/estimate from same folder)
  if action not in ['restore', 'restore-group', 'restore-mbox']:
    if user_email_address.lower() != db_settings['email_address'].lower():
      print "\n\nSorry, this backup folder should only be used with the %s account that it was created with for incremental backups. You specified the %s account" % (db_settings['email_address'], user_email_address)
      sys.exit(5)

def convertDB(sqlconn, uidvalidity, oldversion):
  print "Converting database"
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
      sqlconn.executemany('REPLACE INTO settings (name, value) VALUES (?,?)',
                        (('uidvalidity',uidvalidity), 
                         ('db_version', __db_schema_version__)) )   
      sqlconn.commit()
  except sqlite3.OperationalError, e:
      print "Conversion error: %s" % e.message

  print "GYB database converted to version %s" % __db_schema_version__

def getMessageIDs (sqlconn, backup_folder):   
  sqlcur = sqlconn.cursor()
  header_parser = email.parser.HeaderParser()
  for message_num, filename in sqlconn.execute('''
               SELECT message_num, message_filename FROM messages 
                      WHERE rfc822_msgid IS NULL'''):
    message_full_filename = os.path.join(backup_folder, filename)
    if os.path.isfile(message_full_filename):
      f = open(message_full_filename, 'rb')
      msgid = header_parser.parse(f, True).get('message-id') or '<DummyMsgID>'
      f.close()
      sqlcur.execute(
          'UPDATE messages SET rfc822_msgid = ? WHERE message_num = ?',
                     (msgid, message_num))
  sqlconn.commit()
 
def rebuildUIDTable(imapconn, sqlconn):
  sqlcur = sqlconn.cursor()
  header_parser = email.parser.HeaderParser()
  sqlcur.execute('DELETE FROM uids')
  # Create an index on the Message ID to speed up the process
  sqlcur.execute('CREATE INDEX IF NOT EXISTS msgidx on messages(rfc822_msgid)')
  exists = imapconn.response('exists')
  exists = int(exists[1][0])
  batch_size = 1000
  for batch_start in xrange(1, exists, batch_size):
    batch_end = min(exists, batch_start+batch_size-1)
    t, d = imapconn.fetch('%d:%d' % (batch_start, batch_end),
                '(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS '
                             '(FROM TO SUBJECT MESSAGE-ID)])')
    if t != 'OK':
      print "\nError: failed to retrieve messages."
      print "%s %s" % (t, d)
      sys.exit(5)
    for extras, header in (x for x in d if x != ')'):
      uid, message_date = re.search('UID ([0-9]*) (INTERNALDATE \".*\")', 
                                     extras).groups()
      try:
        time_seconds = time.mktime(imaplib.Internaldate2tuple(message_date))
      except OverflowError:
        time_seconds = time.time()
      message_internaldate = datetime.datetime.fromtimestamp(time_seconds)
      m = header_parser.parsestr(header, True)
      msgid = m.get('message-id') or '<DummyMsgID>'
      message_to = m.get('to')
      message_from = m.get('from')
      message_subject = m.get('subject')
      try:
        sqlcur.execute('''
          INSERT INTO uids (uid, message_num) 
            SELECT ?, message_num FROM messages WHERE
                   rfc822_msgid = ? AND
                   message_internaldate = ?
                   GROUP BY rfc822_msgid 
                   HAVING count(*) = 1''',
                   (uid,
                    msgid,
                    message_internaldate))
      except Exception, e:
       print e
       print e.message
       print uid, msgid
      if sqlcur.lastrowid is None:
        print uid, rfc822_msgid
    print "\b.",
    sys.stdout.flush() 
  # There is no need to maintain the Index for normal operations
  sqlcur.execute('DROP INDEX msgidx')
  sqlconn.commit()

def doesTokenMatchEmail(cli_email, debug=False):
  cfgFile = '%s%s.cfg' % (getProgPath(), cli_email)
  storage = oauth2client.file.Storage(cfgFile)
  credentials = storage.get()
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(ca_certs=getProgPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  if debug:
    httplib2.debuglevel = 4
  if credentials.access_token_expired:
    credentials.refresh(http)
  oa2 = apiclient.discovery.build('oauth2', 'v2', http=http)
  token_info = callGAPI(service=oa2, function='tokeninfo', access_token=credentials.access_token)
  if token_info['email'].lower() == cli_email.lower():
    return True
  return False

def restart_line():
  sys.stdout.write('\r')
  sys.stdout.flush()

def initializeDB(sqlcur, sqlconn, email, uidvalidity):
  sqlcur.executescript('''
   CREATE TABLE messages(message_num INTEGER PRIMARY KEY, 
                         message_filename TEXT, 
                         message_to TEXT, 
                         message_from TEXT, 
                         message_subject TEXT, 
                         message_internaldate TIMESTAMP,
                         rfc822_msgid TEXT);
   CREATE TABLE labels (message_num INTEGER, label TEXT);
   CREATE TABLE flags (message_num INTEGER, flag TEXT);
   CREATE TABLE uids (message_num INTEGER, uid INTEGER PRIMARY KEY);
   CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT);
   CREATE UNIQUE INDEX labelidx ON labels (message_num, label);
   CREATE UNIQUE INDEX flagidx ON flags (message_num, flag);
  ''')
  sqlcur.executemany('INSERT INTO settings (name, value) VALUES (?, ?)', 
         (('email_address', email),
          ('db_version', __db_schema_version__),
          ('uidvalidity', uidvalidity)))
  sqlconn.commit()

def get_message_size(imapconn, uids):
  if type(uids) == type(int()):
    uid_string == str(uid)
  else:
    uid_string = ','.join(uids)
  t, d = imapconn.uid('FETCH', uid_string, '(RFC822.SIZE)')
  if t != 'OK':
    print "Failed to retrieve size for message %s" % uid
    print "%s %s" % (t, d)
    exit(9)
  total_size = 0
  for x in d:
    message_size = int(re.search('^[0-9]* \(UID [0-9]* RFC822.SIZE ([0-9]*)\)$', x).group(1))
    total_size = total_size + message_size
  return total_size

def getGYBVersion(divider="\n"):
  return ('Got Your Back %s~DIV~%s - %s~DIV~Python %s.%s.%s %s-bit %s~DIV~%s %s' % (__version__, __author__, __email__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2], struct.calcsize('P')*8,
                   sys.version_info[3], platform.platform(), platform.machine())).replace('~DIV~', divider)

def main(argv):
  options_parser = SetupOptionParser()
  (options, args) = options_parser.parse_args(args=argv)
  if options.version:
    print getGYBVersion()
    sys.exit(0)
  if not options.email:
    options_parser.print_help()
    print "\nERROR: --email is required."
    return
  if options.local_folder == 'XXXuse-email-addressXXX':
    options.local_folder = "GYB-GMail-Backup-%s" % options.email
  if options.service_account: # Service Account OAuth
    if not os.path.isfile(getProgPath()+'privatekey.p12'):
      print 'Error: you must have a privatekey.p12 file downloaded from the Google API Console and saved to the same path as GYB to use a service account.'
      sys.exit(1)
  else:  # 3-Legged OAuth
    if options.use_admin:
      auth_as = options.use_admin
    else:
      auth_as = options.email
    requestOAuthAccess(auth_as, options.debug)
    if not doesTokenMatchEmail(auth_as, options.debug):
      print "Error: you did not authorize the OAuth token in the browser with the %s Google Account. Please make sure you are logged in to the correct account when authorizing the token in the browser." % auth_as
      cfgFile = '%s%s.cfg' % (getProgPath(), auth_as)
      os.remove(cfgFile)
      sys.exit(9)

  if not os.path.isdir(options.local_folder):
    if options.action in ['backup',]:
      os.mkdir(options.local_folder)
    elif options.action in ['restore', 'restore-group']:
      print 'Error: Folder %s does not exist. Cannot restore.' % options.local_folder
      sys.exit(3)

  if options.action not in ['restore-group']:
    imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
    global ALL_MAIL, TRASH, SPAM
    label_mappings = gimaplib.GImapGetFolders(imapconn)
    try:
      ALL_MAIL = label_mappings[u'\\All']
    except KeyError:
      print 'Error: Cannot find the Gmail "All Mail" folder. Please make sure it is not hidden from IMAP.'
      sys.exit(3)
    if not options.use_folder:
      options.use_folder = ALL_MAIL
    r, d = imapconn.select(ALL_MAIL, readonly=True)
    if r == 'NO':
      print "Error: Cannot select the Gmail \"All Mail\" folder. Please make sure it is not hidden from IMAP."
      sys.exit(3)
    uidvalidity = imapconn.response('UIDVALIDITY')[1][0]

  sqldbfile = os.path.join(options.local_folder, 'msg-db.sqlite')
  # Do we need to initialize a new database?
  newDB = (not os.path.isfile(sqldbfile)) and (options.action in ['backup', u'restore-mbox'])
  
  #If we're not doing a estimate or if the db file actually exists we open it (creates db if it doesn't exist)
  if options.action not in ['estimate', 'count', 'purge', 'purge-labels'] or os.path.isfile(sqldbfile):
    print "\nUsing backup folder %s" % options.local_folder
    global sqlconn
    global sqlcur
    sqlconn = sqlite3.connect(sqldbfile, detect_types=sqlite3.PARSE_DECLTYPES)
    sqlconn.text_factory = str
    sqlcur = sqlconn.cursor()
    if newDB:
      initializeDB(sqlcur, sqlconn, options.email, uidvalidity)
    db_settings = get_db_settings(sqlcur)
    check_db_settings(db_settings, options.action, options.email)
    if options.action not in ['restore', 'restore-group', u'restore-mbox']:
      if ('uidvalidity' not in db_settings or 
          db_settings['db_version'] <  __db_schema_version__):
        convertDB(sqlconn, uidvalidity, db_settings['db_version'])
        db_settings = get_db_settings(sqlcur)
      if options.action == 'reindex':
        getMessageIDs(sqlconn, options.local_folder)
        rebuildUIDTable(imapconn, sqlconn)
        sqlconn.execute('''
            UPDATE settings SET value = ? where name = 'uidvalidity'
        ''', ((uidvalidity),))
        sqlconn.commit()
        sys.exit(0)

      if db_settings['uidvalidity'] != uidvalidity:
        print "Because of changes on the Gmail server, this folder cannot be used for incremental backups."
        sys.exit(3)

  # BACKUP #
  if options.action == 'backup':
    print 'Using folder %s' % options.use_folder
    imapconn.select(options.use_folder, readonly=True)
    messages_to_process = gimaplib.GImapSearch(imapconn, options.gmail_search)
    backup_path = options.local_folder
    if not os.path.isdir(backup_path):
      os.mkdir(backup_path)
    messages_to_backup = []
    messages_to_refresh = []
    #Determine which messages from the search we haven't processed before.
    print "GYB needs to examine %s messages" % len(messages_to_process)
    for message_num in messages_to_process:
      if not newDB and message_is_backed_up(message_num, sqlcur, sqlconn, options.local_folder):
        messages_to_refresh.append(message_num)
      else:
        messages_to_backup.append(message_num)
    print "GYB already has a backup of %s messages" % (len(messages_to_process) - len(messages_to_backup))
    backup_count = len(messages_to_backup)
    print "GYB needs to backup %s messages" % backup_count
    messages_at_once = options.batch_size
    backed_up_messages = 0
    header_parser = email.parser.HeaderParser()
    for working_messages in batch(messages_to_backup, messages_at_once):
      #Save message content
      batch_string = ','.join(working_messages)
      bad_count = 0
      while True:
        try:
          r, d = imapconn.uid('FETCH', batch_string, '(X-GM-LABELS INTERNALDATE FLAGS BODY.PEEK[])')
          if r != 'OK':
            bad_count = bad_count + 1
            if bad_count > 7:
              print "\nError: failed to retrieve messages."
              print "%s %s" % (r, d)
              sys.exit(5)
            sleep_time = math.pow(2, bad_count)
            sys.stdout.write("\nServer responded with %s %s, will retry in %s seconds" % (r, d, str(sleep_time)))
            time.sleep(sleep_time) # sleep 2 seconds, then 4, 8, 16, 32, 64, 128
            imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
            imapconn.select(ALL_MAIL, readonly=True)
            continue
          break
        except imaplib.IMAP4.abort, e:
          print 'imaplib.abort error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL, readonly=True)
        except socket.error, e:
          print 'socket.error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL, readonly=True)
      for everything_else_string, full_message in (x for x in d if x != ')'):
        search_results = re.search('X-GM-LABELS \((.*)\) UID ([0-9]*) (INTERNALDATE \".*\") (FLAGS \(.*\))', everything_else_string)
        labels_str = search_results.group(1)
        quoted_labels = shlex.split(labels_str, posix=False)
        labels = []
        for label in quoted_labels:
          if label[0] == '"' and label[-1] == '"':
            label = label[1:-1]
          if label[:2] == '\\\\':
            label = label[1:]
          labels.append(label)
        uid = search_results.group(2)
        message_date_string = search_results.group(3)
        message_flags_string = search_results.group(4)
        try:
          message_date = imaplib.Internaldate2tuple(message_date_string)
        except OverflowError: # Bad internal time? Use now...
          message_date = time.gmtime()
        time_seconds_since_epoch = time.mktime(message_date)
        message_internal_datetime = datetime.datetime.fromtimestamp(time_seconds_since_epoch)
        message_flags = imaplib.ParseFlags(message_flags_string)
        message_file_name = "%s-%s.eml" % (uidvalidity, uid)
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
        f.write(full_message)
        f.close()
        m = header_parser.parsestr(full_message, True)
        message_from = m.get('from')
        message_to = m.get('to')
        message_subj = m.get('subject')
        message_id = m.get('message-id')
        sqlcur.execute("""
             INSERT INTO messages (
                         message_filename, 
                         message_to, 
                         message_from, 
                         message_subject, 
                         message_internaldate,
                         rfc822_msgid) VALUES (?, ?, ?, ?, ?, ?)""", 
                        (message_rel_filename, 
                         message_to, 
                         message_from, 
                         message_subj, 
                         message_internal_datetime,
                         message_id))
        message_num = sqlcur.lastrowid
        sqlcur.execute("""
             REPLACE INTO uids (message_num, uid) VALUES (?, ?)""", 
                               (message_num, uid))
        for label in labels:
          sqlcur.execute("""
             INSERT INTO labels (message_num, label) VALUES (?, ?)""",  
                                (message_num, label))
        for flag in message_flags:
          sqlcur.execute("""
             INSERT INTO flags (message_num, flag) VALUES (?, ?)""", 
                               (message_num, flag))
        backed_up_messages += 1

      sqlconn.commit()
      restart_line()
      sys.stdout.write("backed up %s of %s messages" % (backed_up_messages, backup_count))
      sys.stdout.flush()
    print "\n"
 
    if not options.refresh:
      messages_to_refresh = []
    backed_up_messages = 0
    backup_count = len(messages_to_refresh)
    print "GYB needs to refresh %s messages" % backup_count
    sqlcur.executescript("""
       CREATE TEMP TABLE current_labels (label TEXT);
       CREATE TEMP TABLE current_flags (flag TEXT);
    """)
    messages_at_once *= 100
    for working_messages in batch(messages_to_refresh, messages_at_once):
      #Save message content
      batch_string = ','.join(working_messages)
      bad_count = 0
      while True:
        try:
          r, d = imapconn.uid('FETCH', batch_string, '(X-GM-LABELS FLAGS)')
          if r != 'OK':
            bad_count = bad_count + 1
            if bad_count > 7:
              print "\nError: failed to retrieve messages."
              print "%s %s" % (r, d)
              sys.exit(5)
            sleep_time = math.pow(2, bad_count)
            sys.stdout.write("\nServer responded with %s %s, will retry in %s seconds" % (r, d, str(sleep_time)))
            time.sleep(sleep_time) # sleep 2 seconds, then 4, 8, 16, 32, 64, 128
            imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
            imapconn.select(ALL_MAIL, readonly=True)
            continue
          break
        except imaplib.IMAP4.abort, e:
          print 'imaplib.abort error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL, readonly=True)
        except socket.error, e:
          print 'socket.error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL, readonly=True)
      for results in d:
        search_results = re.search('X-GM-LABELS \((.*)\) UID ([0-9]*) (FLAGS \(.*\))', results)
        labels = shlex.split(search_results.group(1), posix=False)
        uid = search_results.group(2)
        message_flags_string = search_results.group(3)
        message_flags = imaplib.ParseFlags(message_flags_string)
        sqlcur.execute('DELETE FROM current_labels')
        sqlcur.execute('DELETE FROM current_flags')
        sqlcur.executemany(
           'INSERT INTO current_labels (label) VALUES (?)',
              ((label,) for label in labels))
        sqlcur.executemany(
           'INSERT INTO current_flags (flag) VALUES (?)',
              ((flag,) for flag in message_flags))
        sqlcur.execute("""DELETE FROM labels where message_num = 
                   (SELECT message_num from uids where uid = ?)
                    AND label NOT IN current_labels""", ((uid),))
        sqlcur.execute("""DELETE FROM flags where message_num = 
                   (SELECT message_num from uids where uid = ?)
                    AND flag NOT IN current_flags""", ((uid),))
        sqlcur.execute("""INSERT INTO labels (message_num, label) 
            SELECT message_num, label from uids, current_labels 
               WHERE uid = ? AND label NOT IN 
               (SELECT label FROM labels 
                  WHERE message_num = uids.message_num)""", ((uid),))
        sqlcur.execute("""INSERT INTO flags (message_num, flag) 
            SELECT message_num, flag from uids, current_flags 
               WHERE uid = ? AND flag NOT IN 
               (SELECT flag FROM flags 
                  WHERE message_num = uids.message_num)""", ((uid),))
        backed_up_messages += 1

      sqlconn.commit()
      restart_line()
      sys.stdout.write("refreshed %s of %s messages" % (backed_up_messages, backup_count))
      sys.stdout.flush()
    print "\n"
 
  # RESTORE #
  elif options.action == 'restore':
    print 'using IMAP folder %s' % options.use_folder
    imapconn.select(options.use_folder)
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
    sqlcur.execute('''INSERT INTO skip_messages SELECT message_num from restored_messages''')
    sqlcur.execute('''SELECT message_num, message_internaldate, message_filename FROM messages
                      WHERE message_num NOT IN skip_messages ORDER BY message_internaldate DESC''') # All messages

    messages_to_restore_results = sqlcur.fetchall()
    restore_count = len(messages_to_restore_results)
    current = 0
    created_labels = []
    for x in messages_to_restore_results:
      restart_line()
      current += 1
      message_filename = x[2]
      sys.stdout.write("restoring message %s of %s from %s" % (current, restore_count, message_filename))
      sys.stdout.flush()
      message_num = x[0]
      message_internaldate = x[1]
      message_internaldate_seconds = time.mktime(message_internaldate.timetuple())
      if not os.path.isfile(os.path.join(options.local_folder, message_filename)):
        print 'WARNING! file %s does not exist for message %s' % (os.path.join(options.local_folder, message_filename), message_num)
        print '  this message will be skipped.'
        continue
      f = open(os.path.join(options.local_folder, message_filename), 'rb')
      full_message = f.read()
      f.close()
      full_message = full_message.replace('\x00', '') # No NULL chars
      labels = []
      if not options.strip_labels:
        labels_query = sqlcur.execute('SELECT DISTINCT label FROM labels WHERE message_num = ?', (message_num,))
        labels_results = sqlcur.fetchall()
        for l in labels_results:
          labels.append(l[0].replace('\\','\\\\').replace('"','\\"'))
      if options.label_restored:
        labels.append(options.label_restored)
      for label in labels:
        if label not in created_labels and label.find('/') != -1: # create parent labels
          create_label = label
          while True:
            imapconn.create(create_label)
            created_labels.append(create_label)
            if create_label.find('/') == -1:
              break
            create_label = create_label[:create_label.rfind('/')] 
      flags_query = sqlcur.execute('SELECT DISTINCT flag FROM flags WHERE message_num = ?', (message_num,))
      flags_results = sqlcur.fetchall()
      flags = []
      for f in flags_results:
        flags.append(f[0])
      flags_string = ' '.join(flags)
      while True:
        try:
          r, d = imapconn.append(options.use_folder, flags_string, message_internaldate_seconds, full_message)
          if r != 'OK':
            print '\nError: %s %s' % (r,d)
            sys.exit(5)
          try:
            restored_uid = int(re.search('^[APPENDUID [0-9]* ([0-9]*)] \(Success\)$', d[0]).group(1))
          except AttributeError:
            print '\nerror retrieving uid: %s: retrying...' % d
            time.sleep(3)
            imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
            imapconn.select(ALL_MAIL)
          if len(labels) > 0:
            labels_string = '("'+'" "'.join(labels)+'")'
            r, d = imapconn.uid('STORE', restored_uid, '+X-GM-LABELS', labels_string)
            if r != 'OK':
              print '\nGImap Set Message Labels Failed: %s %s' % (r, d)
              sys.exit(33)
          break
        except imaplib.IMAP4.abort, e:
          print '\nimaplib.abort error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL)
        except socket.error, e:
          print '\nsocket.error:%s, retrying...' % e
          imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
          imapconn.select(ALL_MAIL)
      #Save the fact that it is completed
      sqlconn.execute(
        'INSERT OR IGNORE INTO restored_messages (message_num) VALUES (?)',
           (message_num,))
      sqlconn.commit()
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

 # RESTORE-MBOX #
  elif options.action == 'restore-mbox':
    imapconn.select(options.use_folder)
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
    sqlcur.executescript('''CREATE TABLE IF NOT EXISTS mbox_resume.restored_messages 
                        (message TEXT PRIMARY KEY)''')
    sqlcur.execute('''SELECT message FROM mbox_resume.restored_messages''')
    messages_to_skip_results = sqlcur.fetchall()
    messages_to_skip = []
    for a_message in messages_to_skip_results:
      messages_to_skip.append(a_message[0])
    if os.name == 'windows' or os.name == 'nt':
      divider = '\\'
    else:
      divider = '/'
    created_labels = []
    for path, subdirs, files in os.walk(options.local_folder):
      for filename in files:
        if filename[-4:].lower() != u'.mbx' and filename[-5:].lower() != u'.mbox':
          continue
        file_path = '%s%s%s' % (path, divider, filename)
        mbox = mailbox.mbox(file_path)
        mbox_count = len(mbox.items())
        current = 0
        print "\nRestoring from %s" % file_path
        for message in mbox:
          current += 1
          message_marker = '%s-%s' % (file_path, current)
          if message_marker in messages_to_skip:
            continue
          restart_line()
          labels = message[u'X-Gmail-Labels']
          if labels != None and labels != u'' and not options.strip_labels:
            bytes, encoding = email.header.decode_header(labels)[0]
            if encoding != None:
              try:
                labels = bytes.decode(encoding)
              except UnicodeDecodeError:
                pass
            else:
              labels = labels.decode('string-escape')
            labels = labels.split(u',')
          else:
            labels = []
          if options.label_restored:
            labels.append(options.label_restored)
          for label in labels:
            if label not in created_labels and label.find('/') != -1: # create parent labels
              create_label = label
              while True:
                imapconn.create(create_label)
                created_labels.append(create_label)
                if create_label.find('/') == -1:
                  break
                create_label = create_label[:create_label.rfind('/')]
          flags = []
          if u'Unread' in labels:
            labels.remove(u'Unread')
          else:
            flags.append(u'\Seen')
          if u'Starred' in labels:
            flags.append(u'\Flagged')
            labels.remove(u'Starred')
          if u'Sent' in labels:
            labels.remove(u'Sent')
            labels.append(u'\\\\Sent')
          if u'Inbox' in labels:
            labels.remove(u'Inbox')
            labels.append(u'\\\\Inbox')
          if u'Important' in labels:
            labels.remove(u'Important')
            labels.append(u'\\\\Important')
          if u'Drafts' in labels:
            labels.remove(u'Drafts')
            labels.append(u'\\\\Draft')
          if u'Chat' in labels:
            labels.remove(u'Chat')
            labels.append(u'Restored Chats')
          escaped_labels = []
          for label in labels:
            if label.find('\"') != -1:
              escaped_labels.append(label.replace('\"', '\\"'))
            else:
              escaped_labels.append(label)
          del message[u'X-Gmail-Labels']
          del message[u'X-GM-THRID']
          flags_string = ' '.join(flags)
          msg_account, internal_datetime = message.get_from().split(' ', 1)
          internal_datetime_seconds = time.mktime(email.utils.parsedate(internal_datetime))
          sys.stdout.write(" message %s of %s" % (current, mbox_count))
          sys.stdout.flush()
          full_message = message.as_string()
          while True:
            try:
              r, d = imapconn.append(options.use_folder, flags_string, internal_datetime_seconds, full_message)
              if r != 'OK':
                print '\nError: %s %s' % (r,d)
                sys.exit(5)
              restored_uid = int(re.search('^[APPENDUID [0-9]* ([0-9]*)] \(Success\)$', d[0]).group(1))
              if len(labels) > 0:
                labels_string = '("'+'" "'.join(escaped_labels)+'")'
                r, d = imapconn.uid('STORE', restored_uid, '+X-GM-LABELS', labels_string)
                if r != 'OK':
                  print '\nGImap Set Message Labels Failed: %s %s' % (r, d)
                  sys.exit(33)
              break
            except imaplib.IMAP4.abort, e:
              print '\nimaplib.abort error:%s, retrying...' % e
              imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
              imapconn.select(ALL_MAIL)
            except socket.error, e:
              print '\nsocket.error:%s, retrying...' % e
              imapconn = gimaplib.ImapConnect(generateXOAuthString(options.email, options.service_account), options.debug)
              imapconn.select(ALL_MAIL)
          #Save the fact that it is completed
          sqlconn.execute(
            'INSERT INTO restored_messages (message) VALUES (?)',
             (message_marker,))
          sqlconn.commit()
    sqlconn.execute('DETACH mbox_resume')
    sqlconn.commit()

  # RESTORE-GROUP #
  elif options.action == 'restore-group':
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
    sqlcur.execute('''INSERT INTO skip_messages SELECT message_num from restored_messages''')
    sqlcur.execute('''SELECT message_num, message_internaldate, message_filename FROM messages
          WHERE message_num NOT IN skip_messages ORDER BY message_internaldate DESC''') # All messages
    messages_to_restore_results = sqlcur.fetchall()
    restore_count = len(messages_to_restore_results)
    if options.service_account:
      if not options.use_admin:
        print 'Error: --restore_group and --service_account require --user_admin to specify Google Apps Admin to utilize.'
        sys.exit(5)
      f = file(getProgPath()+'privatekey.p12', 'rb')
      key = f.read()
      f.close()
      scope = 'https://www.googleapis.com/auth/apps.groups.migration'
      credentials = oauth2client.client.SignedJwtAssertionCredentials(options.service_account, key, scope=scope, prn=options.use_admin)
      disable_ssl_certificate_validation = False
      if os.path.isfile(getProgPath()+'noverifyssl.txt'):
        disable_ssl_certificate_validation = True
      http = httplib2.Http(ca_certs=getProgPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
      if options.debug:
        httplib2.debuglevel = 4
      http = credentials.authorize(http)
    elif options.use_admin:
      cfgFile = '%s%s.cfg' % (getProgPath(), options.use_admin)
      f = open(cfgFile, 'rb')
      token = simplejson.load(f)
      f.close()
      storage = oauth2client.file.Storage(cfgFile)
      credentials = storage.get()
      disable_ssl_certificate_validation = False
      if os.path.isfile(getProgPath()+'noverifyssl.txt'):
        disable_ssl_certificate_validation = True
      http = httplib2.Http(ca_certs=getProgPath()+'cacert.pem', disable_ssl_certificate_validation=disable_ssl_certificate_validation)
      if options.debug:
        httplib2.debuglevel = 4
      http = credentials.authorize(http)
    else:
      print 'Error: restore-group requires that --use_admin is also specified.'
      sys.exit(5)
    gmig = apiclient.discovery.build('groupsmigration', 'v1', http=http)
    current = 0
    for x in messages_to_restore_results:
      restart_line()
      current += 1
      sys.stdout.write("restoring message %s of %s from %s" % (current, restore_count, x[1]))
      sys.stdout.flush()
      message_num = x[0]
      message_internaldate = x[1]
      message_filename = x[2]
      if not os.path.isfile(os.path.join(options.local_folder, message_filename)):
        print 'WARNING! file %s does not exist for message %s' % (os.path.join(options.local_folder, message_filename), message_num)
        print '  this message will be skipped.'
        continue
      f = open(os.path.join(options.local_folder, message_filename), 'rb')
      full_message = f.read()
      f.close()
      media = apiclient.http.MediaFileUpload(os.path.join(options.local_folder, message_filename), mimetype='message/rfc822')
      callGAPI(service=gmig.archive(), function='insert', groupId=options.email, media_body=media)
      #Save the fact that it is completed
      sqlconn.execute(
#        'INSERT OR IGNORE INTO restored_messages (message_num) VALUES (?)',
         'INSERT INTO restored_messages (message_num) VALUES (?)',
           (message_num,))
      sqlconn.commit()
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

  # COUNT 
  elif options.action == 'count':
    print 'Using label %s' % options.use_folder
    imapconn.select(options.use_folder, readonly=True)
    messages_to_process = gimaplib.GImapSearch(imapconn, options.gmail_search)
    messages_to_estimate = []
    #if we have a sqlcur , we'll compare messages to the db
    #otherwise just estimate everything
    for message_num in messages_to_process:
      try:
        sqlcur
        if message_is_backed_up(message_num, sqlcur, sqlconn, options.local_folder):
          continue
        else:
          messages_to_estimate.append(message_num)
      except NameError:
        messages_to_estimate.append(message_num)
    estimate_count = len(messages_to_estimate)
    total_size = float(0)
    list_position = 0
    messages_at_once = 10000
    loop_count = 0
    print "%s,%s" % (options.email, estimate_count)

  # PURGE #
  elif options.action == 'purge':
    print 'Using label %s' % options.use_folder
    imapconn.select(options.use_folder, readonly=False)
    messages_to_process = gimaplib.GImapSearch(imapconn, options.gmail_search)
    print 'Moving %s messages from All Mail to Trash for %s' % (len(messages_to_process), options.email)
    messages_at_once = 1000
    loop_count = 0
    for working_messages in batch(messages_to_process, messages_at_once):
      uid_string = ','.join(working_messages)
      t, d = imapconn.uid('STORE', uid_string, '+X-GM-LABELS', '\\Trash')
    try:
      SPAM = label_mappings[u'\\Junk']
    except KeyError:
      print 'Error: could not select the Spam folder. Please make sure it is not hidden from IMAP.'
      sys.exit(2)
    r, d = imapconn.select(SPAM, readonly=False)
    if r == 'NO':
      print "Error: Cannot select the Gmail \"Spam\" folder. Please make sure it is not hidden from IMAP."
      sys.exit(3)
    spam_uids = gimaplib.GImapSearch(imapconn, options.gmail_search)
    print 'Purging %s Spam messages for %s' % (len(spam_uids), options.email)
    for working_messages in batch(spam_uids, messages_at_once):
      spam_uid_string = ','.join(working_messages)
      t, d = imapconn.uid('STORE', spam_uid_string, '+FLAGS', '\Deleted')
    imapconn.expunge()
    try:
      TRASH = label_mappings[u'\\Trash']
    except KeyError:
      print 'Error: could not select the Trash folder. Please make sure it is not hidden from IMAP.'
      sys.exit(4)
    r, d = imapconn.select(TRASH, readonly=False)
    if r == 'NO':
      print "Error: Cannot select the Gmail \"Trash\" folder. Please make sure it is not hidden from IMAP."
      sys.exit(3)
    trash_uids = gimaplib.GImapSearch(imapconn, options.gmail_search) 
    print 'Purging %s Trash messages for %s' % (len(trash_uids), options.email)
    for working_messages in batch(trash_uids, messages_at_once):
      trash_uid_string = ','.join(working_messages)
      t, d = imapconn.uid('STORE', trash_uid_string, '+FLAGS', '\Deleted')
    imapconn.expunge()

  # PURGE-LABELS #
  elif options.action == u'purge-labels':
    pattern = options.gmail_search
    if pattern == u'in:anywhere':
      pattern = u'*'
    pattern = r'%s' % pattern
    r, existing_labels = imapconn.list(pattern=pattern)
    for label_result in existing_labels:
      if type(label_result) is not str:
        continue 
      label = re.search(u'\" \"(.*)\"$', label_result).group(1)
      if label == u'INBOX' or label == u'Deleted' or label[:7] == u'[Gmail]':
        continue

      # ugly hacking of imaplib to keep it from overquoting/escaping
      funcType = type(imapconn._quote)
      imapconn._quote = funcType(just_quote, imapconn, imapconn)

      print u'Deleting label %s' % label
      try:
        r, d = imapconn.delete(label)
      except imaplib.IMAP4.error, e:
        print 'bad response: %s' % e

  # ESTIMATE #
  elif options.action == 'estimate':
    imapconn.select(options.use_folder, readonly=True)
    messages_to_process = gimaplib.GImapSearch(imapconn, options.gmail_search)
    messages_to_estimate = []
    #if we have a sqlcur , we'll compare messages to the db
    #otherwise just estimate everything
    for message_num in messages_to_process:
      try:
        sqlcur
        if message_is_backed_up(message_num, sqlcur, sqlconn, options.local_folder):
          continue
        else:
          messages_to_estimate.append(message_num)
      except NameError:
        messages_to_estimate.append(message_num)
    estimate_count = len(messages_to_estimate)
    total_size = float(0)
    list_position = 0
    messages_at_once = 10000
    loop_count = 0
    print 'Email: %s' % options.email
    print "Messages to estimate: %s" % estimate_count
    estimated_messages = 0
    for working_messages in batch(messages_to_estimate, messages_at_once):
      messages_size = get_message_size(imapconn, working_messages)
      total_size = total_size + messages_size
      if total_size > 1048576:
        math_size = total_size/1048576
        print_size = "%.2fM" % math_size
      elif total_size > 1024:
        math_size = total_size/1024
        print_size = "%.2fK" % math_size
      else:
        print_size = "%.2fb" % total_size
      if estimated_messages+messages_at_once < estimate_count:
        estimated_messages = estimated_messages + messages_at_once
      else:
        estimated_messages = estimate_count
      restart_line()
      sys.stdout.write("Messages estimated: %s  Estimated size: %s" % (estimated_messages, print_size))
      sys.stdout.flush()
      time.sleep(1)
    print ""
  try:
    sqlconn.close()
  except NameError:
    pass
  try:
    imapconn.logout()
  except UnboundLocalError: # group-restore never does imapconn
    pass
  
if __name__ == '__main__':
  reload(sys)
  sys.setdefaultencoding(u'UTF-8')
  if os.name == u'nt':
    sys.argv = win32_unicode_argv() # cleanup sys.argv on Windows
  doGYBCheckForUpdates()
  try:
    main(sys.argv[1:])
  except KeyboardInterrupt:
    try:
      sqlconn.commit()
      sqlconn.close()
      print
    except NameError:
      pass
    sys.exit(4)
