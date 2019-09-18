#!/usr/bin/env python3
#
# Got Your Back
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""\n%s\n\nGot Your Back (GYB) is a command line tool which allows users to
backup and restore their Gmail.

For more information, see https://git.io/gyb/
"""

global __name__, __author__, __email__, __version__, __license__
__program_name__ = 'Got Your Back: Gmail Backup'
__author__ = 'Jay Lee'
__email__ = 'jay0lee@gmail.com'
__version__ = '1.31'
__license__ = 'Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0)'
__website__ = 'https://git.io/gyb'
__db_schema_version__ = '6'
__db_schema_min_version__ = '6'        #Minimum for restore

global extra_args, options, allLabelIds, allLabels, gmail, reserved_labels
extra_args = {'prettyPrint': False}
allLabelIds = dict()
allLabels = dict()
reserved_labels = ['inbox', 'spam', 'trash', 'unread', 'starred', 'important',
  'sent', 'draft', 'chat', 'chats', 'migrated', 'todo', 'todos', 'buzz',
  'bin', 'allmail', 'drafts', 'archived']
system_labels = ['INBOX', 'SPAM', 'TRASH', 'UNREAD', 'STARRED', 'IMPORTANT',
                 'SENT', 'DRAFT', 'CATEGORY_PERSONAL', 'CATEGORY_SOCIAL',
                 'CATEGORY_PROMOTIONS', 'CATEGORY_UPDATES', 'CATEGORY_FORUMS']
import argparse
import importlib
import sys
import os
import os.path
import time
import calendar
import random
import struct
import platform
import datetime
import socket
import sqlite3
import ssl
import email
import hashlib
import re
import string
from itertools import islice, chain
import base64
import json
import xml.etree.ElementTree as etree
from urllib.parse import urlencode
import configparser
import webbrowser

import httplib2
import google.oauth2.service_account
import google_auth_oauthlib.flow
import google_auth_httplib2
import google.oauth2.id_token
import googleapiclient
import googleapiclient.discovery
import googleapiclient.errors

import fmbox
import labellang

def getGYBVersion(divider="\n"):
  return ('Got Your Back %s~DIV~%s~DIV~%s - %s~DIV~Python %s.%s.%s %s-bit \
%s~DIV~google-api-client %s~DIV~%s %s' % (__version__, __website__, __author__, __email__,
sys.version_info[0], sys.version_info[1], sys.version_info[2],
struct.calcsize('P')*8, sys.version_info[3], googleapiclient.__version__, platform.platform(),
platform.machine())).replace('~DIV~', divider)

USER_AGENT = getGYBVersion(' | ')
# Override and wrap google_auth_httplib2 request methods so that the
# user-agent string is inserted into HTTP request headers.
def _request_with_user_agent(request_method):
  """Inserts the user-agent header kwargs sent to a method."""
  def wrapped_request_method(self, *args, **kwargs):
    if kwargs.get('headers') is not None:
      if kwargs['headers'].get('user-agent'):
        if USER_AGENT not in kwargs['headers']['user-agent']:
          # Save the existing user-agent header and tack on the user-agent.
          kwargs['headers']['user-agent'] = '%s %s' % (USER_AGENT, kwargs['headers']['user-agent'])
      else:
        kwargs['headers']['user-agent'] = USER_AGENT
    else:
      kwargs['headers'] = {'user-agent': USER_AGENT}
    return request_method(self, *args, **kwargs)
  return wrapped_request_method

google_auth_httplib2.Request.__call__ = _request_with_user_agent(
  google_auth_httplib2.Request.__call__)
google_auth_httplib2.AuthorizedHttp.request = _request_with_user_agent(
  google_auth_httplib2.AuthorizedHttp.request)

def SetupOptionParser(argv):
  tls_choices = []
  if getattr(ssl, 'TLSVersion', False):
    tls_min_default = 'TLSv1_2'
    tls_vals = list(ssl.TLSVersion)[1:-1]
    tls_choices = []
    for val in tls_vals:
      tls_choices.append(val.name)
  else:
    tls_min_default = None
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument('--email',
    dest='email',
    help='Full email address of user or group to act against')
  action_choices = ['backup','restore', 'restore-group', 'restore-mbox',
    'count', 'purge', 'purge-labels', 'print-labels', 'estimate', 'quota', 'reindex', 'revoke',
    'split-mbox', 'create-project', 'delete-projects', 'check-service-account']
  parser.add_argument('--action',
    choices=action_choices,
    dest='action',
    default='backup',
    help='Action to perform. Default is backup.')
  parser.add_argument('--search',
    dest='gmail_search',
    default='-is:chat',
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
uploaded messages with a gyb-restored label.',
    default=[])
  parser.add_argument('--label-prefix',
                      action='append',
                      dest='label_prefix',
                      help='Optional: On restore, all labels will additionally receive \
  this prefix label. For example, "--label-prefix gyb-archive" will become main label of all \
  uploaded labels with a gyb-prefix label. \
  ATTENTION - This is not compatible with --label-strip \
  ATTENTION - this will also create one INBOX and SENT specific label',
                      default=[])
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
    help='G Suite only. Use OAuth 2.0 Service \
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
  parser.add_argument('--memory-limit',
    dest='memory_limit',
    type=int,
    default=0,
    help='Limit in megabytes batch requests allow. Prevents memory issues.')
  if tls_choices:
    parser.add_argument('--tls-min-version',
      dest='tls_min_version',
      default=tls_min_default,
      choices=tls_choices,
      help='Python 3.7+ only. Set minimum version of TLS HTTPS connections require. Default is TLSv1_2')
    parser.add_argument('--tls-max-version',
      dest='tls_max_version',
      default=None,
      choices=tls_choices,
      help='Python 3.7+ only. Set maximum version of TLS HTTPS connections use. Default is no max')
  parser.add_argument('--ca-file',
    dest='ca_file',
    default=None,
    help='specify a certificate authority to use for validating HTTPS hosts.')
  parser.add_argument('--version',
    action='store_true',
    dest='version',
    help='print GYB version and quit')
  parser.add_argument('--short-version',
    action='store_true',
    dest='shortversion',
    help='Just print version and quit')
  parser.add_argument('--help',
    action='help',
    help='Display this message.')
  return parser.parse_args(argv)

def getProgPath():
  if os.environ.get('STATICX_PROG_PATH', False):
    # StaticX static executable
    return os.path.dirname(os.environ['STATICX_PROG_PATH'])
  elif getattr(sys, 'frozen', False):
    # PyInstaller exe
    return os.path.dirname(sys.executable)
  else:
    # Source code
    return os.path.dirname(os.path.realpath(__file__))

def getValidOauth2TxtCredentials(force_refresh=False):
  """Gets OAuth2 credentials which are guaranteed to be fresh and valid."""
  credentials = getOauth2TxtStorageCredentials()
  if (credentials and credentials.expired) or force_refresh:
    retries = 3
    for n in range(1, retries+1):
      try:
        credentials.refresh(google_auth_httplib2.Request(_createHttpObj()))
        writeCredentials(credentials)
        break
      except google.auth.exceptions.RefreshError as e:
        systemErrorExit(18, str(e))
      except (google.auth.exceptions.TransportError, httplib2.ServerNotFoundError, RuntimeError) as e:
        if n != retries:
          waitOnFailure(n, retries, str(e))
          continue
        systemErrorExit(4, str(e))
  elif credentials is None or not credentials.valid:
    requestOAuthAccess()
    credentials = getOauth2TxtStorageCredentials()
  return credentials

def getOauth2TxtStorageCredentials():
  auth_as = options.use_admin if options.use_admin else options.email
  cfgFile = os.path.join(getProgPath(), '%s.cfg' % auth_as)
  oauth_string = readFile(cfgFile, continueOnError=True, displayError=False)
  if not oauth_string:
    return
  oauth_data = json.loads(oauth_string)
  creds = google.oauth2.credentials.Credentials.from_authorized_user_file(cfgFile)
  creds.token = oauth_data.get('token', oauth_data.get('auth_token', ''))
  creds._id_token = oauth_data.get('id_token_jwt', oauth_data.get('id_token', None))
  token_expiry = oauth_data.get('token_expiry', '1970-01-01T00:00:01Z')
  creds.expiry = datetime.datetime.strptime(token_expiry, '%Y-%m-%dT%H:%M:%SZ')
  return creds

def getOAuthClientIDAndSecret():
  """Retrieves the OAuth client ID and client secret from JSON."""
  MISSING_CLIENT_SECRETS_MESSAGE = """Please configure a project

To make GYB run you will need to populate the client_secrets.json file. Try
running:

%s --action create-project --email %s

""" % (sys.argv[0], options.email)
  filename = os.path.join(getProgPath(), 'client_secrets.json')
  cs_data = readFile(filename, continueOnError=True, displayError=True)
  if not cs_data:
    systemErrorExit(14, MISSING_CLIENT_SECRETS_MESSAGE)
  try:
    cs_json = json.loads(cs_data)
    client_id = cs_json['installed']['client_id']
    # chop off .apps.googleusercontent.com suffix as it's not needed
    # and we need to keep things short for the Auth URL.
    client_id = re.sub(r'\.apps\.googleusercontent\.com$', '', client_id)
    client_secret = cs_json['installed']['client_secret']
  except (ValueError, IndexError, KeyError):
    systemErrorExit(3, 'the format of your client secrets file:\n\n%s\n\n'
                    'is incorrect. Please recreate the file.' % filename)
  return (client_id, client_secret)

def requestOAuthAccess():
  auth_as = options.use_admin if options.use_admin else options.email
  credentials = getOauth2TxtStorageCredentials()
  if credentials and credentials.valid:
    return
  client_id, client_secret = getOAuthClientIDAndSecret()
  possible_scopes = ['https://www.googleapis.com/auth/gmail.modify', # Gmail modify
                     'https://www.googleapis.com/auth/gmail.readonly', # Gmail readonly
                     'https://www.googleapis.com/auth/gmail.insert https://www.googleapis.com/auth/gmail.labels', # insert and labels
                     'https://mail.google.com/', # Gmail Full Access
                     '', # No Gmail
                     'https://www.googleapis.com/auth/apps.groups.migration', # Groups Archive Restore
                     'https://www.googleapis.com/auth/drive.appdata'] # Drive app config (used for quota)
  selected_scopes = [' ', ' ', ' ', '*', ' ', '*', '*']
  menu = '''Select the actions you wish GYB to be able to perform for %s

[%s]  0)  Gmail Backup And Restore - read/write mailbox access
[%s]  1)  Gmail Backup Only - read-only mailbox access
[%s]  2)  Gmail Restore Only - write-only mailbox access and label management
[%s]  3)  Gmail Full Access - read/write mailbox access and message purge
[%s]  4)  No Gmail Access

[%s]  5)  Groups Restore - write to G Suite Groups Archive
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
  credentials = _run_oauth_flow(client_id, client_secret, scopes, access_type='offline', login_hint=auth_as)
  writeCredentials(credentials)

def writeCredentials(creds):
  auth_as = options.use_admin if options.use_admin else options.email
  cfgFile = os.path.join(getProgPath(), '%s.cfg' % auth_as)
  creds_data = {
    'token': creds.token,
    'refresh_token': creds.refresh_token,
    'token_uri': creds.token_uri,
    'client_id': creds.client_id,
    'client_secret': creds.client_secret,
    'id_token': creds.id_token,
    'token_expiry': creds.expiry.strftime('%Y-%m-%dT%H:%M:%SZ'),
    }
  expected_iss = ['https://accounts.google.com', 'accounts.google.com']
  if _getValueFromOAuth('iss', creds) not in expected_iss:
    systemErrorExit(13, 'Wrong OAuth 2.0 credentials issuer. Got %s, expected one of %s' % (_getValueFromOAuth('iss', creds), ', '.join(expected_iss)))
  creds_data['decoded_id_token'] = _decodeIdToken(creds)
  data = json.dumps(creds_data, indent=2, sort_keys=True)
  writeFile(cfgFile, data)

def _decodeIdToken(credentials=None):
  credentials = credentials if credentials is not None else getValidOauth2TxtCredentials()
  httpc = google_auth_httplib2.Request(_createHttpObj())
  return google.oauth2.id_token.verify_oauth2_token(credentials.id_token, httpc)

def _getValueFromOAuth(field, credentials=None):
  id_token = _decodeIdToken(credentials)
  return id_token.get(field, 'Unknown')

#
# Read a file
#
def readFile(filename, mode='r', continueOnError=False, displayError=True, encoding=None):
  try:
    if filename != '-':
      if not encoding:
        with open(os.path.expanduser(filename), mode) as f:
          return f.read()
      with codecs.open(os.path.expanduser(filename), mode, encoding) as f:
        content = f.read()
# codecs does not strip UTF-8 BOM (ef:bb:bf) so we must
        if not content.startswith(codecs.BOM_UTF8):
          return content
        return content[3:]
    return unicode(sys.stdin.read())
  except IOError as e:
    if continueOnError:
      if displayError:
        sys.stderr.write(str(e))
      return None
    systemErrorExit(6, e)
  except (LookupError, UnicodeDecodeError, UnicodeError) as e:
    systemErrorExit(2, str(e))

def doGYBCheckForUpdates(forceCheck=False, debug=False):

  def _LatestVersionNotAvailable():
    if forceCheck:
      systemErrorExit(4, 'GYB Latest Version information not available')
  last_update_check_file = os.path.join(getProgPath(), 'lastcheck.txt')
  current_version = __version__
  now_time = calendar.timegm(time.gmtime())
  check_url = 'https://api.github.com/repos/jay0lee/got-your-back/releases' # includes pre-releases
  if not forceCheck:
    last_check_time_str = readFile(last_update_check_file, continueOnError=True, displayError=False)
    last_check_time = int(last_check_time_str) if last_check_time_str and last_check_time_str.isdigit() else 0
    if last_check_time > now_time-604800:
      return
    check_url = check_url + '/latest' # latest full release
  headers = {'Accept': 'application/vnd.github.v3.text+json',
             'User-Agent': getGYBVersion(' | ')}
  anonhttpc = _createHttpObj()
  try:
    (_, c) = anonhttpc.request(check_url, 'GET', headers=headers)
    try:
      release_data = json.loads(c.decode('utf-8'))
    except ValueError:
      _LatestVersionNotAvailable()
      return
    if isinstance(release_data, list):
      release_data = release_data[0] # only care about latest release
    if not isinstance(release_data, dict) or 'tag_name' not in release_data:
      _LatestVersionNotAvailable()
      return
    latest_version = release_data['tag_name']
    if latest_version[0].lower() == 'v':
      latest_version = latest_version[1:]
    if forceCheck or (latest_version > current_version):
      print('Version Check:\n Current: {0}\n Latest: {1}'.format(current_version, latest_version))
    if latest_version <= current_version:
      writeFile(last_update_check_file, str(now_time), continueOnError=True, displayError=forceCheck)
      return
    announcement = release_data.get('body_text', 'No details about this release')
    sys.stderr.write('\nGYB %s release notes:\n\n' % latest_version)
    sys.stderr.write(announcement)
    try:
      print('\n\nHit CTRL+C to visit the GYB website and download the latest release or wait 15 seconds to continue with this boring old version. GYB won\'t bother you with this announcement for 1 week or you can create a file named noupdatecheck.txt in the same location as gyb.py or gyb.exe and GYB won\'t ever check for updates.')
      time.sleep(15)
    except KeyboardInterrupt:
      webbrowser.open(release_data['html_url'])
      print('GYB exiting for update...')
      sys.exit(0)
    writeFile(last_update_check_file, str(now_time), continueOnError=True, displayError=forceCheck)
    return
  except (httplib2.HttpLib2Error, httplib2.ServerNotFoundError):
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
  credentials = getValidOauth2TxtCredentials()
  httpc = google_auth_httplib2.AuthorizedHttp(credentials, _createHttpObj())
  if options.debug:
    extra_args['prettyPrint'] = True
  if os.path.isfile(os.path.join(getProgPath(), 'extra-args.txt')):
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(os.path.join(getProgPath(), 'extra-args.txt'))
    extra_args.update(dict(config.items('extra-args')))
  version = getAPIVer(api)
  try:
    return googleapiclient.discovery.build(api, version, http=httpc, cache_discovery=False)
  except googleapiclient.errors.UnknownApiNameOrVersion:
    disc_file = os.path.join(getProgPath(), '%s-%s.json' % (api, version))
    if os.path.isfile(disc_file):
      f = file(disc_file, 'r')
      discovery = f.read()
      f.close()
      return googleapiclient.discovery.build_from_document(discovery,
        base='https://www.googleapis.com', http=httpc)
    else:
      print('No online discovery doc and %s does not exist locally'
        % disc_file)
      raise

def buildGAPIServiceObject(api, soft_errors=False):
  global extra_args
  auth_as = options.use_admin if options.use_admin else options.email
  scopes = getAPIScope(api)
  _, credentials = getSvcAcctCredentials(scopes, auth_as)
  if options.debug:
    extra_args['prettyPrint'] = True
  if os.path.isfile(os.path.join(getProgPath(), 'extra-args.txt')):
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(getGamPath()+'extra-args.txt')
    extra_args.update(dict(config.items('extra-args')))
  httpc = _createHttpObj()
  request = google_auth_httplib2.Request(httpc)
  credentials.refresh(request)
  version = getAPIVer(api)
  try:
    service = googleapiclient.discovery.build(api, version, http=httpc, cache_discovery=False)
    service._http = google_auth_httplib2.AuthorizedHttp(credentials, http=httpc)
    return service
  except (httplib2.ServerNotFoundError, RuntimeError) as e:
    systemErrorExit(4, e)
  except google.auth.exceptions.RefreshError as e:
    if isinstance(e.args, tuple):
      e = e.args[0]
    systemErrorExit(5, e)

def callGAPI(service, function, soft_errors=False, throw_reasons=[], **kwargs):
  retries = 10
  parameters = kwargs.copy()
  parameters.update(extra_args)
  for n in range(1, retries+1):
    try:
      if function:
        method = getattr(service, function)(**parameters)
      else:
        method = service
      return method.execute()
    except googleapiclient.errors.MediaUploadSizeError as e:
      sys.stderr.write('\nERROR: %s' % (e))
      if soft_errors:
        sys.stderr.write(' - Giving up.\n')
        return
      else:
        sys.exit(int(http_status))
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
    except google.auth.exceptions.RefreshError as e:
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

VALIDEMAIL_PATTERN = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

def getValidateLoginHint(login_hint):
  if login_hint:
    login_hint = login_hint.strip()
    if VALIDEMAIL_PATTERN.match(login_hint):
      return login_hint
  while True:
    login_hint = input('\nWhat is your G Suite admin email address? ').strip()
    if VALIDEMAIL_PATTERN.match(login_hint):
      return login_hint
    print('Error: that is not a valid email address')

def percentage(part, whole):
  return '{0:.2f}'.format(100 * float(part)/float(whole))

class ShortURLFlow(google_auth_oauthlib.flow.InstalledAppFlow):
  def authorization_url(self, **kwargs):
    long_url, state = super(ShortURLFlow, self).authorization_url(**kwargs)
    simplehttp = _createHttpObj(timeout=10)
    url_shortnr = 'https://gyb-shortn.jaylee.us/create'
    headers = {'Content-Type': 'application/json'}
    try:
      resp, content = simplehttp.request(url_shortnr, 'POST', '{"long_url": "%s"}' % long_url, headers=headers)
    except:
      return long_url, state
    if resp.status != 200:
      return long_url, state
    try:
      return json.loads(content).get('short_url', long_url), state
    except:
      return long_url, state

MESSAGE_CONSOLE_AUTHORIZATION_PROMPT = '\nGo to the following link in your browser:\n\n\t{url}\n'
MESSAGE_CONSOLE_AUTHORIZATION_CODE = 'Enter verification code: '
MESSAGE_LOCAL_SERVER_AUTHORIZATION_PROMPT = '\nYour browser has been opened to visit:\n\n\t{url}\n\nIf your browser is on a different machine then press CTRL+C and delete the oauthbrowser.txt file in the same folder as GYB.\n'
MESSAGE_LOCAL_SERVER_SUCCESS = 'The authentication flow has completed. You may close this browser window and return to GYB.'
def _run_oauth_flow(client_id, client_secret, scopes, access_type, login_hint=None):
  client_config = {
    'installed': {
      'client_id': client_id, 'client_secret': client_secret,
      'redirect_uris': ['http://localhost', 'urn:ietf:wg:oauth:2.0:oob'],
      'auth_uri': 'https://accounts.google.com/o/oauth2/v2/auth',
      'token_uri': 'https://oauth2.googleapis.com/token',
      }
    }
  flow = ShortURLFlow.from_client_config(client_config, scopes)
  kwargs = {'access_type': access_type}
  if login_hint:
    kwargs['login_hint'] = login_hint
  # Needs to be set so oauthlib doesn't puke when Google changes our scopes
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = 'true'
  if not os.path.isfile(os.path.join(getProgPath(), 'oauthbrowser.txt')):
    flow.run_console(
            authorization_prompt_message=MESSAGE_CONSOLE_AUTHORIZATION_PROMPT,
            authorization_code_message=MESSAGE_CONSOLE_AUTHORIZATION_CODE,
            **kwargs)
  else:
    flow.run_local_server(
            authorization_prompt_message=MESSAGE_LOCAL_SERVER_AUTHORIZATION_PROMPT,
            success_message=MESSAGE_LOCAL_SERVER_SUCCESS,
            **kwargs)
  return flow.credentials

def getCRMService(login_hint):
  scope = 'https://www.googleapis.com/auth/cloud-platform'
  client_id = '297408095146-fug707qsjv4ikron0hugpevbrjhkmsk7.apps.googleusercontent.com'
  client_secret = 'qM3dP8f_4qedwzWQE1VR4zzU'
  credentials = _run_oauth_flow(client_id, client_secret, scope, 'online', login_hint)
  httpc = google_auth_httplib2.AuthorizedHttp(credentials)
  crm = googleapiclient.discovery.build('cloudresourcemanager', 'v1',
      http=httpc, cache_discovery=False,
      discoveryServiceUrl=googleapiclient.discovery.V2_DISCOVERY_URI)
  return (crm, httpc)

GYB_PROJECT_APIS = 'https://raw.githubusercontent.com/jay0lee/got-your-back/master/project-apis.txt?'
def enableProjectAPIs(project_name, checkEnabled, httpc):
  anonhttpc = _createHttpObj()
  headers = {'User-Agent': getGYBVersion(' | ')}
  s, c = anonhttpc.request(GYB_PROJECT_APIS, 'GET', headers=headers)
  if s.status < 200 or s.status > 299:
    print('ERROR: tried to retrieve %s but got %s' % (GYB_PROJECT_APIS, s.status))
    sys.exit(0)
  apis = c.decode("utf-8").splitlines()
  serveman = googleapiclient.discovery.build('servicemanagement', 'v1',
          http=httpc, cache_discovery=False,
          discoveryServiceUrl=googleapiclient.discovery.V2_DISCOVERY_URI)
  if checkEnabled:
    enabledServices = callGAPIpages(serveman.services(), 'list', 'services',
                                    consumerId=project_name, fields='nextPageToken,services(serviceName)')
    for enabled in enabledServices:
      if 'serviceName' in enabled:
        if enabled['serviceName'] in apis:
          print(' API %s already enabled...' % enabled['serviceName'])
          apis.remove(enabled['serviceName'])
        else:
          print(' API %s (non-GYB) is enabled (which is fine)' % enabled['serviceName'])
  for api in apis:
    while True:
      print(' enabling API %s...' % api)
      try:
        callGAPI(serveman.services(), 'enable',
                 throw_reasons=['failedPrecondition'],
                 serviceName=api, body={'consumerId': project_name})
        break
      except googleapiclient.errors.HttpError as e:
        print('\nThere was an error enabling %s. Please resolve error as described below:' % api)
        print
        print('\n%s\n' % e)
        print
        input('Press enter once resolved and we will try enabling the API again.')

def writeFile(filename, data, mode='wb', continueOnError=False, displayError=True):
  if isinstance(data, str):
    data = data.encode('utf-8')
  try:
    with open(os.path.expanduser(filename), mode) as f:
      f.write(data)
    return True
  except IOError as e:
    if continueOnError:
      if displayError:
        stderrErrorMsg(e)
      return False
    systemErrorExit(6, e)

def _createClientSecretsOauth2service(projectId):

  def _checkClientAndSecret(client_id, client_secret):
    url = 'https://www.googleapis.com/oauth2/v4/token'
    post_data = {'client_id': client_id, 'client_secret': client_secret,
                 'code': 'ThisIsAnInvalidCodeOnlyBeingUsedToTestIfClientAndSecretAreValid',
                 'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob', 'grant_type': 'authorization_code'}
    headers = {'Content-type': 'application/x-www-form-urlencoded',
               'User-Agent': getGYBVersion(' | ')}
    anonhttpc = _createHttpObj()
    _, content = anonhttpc.request(url, 'POST', urlencode(post_data), headers=headers)
    try:
      content = json.loads(content.decode('utf-8'))
    except ValueError:
      print('Unknown error: %s' % content)
      return False
    if not 'error' in content or not 'error_description' in content:
      print('Unknown error: %s' % content)
      return False
    if content['error'] == 'invalid_grant':
      return True
    if content['error_description'] == 'The OAuth client was not found.':
      print('Ooops!!\n\n%s\n\nIs not a valid client ID. Please make sure you are following the directions exactly and that there are no extra spaces in your client ID.' % client_id)
      return False
    if content['error_description'] == 'Unauthorized':
      print('Ooops!!\n\n%s\n\nIs not a valid client secret. Please make sure you are following the directions exactly and that there are no extra spaces in your client secret.' % client_secret)
      return False
    print('Unknown error: %s' % content)
    return False

  console_credentials_url = 'https://console.developers.google.com/apis/credentials/consent?createClient&project=%s' % projectId
  while True:
    print('''Please go to:

%s

1. Enter "GYB" for "Application name".
2. Leave other fields blank. Click "Save" button.
3. Choose "Other". Enter a desired value for "Name". Click the blue "Create" button.
4. Copy your "client ID" value.
''' % console_credentials_url)
# If you use Firefox to copy the Client ID and Secret, the data has leading and trailing newlines
# The first input will get the leading newline, thus we have to issue another input to get the data
# If the newlines are not present, the data is correctly read with the first input
    client_id = input('Enter your Client ID: ').strip()
    if not client_id:
      client_id = input().strip()
    print('\nNow go back to your browser and copy your client secret.')
    client_secret = input('Enter your Client Secret: ').strip()
    if not client_secret:
      client_secret = input().strip()
    client_valid = _checkClientAndSecret(client_id, client_secret)
    if client_valid:
      break
    print()
  cs_data = '''{
    "installed": {
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "client_id": "%s",
        "client_secret": "%s",
        "project_id": "%s",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
        "token_uri": "https://accounts.google.com/o/oauth2/token"
    }
}''' % (client_id, client_secret, projectId)
  client_secrets_file = os.path.join(getProgPath(), 'client_secrets.json')
  writeFile(client_secrets_file, cs_data, continueOnError=False)

PROJECTID_PATTERN = re.compile(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$')
PROJECTID_FORMAT_REQUIRED = '[a-z][a-z0-9-]{4,28}[a-z0-9]'
def _getLoginHintProjects():
  login_hint = options.email
  pfilter = options.gmail_search
  if not pfilter:
    pfilter = 'current'
  elif pfilter.lower() == 'all':
    pfilter = None
  elif pfilter.lower() == 'gyb':
    pfilter = 'id:gyb-project-*'
  elif PROJECTID_PATTERN.match(pfilter):
    pfilter = 'id:{0}'.format(pfilter)
  else:
    print('ERROR: delete-projects action requires --email and a project --search argument')
    sys.exit(3)
  login_hint = getValidateLoginHint(login_hint)
  crm, _ = getCRMService(login_hint)
  client_secrets_file = os.path.join(getProgPath(), 'client_secrets.json')
  if pfilter == 'current':
    cs_data = readFile(client_secrets_file, mode='rb', continueOnError=True, displayError=True, encoding=None)
    if not cs_data:
      systemErrorExit(14, 'Your client secrets file:\n\n%s\n\nis missing. Please recreate the file.' % client_secrets_file)
    try:
      cs_json = json.loads(cs_data)
      projects = [{'projectId': cs_json['installed']['project_id']}]
    except (ValueError, IndexError, KeyError):
      print('The format of your client secrets file:\n\n%s\n\nis incorrect. Please recreate the file.' % client_secrets_file)
  else:
    projects = _getProjects(crm, pfilter)
  return (crm, login_hint, projects)

def systemErrorExit(code=1, error_text='Unknown Error'):
  print('ERROR: %s' % error_text)
  sys.exit(code)

def _getProjects(crm, pfilter):
  return callGAPIpages(crm.projects(), 'list', 'projects', filter=pfilter)

def doDelProjects():
  crm, login_hint, projects = _getLoginHintProjects()
  count = len(projects)
  print('User: {0}, Delete {1} Projects'.format(login_hint, count))
  i = 0
  for project in projects:
    i += 1
    projectId = project['projectId']
    callGAPI(crm.projects(), 'delete', projectId=projectId, soft_errors=True)
    print('  Project: {0} Deleted ({1}/{2})'.format(projectId, i, count))

def doCreateProject():
  service_account_file = os.path.join(getProgPath(), 'oauth2service.json')
  client_secrets_file = os.path.join(getProgPath(), 'client_secrets.json')
  for a_file in [service_account_file, client_secrets_file]:
    if os.path.exists(a_file):
      print('File %s already exists. Please delete or rename it before attempting to create another project.' % a_file)
      sys.exit(5)
  login_hint = options.email
  login_domain = login_hint[login_hint.find('@')+1:]
  crm, httpc = getCRMService(login_hint)
  project_id = 'gyb-project'
  for i in range(3):
    project_id += '-%s' % ''.join(random.choice(string.digits + string.ascii_lowercase) for i in range(3))
  project_name = 'project:%s' % project_id
  body = {'projectId': project_id, 'name': 'Got Your Back Project'}
  while True:
    create_again = False
    print('Creating project "%s"...' % body['name'])
    create_operation = callGAPI(crm.projects(), 'create',
                                body=body)
    operation_name = create_operation['name']
    time.sleep(5) # Google recommends always waiting at least 5 seconds
    for i in range(1, 5):
      print('Checking project status...')
      status = callGAPI(crm.operations(), 'get',
                        name=operation_name)
      if 'error' in status:
        if status['error'].get('message', '') == 'No permission to create project in organization':
          print('Hmm... Looks like you have no rights to your Google Cloud Organization.')
          print('Attempting to fix that...')
          getorg = callGAPI(crm.organizations(), 'search',
                            body={'filter': 'domain:%s' % login_domain})
          try:
            organization = getorg['organizations'][0]['name']
            print('Your organization name is %s' % organization)
          except (KeyError, IndexError):
            print('you have no rights to create projects for your organization and you don\'t seem to be a super admin! Sorry, there\'s nothing more I can do.')
            sys.exit(3)
          org_policy = callGAPI(crm.organizations(), 'getIamPolicy',
                                resource=organization, body={})
          if 'bindings' not in org_policy:
            org_policy['bindings'] = []
            print('Looks like no one has rights to your Google Cloud Organization. Attempting to give you create rights...')
          else:
            print('The following rights seem to exist:')
            for a_policy in org_policy['bindings']:
              if 'role' in a_policy:
                print(' Role: %s' % a_policy['role'])
              if 'members' in a_policy:
                print(' Members:')
                for member in a_policy['members']:
                  print('  %s' % member)
              print
          my_role = 'roles/resourcemanager.projectCreator'
          print('Giving %s the role of %s...' % (login_hint, my_role))
          org_policy['bindings'].append({'role': my_role, 'members': ['user:%s' % login_hint]})
          callGAPI(crm.organizations(), 'setIamPolicy',
                   resource=organization, body={'policy': org_policy})
          create_again = True
          break
        try:
          if status['error']['details'][0]['violations'][0]['description'] == 'Callers must accept Terms of Service':
            print('''Please go to:
https://console.cloud.google.com/start
and accept the Terms of Service (ToS). As soon as you've accepted the ToS popup, you can return here and press enter.''')
            input()
            create_again = True
            break
        except (IndexError, KeyError):
          pass
        print(status)
        sys.exit(1)
      if status.get('done', False):
        break
      sleep_time = i ** 2
      print('Project still being created. Sleeping %s seconds' % sleep_time)
      time.sleep(sleep_time)
    if create_again:
      continue
    if not status.get('done', False):
      print('Failed to create project: %s' % status)
      sys.exit(1)
    elif 'error' in status:
      print(status['error'])
      sys.exit(2)
    break
  enableProjectAPIs(project_name, False, httpc)
  iam = googleapiclient.discovery.build('iam', 'v1', http=httpc,
          cache_discovery=False,
          discoveryServiceUrl=googleapiclient.discovery.V2_DISCOVERY_URI)
  print('Creating Service Account')
  service_account = callGAPI(iam.projects().serviceAccounts(), 'create',
                             name='projects/%s' % project_id,
                             body={'accountId': project_id, 'serviceAccount': {'displayName': 'GYB Project Service Account'}})
  key = callGAPI(iam.projects().serviceAccounts().keys(), 'create',
                 name=service_account['name'], body={'privateKeyType': 'TYPE_GOOGLE_CREDENTIALS_FILE', 'keyAlgorithm': 'KEY_ALG_RSA_2048'})
  oauth2service_data = base64.b64decode(key['privateKeyData'])
  writeFile(service_account_file, oauth2service_data, continueOnError=False)
  _createClientSecretsOauth2service(project_id)
  print('That\'s it! Your GYB Project is created and ready to use.')

API_SCOPE_MAPPING = {
  'email': ['https://www.googleapis.com/auth/userinfo.email'],
  'drive': ['https://www.googleapis.com/auth/drive.appdata',],
  'gmail': ['https://mail.google.com/',],
  'groupsmigration': ['https://www.googleapis.com/auth/apps.groups.migration',],
}

MESSAGE_INSTRUCTIONS_OAUTH2SERVICE_JSON = 'Please run\n\ngyb --action create-project\ngyb --action check-service-account\n\nto create and configure a service account.'
def getSvcAcctCredentials(scopes, act_as):
  try:
    json_string = readFile(os.path.join(getProgPath(), 'oauth2service.json'), continueOnError=True, displayError=True)
    if not json_string:
      print(MESSAGE_INSTRUCTIONS_OAUTH2SERVICE_JSON)
      systemErrorExit(6, None)
    sa_info = json.loads(json_string)
    credentials = google.oauth2.service_account.Credentials.from_service_account_info(sa_info)
    credentials = credentials.with_scopes(scopes)
    credentials = credentials.with_subject(act_as)
    request = google_auth_httplib2.Request(_createHttpObj())
    credentials.refresh(request)
    return sa_info['client_id'], credentials
  except (ValueError, KeyError):
    print(MESSAGE_INSTRUCTIONS_OAUTH2SERVICE_JSON)
    systemErrorExit(6, 'oauth2service.json is invalid.')

def doCheckServiceAccount():
  all_scopes = []
  for _, scopes in API_SCOPE_MAPPING.items():
    for scope in scopes:
      if scope not in all_scopes:
        all_scopes.append(scope)
  all_scopes.sort()
  all_scopes_pass = True
  oa2 = googleapiclient.discovery.build('oauth2', 'v1', _createHttpObj())
  for scope in all_scopes:
    try:
      client_id, credentials = getSvcAcctCredentials([scope, 'https://www.googleapis.com/auth/userinfo.email'], options.email)
      granted_scopes = callGAPI(oa2, 'tokeninfo', access_token=credentials.token)
      if scope in granted_scopes['scope'].split(' ') and \
         granted_scopes.get('email', '').lower() == options.email.lower():
        result = 'PASS'
      else:
        result = 'FAIL'
        all_scopes_pass = False
    except httplib2.ServerNotFoundError as e:
      print(e)
      sys.exit(4)
    except google.auth.exceptions.RefreshError:
      result = 'FAIL'
      all_scopes_pass = False
    print(' Scope: {0:60} {1}'.format(scope, result))
  if all_scopes_pass:
    print('\nAll scopes passed!\nService account %s is fully authorized.' % client_id)
    return
  user_domain = options.email[options.email.find('@')+1:]
  scopes_failed = '''SOME SCOPES FAILED! Please go to:

https://admin.google.com/%s/AdminHome?#OGX:ManageOauthClients

and grant Client name:

%s

Access to scopes:

%s\n''' % (user_domain, credentials.client_id, ',\n'.join(all_scopes))
  print('')
  print(scopes_failed)  
  sys.exit(3)

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

suffixes = ['b', 'kb', 'mb', 'gb', 'tb', 'pb']
def humansize(myobject):
  if isinstance(myobject, (str, bytes)):
    nbytes = os.stat(myobject).st_size
  else:
    nbytes = myobject
  if nbytes == 0: return '0 B'
  i = 0
  while nbytes >= 1024 and i < len(suffixes)-1:
    nbytes /= 1024.
    i += 1
  f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
  return '%s%s' % (f, suffixes[i])

def doesTokenMatchEmail():
  auth_as = options.use_admin if options.use_admin else options.email
  oa2 = buildGAPIObject('oauth2')
  user_info = callGAPI(service=oa2.userinfo(), function='get',
    fields='email')
  if user_info['email'].lower() == auth_as.lower():
    return True
  print("Error: you did not authorize the OAuth token in the browser with the \
%s Google Account. Please make sure you are logged in to the correct account \
when authorizing the token in the browser." % auth_as)
  cfgFile = os.path.join(getProgPath(), '%s.cfg' % auth_as)
  os.remove(cfgFile)
  return False

def rewrite_line(mystring):
  if not options.debug:
    print(' ' * 80, end='\r')
  else:
    print()
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
    # convert language system labels to standard
    label = labellang.mappings.get(label.upper(), label)
    if label.upper() in system_labels:
      labelIds.append(label.upper())
      continue
    base_label = label.split('/')[0]
    if base_label.lower() in reserved_labels and base_label not in allLabels.keys():
      label = '_%s' % (label)
    if label not in allLabels.keys():
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

def backup_message(request_id, response, exception):
  if exception is not None:
    print(exception)
  else:
    if 'labelIds' in response:
      labelIds = response['labelIds']
    else:
      labelIds = list()
    if 'CHATS' in labelIds: # skip CHATS
      return
    labels = labelIdsToLabels(labelIds)
    message_file_name = "%s.eml" % (response['id'])
    message_time = int(response['internalDate'])/1000
    message_date = time.gmtime(message_time)
    try:
      time_for_sqlite = datetime.datetime.fromtimestamp(message_time)
    except (OSError, IOError, OverflowError):
      time_for_sqlite = datetime.datetime.fromtimestamp(86400) # minimal value Win accepts
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

def _createHttpObj(cache=None, timeout=None):
  http_args = {'cache': cache, 'timeout': timeout}
  if 'tls_maximum_version' in options:
    http_args['tls_maximum_version'] = options.tls_maximum_version
  if 'tls_minimum_version' in options:
    http_args['tls_minimum_version'] = options.tls_minimum_version
  return httplib2.Http(**http_args)

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

def getSizeOfMessages(messages, gmail):
  def _estimate_message(request_id, response, exception):
    nonlocal running_size, message_sizes
    if exception is not None:
      raise exception
    else:
      message_size = int(response['sizeEstimate'])
      message_id = response['id']
      running_size += message_size
      message_sizes[message_id] = message_size

  estimate_count = len(messages)
  estimated_messages = 0
  gbatch = gmail.new_batch_http_request()
  message_sizes = {}
  running_size = 0
  for a_message in messages:
    gbatch.add(gmail.users().messages().get(userId='me',
      id=a_message, format='minimal',
        fields='id,sizeEstimate'),
        callback=_estimate_message)
    estimated_messages += 1
    if len(gbatch._order) == options.batch_size:
      callGAPI(gbatch, None)
      gbatch = gmail.new_batch_http_request()
      rewrite_line("Estimated size %s %s/%s messages" %
        (bytes_to_larger(running_size), estimated_messages,
         estimate_count))
  if len(gbatch._order) > 0:
    callGAPI(gbatch, None)
    rewrite_line("Estimated size %s %s/%s messages" %
      (bytes_to_larger(running_size), estimated_messages,
       estimate_count))
  print('\n')
  return message_sizes

def main(argv):
  global options, gmail
  options = SetupOptionParser(argv)
  if options.debug:
    httplib2.debuglevel = 4
  doGYBCheckForUpdates(debug=options.debug)
  if options.version:
    print(getGYBVersion())
    print('Path: %s' % getProgPath())
    print(ssl.OPENSSL_VERSION)
    anonhttpc = _createHttpObj()
    headers = {'User-Agent': getGYBVersion(' | ')}
    anonhttpc.request('https://www.googleapis.com', headers=headers)
    cipher_name, tls_ver, _ = anonhttpc.connections['https:www.googleapis.com'].sock.cipher()
    print('www.googleapis.com connects using %s %s' % (tls_ver, cipher_name))
    sys.exit(0)
  if options.shortversion:
    sys.stdout.write(__version__)
    sys.exit(0)
  if options.action == 'split-mbox':
    print('split-mbox is no longer necessary and is deprecated. Mbox file size should not impact restore performance in this version.')
    sys.exit(1)
  if not options.email:
    print('ERROR: --email is required.')
    sys.exit(1)
  if options.local_folder == 'XXXuse-email-addressXXX':
    options.local_folder = "GYB-GMail-Backup-%s" % options.email
  if options.action == 'create-project':
    doCreateProject()
    sys.exit(0)
  elif options.action == 'delete-projects':
    doDelProjects()
    sys.exit(0)
  elif options.action == 'check-service-account':
    doCheckServiceAccount()
    sys.exit(0)
  if not options.service_account:  # 3-Legged OAuth
    getValidOauth2TxtCredentials()
    if not doesTokenMatchEmail():
      sys.exit(9)
    gmail = buildGAPIObject('gmail')
  else:
    gmail = buildGAPIServiceObject('gmail')
  if not os.path.isdir(options.local_folder):
    if options.action in ['backup',]:
      os.mkdir(options.local_folder)
    elif options.action in ['restore', 'restore-group', 'restore-mbox']:
      print('ERROR: Folder %s does not exist. Cannot restore.'
        % options.local_folder)
      sys.exit(3)

  sqldbfile = os.path.join(options.local_folder, 'msg-db.sqlite')
  # Do we need to initialize a new database?
  newDB = (not os.path.isfile(sqldbfile)) and \
    (options.action in ['backup', 'restore-mbox'])
  
  # If we're not doing a estimate or if the db file actually exists we open it
  # (creates db if it doesn't exist)
  if options.action not in ['count', 'purge', 'purge-labels', 'print-labels',
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
      function='list', items='messages', page_message=page_message, maxResults=500,
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    backup_path = options.local_folder
    if not os.path.isdir(backup_path):
      os.mkdir(backup_path)
    messages_to_backup = []
    messages_to_refresh = []
    # Determine which messages from the search we haven't processed before.
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
    if options.memory_limit:
      memory_limit = options.memory_limit * 1024 * 1024
      message_sizes = getSizeOfMessages(messages_to_backup, gmail)
      request_size = 0
    backed_up_messages = 0
    gbatch = gmail.new_batch_http_request()
    for a_message in messages_to_backup:
      if options.memory_limit:
        request_size += message_sizes[a_message]
      if len(gbatch._order) == options.batch_size or (options.memory_limit and request_size >= memory_limit):
        callGAPI(gbatch, None, soft_errors=True)
        gbatch = gmail.new_batch_http_request()
        sqlconn.commit()
        if options.memory_limit:
          request_size = message_sizes[a_message]
        rewrite_line("backed up %s of %s messages" %
          (backed_up_messages, backup_count))
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='raw',
        fields='id,labelIds,internalDate,raw'),
        callback=backup_message)
      backed_up_messages += 1
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None, soft_errors=True)
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
    gbatch = gmail.new_batch_http_request()
    for a_message in messages_to_refresh:
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='minimal',
        fields='id,labelIds'),
        callback=refresh_message)
      refreshed_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None, soft_errors=True)
        gbatch = gmail.new_batch_http_request()
        sqlconn.commit()
        rewrite_line("refreshed %s of %s messages" %
          (refreshed_messages, refresh_count))
    if len(gbatch._order) > 0:
      callGAPI(gbatch, None, soft_errors=True)
      sqlconn.commit()
      rewrite_line("refreshed %s of %s messages" %
        (refreshed_messages, refresh_count))
    print("\n")

  # RESTORE #
  elif options.action == 'restore':
    if options.batch_size == 0:
      options.batch_size = 5
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
    gbatch = gmail.new_batch_http_request()
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
          if options.label_prefix:
            if l[0].lower()!="unread":
              labels.append(options.label_prefix[0] + "/" + l[0])
            else:
              labels.append(l[0])
          else:
            labels.append(l[0])
      if options.label_restored:
        for restore_label in options.label_restored:
          labels.append(restore_label)
      labelIds = labelsToLabelIds(labels)
      body = {'labelIds': labelIds}
      b64_message_size = (len(full_message)/3) * 4
      if b64_message_size > 1 * 1024 * 1024 or options.batch_size == 1:
        # don't batch/raw >1mb messages, just do single
        rewrite_line('restoring %s message (%s/%s)' %
          (humansize(b64_message_size), current, restore_count))
        # Note resumable=True is important here, it prevents errors on (bad)
        # messages that should be ASCII but contain extended chars.
        # What's that? No, no idea why
        media_body = googleapiclient.http.MediaInMemoryUpload(full_message,
          mimetype='message/rfc822', resumable=True)
        try:
          response = callGAPI(service=restore_serv, function=restore_func,
            userId='me', throw_reasons=['invalidArgument',], media_body=media_body, body=body,
            deleted=options.vault, soft_errors=True, **restore_params)
          exception = None
        except (googleapiclient.errors.HttpError, googleapiclient.errors.MediaUploadSizeError) as e:
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
        callGAPI(gbatch, None, soft_errors=True)
        gbatch = gmail.new_batch_http_request()
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
        callGAPI(gbatch, None, soft_errors=True)
        gbatch = gmail.new_batch_http_request()
        sqlconn.commit()
        current_batch_bytes = 5000
        largest_in_batch = 0
    if len(gbatch._order) > 0:
      rewrite_line("restoring %s messages (%s/%s)" % (len(gbatch._order),
        current, restore_count))
      callGAPI(gbatch, None, soft_errors=True)
      sqlconn.commit()
    print("\n")
    sqlconn.commit()
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

 # RESTORE-MBOX #
  elif options.action == 'restore-mbox':
    if options.batch_size == 0:
      options.batch_size = 5
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
    current_batch_bytes = 5000
    gbatch = gmail.new_batch_http_request()
    restore_serv = gmail.users().messages()
    if options.fast_restore:
      restore_func = 'insert'
      restore_params = {'internalDateSource': 'dateHeader'}
    else:
      restore_func = 'import_'
      restore_params = {'neverMarkSpam': True}
    restore_method = getattr(restore_serv, restore_func)
    max_batch_bytes = 8 * 1024 * 1024
    # Look for Google Vault XML metadata which contains message labels map
    vault_label_map = {}
    if not options.strip_labels:
      for path, subdirs, files in os.walk(options.local_folder):
        for filename in files:
          if filename[-4:].lower() != '.xml':
            continue
          file_path = os.path.join(path, filename)
          print("\nReading Vault labels from %s file %s" % (humansize(file_path), file_path))
          print("large files may take some time to read...")
          for _, elem in etree.iterparse(file_path, events=('end',)):
            if elem.tag == 'Document':
              labels = ''
              fileid = None
              for tag in elem.iter('Tag'):
                if tag.attrib['TagName'] == 'Labels':
                  labels = tag.attrib.get('TagValue', '')
              for file in elem.iter('ExternalFile'):
                fileid = file.attrib.get('FileName', None)
              if fileid and labels:
                vault_label_map[fileid] = labels
              elem.clear()  # keep memory usage down on very large files
    # Look for and restore mbox files
    for path, subdirs, files in os.walk(options.local_folder):
      for filename in files:
        if filename[-4:].lower() != '.mbx' and \
          filename[-5:].lower() != '.mbox':
          continue
        file_path = os.path.join(path, filename)
        print("\nRestoring from %s file %s..." % (humansize(file_path), file_path))
        mbox = fmbox.fmbox(file_path)
        current = 0
        while True:
          current += 1
          message_marker = '%s-%s' % (file_path, current)
          # shorten request_id to prevent content-id errors
          request_id = hashlib.md5(message_marker.encode('utf-8')).hexdigest()[:25]
          if request_id in messages_to_skip:
            rewrite_line(' skipping already restored message #%s' % (current,))
            try:
              mbox.skip()
            except StopIteration:
              break
            continue
          try:
            message = mbox.next()
          except StopIteration:
            break
          if not message.get_header(b'from', case_insensitive=True):
            message.set_headers({b'From': b'Not Set <not@set.net>'})
          mbox_pct = percentage(mbox._mbox_position, mbox._mbox_size)
          deleted = options.vault
          labels = options.label_restored
          if not options.strip_labels:
            if vault_label_map:
              mbox_from = message.get_from()
              mbox_fileid = mbox_from.split('@')[0]
              labels_str = vault_label_map.get(mbox_fileid, '')
            else:
              labels_str = message.get_header(b'X-Gmail-Labels')
            mybytes, encoding = email.header.decode_header(labels_str)[0]
            if encoding != None:
              try:
                labels_str = mybytes.decode(encoding)
              except UnicodeDecodeError:
                pass
            labels = [p.strip(string.whitespace+'\"') for p in re.split("(,|\\\".*?\\\"|'.*?')", labels_str) if p.strip(',')]
          cased_labels = []
          for label in labels:
            if label == '' or label == None:
              labels.remove(label)
              continue
            label = label.strip()
            if label == '^OPENED':
              labels.remove(label)
              continue
            elif label == '^DELETED':
              deleted = True
              labels.remove(label)
              continue
            elif label[0] == '^':
              label = label[1:]
            if label.lower() in reserved_labels:
              label = label.upper()
              if label in ['CHAT', 'CHATS']:
                cased_labels.append('Chats_restored')
                continue
              if label == 'DRAFTS':
                label = 'DRAFT' 
              cased_labels.append(label)
            else:
              cased_labels.append(label)
          labelIds = labelsToLabelIds(cased_labels)
          rewrite_line(" message %s - %s%%" % (current, mbox_pct))
          full_message = message.as_bytes()
          body = {}
          if labelIds:
            body['labelIds'] = labelIds
          b64_message_size = (len(full_message)/3) * 4
          rewrite_line(" reading message %s... - %s%%" % (current, mbox_pct))
          if b64_message_size > 1 * 1024 * 1024:
            # don't batch/raw >1mb messages, just do single
            rewrite_line(" restoring %s message %s - %s%%" % (humansize(b64_message_size),current,mbox_pct))
            media_body = googleapiclient.http.MediaInMemoryUpload(full_message,
              mimetype='message/rfc822', resumable=True)
            try:
              response = callGAPI(service=restore_serv, function=restore_func,
                userId='me', throw_reasons=['invalidArgument',], media_body=media_body, body=body,
                deleted=deleted, soft_errors=True, **restore_params)
              if response == None:
                continue
              exception = None
            except (googleapiclient.errors.HttpError, googleapiclient.errors.MediaUploadSizeError) as e:
              response = None
              exception = e
            restored_message(request_id=request_id, response=response,
              exception=exception)
            rewrite_line(" restored single large message (%s)" % (current,))
            continue
          raw_message = base64.urlsafe_b64encode(full_message).decode('utf-8')
          body['raw'] = raw_message
          current_batch_bytes += len(raw_message)
          if len(gbatch._order) > 0 and current_batch_bytes > max_batch_bytes:
            # this message would put us over max, execute current batch first
            rewrite_line(" restoring %s messages %s - %s%%" % (len(gbatch._order), current, mbox_pct))
            callGAPI(gbatch, None, soft_errors=True)
            gbatch = gmail.new_batch_http_request()
            sqlconn.commit()
            current_batch_bytes = 5000
            largest_in_batch = 0
          gbatch.add(restore_method(userId='me',
            body=body, fields='id',
            deleted=deleted, **restore_params),
            callback=restored_message,
            request_id=request_id)
          if len(gbatch._order) == options.batch_size:
            rewrite_line(" restoring %s messages (%s) - %s%%" % (len(gbatch._order), current, mbox_pct))
            callGAPI(gbatch, None, soft_errors=True)
            gbatch = gmail.new_batch_http_request()
            sqlconn.commit()
            current_batch_bytes = 5000
            largest_in_batch = 0
        if len(gbatch._order) > 0:
          rewrite_line( "restoring %s messages (%s)" % (len(gbatch._order), current,))
          callGAPI(gbatch, None, soft_errors=True)
          sqlconn.commit()
    print('\ndone!')
    sqlconn.commit()
    sqlconn.execute('DETACH mbox_resume')
    sqlconn.commit()

  # RESTORE-GROUP #
  elif options.action == 'restore-group':
    if not options.service_account:  # 3-Legged OAuth
      gmig = buildGAPIObject('groupsmigration')
    else:
      gmig = buildGAPIServiceObject('groupsmigration')
    max_message_size = gmig._rootDesc['resources']['archive']['methods']['insert']['mediaUpload']['maxSize']
    print('Groups supports restore of messages up to %s' % max_message_size)
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
        mimetype='message/rfc822', resumable=True)
      try:
        callGAPI(service=gmig.archive(), function='insert',
          groupId=options.email, media_body=media, soft_errors=True)
      except googleapiclient.errors.MediaUploadSizeError as e:
        print('\n ERROR: Message is to large for groups (%smb limit). \
          Skipping...' % max_message_size)
        continue
      sqlconn.execute(
         'INSERT OR IGNORE INTO restored_messages (message_num) VALUES (?)',
           (message_num,))
      sqlconn.commit()
    sqlconn.commit()
    sqlconn.execute('DETACH resume')
    sqlconn.commit()

  # COUNT 
  elif options.action == 'count':
    if options.batch_size == 0:
      options.batch_size = 100
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', maxResults=500,
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      fields='nextPageToken,messages/id')
    estimate_count = len(messages_to_process)
    print("%s,%s" % (options.email, estimate_count))

  # PURGE #
  elif options.action == 'purge':
    if options.batch_size == 0:
      options.batch_size = 1000
    page_message = 'Got %%total_items%% Message IDs'
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', page_message=page_message,
      userId='me', includeSpamTrash=True, q=options.gmail_search,
      maxResults=500, fields='nextPageToken,messages/id')
    purge_count = len(messages_to_process)
    purged_messages = 0
    i = 0
    purge_chunks = [[]]
    for a_message in messages_to_process:
      purge_chunks[i].append(a_message['id'])
      if len(purge_chunks[i]) == options.batch_size:
        i += 1
        purge_chunks.append([])
      purged_messages += 1
    for purge_chunk in purge_chunks:
      if purge_chunk: # make sure we actually have some IDs
        callGAPI(gmail.users().messages(), function='batchDelete',
          userId='me', body={'ids': purge_chunk})
        rewrite_line("purged %s of %s messages" % (purged_messages, purge_count))
    print("\n")

  # PURGE-LABELS #
  elif options.action == 'purge-labels':
    pattern = options.gmail_search
    safe_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    if pattern == '-is:chat':
      pattern = '.*'
    pattern = re.compile(pattern)
    existing_labels = callGAPI(service=gmail.users().labels(), function='list',
      userId='me', fields='labels(id,name,type)')
    for label_result in existing_labels['labels']:
      if label_result['type'] == 'system' or not \
        pattern.search(label_result['name']):
        continue
      try:
        rewrite_line('Deleting label %s' % label_result['name'])
      except UnicodeEncodeError:
        printable_name = ''.join(c for c in label_result['name'] if c in safe_chars)
        rewrite_line('Deleting label %s' % printable_name)
      callGAPI(service=gmail.users().labels(), function='delete',
        userId='me', id=label_result['id'], soft_errors=True)
    print('\n')

  # PRINT-LABELS #
  elif options.action == 'print-labels':
    labels = callGAPI(service=gmail.users().labels(), function='list',
                               userId='me', fields='labels(id,name,type)')
    user_labels = []
    for label in labels.get('labels'):
      print('%s (%s)' % (label['name'], label['id']))
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
    auth_as = options.use_admin if options.use_admin else options.email
    oauth2file = os.path.join(getProgPath(), '%s.cfg' % auth_as)
    credentials = getOauth2TxtStorageCredentials()
    if credentials is None:
      return
    simplehttp = _createHttpObj()
    params = {'token': credentials.refresh_token}
    revoke_uri = 'https://accounts.google.com/o/oauth2/revoke?%s' % urlencode(params)
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
    simplehttp.request(revoke_uri, 'GET')
    os.remove(oauth2file)

  # ESTIMATE #
  elif options.action == 'estimate':
    if options.batch_size == 0:
      options.batch_size = 100
    page_message = 'Got %%total_items%% Message IDs'
    messages_to_process = callGAPIpages(service=gmail.users().messages(),
      function='list', items='messages', page_message=page_message,
      userId='me', includeSpamTrash=options.spamtrash, q=options.gmail_search,
      maxResults=500, fields='nextPageToken,messages/id')
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
    getSizeOfMessages(messages_to_estimate, gmail)

if __name__ == '__main__':
  if sys.version_info[0] < 3 or sys.version_info[1] < 5:
    print('ERROR: GYB requires Python 3.7 or greater.')
    sys.exit(3)
  try:
    main(sys.argv[1:])
  except MemoryError:
    print('''ERROR: GYB ran out of memory during %s. Try the following:

1) Use a 64-bit version of GYB. It has access to more memory.
2) Add "--memory-limit 100" argument to GYB to reduce memory usage.''' % options.action)
    sys.exit(5)
  except ssl.SSLError as e:
    if e.reason == 'NO_PROTOCOLS_AVAILABLE':
      print('ERROR: %s - Please adjust your --tls-min-version and --tls-max-version arguments.' % e.reason)
    else:
      raise
  except KeyboardInterrupt:
    try:
      sqlconn.commit()
      sqlconn.close()
      print()
    except NameError:
      pass
    sys.exit(4)
