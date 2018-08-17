#!/usr/bin/env python3.7
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
__version__ = '1.1'
__license__ = 'Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)'
__website__ = 'http://git.io/gyb'
__db_schema_version__ = '6'
__db_schema_min_version__ = '6'        #Minimum for restore

global extra_args, options, allLabelIds, allLabels, gmail, reserved_labels, path_divider
extra_args = {'prettyPrint': False}
allLabelIds = dict()
allLabels = dict()
reserved_labels = ['inbox', 'spam', 'trash', 'unread', 'starred', 'important',
  'sent', 'draft', 'chat', 'chats', 'migrated', 'todo', 'todos', 'buzz',
  'bin', 'allmail', 'drafts']

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
import re
import string
from itertools import islice, chain
import base64
import json
import xml.etree.ElementTree as etree

import httplib2
import oauth2client.client
import oauth2client.file
from oauth2client.service_account import ServiceAccountCredentials
import oauth2client.tools
import googleapiclient
import googleapiclient.discovery
import googleapiclient.errors

import fmbox

if os.name == 'windows' or os.name == 'nt':
  path_divider = '\\'
else:
  path_divider = '/'

# Override some oauth2client.tools strings saving us a few GAM-specific mods to oauth2client
oauth2client.tools._FAILED_START_MESSAGE = """
Failed to start a local webserver listening on either port 8080
or port 8090. Please check your firewall settings and locally
running programs that may be blocking or using those ports.

Falling back to nobrowser.txt and continuing with
authorization.
"""

oauth2client.tools._BROWSER_OPENED_MESSAGE = """
Your browser has been opened to visit:

    {address}

If your browser is on a different machine then press CTRL+C and
create a file called nobrowser.txt in the same folder as GYB.
"""

oauth2client.tools._GO_TO_LINK_MESSAGE = """
Go to the following link in your browser:

    {address}
"""

def SetupOptionParser(argv):
  parser = argparse.ArgumentParser(add_help=False)
  #parser.usage = parser.print_help()
  parser.add_argument('--email',
    dest='email',
    help='Full email address of user or group to act against')
  action_choices = ['backup','restore', 'restore-group', 'restore-mbox',
    'count', 'purge', 'purge-labels', 'estimate', 'quota', 'reindex', 'revoke',
    'split-mbox', 'create-project', 'check-service-account']
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
  parser.add_argument('--version',
    action='store_true',
    dest='version',
    help='print GYB version and quit')
  parser.add_argument('--help',
    action='help',
    help='Display this message.')
  return parser.parse_args(argv)

def getProgPath():
  return os.path.dirname(os.path.realpath(sys.argv[0]))+path_divider

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
  if not os.path.exists(CLIENT_SECRETS) and hasattr(sys, '_MEIPASS'):
    CLIENT_SECRETS = os.path.join(sys._MEIPASS, 'client_secrets.json')
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
    FLOW = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS,
      scope=scopes, message=MISSING_CLIENT_SECRETS_MESSAGE, login_hint=auth_as)
    credentials = oauth2client.tools.run_flow(flow=FLOW, storage=storage,
      flags=flags, http=http)
    disable_ssl_certificate_validation = False
    if os.path.isfile(getProgPath()+'noverifyssl.txt'):
      disable_ssl_certificate_validation = True
    http = httplib2.Http(
      disable_ssl_certificate_validation=disable_ssl_certificate_validation)

#
# Read a file
#
def readFile(filename, mode=u'rb', continueOnError=False, displayError=True, encoding=None):
  try:
    if filename != u'-':
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
        stderrWarningMsg(e)
      return None
    systemErrorExit(6, e)
  except (LookupError, UnicodeDecodeError, UnicodeError) as e:
    systemErrorExit(2, str(e))

def doGYBCheckForUpdates(forceCheck=False, debug=False):
  import calendar

  def _LatestVersionNotAvailable():
    if forceCheck:
      systemErrorExit(4, u'GYB Latest Version information not available')

  if options.debug:
    httplib2.debuglevel = 4 
  last_update_check_file = getProgPath()+'lastcheck.txt'
  current_version = __version__
  now_time = calendar.timegm(time.gmtime())
  check_url = 'https://api.github.com/repos/jay0lee/got-your-back/releases' # includes pre-releases
  if not forceCheck:
    last_check_time_str = readFile(last_update_check_file, continueOnError=True, displayError=False)
    last_check_time = int(last_check_time_str) if last_check_time_str and last_check_time_str.isdigit() else 0
    if last_check_time > now_time-604800:
      return
    check_url = check_url + '/latest' # latest full release
  headers = {u'Accept': u'application/vnd.github.v3.text+json'}
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  simplehttp = httplib2.Http(disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  try:
    (_, c) = simplehttp.request(check_url, u'GET', headers=headers)
    try:
      release_data = json.loads(c)
    except ValueError:
      _LatestVersionNotAvailable()
      return
    if isinstance(release_data, list):
      release_data = release_data[0] # only care about latest release
    if not isinstance(release_data, dict) or u'tag_name' not in release_data:
      _gamLatestVersionNotAvailable()
      return
    latest_version = release_data[u'tag_name']
    if latest_version[0].lower() == u'v':
      latest_version = latest_version[1:]
    if forceCheck or (latest_version > current_version):
      print('Version Check:\n Current: {0}\n Latest: {1}'.format(current_version, latest_version))
    if latest_version <= current_version:
      writeFile(last_update_check_file, str(now_time), continueOnError=True, displayError=forceCheck)
      return
    announcement = release_data.get(u'body_text', u'No details about this release')
    sys.stderr.write(u'\nGYB %s release notes:\n\n' % latest_version)
    sys.stderr.write(announcement)
    try:
      print('\n\nHit CTRL+C to visit the GYB website and download the latest release or wait 15 seconds to continue with this boring old version. GYB won\'t bother you with this announcement for 1 week or you can create a file named noupdatecheck.txt in the same location as gyb.py or gyb.exe and GYB won\'t ever check for updates.')
      time.sleep(15)
    except KeyboardInterrupt:
      import webbrowser
      webbrowser.open(release_data[u'html_url'])
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
    message = e.args[0]
    if message in ['access_denied',
                   'unauthorized_client: Unauthorized client or scope in request.',
                   'access_denied: Requested client not authorized.']:
      print('Error: Access Denied. Please make sure the Client Name:\
\n\n%s\n\nis authorized for the API Scope(s):\n\n%s\n\nThis can be \
configured in your Control Panel under:\n\nSecurity -->\nAdvanced \
Settings -->\nManage third party OAuth Client access'
% (credentials.client_id, ','.join(scopes)))
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

def getCRMService(login_hint):
  from oauth2client.contrib.dictionary_storage import DictionaryStorage
  scope = 'https://www.googleapis.com/auth/cloud-platform'
  client_id = '297408095146-fug707qsjv4ikron0hugpevbrjhkmsk7.apps.googleusercontent.com'
  client_secret = 'qM3dP8f_4qedwzWQE1VR4zzU'
  flow = oauth2client.client.OAuth2WebServerFlow(client_id=client_id,
                    client_secret=client_secret, scope=scope, redirect_uri=oauth2client.client.OOB_CALLBACK_URN,
                    access_type=u'online', response_type=u'code', login_hint=login_hint)
  storage_dict = {}
  storage = DictionaryStorage(storage_dict, u'credentials')
  flags = cmd_flags()
  if os.path.isfile(getProgPath()+'nobrowser.txt'):
    flags.noauth_local_webserver = True
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  http = httplib2.Http(disable_ssl_certificate_validation=disable_ssl_certificate_validation)
  try:
    credentials = oauth2client.tools.run_flow(flow=flow, storage=storage, flags=flags, http=http)
  except httplib2.CertificateValidationUnsupported:
    print('ERROR: Your Python installation does not support SSL.')
    sys.exit(3)
  http = credentials.authorize(httplib2.Http(disable_ssl_certificate_validation=disable_ssl_certificate_validation,
                 cache=None))
  return (googleapiclient.discovery.build('cloudresourcemanager', u'v1', http=http, cache_discovery=False), http)

GYB_PROJECT_APIS = 'https://raw.githubusercontent.com/jay0lee/got-your-back/master/project-apis.txt?'
def enableProjectAPIs(httpObj, project_name, checkEnabled):
  simplehttp = httplib2.Http()
  s, c = simplehttp.request(GYB_PROJECT_APIS, 'GET')
  if s.status < 200 or s.status > 299:
    print('ERROR: tried to retrieve %s but got %s' % (GYB_PROJECT_APIS, s.status))
    sys.exit(0)
  apis = c.decode("utf-8").splitlines()
  serveman = googleapiclient.discovery.build('servicemanagement', 'v1', http=httpObj, cache_discovery=False)
  if checkEnabled:
    enabledServices = callGAPIpages(serveman.services(), 'list', 'services',
                                    consumerId=project_name, fields='nextPageToken,services(serviceName)')
    for enabled in enabledServices:
      if 'serviceName' in enabled:
        if enabled['serviceName'] in apis:
          print(' API %s already enabled...' % enabled['serviceName'])
          apis.remove(enabled['serviceName'])
        else:
          print(' API %s (non-GYB) is enabled (which is fine)' % enabled[u'serviceName'])
  for api in apis:
    while True:
      print(' enabling API %s...' % api)
      try:
        callGAPI(serveman.services(), u'enable',
                 throw_reasons=['failedPrecondition'],
                 serviceName=api, body={u'consumerId': project_name})
        break
      except googleapiclient.errors.HttpError as e:
        print('\nThere was an error enabling %s. Please resolve error as described below:' % api)
        print
        print('\n%s\n' % e)
        print
        input('Press enter once resolved and we will try enabling the API again.')

def writeFile(filename, data, mode=u'wb', continueOnError=False, displayError=True):
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

def doCreateProject():
  service_account_file = 'oauth2service.json'
  for a_file in [service_account_file]:
    if os.path.exists(a_file):
      print('File %s already exists. Please delete or rename it before attempting to create another project.' % a_file)
      sys.exit(5)
  if not options.email:
    print('ERROR: the --email argument is required')
    sys.exit(3)
  login_hint = options.email
  login_domain = login_hint[login_hint.find(u'@')+1:]
  crm, httpObj = getCRMService(login_hint)
  project_id = u'gyb-project'
  for i in range(3):
    project_id += u'-%s' % ''.join(random.choice(string.digits + string.ascii_lowercase) for i in range(3))
  project_name = u'project:%s' % project_id
  body = {u'projectId': project_id, u'name': u'Got Your Back Project'}
  while True:
    create_again = False
    print('Creating project "%s"...' % body[u'name'])
    create_operation = callGAPI(crm.projects(), u'create',
                                body=body)
    operation_name = create_operation[u'name']
    time.sleep(5) # Google recommends always waiting at least 5 seconds
    for i in range(1, 5):
      print('Checking project status...')
      status = callGAPI(crm.operations(), u'get',
                        name=operation_name)
      if u'error' in status:
        if status[u'error'].get(u'message', u'') == u'No permission to create project in organization':
          print('Hmm... Looks like you have no rights to your Google Cloud Organization.')
          print('Attempting to fix that...')
          getorg = callGAPI(crm.organizations(), u'search',
                            body={u'filter': u'domain:%s' % login_domain})
          try:
            organization = getorg[u'organizations'][0][u'name']
            print('Your organization name is %s' % organization)
          except (KeyError, IndexError):
            print('you have no rights to create projects for your organization and you don\'t seem to be a super admin! Sorry, there\'s nothing more I can do.')
            sys.exit(3)
          org_policy = callGAPI(crm.organizations(), u'getIamPolicy',
                                resource=organization, body={})
          if u'bindings' not in org_policy:
            org_policy[u'bindings'] = []
            print('Looks like no one has rights to your Google Cloud Organization. Attempting to give you create rights...')
          else:
            print('The following rights seem to exist:')
            for a_policy in org_policy[u'bindings']:
              if u'role' in a_policy:
                print(' Role: %s' % a_policy[u'role'])
              if u'members' in a_policy:
                print(' Members:')
                for member in a_policy[u'members']:
                  print('  %s' % member)
              print
          my_role = u'roles/resourcemanager.projectCreator'
          print('Giving %s the role of %s...' % (login_hint, my_role))
          org_policy[u'bindings'].append({u'role': my_role, u'members': [u'user:%s' % login_hint]})
          callGAPI(crm.organizations(), u'setIamPolicy',
                   resource=organization, body={u'policy': org_policy})
          create_again = True
          break
        try:
          if status[u'error'][u'details'][0][u'violations'][0][u'description'] == u'Callers must accept Terms of Service':
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
      if status.get(u'done', False):
        break
      sleep_time = i ** 2
      print('Project still being created. Sleeping %s seconds' % sleep_time)
      time.sleep(sleep_time)
    if create_again:
      continue
    if not status.get(u'done', False):
      print('Failed to create project: %s' % status)
      sys.exit(1)
    elif u'error' in status:
      print(status[u'error'])
      sys.exit(2)
    break
  disable_ssl_certificate_validation = False
  if os.path.isfile(getProgPath()+'noverifyssl.txt'):
    disable_ssl_certificate_validation = True
  enableProjectAPIs(httpObj, project_name, False)
  iam = googleapiclient.discovery.build(u'iam', u'v1', http=httpObj, cache_discovery=False)
  print('Creating Service Account')
  service_account = callGAPI(iam.projects().serviceAccounts(), u'create',
                             name=u'projects/%s' % project_id,
                             body={u'accountId': project_id, u'serviceAccount': {u'displayName': u'GYB Project Service Account'}})
  key = callGAPI(iam.projects().serviceAccounts().keys(), u'create',
                 name=service_account['name'], body={'privateKeyType': 'TYPE_GOOGLE_CREDENTIALS_FILE', 'keyAlgorithm': u'KEY_ALG_RSA_2048'})
  oauth2service_data = base64.b64decode(key[u'privateKeyData'])
  writeFile(service_account_file, oauth2service_data, continueOnError=False)
  sa_url = 'https://console.developers.google.com/iam-admin/serviceaccounts/project?project=%s' % project_id
  print('''Almost there! Now please go to:

%s

1. Click the 3 dots to the right of your service account.
2. Choose Edit.
3. Check the "Enable G Suite Domain-wide Delegation" box and click Save.
''')
  input('Press Enter when done...')
  print('That\'s it! Your GYB Project is created and ready to use.')

API_SCOPE_MAPPING = {
  u'drive': ['https://www.googleapis.com/auth/drive.appdata',],
  u'gmail': ['https://mail.google.com/',],
  u'groupsmigration': ['https://www.googleapis.com/auth/apps.groups.migration',],
}
def doCheckServiceAccount():
  all_scopes = []
  for _, scopes in API_SCOPE_MAPPING.items():
    for scope in scopes:
      if scope not in all_scopes:
        all_scopes.append(scope)
  all_scopes.sort()
  all_scopes_pass = True
  for scope in all_scopes:
    try:
      credentials = oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name(
          'oauth2service.json', [scope])
      credentials = credentials.create_delegated(options.email)
      credentials.user_agent = getGYBVersion(' | ')
      credentials.refresh(httplib2.Http())
      result = u'PASS'
    except httplib2.ServerNotFoundError as e:
      print(e)
      sys.exit(4)
    except oauth2client.client.HttpAccessTokenRefreshError:
      result = u'FAIL'
      all_scopes_pass = False
    print(' Scope: {0:60} {1}'.format(scope, result))
  if all_scopes_pass:
    print('\nAll scopes passed!\nService account %s is fully authorized.' % credentials.client_id)
    return
  user_domain = options.email[options.email.find(u'@')+1:]
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
    if 'CHATS' in labelIds: # skip CHATS
      return
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
  doGYBCheckForUpdates()
  if options.version:
    print(getGYBVersion())
    sys.exit(0)
  if options.local_folder == 'XXXuse-email-addressXXX':
    options.local_folder = "GYB-GMail-Backup-%s" % options.email

  if options.debug:
    httplib2.debuglevel = 4
  if options.action == 'create-project':
    doCreateProject()
    sys.exit(0)
  elif options.action == 'check-service-account':
    doCheckServiceAccount()
    sys.exit(0)
  elif options.action == 'split-mbox':
    print('split-mbox is no longer necessary and is deprecated. Mbox file size should not impact restore performance in this version.')
    sys.exit(0)

  if not options.email:
    print('ERROR: --email is required.')
    sys.exit(1)
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
      function='list', items='messages', page_message=page_message, maxResults=500,
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
    gbatch = gmail.new_batch_http_request()
    for a_message in messages_to_backup:
      gbatch.add(gmail.users().messages().get(userId='me',
        id=a_message, format='raw',
        fields='id,labelIds,internalDate,raw'),
        callback=backup_message)
      backed_up_messages += 1
      if len(gbatch._order) == options.batch_size:
        callGAPI(gbatch, None, soft_errors=True)
        gbatch = gmail.new_batch_http_request()
        sqlconn.commit()
        rewrite_line("backed up %s of %s messages" %
          (backed_up_messages, backup_count))
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
          (humansize(b65_message_size), current, restore_count))
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
          file_path = '%s%s%s' % (path, path_divider, filename)
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
        file_path = '%s%s%s' % (path, path_divider, filename)
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
          mbox_pct = percentage(mbox._mbox_position, mbox._mbox_size)
          deleted = options.vault
          labels = options.label_restored
          if not options.strip_labels:
            if vault_label_map:
              mbox_from = message.get_from()
              mbox_fileid = mbox_from.split('@')[0]
              labels_str = vault_label_map.get(mbox_fileid, '')
            else:
              labels_str = message.get_header('X-Gmail-Labels')
            mybytes, encoding = email.header.decode_header(labels_str)[0]
            if encoding != None:
              try:
                labels_str = mybytes.decode(encoding)
              except UnicodeDecodeError:
                pass
            labels = labels_str.split(',')
          cased_labels = []
          for label in labels:
            if label == '' or label == None:
              labels.remove(label)
              continue
            elif label == '^OPENED':
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
                label = u'DRAFT' 
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
            except googleapiclient.errors.HttpError as e:
              response = None
              exception = e
            restored_message(request_id=request_id, response=response,
              exception=None)
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
        mimetype='message/rfc822', resumable=True)
      try:
        callGAPI(service=gmig.archive(), function='insert',
          groupId=options.email, media_body=media, soft_errors=True)
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
      callGAPI(gmail.users().messages(), function='batchDelete',
        userId='me', body={'ids': purge_chunk})
      rewrite_line("purged %s of %s messages" % (purged_messages, purge_count))
    print("\n")

  # PURGE-LABELS #
  elif options.action == 'purge-labels':
    pattern = options.gmail_search
    if pattern == '-is:chat':
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
        userId='me', id=label_result['id'], soft_errors=True)
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
    estimate_count = len(messages_to_estimate)
    print("GYB needs to estimate %s messages" % estimate_count)
    estimated_messages = 0
    gbatch = gmail.new_batch_http_request()
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
        gbatch = gmail.new_batch_http_request()
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
  if sys.version_info[0] < 3 or sys.version_info[1] < 5:
    print('ERROR: GYB requires Python 3.5 or greater.')
    sys.exit(3)
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
