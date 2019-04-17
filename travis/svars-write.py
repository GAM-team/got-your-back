import sys
import json
import os

cfg = json.load(sys.stdin)
cfg['client_secret'] = os.getenv('client_secret')
jid = os.getenv('jid')
cfg['refresh_token'] = os.getenv('refresh_%s' % jid)
cfg_file = os.getenv('gyb_user_file')
with open(cfg_file, 'w') as f:
  json.dump(cfg, f)
