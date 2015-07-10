from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(
  console = ['gyb.py'],

  zipfile = None,
  options = {'py2exe': 
              {'optimize': 2,
               'bundle_files': 3,
               'dist_dir' : 'gyb'}
            }
  )
