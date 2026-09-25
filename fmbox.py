#! /usr/bin/env python

# Optimized library for reading mbox files sequentially

import os

class Error(Exception):
    """Raised for module-specific errors."""

class NoSuchMailboxError(Error):
    """The specified mailbox does not exist and won't be created."""

linesep = os.linesep.encode('ascii')

class fmsg():

  def __init__(self, msg_bytes):
    self.msg_bytes = msg_bytes
 
  def get_header(self, header, case_insensitive=False):
    if case_insensitive:
      header = header.lower()
    header_value = b''
    check_folded_header = False
    for line in self.msg_bytes.split(b'\n'):
      if case_insensitive:
        search_line = line.lower()
      else:
        search_line = line
      if check_folded_header:
        if line.startswith(b' ') or line.startswith(b'\t'):
          header_value += line.lstrip()
        else:
          return header_value.decode()
      elif search_line.startswith(b'%s: ' % header):
        header_value = line[len(header)+2:]
        check_folded_header = True
      elif line == '':
        return header_value.decode()
    return header_value.decode()

  def set_headers(self, headers):
    new_msg = b''
    for key, value in headers.items():
      new_msg += b'%s: %s\n' % (key, value)
    new_msg += self.msg_bytes
    self.msg_bytes = new_msg

  def remove_header(self, header):
    new_msg = b''
    old_msg = self.msg_bytes.split('\n')
    i = 0
    while True:
      line = old_msg[i]
      i += 1
      if not line.startswith(b'%s: ' % header):
        new_msg += line
      if line == '':
        break
    new_msg += old_msg[i:]
    self.msg_bytes = new_msg

  def set_from(self, _from):
    self._from = _from
    
  def get_from(self):
    return self._from

  def as_bytes(self):
    return self.msg_bytes

class fmbox():

  def __init__(self, path):
    try:
      self._mbox_size = os.stat(path).st_size
      self._file = open(path, 'rb')
    except IOError:
      raise NoSuchMailboxError(path)
    self._mbox_position = self._file.tell()
    first = self._file.readline().replace(linesep, b'')
    if first.startswith(b'From '):
      self._last_from_line = first
    else:
      # Not an mbox. Rewind and treat whole file as one message.
      self._file.seek(0)
      self._last_from_line = b'From MAILER-DAEMON Sat Jan  1 00:00:00 2000'

  def __iter__(self):
    return self

  def next(self):
    if not self._last_from_line:
      raise StopIteration
    msg_bytes = bytearray(b'')
    while True:
      line = self._file.readline()
      if not line or line.startswith(b'From '):
        msg = fmsg(bytes(msg_bytes).replace(linesep, b'\n'))
        msg.set_from(self._last_from_line[5:].decode())
        if line:
          self._last_from_line = line.replace(linesep, b'')
        else:
          self._last_from_line = None
        self._mbox_position = self._file.tell()
        return msg
      else:
        msg_bytes.extend(line)

  def skip(self):
    if not self._last_from_line:
      raise StopIteration
    while True:
      line = self._file.readline()
      if not line:
        raise StopIteration
      elif line.startswith(b'From '):
        self._last_from_line = line.replace(linesep, b'')
        return
