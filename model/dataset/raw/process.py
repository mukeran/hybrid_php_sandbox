import os
import json
import sqlite3
import hashlib
import time
import json

from lib.FastCGI import FastCGIEncoder
from lib.logger import logger
from sandbox import Execution

overwrite = False

def init_database(target, _overwrite):
  global con, overwrite
  overwrite = _overwrite
  con = sqlite3.connect(target)
  con.row_factory = sqlite3.Row
  cur = con.cursor()
  cur.execute('''create table if not exists data (
    category text,
    request_file text,
    request_file_md5 text,
    php_file text,
    php_file_md5 text,
    syscall text,
    php_function_call text,
    suspicious_syscall text,
    suspicious_php_function_call text,
    success integer,
    stdout blob,
    stderr blob,
    timestamp integer,
    serial integer
  )''')
  cur.execute('''create table if not exists serial (
    id integer primary key autoincrement,
    created_at integer
  )''')
  con.commit()

def process():
  global con, overwrite
  cur = con.cursor()
  result = cur.execute('''insert into serial (created_at) values (?)''', (int(time.time()), ))
  con.commit()
  serial = result.lastrowid
  raw_path = os.path.dirname(__file__)
  root_meta = json.load(open(os.path.join(raw_path, 'meta.json'), 'rb'))
  for category in root_meta['categories']:
    category_meta = json.load(open(os.path.join(raw_path, category, 'meta.json')))
    for request in category_meta['requests']:
      http = os.path.join(raw_path, category, request['request_file'])
      php = os.path.join(raw_path, category, request['php_file'])
      http_md5 = hashlib.md5(open(http, 'rb').read()).hexdigest()
      php_md5 = hashlib.md5(open(php, 'rb').read()).hexdigest()
      if not overwrite:
        row = cur.execute('select * from data where category=? and request_file=? and php_file=?', (category, request['request_file'], request['php_file'])).fetchone()
        if not row is None and row['request_file_md5'] == http_md5 and row['php_file_md5'] == php_md5:
          cur.execute('''insert into data
            (category, request_file, request_file_md5, php_file, php_file_md5, syscall, php_function_call, suspicious_syscall, suspicious_php_function_call, success, stdout, stderr, timestamp, serial)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ''', (row['category'], row['request_file'], row['request_file_md5'], row['php_file'], row['php_file_md5'], row['syscall'], row['php_function_call'], row['suspicious_syscall'], row['suspicious_php_function_call'], row['success'], row['stdout'], row['stderr'], row['timestamp'], serial))
          con.commit()
          continue
      params, stdin = FastCGIEncoder.from_http(open(http, 'rb').read())
      execution = Execution(params, stdin, copy_script_path=php)
      copy_file = {}
      if 'copy_file' in request:
        for file in request['copy_file'].keys():
          copy_file[os.path.join(raw_path, category, file)] = request['copy_file'][file]
      logger.info('Executing {}/{}, id: {}'.format(category, request['request_file'], execution.id))
      success, stdout, stderr = execution.execute(copy_file=copy_file)
      logger.debug('syscall: {}'.format(execution.syscall))
      logger.debug('php_function_call: {}'.format(execution.php_function_call))
      logger.debug('suspicious_syscall: {}'.format(execution.suspicious_syscall))
      logger.debug('suspicious_php_function_call: {}'.format(execution.suspicious_php_function_call))
      execution.stop_sandbox()
      execution.stop_server()
      cur.execute('''insert into data
        (category, request_file, request_file_md5, php_file, php_file_md5, syscall, php_function_call, suspicious_syscall, suspicious_php_function_call, success, stdout, stderr, timestamp, serial)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ''', (category, request['request_file'], http_md5, request['php_file'], php_md5, json.dumps(execution.syscall), json.dumps(execution.php_function_call), json.dumps(execution.suspicious_syscall), json.dumps(execution.suspicious_php_function_call), int(success), stdout, stderr, int(time.time()), serial))
      con.commit()
