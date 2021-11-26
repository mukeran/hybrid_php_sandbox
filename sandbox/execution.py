import logging
import random
import string
import os
import subprocess
import shutil
import psutil
import signal
import time
from enum import IntEnum
from threading import Thread
from typing import List, Tuple
from socket import socket, AF_UNIX, SOCK_STREAM
from lib.FastCGI import FastCGIEncoder, FastCGIDecoder, _fcgi_request_type

SANDBOX_BASE = os.path.join(os.getcwd(), 'sandbox')

executions = {}

class server_record_type(IntEnum):
  SYSCALL = 1
  PHP_FUNCTION_CALL = 2
  SUSPICIOUS_SYSCALL = 3
  SUSPICIOUS_PHP_FUNCTION_CALL = 4

class Execution:
  syscall: List[int]
  php_function_call: List[str]
  suspicious_syscall: List[Tuple[int, bytes]]
  suspicious_php_function_call: List[Tuple[int, bytes]]

  def __init__(self, params, stdin):
    self.id = ''.join(random.sample(string.ascii_letters, 6))
    self.rootfs = '/tmp/sandbox-{}'.format(self.id)
    self.params = params
    self.stdin = stdin
    self.syscall = []
    self.php_function_call = []
    self.suspicious_syscall = []
    self.suspicious_php_function_call = []
    self.is_sandbox_started = False
    executions[self.id] = self
  
  def init_server(self):
    self.server = socket(AF_UNIX, SOCK_STREAM)
    self.server.bind(os.path.join(self.rootfs, 'run/server.sock'))

  def start_server(self):
    self.server.listen(1)
    while True:
      conn, addr = self.server.accept()
      type = server_record_type(int.from_bytes(conn.recv(1), byteorder='big'))
      length = int.from_bytes(conn.recv(2), byteorder='big')
      data = self.server.recv(length)
      if type == server_record_type.SYSCALL:
        assert length == 4
        self.syscall.append(int.from_bytes(data, byteorder='big'))
      elif type == server_record_type.PHP_FUNCTION_CALL:
        self.php_function_call.append(string(data))
      elif type == server_record_type.SUSPICIOUS_SYSCALL:
        syscall_number = int.from_bytes(data[:4], byteorder='big')
        params = data[4:]
        self.suspicious_syscall.append((syscall_number, params))
      elif type == server_record_type.SUSPICIOUS_PHP_FUNCTION_CALL:
        function_length = int.from_bytes(data[:2], byteorder='big')
        function = string(data[2:2+function_length])
        params = data[2+function_length:]
        self.suspicious_php_function_call.append((function, params))

  def stop_server(self):
    self.server.close()

  def start_sandbox(self):
    # Run sandbox and prepare rootfs
    self.sandbox_process = subprocess.Popen(['./sandbox', self.rootfs, self.id], cwd=SANDBOX_BASE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Wait for sandbox to complete initialization
    while True:
      if os.path.exists(os.path.join(self.rootfs, 'run/.initialized')):
        break
      time.sleep(1)
    # Start observation server
    self.init_server()
    self.server_thread = Thread(target=self.start_server)
    self.server_thread.start()
    # Copy PHP script file
    script_filename: str = self.params['SCRIPT_FILENAME']
    save_path = os.path.join(self.rootfs, script_filename.strip('/'))
    try:
      os.makedirs(os.path.dirname(save_path), 755)
    except FileExistsError:
      pass
    except Exception:
      logging.error('Failed to mkdir {}'.format(save_path))
      return False
    shutil.copyfile(script_filename, save_path)
    os.chmod(save_path, 755)
    # Add FPM parameters
    self.params['EXECUTION_ID'] = self.id
    return True
  
  def stop_sandbox(self):
    process = psutil.Process(self.sandbox_process.pid)
    for child in process.children():
      child: psutil.Process
      child.kill()
    process.kill()
    # Prevent <defunct>
    self.sandbox_process.wait()

  def execute(self):
    # Start sandbox first
    if not self.start_sandbox():
      return False, '', ''
    # Connect to sandbox
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(os.path.join(self.rootfs, 'run/php-fpm.sock'))
    # Send FPM request
    sock.send(FastCGIEncoder.encode(1, _fcgi_request_type.FCGI_BEGIN_REQUEST))
    sock.send(FastCGIEncoder.encode(1, _fcgi_request_type.FCGI_PARAMS, self.params))
    sock.send(FastCGIEncoder.encode(1, _fcgi_request_type.FCGI_STDIN, self.stdin))
    stdout = b''
    stderr = b''
    success = False
    # Receive FPM response
    while True:
      header_raw = sock.recv(8)
      if header_raw == None:
        return None, None
      if len(header_raw) < 8:
        return None, None
      header = FastCGIDecoder.decodeHeader(header_raw)
      type = header['type']
      contentLength = header['contentLength']
      paddingLength = header['paddingLength']
      content = b''
      if contentLength != 0:
        content = sock.recv(contentLength)
      if paddingLength != 0:
        sock.recv(paddingLength)
      if type == None:
        break
      if type == _fcgi_request_type.FCGI_STDOUT:
        stdout += content
      elif type == _fcgi_request_type.FCGI_STDERR:
        stderr += content
      elif type == _fcgi_request_type.FCGI_END_REQUEST:
        success = True
        break
    return success, stdout, stderr
