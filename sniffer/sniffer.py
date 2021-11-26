import logging
import threading
import os
from enum import Enum
from scapy.all import sniff, TCP

from lib.FastCGI import FastCGIDecoder, _fcgi_request_type
from sandbox import Execution

PROXY_URL = 'http://127.0.0.1:9001'

class InvalidUnixSocketException(Exception):
  def __init__(self, args):
    super().__init__(args)

class FPMSnifferMode(Enum):
  TCP = 0
  Unix = 1

class FPMSniffer:
  def __init__(self, mode=FPMSnifferMode.TCP, **kwargs):
    self.mode = mode
    if mode == FPMSnifferMode.TCP:
      self.iface = kwargs['iface'] if 'iface' in kwargs else 'lo'
      self.port = kwargs['port'] if 'port' in kwargs else 9000
    else:
      self.sock = kwargs['sock'] if 'sock' in kwargs else '/run/php/php7.2-fpm.sock'
      self.port = kwargs['port'] if 'port' in kwargs else 9001
      if not os.path.exists(self.sock):
        raise InvalidUnixSocketException

  def start(self):
    if self.mode == FPMSnifferMode.Unix:
      self.originalSock = self.sock + '.original'
      os.system('mv {} {}'.format(self.sock, self.originalSock))
      os.system('socat TCP-LISTEN:{},reuseaddr,fork UNIX-CONNECT:{}'.format(self.port, self.originalSock))
      os.system('socat UNIX-LISTEN:{},fork TCP-CONNECT:127.0.0.1:{}'.format(self.sock, self.port))
    self.t = threading.Thread(
      target=sniff,
      kwargs={ "iface": self.iface, "prn": self.parse, "filter": "tcp and port {}".format(self.port) }
    )
    self.t.start()
    logging.info('FPMSniffer started')

  def join(self):
    self.t.join()

  def parse(self, pkt):
    payload = bytes(pkt[TCP].payload)
    if len(payload) == 0:
      return
    packets = FastCGIDecoder.decode(payload)
    if packets[0]['type'] ==_fcgi_request_type.FCGI_BEGIN_REQUEST:
      params = {}
      stdin = b''
      for packet in packets:
        if packet['type'] == _fcgi_request_type.FCGI_PARAMS:
          params.update(packet['params'])
        elif packet['type'] == _fcgi_request_type.FCGI_STDIN:
          stdin += packet['content']
      if len(params) != 0:
        execution = Execution(params, stdin)
        print(execution.id)
        execution.execute()
        execution.stop_sandbox()
