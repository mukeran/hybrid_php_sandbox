import threading
import os
from enum import Enum
from scapy.all import sniff, TCP

from lib.FastCGI import FastCGIDecoder, _fcgi_request_type
from lib.logger import logger, logging
from sandbox import Execution
from judge import judge

PROXY_URL = 'http://127.0.0.1:9001'

class InvalidUnixSocketException(Exception):
  def __init__(self, args):
    super().__init__(args)

class FPMSnifferMode(Enum):
  TCP = 0
  Unix = 1

# lo is a virtual interface, so that one packet can be captured twice (in and out). last_payload is used to ignore two consecutive identical packet.
last_payload = b''

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
    logger.info('FPMSniffer started')

  def join(self):
    self.t.join()

  def parse(self, pkt):
    global last_payload
    payload = bytes(pkt[TCP].payload)
    if len(payload) == 0 or payload == last_payload:
      last_payload = b''
      return
    last_payload = payload
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
        logger.info('New execution: {}, PHP File Path: {}'.format(execution.id, params['SCRIPT_FILENAME']))
        success, stdout, stderr = execution.execute()
        logger.debug('Execution result: {}, {}, {}'.format(success, stdout, stderr))
        logger.debug('Syscall: {}'.format(execution.syscall))
        logger.debug('Suspicious Syscall: {}'.format(execution.suspicious_syscall))
        logger.debug('PHP Function Call: {}'.format(execution.php_function_call))
        logger.debug('Suspicious PHP Function Call: {}'.format(execution.suspicious_php_function_call))
        execution.stop_sandbox()
        execution.stop_server()
        category, reason = judge(execution.syscall, execution.suspicious_syscall, execution.php_function_call, execution.suspicious_php_function_call)
        logger.log(logging.INFO if category == 'normal' else logging.WARNING, 'Judge result: {}, reason: {}'.format(category, reason))
