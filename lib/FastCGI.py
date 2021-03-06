from enum import IntEnum

class _fcgi_request_type(IntEnum):
  FCGI_BEGIN_REQUEST = 1
  FCGI_ABORT_REQUEST = 2
  FCGI_END_REQUEST = 3
  FCGI_PARAMS = 4
  FCGI_STDIN = 5
  FCGI_STDOUT = 6
  FCGI_STDERR = 7
  FCGI_DATA = 8
  FCGI_GET_VALUES = 9
  FCGI_GET_VALUES_RESULT = 10

class FastCGIDecoder:
  @staticmethod
  def decodeHeader(raw):
    header = dict()
    header['version'] = raw[0]
    header['type'] = raw[1]
    header['requestId'] = (raw[2] << 8) + raw[3]
    header['contentLength'] = (raw[4] << 8) + raw[5]
    header['paddingLength'] = raw[6]
    header['reserved'] = raw[7]
    return header
  
  def decodeParams(raw):
    params = {}
    while len(raw) != 0:
      keyLength = raw[0]
      if keyLength >= 0x80:
        keyLength = ((raw[0] ^ 0x80) << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
        raw = raw[4:]
      else:
        raw = raw[1:]
      valueLength = raw[0]
      if valueLength >= 0x80:
        valueLength = ((raw[0] ^ 0x80) << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
        raw = raw[4:]
      else:
        raw = raw[1:]
      key = raw[:keyLength].decode()
      value = raw[keyLength:keyLength+valueLength].decode()
      raw = raw[keyLength+valueLength:]
      params[key] = value
    return params
      

  @staticmethod
  def decode(raw):
    packets = []
    while len(raw) != 0:
      packet = FastCGIDecoder.decodeHeader(raw)
      raw = raw[8:]
      contentLength = packet['contentLength']
      packet['content'] = raw[:contentLength]
      raw = raw[contentLength:]
      paddingLength = packet['paddingLength']
      raw = raw[paddingLength:]
      packets.append(packet)
      if packet['type'] == _fcgi_request_type.FCGI_PARAMS:
        packet['params'] = FastCGIDecoder.decodeParams(packet['content'])
    return packets

class FastCGIEncoder:
  @staticmethod
  def encode(request_id, type, params = None, version = 1):
    content = b''
    if type == _fcgi_request_type.FCGI_BEGIN_REQUEST:
      content = b'\x00\x01\x00\x00\x00\x00\x00\x00'
    elif type == _fcgi_request_type.FCGI_PARAMS:
      for key, value in params.items():
        key = key.encode()
        value = value.encode()
        key_length = len(key)
        value_length = len(value)
        if key_length < 0x80:
          content += key_length.to_bytes(1, 'big')
        else:
          content += (key_length | 0x80000000).to_bytes(4, 'big')
        if value_length < 0x80:
          content += value_length.to_bytes(1, 'big')
        else:
          content += (value_length | 0x80000000).to_bytes(4, 'big')
        content += key + value
    elif type == _fcgi_request_type.FCGI_STDIN:
      content = params
    packet = b''
    while True:
      packet += version.to_bytes(1, 'big') + type.to_bytes(1, 'big') + request_id.to_bytes(2, 'big')
      if len(content) > 0xffff:
        current_content = content[:0xffff]
        content = content[0xffff:]
      else:
        current_content = content
        content = b''
      padding_len = (8 - (len(current_content) % 8)) % 8
      packet += len(current_content).to_bytes(2, 'big') + padding_len.to_bytes(1, 'big') + b'\x00'
      packet += current_content + padding_len * b'\x00'
      if len(content) == 0:
        break
    if type == _fcgi_request_type.FCGI_PARAMS or type == _fcgi_request_type.FCGI_STDIN:
      packet += version.to_bytes(1, 'big') + type.to_bytes(1, 'big') + request_id.to_bytes(2, 'big') + b'\x00\x00\x00\x00'
    return packet
  
  @staticmethod
  def from_http(http_request: bytes):
    body_seperator = http_request.find(b'\r\n\r\n')
    header_lines = http_request[:body_seperator].split(b'\r\n')
    body = http_request[body_seperator+4:]
    first_line_split = header_lines[0].split(b' ')
    method = first_line_split[0]
    query = b'?'.join(first_line_split[1].split(b'?')[1:])
    uri = first_line_split[1].split(b'?')[0].replace(b'{script_path}', b'/')
    headers = {}
    for header_line in header_lines[1:]:
      split = header_line.split(b':')
      key = split[0].strip()
      value = b':'.join(split[1:]).strip()
      headers[key.decode().lower()] = value
    params = {
      'PATH_INFO': '',
      'SCRIPT_FILENAME': '/var/www/html/index.php',
      'QUERY_STRING': query.decode(),
      'REQUEST_METHOD': method.decode(),
      'CONTENT_TYPE': headers['content-type'].decode() if 'content-type' in headers else '',
      'CONTENT_LENGTH': '' if method == b'GET' else headers['content-length'].decode(),
      'SCRIPT_NAME': '/index.php',
      'REQUEST_URI': uri.decode(),
      'DOCUMENT_URI': '/index.php',
      'DOCUMENT_ROOT': '/var/www/html',
      'SERVER_PROTOCOL': 'HTTP/1.1',
      'REQUEST_SCHEME': 'http',
      'GATEWAY_INTERFACE': 'CGI/1.1',
      'SERVER_SOFTWARE': 'nginx/1.18.0',
      'REMOTE_ADDR': '10.104.252.238',
      'REMOTE_PORT': '50001',
      'SERVER_ADDR': '10.104.252.122',
      'SERVER_PORT': '80',
      'SERVER_NAME': 'sandbox.local',
      'REDIRECT_STATUS': '200'
    }
    for key in headers.keys():
      key: str
      params['HTTP_'+key.replace('-', '_').upper()] = headers[key].decode()
    return params, body
