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
      if len(content) > 65535:
        current_content = content[:65535]
        content = content[65535:]
      else:
        current_content = content
        content = b''
      packet += len(current_content).to_bytes(2, 'big') + b'\x00\x00'
      packet += current_content
      if len(content) == 0:
        break
    return packet
