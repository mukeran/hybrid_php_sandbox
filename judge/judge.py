import base64

from model.predict import predict
from model.train import check

suspicious_openat = [
  b'/etc/passwd', b'/etc/shadow', b'/etc/hosts', b'/proc/self/cmdline', b'/proc/self/environ', b'/proc/net/arp'
]

suspicious_execve = [
  b'/bin/sh', b'/bin/bash', b'/bin/ls'
]

def check_suspicious_syscall(suspicious_syscall):
  for syscall in suspicious_syscall:
    params = base64.b64decode(syscall[1]).strip(b'\x00\x2b')
    if syscall[0] in [2, 257] and params in suspicious_openat:
      return True, 'webshell_exec', 'open/openat {}'.format(params)
    if syscall[0] in [59, 322] and params in suspicious_execve:
      return True, 'webshell_exec', 'execve/execveat {}'.format(params)
    return False, None, None

def judge(syscall, suspicious_syscall, php_function_call, suspicious_php_function_call):
  found, category, reason = check_suspicious_syscall(suspicious_syscall)
  if found:
    return category, 'Found suspicious syscall: {}'.format(reason)
  if len(suspicious_php_function_call) != 0:
    return 'webshell_exec', 'Found suspicious php function call: {}'.format(suspicious_php_function_call)
  category = predict(syscall, php_function_call)
  return category, 'Model predict syscall and php_function_call array as {}'.format(category)
