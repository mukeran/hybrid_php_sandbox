import json
import pandas as pd
import numpy as np

from tensorflow.keras.models import load_model

from .train import SYSCALL_MODEL, PHP_FUNCTION_CALL_MODEL, PHP_FUNCTIONS_CACHE_FILE, CATEGORY_CACHE_FILE, SEQUENCE_TRUNCATE_LENGTH

def predict(syscall, php_function_call):
  php_functions = json.loads(open(PHP_FUNCTIONS_CACHE_FILE, 'r').read())
  categories = json.loads(open(CATEGORY_CACHE_FILE, 'r').read())

  php_function_call = [php_functions.index(name) for name in php_function_call]

  syscall = pd.DataFrame(data=[syscall, [np.nan for i in range(SEQUENCE_TRUNCATE_LENGTH)]])
  syscall = np.dstack([syscall])
  php_function_call = pd.DataFrame(data=[php_function_call, [np.nan for i in range(SEQUENCE_TRUNCATE_LENGTH)]])
  php_function_call = np.dstack([php_function_call])
  
  syscall_model = load_model(SYSCALL_MODEL)
  php_function_model = load_model(PHP_FUNCTION_CALL_MODEL)
  
  syscall_predict = np.argmax(syscall_model.predict(syscall)[0])
  php_function_model_predict = np.argmax(php_function_model.predict(php_function_call)[0])

  if categories[syscall_predict] == 'normal':
    return categories[php_function_model_predict]
  return categories[syscall_predict]
