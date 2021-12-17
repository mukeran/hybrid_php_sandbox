import sqlite3
import json
import pandas as pd
import numpy as np
import importlib

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.layers import LSTM
from tensorflow.keras.utils import to_categorical

from lib.logger import logger

required_packages = ['pandas', 'numpy', 'tensorflow', 'tensorflow.keras']

def check():
  not_found_packges = []
  for package in required_packages:
    if importlib.find_loader(package) is None:
      not_found_packges.append(package)
  if len(not_found_packges) != 0:
    logger.error('Please check if those packages are installed: {}'.format(not_found_packges))
    return False
  return True

PHP_FUNCTIONS_CACHE_FILE = 'model/php_functions.json'
CATEGORY_CACHE_FILE = 'model/category.json'

SYSCALL_MODEL = 'model/save/syscall'
PHP_FUNCTION_CALL_MODEL = 'model/save/php_function_call'

SEQUENCE_TRUNCATE_LENGTH = 256

def train_model():
  pass

def load_dataset(sqlite3_file):
  con = sqlite3.connect(sqlite3_file)
  con.row_factory = sqlite3.Row
  cur = con.cursor()

  result = cur.execute('select max(id) as id from serial limit 1').fetchone()
  serial = result['id']

  syscall = []
  php_function_call_raw = []
  category_raw = []
  php_functions = set()

  for row in cur.execute('select syscall, php_function_call, category from data where serial=?', (serial, )):
    tmp = json.loads(row['syscall'])
    if len(tmp) > SEQUENCE_TRUNCATE_LENGTH:
      tmp = tmp[:SEQUENCE_TRUNCATE_LENGTH]
    syscall.append(tmp)
    tmp = json.loads(row['php_function_call'])
    php_functions.update(tmp)
    if len(tmp) > SEQUENCE_TRUNCATE_LENGTH:
      tmp = tmp[:SEQUENCE_TRUNCATE_LENGTH]
    php_function_call_raw.append(tmp)
    category_raw.append(row['category'])

  php_functions = sorted(php_functions)
  php_function_call = []
  for raw in php_function_call_raw:
    php_function_call.append([php_functions.index(name) for name in raw])
  open(PHP_FUNCTIONS_CACHE_FILE, 'w').write(json.dumps(php_functions))

  categories = sorted(set(category_raw))
  category = [categories.index(name) for name in category_raw]
  open(CATEGORY_CACHE_FILE, 'w').write(json.dumps(categories))

  syscall = pd.DataFrame(data=syscall)
  syscall = np.dstack([syscall])
  php_function_call = pd.DataFrame(data=php_function_call)
  php_function_call = np.dstack([php_function_call])
  category = pd.DataFrame(data=category)
  category = to_categorical(category, num_classes=len(categories))
  return syscall, php_function_call, category

def run_part(x, y, save_path):
  epochs, batch_size = 32, 64
  n_timesteps, n_features, n_outputs = x.shape[1], x.shape[2], y.shape[1]

  model = Sequential()
  model.add(LSTM(100, input_shape=(n_timesteps, n_features)))
  model.add(Dense(100, activation='relu'))
  model.add(Dense(n_outputs, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

  model.fit(x, y, epochs=epochs, batch_size=batch_size, verbose=2)
  model.save(save_path)

def run(sqlite3_file):
  syscall, php_function_call, category = load_dataset(sqlite3_file)

  run_part(syscall, category, SYSCALL_MODEL)
  run_part(php_function_call, category, PHP_FUNCTION_CALL_MODEL)
