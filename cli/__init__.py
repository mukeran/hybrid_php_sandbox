import argparse
import importlib

from lib.logger import init

parser = argparse.ArgumentParser(description='A hybrid php runtime sandbox by Keran Mu for Enterprise Engineering Practice course.')
parser.add_argument('--process_raw', action='store_true', help='Process raw data')
parser.add_argument('--overwrite', action='store_true', help='Overwrite original parsed data')
parser.add_argument('--train', action='store_true', help='Start training')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')

STRUCTURED_DATA_PATH = 'model/dataset/structured/data.sqlite3'

def dispatch():
  args = parser.parse_args()
  init(args.debug)
  if args.process_raw:
    importlib.import_module('cli.process_raw').process_raw(STRUCTURED_DATA_PATH, args.overwrite)
  if args.train:
    importlib.import_module('cli.train').train(STRUCTURED_DATA_PATH)
  importlib.import_module('cli.start_sniffing').start_sniffing()
