import argparse
import logging

import sniffer
import model.dataset.raw
import model.train

parser = argparse.ArgumentParser(description='A hybrid php runtime sandbox by Keran Mu for Enterprise Engineering Practice course.')
parser.add_argument('--process_raw', action='store_true', help='Process raw data')
parser.add_argument('--overwrite', action='store_true', help='Overwrite original parsed data')
parser.add_argument('--train', action='store_true', help='Start training')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')

STRUCTURED_DATA_PATH = 'model/dataset/structured/data.sqlite3'

def start_sniffing():
  logging.info('Starting...')
  fpm_sniffer = sniffer.FPMSniffer()
  fpm_sniffer.start()
  logging.info("Initialized")
  fpm_sniffer.join()

def dispatch():
  args = parser.parse_args()
  if args.debug:
    logging.getLogger().setLevel(logging.DEBUG)
  else:
    logging.getLogger().setLevel(logging.INFO)
  if args.process_raw:
    model.dataset.raw.init_database(STRUCTURED_DATA_PATH, args.overwrite)
    model.dataset.raw.process()
    exit(0)
  if args.train:
    model.train.run(STRUCTURED_DATA_PATH)
    exit(0)
  start_sniffing()
