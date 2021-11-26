#!/usr/bin/env python3
import logging
from sniffer import FPMSniffer

def start():
  logging.info('Starting...')
  sniffer = FPMSniffer()
  sniffer.start()
  logging.info("Initialized")
  sniffer.join()

if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  start()
