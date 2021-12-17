import logging

from lib.logger import logger
import sniffer

def start_sniffing():
  logger.info('Starting...')
  fpm_sniffer = sniffer.FPMSniffer()
  fpm_sniffer.start()
  logger.info("Initialized")
  fpm_sniffer.join()
