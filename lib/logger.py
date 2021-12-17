import logging
import coloredlogs

logger: logging.Logger

def init(debug):
  global logger
  logger = logging.getLogger('hybrid_php_sandbox')
  if debug:
    coloredlogs.install(level='DEBUG', logger=logger)
  else:
    coloredlogs.install(level='INFO', logger=logger)
