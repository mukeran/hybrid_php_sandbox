import model.dataset.raw

def process_raw(STRUCTURED_DATA_PATH, overwrite):
  model.dataset.raw.init_database(STRUCTURED_DATA_PATH, overwrite)
  model.dataset.raw.process()
  exit(0)
