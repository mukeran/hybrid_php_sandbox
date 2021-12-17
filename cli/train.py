import model.train

def train(STRUCTURED_DATA_PATH):
  if not model.train.check():
    exit(-1)
  model.train.run(STRUCTURED_DATA_PATH)
  exit(0)
