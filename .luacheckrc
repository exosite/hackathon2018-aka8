cache = true

exclude_files = {
  'modules/libs/moses.lua'
}

files.routes = {
  globals = {
    'request',
    'response'
  }
}

files.tests = {
  std = '+busted'
}

formatter = 'plain'

globals = {
  'json',
  'Keystore',
  'Tsdb'
}

std = 'lua51'
