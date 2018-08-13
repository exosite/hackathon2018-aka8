cache = true

exclude_files = {
  'modules/libs/moses.lua'
}

files.endpoints = {
	globals = {
		'request',
		'response',
	}
}

files.spec = {
	std = '+busted'
}

formatter = 'plain'

globals = {
	'json',
	'Keystore',
	'Tsdb',
}

std = 'lua51'
