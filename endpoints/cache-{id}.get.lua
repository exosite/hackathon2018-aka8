--#ENDPOINT GET /cache/{id}

local p = request.parameters
local id = p.id
local keys = p.keys
local R = require('moses')
local L = require('lodash')

local output = R.map(Keystore.get({key = id}).value, function(k, v)
	return k, from_json(v)
end)
response.message = output
