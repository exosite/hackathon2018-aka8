--#ENDPOINT GET /cache/{id}/{keys}

local p = request.parameters
local id = p.id
local keys = p.keys
response.message = Keystore.get({key = id}).value
