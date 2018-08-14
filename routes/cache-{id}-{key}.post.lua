--#ENDPOINT POST /cache/{id}/{key}
local result = require('controllers.cache').postIdKey(request)

response.code = result.code
response.message = result.message
