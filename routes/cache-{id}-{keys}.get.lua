--#ENDPOINT GET /cache/{id}/{keys}
local result = require('controllers.cache').getIdKeys(request)

response.code = result.code
response.message = result.message
