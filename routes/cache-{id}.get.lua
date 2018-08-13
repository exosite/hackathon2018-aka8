--#ENDPOINT GET /cache/{id}
local result = require('controllers.cache').getId(request)

response.code = result.code
response.message = result.message
