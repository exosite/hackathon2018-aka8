--#ENDPOINT GET /tsdb
local result = require('controllers.tsdb').get(request)

response.code = result.code
response.message = result.message
