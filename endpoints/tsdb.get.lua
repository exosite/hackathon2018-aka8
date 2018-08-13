--#ENDPOINT GET /tsdb

local p = request.parameters
local R = require('moses')
if R.isString(p.metrics) then
	p.metrics = {p.metrics}
end
response.message = Tsdb.query(p)
