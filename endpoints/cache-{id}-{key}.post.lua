--#ENDPOINT POST /cache/{id}/{key}

local p = request.parameters
local k = p.key
local v = request.body.value
local id = p.id
local o = Keystore.command({
  key = id,
  command = 'hget',
  args = {k},
}).value or '{}'
o = from_json(o)

local count = o.count
local sum = o.sum
local avg = o.avg
local max = o.max
local min = o.min

if o.last then
  max = math.max(max, v)
  min = math.min(min, v)
  sum = sum + v
  count = count + 1
  avg = sum / count
else
	o = {
		avg = v,
		count = 1,
		last = v,
		max = v,
		min = v,
		sum = v,
	}
end
response.message = o
Keystore.command({
  key = id,
  command = 'hset',
  args = {
	  k,
	  to_json(o),
  }
})
response.message = Keystore.get({key = id}).value
