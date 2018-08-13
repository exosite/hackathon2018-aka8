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

if o.last then
  o.max = math.max(o.max, v)
  o.min = math.min(o.min, v)
  o.sum = o.sum + v
  o.count = o.count + 1
  o.avg = o.sum / o.count
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

response.message = {
	kv = Keystore.command({
		key = id,
		command = 'hset',
		args = {
			k,
			to_json(o),
		}
	}),
	tsdb = Tsdb.write({
		tags = {
			id = id,
		},
		metrics = {
			[k] = v
		},
	})
}
