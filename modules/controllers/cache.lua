local cache = {}

local L = require('libs.lodash')
local R = require('libs.moses')

function cache.getId(request)
  local id = request.parameters.id

  if not R.isString(id) then
    return {
      code = 400,
      message = {
        error = 'id is not string'
      }
    }
  end

  local getValue = Keystore.get({ key = id }).value

  if not getValue then
    return {
      code = 200,
      message = {}
    }
  end

  local result = R.map(getValue, function(k, v)
    return k, json.parse(v) or 0
  end)

  return {
    code = 200,
    message = result
  }
end

function cache.getIdKeys(request)
  local id = request.parameters.id

  if not R.isString(id) then
    return {
      code = 400,
      message = {
        error = 'id is not string'
      }
    }
  end

  local keys = request.parameters.keys

  if not R.isString(keys) then
    return {
      code = 400,
      message = {
        error = 'keys is not string'
      }
    }
  end

  local getValue = Keystore.get({ key = id }).value

  if not getValue then
    return {
      code = 200,
      message = {}
    }
  end

  local result = R.map(getValue, function(k, v)
    return k, json.parse(v) or 0
  end)

  result = R.pick(result, L.split(keys, ','))

  return {
    code = 200,
    message = result
  }
end

function cache.postIdKey(request)
  local id = request.parameters.id

  if not R.isString(id) then
    return {
      code = 400,
      message = {
        error = 'id is not string'
      }
    }
  end

  local key = request.parameters.key

  if not R.isString(key) then
    return {
      code = 400,
      message = {
        error = 'key is not string'
      }
    }
  end

  local bodyValue = tonumber(request.body.value)

  if R.isNaN(bodyValue) or not R.isFinite(bodyValue) then
    return {
      code = 400,
      message = {
        error = 'value is not number'
      }
    }
  end

  local hgetValue = Keystore.command({
    key = id,
    command = 'hget',
    args = {
      key
    },
  }).value or '{}'

  hgetValue = json.parse(hgetValue) or {}

  if not hgetValue.last then
    hgetValue.last = bodyValue
    hgetValue.max = bodyValue
    hgetValue.min = bodyValue
    hgetValue.sum = bodyValue
    hgetValue.count = 1
    hgetValue.avg = bodyValue
  else
    hgetValue.last = bodyValue
    hgetValue.max = math.max(hgetValue.max, bodyValue)
    hgetValue.min = math.min(hgetValue.min, bodyValue)
    hgetValue.sum = hgetValue.sum + bodyValue
    hgetValue.count = hgetValue.count + 1
    hgetValue.avg = hgetValue.sum / hgetValue.count
  end

  local result = {
    kv = Keystore.command({
      key = id,
      command = 'hset',
      args = {
        key,
        json.stringify(hgetValue)
      }
    }),
    tsdb = Tsdb.write({
      tags = {
        id = id
      },
      metrics = {
        [key] = bodyValue
      }
    })
  }

  return {
    code = 200,
    message = result
  }
end

return cache
