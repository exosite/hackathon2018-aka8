local tsdb = {}

local R = require('libs.moses')

function tsdb.get(request)
  local query = request.parameters.query

  if not R.isString(query) then
    return {
      code = 400,
      message = {
        error = 'query is not string'
      }
    }
  end

  local options, err = json.parse(query)

  if err then
    return {
      code = 400,
      message = {
        error = err
      }
    }
  end

  local result = Tsdb.query(options)

  if result.error then
    return {
      code = 500,
      message = {
        error = result.error
      }
    }
  end

  return {
    code = 200,
    message = result
  }
end

return tsdb
