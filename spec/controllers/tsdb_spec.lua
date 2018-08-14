describe('tsdb', function()
  _G.json = {}
  _G.Tsdb = {}

  local tsdb = require('controllers.tsdb')

  describe('get', function()
    it('should return 400 when query is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'query is not string'
        }
      }

      local request = {
        parameters = {}
      }

      local actual = tsdb.get(request)

      assert.is_same(expected, actual)
    end)

    it('should return 400 when failed to parse query', function()
      stub(json, 'parse', function()
        return nil, 'error'
      end)

      local expected = {
        code = 400,
        message = {
          error = 'error'
        }
      }

      local request = {
        parameters = {
          query = 'query'
        }
      }

      local actual = tsdb.get(request)

      assert.is_same(expected, actual)
    end)

    it('should return 500 when failed to query tsdb', function()
      stub(json, 'parse', {})

      stub(Tsdb, 'query', {
        error = 'error'
      })

      local expected = {
        code = 500,
        message = {
          error = 'error'
        }
      }

      local request = {
        parameters = {
          query = 'query'
        }
      }

      local actual = tsdb.get(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200', function()
      stub(json, 'parse', {})

      stub(Tsdb, 'query', {})

      local expected = {
        code = 200,
        message = {}
      }

      local request = {
        parameters = {
          query = 'query'
        }
      }

      local actual = tsdb.get(request)

      assert.is_same(expected, actual)
    end)
  end)
end)
