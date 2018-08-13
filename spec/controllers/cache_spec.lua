describe('cache', function()
  _G.json = {}
  _G.Keystore = {}
  _G.Tsdb = {}

  local cache = require('controllers.cache')

  describe('getId', function()
    it('should return 400 when id is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'id is not string'
        }
      }

      local request = {
        parameters = {}
      }

      local actual = cache.getId(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200 when value is nil', function()
      stub(Keystore, 'get', {})

      stub(json, 'parse', {})

      local expected = {
        code = 200,
        message = {}
      }

      local request = {
        parameters = {
          id = 'id'
        }
      }

      local actual = cache.getId(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200', function()
      stub(Keystore, 'get', {
        value = {
          k = 'v'
        }
      })

      stub(json, 'parse', {})

      local expected = {
        code = 200,
        message = {
          k = {}
        }
      }

      local request = {
        parameters = {
          id = 'id'
        }
      }

      local actual = cache.getId(request)

      assert.is_same(expected, actual)
    end)
  end)

  describe('getIdKeys', function()
    it('should return 400 when id is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'id is not string'
        }
      }

      local request = {
        parameters = {}
      }

      local actual = cache.getIdKeys(request)

      assert.is_same(expected, actual)
    end)

    it('should return 400 when keys is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'keys is not string'
        }
      }

      local request = {
        parameters = {
          id = 'id'
        }
      }

      local actual = cache.getIdKeys(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200 when value is nil', function()
      stub(Keystore, 'get', {})

      local expected = {
        code = 200,
        message = {}
      }

      local request = {
        parameters = {
          id = 'id',
          keys = 'keys'
        }
      }

      local actual = cache.getIdKeys(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200', function()
      stub(Keystore, 'get', {
        value = {
          k = 'v'
        }
      })

      stub(json, 'parse', {})

      local expected = {
        code = 200,
        message = {
          k = {}
        }
      }

      local request = {
        parameters = {
          id = 'id',
          keys = 'k'
        }
      }

      local actual = cache.getIdKeys(request)

      assert.is_same(expected, actual)
    end)
  end)

  describe('postIdKey', function()
    it('should return 400 when id is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'id is not string'
        }
      }

      local request = {
        parameters = {}
      }

      local actual = cache.postIdKey(request)

      assert.is_same(expected, actual)
    end)

    it('should return 400 when key is not string', function()
      local expected = {
        code = 400,
        message = {
          error = 'key is not string'
        }
      }

      local request = {
        parameters = {
          id = 'id'
        }
      }

      local actual = cache.postIdKey(request)

      assert.is_same(expected, actual)
    end)

    it('should return 400 when value is not finite number', function()
      local expected = {
        code = 400,
        message = {
          error = 'value is not number'
        }
      }

      local request = {
        body = {},
        parameters = {
          id = 'id',
          key = 'key'
        }
      }

      local actual = cache.postIdKey(request)

      assert.is_same(expected, actual)
    end)

    it('should return 200 when hget is empty', function()
      stub(Keystore, 'command')
        .on_call_with({
          key = 'id',
          command = 'hget',
          args = { 'key' }
        })
        .returns({})
        .on_call_with({
          key = 'id',
          command = 'hset',
          args = { 'key', '{"last":1,"max":1,"min":1,"sum":1,"count":1,"avg":1}' }
        })
        .returns({
          value = 1
        })

      stub(json, 'parse')

      stub(json, 'stringify', '{"last":1,"max":1,"min":1,"sum":1,"count":1,"avg":1}')

      stub(Tsdb, 'write', {
        status_code = 204
      })

      local expected = {
        code = 200,
        message = {
          kv = {
            value = 1
          },
          tsdb = {
            status_code = 204
          }
        }
      }

      local request = {
        body = {
          value = 1
        },
        parameters = {
          id = 'id',
          key = 'key'
        }
      }

      local actual = cache.postIdKey(request)

      assert.is_same(expected, actual)
      assert.stub(json.stringify).is_called_with({
        last = 1,
        max = 1,
        min = 1,
        sum = 1,
        count = 1,
        avg = 1
      })
    end)

    it('should return 200 when hget is not empty', function()
      stub(Keystore, 'command')
        .on_call_with({
          key = 'id',
          command = 'hget',
          args = { 'key' }
        })
        .returns('{"last":1,"max":1,"min":1,"sum":1,"count":1,"avg":1}')
        .on_call_with({
          key = 'id',
          command = 'hset',
          args = { 'key', '{"last":2,"max":2,"min":1,"sum":3,"count":2,"avg":1.5}' }
        })
        .returns({
          value = 0
        })

      stub(json, 'parse', {
        last = 1,
        max = 1,
        min = 1,
        sum = 1,
        count = 1,
        avg = 1
      })

      stub(json, 'stringify', '{"last":2,"max":2,"min":1,"sum":3,"count":2,"avg":1.5}')

      stub(Tsdb, 'write', {
        status_code = 204
      })

      local expected = {
        code = 200,
        message = {
          kv = {
            value = 0
          },
          tsdb = {
            status_code = 204
          }
        }
      }

      local request = {
        body = {
          value = 2
        },
        parameters = {
          id = 'id',
          key = 'key'
        }
      }

      local actual = cache.postIdKey(request)

      assert.is_same(expected, actual)
      assert.stub(json.stringify).is_called_with({
        last = 2,
        max = 2,
        min = 1,
        sum = 3,
        count = 2,
        avg = 1.5
      })
    end)
  end)
end)
