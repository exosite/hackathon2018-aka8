package = package or {}
package.loaded = package.loaded or {
  _G = _G,
  coroutine = coroutine,
  debug = debug,
  io = io,
  math = math,
  os = os,
  package = package,
  string = string,
  table = table
}
package.preload = package.preload or {}

require = require or function(modname)
  if package.loaded[modname] == nil then
    assert(package.preload[modname], ("module '%s' not found"):format(modname))
    local mod = package.preload[modname]()
    package.loaded[modname] = mod == nil or mod
  end
  return package.loaded[modname]
end

package.preload['controllers.oauth2'] = function()
-- local Http = require 'http'
local HttpError = require 'http-error'
local R = require 'modules_moses'
local JSON = require 'modules_json'
local Solution = require 'modules_solution'
local KeystoreLogger = require 'keystore_logger'
local SolutionLogger = require 'solution_logger'

local logger = SolutionLogger:new({functionName = "oauth2"})
local Oauth2Controller = {}
Oauth2Controller.supportIntegreation = { "alexa","googlehome","ifttt"}
Oauth2Controller.integration = ""

local function getCurrentUserFromHeaders(headers)
  if type(headers.cookie) == 'string' then
    local _, _, integrationToken = string.find(headers.cookie, 'integrationToken=([^;]+)')
    if type(integrationToken) == 'string' then
      Oauth2Controller.integrationToken = integrationToken
      return _G.getUserByToken(integrationToken)
    end
  end
end

local function setUserIntegration(oauthToken,grant_type)
  local user = _G.getUserByToken(oauthToken.access_token)
  if user == nil or user.id == nil then
    return
  end

  local UserIntegrationModel = require 'user_integration_model'
  local supported = R.include(Oauth2Controller.supportIntegreation, Oauth2Controller.integration)
  if supported then
    oauthToken.timestamp = os.time()
    oauthToken.grant_type = grant_type
    UserIntegrationModel.add(user.id, {
      [Oauth2Controller.integration] = oauthToken,
    })
    oauthToken.timestamp = nil
    oauthToken.userId = user.id
    oauthToken.integration = Oauth2Controller.integration
    KeystoreLogger.log("integrationToken", oauthToken)
    oauthToken.integration = nil
    oauthToken.grant_type = nil
    oauthToken.userId = nil
    _G.__debugMsg(string.format('handel:: setUserIntegration::set::%s', Oauth2Controller.integration))
    logger:notice(
      string.format('%s Account Link Set UserID:%s Type:%s',
      Oauth2Controller.integration,user.id,grant_type)
    )
  end
end

local function getAccessTokenTtl()
  local Constant = require "constant"
  local expires_in = Solution.getSolutionConfig("o_auth_expires_in")
  if expires_in <=0 then
    expires_in = Solution.getSolutionConfig("o_auth_expires_in_default")
  end
  if Oauth2Controller.integration == "googlehome" and
    Constant.GOOGLEHOME_TOKEN_MAX_EXPIRES_IN_SECONDS < expires_in then
    return Constant.GOOGLEHOME_TOKEN_MAX_EXPIRES_IN_SECONDS
  else
    return expires_in
  end
end

local function checkOauthToken(oauthToken)
  if Oauth2Controller.integration == "googlehome" then
    oauthToken.token_type = "bearer"
  end
  return oauthToken
end

local function getAuthorizationCode(req, res, nxt)
  local data = R.pick(req.body, 'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri')
  data["access_token_ttl"] = getAccessTokenTtl()
  local oauthToken =  User.getOauthToken(data)
  if oauthToken.error ~= nil then
    nxt(HttpError:new(400,oauthToken.error))
    return
  end

  oauthToken = checkOauthToken(oauthToken)
  setUserIntegration(oauthToken,req.body.grant_type)
  res:set("Content-Type","application/json")
  res:send(oauthToken)
  logger:notice({message = 'response', payload = oauthToken})
  nxt()
end

local function getRefreshToken(req, res, nxt)
  local data = R.pick(req.body, 'client_id', 'client_secret', 'grant_type', 'refresh_token', 'redirect_uri')
  data["access_token_ttl"] = getAccessTokenTtl()
  local oauthToken =  User.getOauthToken(data)
  if oauthToken.error ~= nil then
    nxt(HttpError:new(400,oauthToken.error))
    return
  end

  oauthToken = checkOauthToken(oauthToken)
  setUserIntegration(oauthToken,req.body.grant_type)
  res:set("Content-Type","application/json")
  res:send(oauthToken)
  logger:notice({message = 'response', payload = oauthToken})
  nxt()
end

function Oauth2Controller.checkIntegration(req, _, nxt)
  local integration = req.parameters.integration
  if not R.find(Oauth2Controller.supportIntegreation, integration) then
    nxt(HttpError:new(404))
    return
  end
  Oauth2Controller.integration = integration
  nxt()
end

function Oauth2Controller.checkOautchClient(req, _, nxt)
  local data = R.pick(req.parameters, 'client_id', 'response_type','redirect_uri')
  data["scope"] = "profile"
  if type(User.getOauthClientRedirectPath(data)) ~= "string" then
    nxt(HttpError:new(404))
    return
  end
  nxt()
end

function Oauth2Controller.loginAction(req, res, nxt)
  res:set('Set-Cookie','integrationToken=expired; path=/;')
  res:set('Content-Type','text/html')
  res:send(_G.getLoginTemplate(string.gsub(req.uri, 'https?://(.-/)(.*)', '%1')))
  -- to big no log
  logger:notice(string.format('%s Account Link Login',Oauth2Controller.integration))
  nxt()
end

function Oauth2Controller.postLogin(req, res, nxt)
  local ret = User.getUserToken({
    email = req.body.email,
    password = req.body.password,
    time_to_live = 60
  })
  if ret ~= nil and ret.error ~= nil then
    local error = from_json(ret.error)
    nxt(HttpError:new(400,error and error.message or ret.error))
    return
  end
  res:set('Set-Cookie','integrationToken=' .. tostring(ret) .. '; path=/;')
  res:send({['token'] = ret})
  logger:notice({message = 'response', payload = {['token'] = ret}})
  nxt()
end

function Oauth2Controller.checkUser(req, _, nxt)
  local user = getCurrentUserFromHeaders(req.headers)
  if user ~= nil and user.id ~= nil then
    Oauth2Controller.user = user
    nxt()
  else
    nxt(HttpError:new(401))
  end
end

function Oauth2Controller.approvedAction(req, res, nxt)
  local data = R.pick(req.parameters, 'client_id', 'response_type','redirect_uri')
  data["scope"] = "profile"
  if Oauth2Controller.user == nil or Oauth2Controller.integrationToken == nil then
    nxt(HttpError:new(401))
    return
  end
  data["token"]= Oauth2Controller.integrationToken
  local code = User.getOauthAuthorizeApproved(data)
  if not R.isNil(code.error) then
    local error = JSON.parse(code.error)
    nxt(HttpError:new(400,error.message))
    return
  end
  local location = req.parameters.redirect_uri .. "?code=" .. tostring(code)
  if not R.isNil(req.parameters.state) then
    location = location .. "&state=" .. req.parameters.state
  end
  res:set('Location',location)
  res.code = 303
  logger:notice({message = 'response', payload = {['Location'] = location}})
  _G.__debugMsg('handel:: approvedAction::location to::' .. location)
  logger:notice(
    string.format('%s Account Link Approved UserID:%s',
    Oauth2Controller.integration,Oauth2Controller.user.id)
  )
  nxt()
end

function Oauth2Controller.tokenAction(req, res, nxt)
  if req.body.grant_type == "authorization_code" then
    getAuthorizationCode(req, res, nxt)
  elseif req.body.grant_type == "refresh_token" then
    getRefreshToken(req, res, nxt)
  else
    nxt(HttpError:new(400))
  end
end

return Oauth2Controller

end

package.preload['monitor'] = function()
-- luacheck: globals ___start_timer ___end_timer tolua ___dispatch

local Monitor = {}

local stack = {}

local function isFatalError(response)
  response = response or {}
  return response.error
end

local function isTableLike(table)
  local tableType = type(table)
  return tableType == 'table' or tableType == 'map' or tableType == 'slice'
end

local function listen(opt)

  local trace = opt.trace or false
  local errorDetail = opt.errorDetail or false

	setmetatable(_G, {
		__index = function(_, missing_global)
			if missing_global ~= missing_global:gsub('^%l', string.upper) then
				return nil
			end
			local service
			service = setmetatable({}, {
					__index = function(_, missing_method)
						local mt = setmetatable({}, {
								__call = function(_, ...)
									local args = {...}
									local service_args = args[1]
									if service_args == nil then
										service_args = {}
									end
									if not isTableLike(service_args) then
                    error(('arguments to %s.%s must be a table'):format(missing_global, missing_method))
									end

                  local start = ___start_timer()
                  local response = tolua(___dispatch(missing_global, missing_method, service_args))
                  local elapsed = ___end_timer(start)

                  if trace then
                    local record = {
                      service = missing_global,
                      method = missing_method,
                      fn = missing_global .. '.' .. missing_method,
                      args = {...},
                      elapsed = elapsed
                    }
                    if response and response.error then
                      record.error = response.error
                      record.status = response.status
                      record.type = response.type
                    end
                    stack[#stack+1] = record
                  end

                  if errorDetail and isFatalError(response) then
                    print(to_json({
                      error = response.error,
                      status = response.status,
                      type = response.type,
                      service = missing_global .. '.' .. missing_method,
                      opt = service_args
                    }))
                  end

                  return response
								end
						})
						rawset(service, missing_method, mt)
						return mt
					end
			})
			rawset(_G, missing_global, service)
			return service
		end
	})
end

local function dump()
	return stack
end

Monitor.dump = dump
Monitor.listen = listen

return Monitor

end

package.preload['user_share'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'
local JSON = require 'modules_json'
local HamvModel = require 'hamv_model'
local DevicePropertyModel = require 'device_property_model'
local DevicePermissionModel = require 'device_permission_model'

local UserShare = {}
UserShare.meta = { __index = Object }
UserShare.KVkey = 'user_share'

local function shareCodeGen()
  local osTime = os.time()
  math.randomseed(osTime)
  local key = ''
  for i = 1, 8 do
    if (math.random(0,1) == 1) then
      key = key .. string.char(math.random(48 ,57))
    else
      key = key .. string.char(math.random(97 ,122))
    end
  end
  return key
end

local function getToken(tokenCode)
  local res = KV.hget(UserShare.KVkey,tokenCode)
  if res ~= nil then
    local info = JSON.parse(res)
    local deviceUsers = DevicePermissionModel.getDeviceUsers(info.deviceSn)
    if os.time() >= info.expTTL or deviceUsers == nil or #deviceUsers > 10 then
      UserShare.removeToken(tokenCode)
      return nil
    end
    return info
  end
  return nil
end

function UserShare.requestToken(user, deviceSn)
  local code = shareCodeGen()
  local shareData = {ownerUser = user, deviceSn = deviceSn ,expTTL = (os.time() + 259200)}
  local res = KV.hset(UserShare.KVkey,code,JSON.stringify(shareData))
  if res ~= 1 then
    return false
  end

  local domain = string.gsub(ws.uri, 'wss?://(.-/)(.*)', '%1')
  return {
    token = code,
    url = 'https://' .. domain .. 'S/' .. code
  }
end

function UserShare.removeToken(tokenCode)
  local res = KV.hdel(UserShare.KVkey, tokenCode)
  return res
end

function UserShare.getTokenInfo(tokenCode)
  return getToken(tokenCode)
end

function UserShare.getTokenInfoTpl(info,url,domain)
  __debugMsg("getTokenInfoTpl.info::" .. JSON.stringify(info))
  local userProperties = DevicePropertyModel.get(info.ownerUser.id,info.deviceSn)
  __debugMsg("getTokenInfoTpl.userProperties::" .. JSON.stringify(userProperties))
  local displayName = ""
  if userProperties~= nil and userProperties.displayName ~=nil then
      displayName = userProperties.displayName
  end
  local email = ""
  if info ~=nil and info.ownerUser.email ~= nil then
    email = info.ownerUser.email
  end
  local button = ""
  local html = [[
      {{head}}
      <h1>To claim your {{product_name}}, please open this link on any phone or tablet with the {{app_name}} app</h1>
      {{footer}}
  ]]
  if url ~= "" then
    button = [[<h4 style="margin-top: 0px;margin-bottom: 0px;">Step 2. Claim device</h4><!-- Button : Begin -->
                                        <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%%;">
                                            <tr>
                                                <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                    <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: 'Nunito Sans', sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                        <span style="color:#ffffff;" class="button-link">Claim {{displayName}}</span>
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Button : END -->]]
    button = button:gsubnil("{{url}}",url)
    button = button:gsubnil("{{displayName}}",displayName)
    button = button:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
    html = [[{{head}}
                                        <h1>Your {{product_name}} is Ready!</h1>
                                        <span>{{email}}</span> is inviting you to use their {{product_name}}. If you don’t have an account yet, make sure to download the {{app_name}} app and create your account first.
                                        <br>
                                        <br>
                                        <h4 style="margin-top: 0px;margin-bottom: 0px;">Step 1. Create an account</h4>
                                        <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                        <tr>
                                            <td style="text-align: center;">
                                                <a href="{{apple_store}}"><img src="/src/assets/img/appStoreBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                            </td>
                                            <td style="text-align: center;">
                                                <a href="{{google_play}}"><img src="/src/assets/img/googlePlayBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                            </td>
                                        </tr>
                                        </table>
                                        <br>
                                        <br>
                                        {{button}}
                                    {{footer}}
    ]]
  end
  html = html:gsubnil("{{product_name}}",getSolutionConfig("product_name"))
  html = html:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  html = html:gsubnil("{{apple_store}}",getSolutionConfig("apple_store"))
  html = html:gsubnil("{{google_play}}",getSolutionConfig("google_play"))

  local head = getTemplateHead("Share " .. ( getSolutionConfig("product_name") or "") .. " Device",domain)
  html = html:gsubnil("{{head}}",head)

  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{url}}",url)
  html = html:gsubnil("{{email}}",email)
  html = html:gsubnil("{{button}}",button)
  -- __debugMsg("getTokenInfoTpl.button::" .. button)
  return html
end

function UserShare.getTokenExpiredTpl(url,domain)
  local html = [[{{head}}
                                      <h1>Sorry, this share link is no longer available</h1>
                                      If you still want to claim this device, please request a new share link from the device owner.
                                      <br><br>
                                      Also, if you don’t have an account yet, make sure to download the {{app_name}} app and create your account.
                                      <br><br>
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                      <tr>
                                          <td style="text-align: center;">
                                              <a href="{{apple_store}}"><img src="/src/assets/img/appStoreBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                          </td>
                                          <td style="text-align: center;">
                                              <a href="{{google_play}}"><img src="/src/assets/img/googlePlayBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                          </td>
                                      </tr>
                                      </table>
                                  {{footer}}
  ]]
  html = html:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  html = html:gsubnil("{{apple_store}}",getSolutionConfig("apple_store"))
  html = html:gsubnil("{{google_play}}",getSolutionConfig("google_play"))

  local head = getTemplateHead("share link expires",domain)
  html = html:gsubnil("{{head}}",head)

  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{domain}}",domain)
  return html:gsubnil("{{url}}",url)
end

return UserShare

end

package.preload['user_permission_model'] = function()
-- luacheck: globals User.assignUser User.deassignUserParam
local KV = require 'modules_kv'
local L = require 'lodash'
local R = require 'modules_moses'
local UserPermissionModel = {}
local OWNER="owner"
local GUEST="guest"

function UserPermissionModel.genStoreKey(userId)
  return "user_"..userId.."_permissions"
end

function UserPermissionModel.genUserPremission(sn, permission)
  return permission.."_"..sn
end

function UserPermissionModel.checkOwnDevicePermission(userId, sn)
  return UserPermissionModel.checkPermission(userId, UserPermissionModel.genUserPremission(sn, OWNER))
end

function UserPermissionModel.checkShareDevicePermission(userId, sn)
  return UserPermissionModel.checkPermission(userId, UserPermissionModel.genUserPremission(sn, GUEST))
end

function UserPermissionModel.checkPermission(userId, deviceRole)
  return KV.sismember(UserPermissionModel.genStoreKey(userId), deviceRole)
end

function UserPermissionModel.checkAnyPermission(userId, sn)
  local permissionSet={UserPermissionModel.genUserPremission(sn, OWNER),
          UserPermissionModel.genUserPremission(sn, GUEST)}
  return R.size(R.intersection(UserPermissionModel.list(userId), permissionSet)) > 0
end

UserPermissionModel.list = R.memoize(function(userId)
  return KV.smembers(UserPermissionModel.genStoreKey(userId))
end)

function UserPermissionModel.getOwnDevices(userId)
  return UserPermissionModel.getDeviceWithRole(userId, OWNER)
end

function UserPermissionModel.getShareDevices(userId)
  return UserPermissionModel.getDeviceWithRole(userId, GUEST)
end

function UserPermissionModel.getDeviceWithRole(userId, role)
  local permissions = UserPermissionModel.list(userId)
  local devices = L.castArray()
  R(permissions)
    :each(function(_, permission)
      local splitResult = L.split(permission,"_")
      if splitResult[1] == role then
        R.push(devices,splitResult[2])
      end
    end)
  return devices
end

function UserPermissionModel.getDevices(userId)
  local permissions = UserPermissionModel.list(userId)
  local devices = R(permissions)
    :map(function(_, permission)
      local splitResult = L.split(permission, '_')
      return splitResult[2]
    end)
    :value()
  return devices
end

function UserPermissionModel.remove(userId, sn, role)
  --TODO check need removeRoleToUserService or not
  return (KV.srem(UserPermissionModel.genStoreKey(userId),
    UserPermissionModel.genUserPremission(sn, role)) ~= nil)
end

function UserPermissionModel.removeOwnDevice(userId, sn)
  return UserPermissionModel.remove(userId, sn, OWNER)
end

function UserPermissionModel.removeShareDevice(userId, sn)
  return UserPermissionModel.remove(userId, sn, GUEST)
end

function UserPermissionModel.removeDevice(userId, sn)
  return UserPermissionModel.removeOwnDevice(userId, sn, OWNER)
          or UserPermissionModel.removeShareDevice(userId, sn, GUEST)
end

function UserPermissionModel.drop(userId)
  local key = UserPermissionModel.genStoreKey(userId)
  return KV.commandOptionBuilder.del(key)
end

function UserPermissionModel.add(userId, sn, role)
  --TODO check need addRoleToUserService or not
  return (KV.sadd(UserPermissionModel.genStoreKey(userId),
    UserPermissionModel.genUserPremission(sn, role)) ~= nil)
end

function UserPermissionModel.addOwnDevice(userId, sn)
  return UserPermissionModel.add(userId, sn, OWNER)
end

function UserPermissionModel.addShareDevice(userId, sn)
  return UserPermissionModel.add(userId, sn, GUEST)
end

function UserPermissionModel.removeRoleToUserService(userId, sn, role)
  local resp = User.deassignUserParam({
    id = userId,
    role_id = role,
    parameter_name = "sn",
    parameter_value = UserPermissionModel.pruneInvalidCharForUSM(sn)
  })
  if resp.error == nil then
    return true
  else
    return false
  end
end

function UserPermissionModel.addRoleToUserService(userId, sn, role)
  local resp = User.assignUser({
    id = userId,
    roles = {{
      role_id = role,
      parameters = {{
        name = "sn",
        value = UserPermissionModel.pruneInvalidCharForUSM(sn)
      }}
    }}
  })
  if resp.error == nil then
    return true
  else
    if role == OWNER then print(('%s device failed to pair with user (%s)'):format(sn, userId)) end
    return false
  end
end

function UserPermissionModel.pruneInvalidCharForUSM(str)
  local after_prune = str:gsub("%p", "")
  return after_prune
end

return UserPermissionModel

end

package.preload['final-handler'] = function()
--[[--
final-handler
@module final-handler
]]
local function getErrorStatusCode(err)
	if type(err.code) == 'number' and err.code >= 400 and err.code < 600 then
		return err.code
	end
end

local function getResponseStatusCode(res)
	local status = res.code

	if status < 400 or status > 599 then
		status = 500
	end

	return status
end

local function finalHandler(err, _, res)
	if err then
		local status = getErrorStatusCode(err) or getResponseStatusCode(res)
		local body = tostring(err)

		res:status(status):json(body)
	end
end

return finalHandler

end

package.preload['yaml'] = function()
local table_print_value
table_print_value = function(value, indent, done)
  indent = indent or 0
  done = done or {}
  if type(value) == "table" and not done [value] then
    done [value] = true

    local list = {}
    for key in pairs (value) do
      list[#list + 1] = key
    end
    table.sort(list, function(a, b) return tostring(a) < tostring(b) end)
    local last = list[#list]

    local rep = "{\n"
    local comma
    for _, key in ipairs (list) do
      if key == last then
        comma = ''
      else
        comma = ','
      end
      local keyRep
      if type(key) == "number" then
        keyRep = key
      else
        keyRep = string.format("%q", tostring(key))
      end
      rep = rep .. string.format(
        "%s[%s] = %s%s\n",
        string.rep(" ", indent + 2),
        keyRep,
        table_print_value(value[key], indent + 2, done),
        comma
      )
    end

    rep = rep .. string.rep(" ", indent) -- indent it
    rep = rep .. "}"

    done[value] = false
    return rep
  elseif type(value) == "string" then
    return string.format("%q", value)
  else
    return tostring(value)
  end
end

local table_print = function(tt)
  print('return '..table_print_value(tt))
end

local table_clone = function(t)
  local clone = {}
  for k,v in pairs(t) do
    clone[k] = v
  end
  return clone
end

local string_trim = function(s, what)
  what = what or " "
  return s:gsub("^[" .. what .. "]*(.-)["..what.."]*$", "%1")
end

local push = function(stack, item)
  stack[#stack + 1] = item
end

local pop = function(stack)
  local item = stack[#stack]
  stack[#stack] = nil
  return item
end

local context = function (str)
  if type(str) ~= "string" then
    return ""
  end

  str = str:sub(0,25):gsub("\n","\\n"):gsub("\"","\\\"");
  return ", near \"" .. str .. "\""
end

local Parser = {}
function Parser.new (self, tokens)
  self.tokens = tokens
  self.parse_stack = {}
  self.refs = {}
  self.current = 0
  return self
end

local exports = {version = "1.2"}

local word = function(w) return "^("..w..")([%s$%c])" end

local tokens = {
  {"comment",   "^#[^\n]*"},
  {"indent",    "^\n( *)"},
  {"space",     "^ +"},
  {"true",      word("enabled"),  const = true, value = true},
  {"true",      word("true"),     const = true, value = true},
  {"true",      word("yes"),      const = true, value = true},
  {"true",      word("on"),      const = true, value = true},
  {"false",     word("disabled"), const = true, value = false},
  {"false",     word("false"),    const = true, value = false},
  {"false",     word("no"),       const = true, value = false},
  {"false",     word("off"),      const = true, value = false},
  {"null",      word("null"),     const = true, value = nil},
  {"null",      word("Null"),     const = true, value = nil},
  {"null",      word("NULL"),     const = true, value = nil},
  {"null",      word("~"),        const = true, value = nil},
  {"id",    "^\"([^\"]-)\" *(:[%s%c])"},
  {"id",    "^'([^']-)' *(:[%s%c])"},
  {"string",    "^\"([^\"]-)\"",  force_text = true},
  {"string",    "^'([^']-)'",    force_text = true},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)%s+(%d%d?):(%d%d):(%d%d)%s+(%-?%d%d?):(%d%d)"},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)%s+(%d%d?):(%d%d):(%d%d)%s+(%-?%d%d?)"},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)%s+(%d%d?):(%d%d):(%d%d)"},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)%s+(%d%d?):(%d%d)"},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)%s+(%d%d?)"},
  {"timestamp", "^(%d%d%d%d)-(%d%d?)-(%d%d?)"},
  {"doc",       "^%-%-%-[^%c]*"},
  {",",         "^,"},
  {"string",    "^%b{} *[^,%c]+", noinline = true},
  {"{",         "^{"},
  {"}",         "^}"},
  {"string",    "^%b[] *[^,%c]+", noinline = true},
  {"[",         "^%["},
  {"]",         "^%]"},
  {"-",         "^%-"},
  {":",         "^:"},
  {"pipe",      "^(|)(%d*[+%-]?)", sep = "\n"},
  {"pipe",      "^(>)(%d*[+%-]?)", sep = " "},
  {"id",        "^([%w][%w %-_]*)(:[%s%c])"},
  {"string",    "^[^%c]+", noinline = true},
  {"string",    "^[^,%c ]+"}
};
exports.tokenize = function (str)
  local token
  local row = 0
  local ignore
  local indents = 0
  local lastIndents
  local stack = {}
  local indentAmount = 0
  local inline = false
  str = str:gsub("\r\n","\010")

  while #str > 0 do
    for i in ipairs(tokens) do
      local captures = {}
      if not inline or tokens[i].noinline == nil then
        captures = {str:match(tokens[i][2])}
      end

      if #captures > 0 then
        captures.input = str:sub(0, 25)
        token = table_clone(tokens[i])
        token[2] = captures
        local str2 = str:gsub(tokens[i][2], "", 1)
        token.raw = str:sub(1, #str - #str2)
        str = str2

        if token[1] == "{" or token[1] == "[" then
          inline = true
        elseif token.const then
          -- Since word pattern contains last char we're re-adding it
          str = token[2][2] .. str
          token.raw = token.raw:sub(1, #token.raw - #token[2][2])
        elseif token[1] == "id" then
          -- Since id pattern contains last semi-colon we're re-adding it
          str = token[2][2] .. str
          token.raw = token.raw:sub(1, #token.raw - #token[2][2])
          -- Trim
          token[2][1] = string_trim(token[2][1])
        elseif token[1] == "string" then
          -- Finding numbers
          local snip = token[2][1]
          if not token.force_text then
            if snip:match("^(%d+%.%d+)$") or snip:match("^(%d+)$") then
              token[1] = "number"
            end
          end

        elseif token[1] == "comment" then
          ignore = true;
        elseif token[1] == "indent" then
          row = row + 1
          inline = false
          lastIndents = indents
          if indentAmount == 0 then
            indentAmount = #token[2][1]
          end

          if indentAmount ~= 0 then
            indents = (#token[2][1] / indentAmount);
          else
            indents = 0
          end

          if indents == lastIndents then
            ignore = true;
          elseif indents > lastIndents + 2 then
            error("SyntaxError: invalid indentation, got " .. tostring(indents)
              .. " instead of " .. tostring(lastIndents) .. context(token[2].input))
          elseif indents > lastIndents + 1 then
            push(stack, token)
          elseif indents < lastIndents then
            local input = token[2].input
            token = {"dedent", {"", input = ""}}
            token.input = input
            while lastIndents > indents + 1 do
              lastIndents = lastIndents - 1
              push(stack, token)
            end
          end
        end -- if token[1] == XXX
        token.row = row
        break
      end -- if #captures > 0
    end

    if not ignore then
      if token then
        push(stack, token)
        token = nil
      else
        error("SyntaxError " .. context(str))
      end
    end

    ignore = false;
  end

  return stack
end

Parser.peek = function (self, offset)
  offset = offset or 1
  return self.tokens[offset + self.current]
end

Parser.advance = function (self)
  self.current = self.current + 1
  return self.tokens[self.current]
end

Parser.advanceValue = function (self)
  return self:advance()[2][1]
end

Parser.accept = function (self, type)
  if self:peekType(type) then
    return self:advance()
  end
end

Parser.expect = function (self, type, msg)
  return self:accept(type) or
    error(msg .. context(self:peek()[1].input))
end

Parser.expectDedent = function (self, msg)
  return self:accept("dedent") or (self:peek() == nil) or
    error(msg .. context(self:peek()[2].input))
end

Parser.peekType = function (self, val, offset)
  return self:peek(offset) and self:peek(offset)[1] == val
end

Parser.ignore = function (self, items)
  local advanced
  repeat
    advanced = false
    for _,v in pairs(items) do
      if self:peekType(v) then
        self:advance()
        advanced = true
      end
    end
  until advanced == false
end

Parser.ignoreSpace = function (self)
  self:ignore{"space"}
end

Parser.ignoreWhitespace = function (self)
  self:ignore{"space", "indent", "dedent"}
end

Parser.parse = function (self)

  local ref = nil
  if self:peekType("string") and not self:peek().force_text then
    local char = self:peek()[2][1]:sub(1,1)
    if char == "&" then
      ref = self:peek()[2][1]:sub(2)
      self:advanceValue()
      self:ignoreSpace()
    elseif char == "*" then
      ref = self:peek()[2][1]:sub(2)
      return self.refs[ref]
    end
  end

  local result
  local c = {
    indent = self:accept("indent") and 1 or 0,
    token = self:peek()
  }
  push(self.parse_stack, c)

  if c.token[1] == "doc" then
    result = self:parseDoc()
  elseif c.token[1] == "-" then
    result = self:parseList()
  elseif c.token[1] == "{" then
    result = self:parseInlineHash()
  elseif c.token[1] == "[" then
    result = self:parseInlineList()
  elseif c.token[1] == "id" then
    result = self:parseHash()
  elseif c.token[1] == "string" then
    result = self:parseString("\n")
  elseif c.token[1] == "timestamp" then
    result = self:parseTimestamp()
  elseif c.token[1] == "number" then
    result = tonumber(self:advanceValue())
  elseif c.token[1] == "pipe" then
    result = self:parsePipe()
  elseif c.token.const == true then
    self:advanceValue();
    result = c.token.value
  else
    error("ParseError: unexpected token '" .. c.token[1] .. "'" .. context(c.token.input))
  end

  pop(self.parse_stack)
  while c.indent > 0 do
    c.indent = c.indent - 1
    local term = "term "..c.token[1]..": '"..c.token[2][1].."'"
    self:expectDedent("last ".. term .." is not properly dedented")
  end

  if ref then
    self.refs[ref] = result
  end
  return result
end

Parser.parseDoc = function (self)
  self:accept("doc")
  return self:parse()
end

Parser.inline = function (self)
  local current = self:peek(0)
  if not current then
    return {}, 0
  end

  local inline = {}
  local i = 0

  while self:peek(i) and not self:peekType("indent", i) and current.row == self:peek(i).row do
    inline[self:peek(i)[1]] = true
    i = i - 1
  end
  return inline, -i
end

Parser.isInline = function (self)
  local _, i = self:inline()
  return i > 0
end

Parser.parent = function(self, level)
  level = level or 1
  return self.parse_stack[#self.parse_stack - level]
end

Parser.parentType = function(self, type, level)
  return self:parent(level) and self:parent(level).token[1] == type
end

Parser.parseString = function (self)
  if self:isInline() then
    local result = self:advanceValue()

    --[[
      - a: this looks
        flowing: but is
        no: string
    --]]
    local types = self:inline()
    if types["id"] and types["-"] then
      if not self:peekType("indent") or not self:peekType("indent", 2) then
        return result
      end
    end

    --[[
      a: 1
      b: this is
        a flowing string
        example
      c: 3
    --]]
    if self:peekType("indent") then
      self:expect("indent", "text block needs to start with indent")
      local addtl = self:accept("indent")

      result = result .. "\n" .. self:parseTextBlock("\n")

      self:expectDedent("text block ending dedent missing")
      if addtl then
        self:expectDedent("text block ending dedent missing")
      end
    end
    return result
  else
    --[[
      a: 1
      b:
        this is also
        a flowing string
        example
      c: 3
    --]]
    return self:parseTextBlock("\n")
  end
end

Parser.parsePipe = function (self)
  local pipe = self:expect("pipe")
  self:expect("indent", "text block needs to start with indent")
  local result = self:parseTextBlock(pipe.sep)
  self:expectDedent("text block ending dedent missing")
  return result
end

Parser.parseTextBlock = function (self, sep)
  local token = self:advance()
  local result = string_trim(token.raw, "\n")
  local indents = 0
  while self:peek() ~= nil and ( indents > 0 or not self:peekType("dedent") ) do
    local newtoken = self:advance()
    while token.row < newtoken.row do
      result = result .. sep
      token.row = token.row + 1
    end
    if newtoken[1] == "indent" then
      indents = indents + 1
    elseif newtoken[1] == "dedent" then
      indents = indents - 1
    else
      result = result .. string_trim(newtoken.raw, "\n")
    end
  end
  return result
end

Parser.parseHash = function (self, hash)
  hash = hash or {}
  local indents = 0

  if self:isInline() then
    local id = self:advanceValue()
    self:expect(":", "expected semi-colon after id")
    self:ignoreSpace()
    if self:accept("indent") then
      indents = indents + 1
      hash[id] = self:parse()
    else
      hash[id] = self:parse()
      if self:accept("indent") then
        indents = indents + 1
      end
    end
    self:ignoreSpace();
  end

  while self:peekType("id") do
    local id = self:advanceValue()
    self:expect(":","expected semi-colon after id")
    self:ignoreSpace()
    hash[id] = self:parse()
    self:ignoreSpace();
  end

  while indents > 0 do
    self:expectDedent("expected dedent")
    indents = indents - 1
  end

  return hash
end

Parser.parseInlineHash = function (self)
  local id
  local hash = {}
  local i = 0

  self:accept("{")
  while not self:accept("}") do
    self:ignoreSpace()
    if i > 0 then
      self:expect(",","expected comma")
    end

    self:ignoreWhitespace()
    if self:peekType("id") then
      id = self:advanceValue()
      if id then
        self:expect(":","expected semi-colon after id")
        self:ignoreSpace()
        hash[id] = self:parse()
        self:ignoreWhitespace()
      end
    end

    i = i + 1
  end
  return hash
end

Parser.parseList = function (self)
  local list = {}
  while self:accept("-") do
    self:ignoreSpace()
    list[#list + 1] = self:parse()

    self:ignoreSpace()
  end
  return list
end

Parser.parseInlineList = function (self)
  local list = {}
  local i = 0
  self:accept("[")
  while not self:accept("]") do
    self:ignoreSpace()
    if i > 0 then
      self:expect(",","expected comma")
    end

    self:ignoreSpace()
    list[#list + 1] = self:parse()
    self:ignoreSpace()
    i = i + 1
  end

  return list
end

Parser.parseTimestamp = function (self)
  local capture = self:advance()[2]

  return os.time{
    year  = capture[1],
    month = capture[2],
    day   = capture[3],
    hour  = capture[4] or 0,
    min   = capture[5] or 0,
    sec   = capture[6] or 0
  }
end

exports.eval = function (str)
  return Parser:new(exports.tokenize(str)):parse()
end

exports.dump = table_print

return exports

end

package.preload['keystore_logger'] = function()
local KV = require('modules_kv')
local R = require('modules_moses')
local JSON = require('modules_json')
local L = require 'lodash'

local KeystoreLogger = {}
KeystoreLogger.size = 10000

local function genStoreKey(name)
  return "logger_" .. name
end

function KeystoreLogger.setLoggerSize(size)
  KeystoreLogger.size = size
end

function KeystoreLogger.log(name, data)
  local storedObject = {
    data = data,
    timestamp = os.time()
  }
  math.randomseed(storedObject.timestamp)
  if math.random(1,10) >= 8 then
    KV.ltrim(genStoreKey(name), 0, KeystoreLogger.size)
  end
  return not R.isNil(KV.lpush(genStoreKey(name),JSON.stringify(storedObject)))
end

function KeystoreLogger.get(name, option)
  local querySize = math.min(math.max(option.querySize or 10, 10), 1000)
  local page = option.page or 1
  local offset = math.max(querySize * (page - 1), 0)
  local logs = KV.lrange(genStoreKey(name), offset, offset + querySize - 1)
  return L.castArray(R.map(logs, function(_, jsonString)
    return JSON.parse(jsonString)
  end))
end

function KeystoreLogger.destroy(name)
  return not R.isNil(KV.del(genStoreKey(name)))
end

return KeystoreLogger

end

package.preload['provision'] = function()
-- luacheck: globals Config
local JWT = require 'jwt'

local Provision = {}

local PROVISION_PRIVATE_KEY = require 'provision_private_token'

function Provision.getUserIdFromProvisionToken(token)
  local payload, err = JWT.decode(token, PROVISION_PRIVATE_KEY, true, 'HS256')
  if err then
    print(to_json(err))
    return nil
  end

  return payload.sub
end

function Provision.createProvisionToken(userId, ttl)
  local iat = os.time()

  -- TODO - use environment variable instead of dynamic check
  local applicationId = (Config.solution() or {}).id
  local productId = (Config.usage() or {hamv={}}).hamv.service

  assert(applicationId, 'application id not found')
  assert(productId, 'product not configured')

  local payload = {
    iat = iat,
    exp = iat + ttl,
    sub = userId,
    aud = applicationId,
    iss = productId
  }

  return JWT.encode(payload, PROVISION_PRIVATE_KEY, 'HS256')
end

return Provision

end

package.preload['user_group_model'] = function()
local L = require 'lodash'
local R = require 'modules_moses'
local JSON = require 'modules_json'
local KV = require 'modules_kv'
local UserGroupModel = {}

function UserGroupModel.get(userId, groupName)
  return  JSON.parse(KV.hget("user_"..userId.."_group",groupName))
end

function UserGroupModel.getAllUserGroups(userId)
  local groups = KV.hgetall("user_"..userId.."_group") or {}
  return R(groups)
    :reduce(function(_groups, group)
      return R.append(_groups, L.castArray(JSON.parse(group)))
    end, L.castArray())
    :compact()
    :value()
end

function UserGroupModel.list(userId)
  return KV.hkeys("user_"..userId.."_group")
end

-- TODO: add lock to this function
function UserGroupModel.removeDeviceFromGroups(userId, sn)
  local groups = KV.hgetall("user_"..userId.."_group") or {}
  local updatedGroups = L.castArray()
  for _, group in pairs(groups) do
    group = JSON.parse(group)
    if R.contains(group.devices, sn) then
      group.devices = L.castArray(R.difference(group.devices or {}, {sn}))
      UserGroupModel.set(userId, group)
      R.push(updatedGroups,group)
    end
  end
  return updatedGroups
end

function UserGroupModel.remove(userId, groupName)
  return KV.hdel("user_"..userId.."_group",groupName) == 1
end

function UserGroupModel.set(userId, group)
  return KV.hset("user_"..userId.."_group",group.name,JSON.stringify(group)) ~= nil
end

function UserGroupModel.drop(userId)
  return KV.delete("user_"..userId.."_group")
end

return UserGroupModel

end

package.preload['common'] = function()
-- luacheck: globals unserialize

local base64 = require 'base64'
local yaml = require 'yaml'

local Common = {}

function Common.tokenstrDec(tokenstr)
  local token = to_json(base64.decode(tokenstr))
  token = token:gsub("\\u0000","")
  token = token:gsub('*',"")
  token = token:gsub('s:12',"s:9")
  token = token:gsub('s:14',"s:11")
  token = token:gsub('s:15',"s:12")
  return unserialize(from_json(token), 0)
end

function Common.getFileContent(path)
  local file = ''
  for line in io.lines(path) do
    file = file .. line .. '\n'
  end
  return file
end

function Common.getYamlFile(path)
  local str = Common.getFileContent(path)
  return yaml.eval(str)
end

return Common

end

package.preload['google_home'] = function()
local KV = require "modules_kv"
local R = require "modules_moses"
local JSON = require "modules_json"
local informationModel = require "information_model"
local HamvModel = require 'hamv_model'
local DevicePermissionModel = require 'device_permission_model'
local UserPermissionModel = require 'user_permission_model'
local DevicePropertyModel = require 'device_property_model'
local SolutionLogger = require 'solution_logger'

local logger = SolutionLogger:new({functionName = "google_home"})
local googleHome = {}
googleHome.meta = { __index = Object }
googleHome.response = {}
googleHome.request = {}
googleHome.userObj = {}

local function googleHomeErrorMessage(message)
    googleHome.response.message = { requestId = googleHome.request.body.requestId, payload = {errorCode = message}}
    __debugMsg("googleHome.response.message::" .. message)
end

local function sendRespons(payload)
    googleHome.response.message = { requestId = googleHome.request.body.requestId, payload = payload}
    __debugMsg("googleHome::sendRespons::".. to_json({ requestId = googleHome.request.body.requestId, payload = payload}) )
    logger:notice({message = 'response', payload = { requestId = googleHome.request.body.requestId, payload = payload} })
end
--TODO function common with alexa
local function decodeSNAndModelFromApplianceId(applianceId)
    if string.match(applianceId, '.*::.*') == applianceId then
        return {
            ["deviceSn"] = string.match(applianceId, '(.*)::.*'),
            ["deviceModel"] = string.match(applianceId, '.*::(.*)')
        }
    end
end

local function sendRequestToDevice(id,deviceSn,code,value)
    local request = {
        ["id"] = id,
        ["request"] = "set",
        ["data"] = {
            [code] = value
        }
    }
    HamvModel.sendSetAction(deviceSn, {[code] = value}, "voiceControlToken_"..id)
end

local function sendRequestToDeviceBefore(deviceSn,before)
    -- id here is not meaningful, cloud be random number
    local id = 99
    for key,value in pairs(before) do
        sendRequestToDevice(id,deviceSn, value.key, value.value)
        id = id + 1
    end
end

local function getDevicePercentage(deviceSn,Percentage)
    local code = Percentage.key
    local status = HamvModel.getDeviceStatus(deviceSn)
    if status[code] ~= nil then
        return status[code]
    end
    return 0
end


local function getDeviceOnOff(deviceSn,On_Off)
    local onCode = On_Off.key
    local onValue = On_Off.values.on
    local status = HamvModel.getDeviceStatus(deviceSn)
    if status[onCode] == onValue then
        return false
    end
    return false
end

local function getDeviceStatus(deviceId)
    local ret = {}
    local data = decodeSNAndModelFromApplianceId(deviceId)
    __debugMsg("googleHome::getDeviceStatus::data::" .. to_json(data))
    if data == nil then
        ret["id"] = deviceId
        ret["status"] = "ERROR"
        ret["errorCode"] = "unknownError"
        return ret
    end

    local ret = {}
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    local userID = googleHome.userObj.id
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    local this_Device_EI = googleHome.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)

    -- __debugMsg("googleHome.getDeviceStatus::online")
    if not HamvModel.isConnected(deviceSn) then
        ret["online"] = false
    else
        ret["online"] = true
    end
    ret["on"] = getDeviceOnOff(deviceSn,this_Device_EI_trait:getTraitAttributes("on_off"))
    __debugMsg("informationGoogleHome.getDeviceStatus::LIGHT")

    if getDisplayType(this_Device_EI_trait) == 'LIGHT' then
        if this_Device_EI_trait:getTraitAttributes("brightness") ~= nil then
            ret["brightness"] = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("brightness"))
        elseif this_Device_EI_trait:getTraitAttributes("percentage") ~= nil then
            ret["brightness"] = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("percentage"))
        end
    end
    return ret
end

local function getDisplayType(deviceTrait)
    local type = deviceTrait:getTraitType()
    local _map = {
        light = "LIGHT",
        switch = "SWITCH",
        smartplug = "OUTLET",
        thermostat = "THERMOSTAT"
    }
    if _map[type] ~= nil then
        return _map[type]
    else
        return "SWITCH"  --default get SWITCH
    end
end

function googleHome.discoverDevice(userID)
    __debugMsg("googleHome::discoverDevice")
    local list  = UserPermissionModel.getDevices(userID)
    local ret = setmetatable({}, { __type = 'slice' })
    if #list ~= 0 and googleHome.externalIntegration ~= nil then
        for key,value in pairs(list) do
            local deviceSn = value
            local this_Device_EI = googleHome.externalIntegration:getMapModelByDeviceSn(deviceSn)
            if this_Device_EI then
                for _key,_value in pairs(this_Device_EI:getTraitsIds()) do
                    local this_Device_EI_trait = this_Device_EI:getTraits(_value)

                    local traits = setmetatable({}, { __type = 'slice' })
                    if this_Device_EI_trait:getTraitAttributes("on_off") ~= nil then
                        R.push(traits, "action.devices.traits.OnOff")
                    end
                    if getDisplayType(this_Device_EI_trait) == 'LIGHT' then
                        if this_Device_EI_trait:getTraitAttributes("brightness") ~= nil then
                            R.push(traits, "action.devices.traits.Brightness")
                        elseif this_Device_EI_trait:getTraitAttributes("percentage") ~= nil then
                            R.push(traits,"action.devices.traits.Brightness")
                        end
                    end

                    local id = deviceSn .. "::" .. _value
                    local name = ""
                    local deviceProperty = DevicePropertyModel.get(userID, deviceSn)
                    if deviceProperty and deviceProperty.displayName then
                        name = deviceProperty.displayName
                    end
                    local APPEND_NAME = this_Device_EI_trait:getTraitAppendName()
                    if APPEND_NAME ~= nil then
                        name = name .. APPEND_NAME
                    end
                    --TODO error handling
                    local esh = HamvModel.getEsh(deviceSn)
                    local data = {
                        ["id"] = id,
                        ["traits"] = traits,
                        ["type"] = "action.devices.types." .. getDisplayType(this_Device_EI_trait),
                        ["name"] = { name = name },
                        ["willReportState"] = false,
                        ["deviceInfo"]= {
                            manufacturer= esh.brand,
                            --TODO error handling
                            model = HamvModel.getModel(deviceSn),
                            hwVersion = esh.esh_version
                        }
                    }
                    R.push(ret, data)
                end
            end
        end
    end
    return ret
end


function googleHome.requestRun(request,userObj,response)
    __debugMsg("googleHome.requestRun")
    googleHome.userObj = userObj
    googleHome.response = response
    googleHome.request = request
    logger:notice({message = 'input', payload = request})
    ok, googleHome.externalIntegration = pcall(function() return informationModel:new():loadExternalIntegration():getExternalIntegration() end)
    if not ok then
        __debugMsg('googleHome:: Error!! informationModel not fund.')
        logger:error('InformationModel not fund!')
        googleHomeErrorMessage("unknownError")
        return
    end
    local inputs = googleHome.request.body.inputs
    if #inputs > 0 then
        for key,value in pairs(inputs) do
            local requestCall = googleHome[value.intent]
            if(requestCall) then
                return requestCall(value)
            end
        end
    end
    __debugMsg("googleHome.requestRun::inputs::" .. to_json(inputs))
    --TODO error handling here
    return true
end

googleHome["action.devices.SYNC"] = function()
    __debugMsg("googleHome.action.devices.SYNC")
    local payload = {}
    payload["agentUserId"] = googleHome.userObj.id .."::"..googleHome.request.timestamp
    payload["devices"] = googleHome.discoverDevice(googleHome.userObj.id)
    __debugMsg("googleHome.action.devices.SYNC::payload::" .. to_json(payload))
    logger:notice(string.format('SYNC discoverDevice UserID:%s',googleHome.userObj.id))
    sendRespons(payload)
end

googleHome["action.devices.EXECUTE"] = function(intent)
    __debugMsg("googleHome.action.devices.EXECUTE::" .. to_json(intent))
    local payload = {commands = {}}

    for key,value in pairs(intent.payload.commands) do
        __debugMsg("googleHome.action.devices.EXECUTE::commands::" .. to_json(value))
        for key2,value2 in pairs(value.devices) do
            local requestCall = googleHome[value.execution[1].command]
                if(requestCall) then
                    local ret = requestCall(value2.id,value.execution[1].params)
                    if ret ~= nil then
                        R.push(payload.commands, ret)
                    end
                end
        end
    end
    sendRespons(payload)
end

googleHome["action.devices.QUERY"] = function(intent)
    __debugMsg("googleHome.action.devices.QUERY::deviceSn::" .. to_json(intent))
    local payload = {devices = {}}

    for key,value in pairs(intent.payload.devices) do
        __debugMsg("googleHome.action.devices.QUERY::devices::" .. to_json(value))
        payload.devices[value.id] = getDeviceStatus(value.id)
    end
    logger:notice(string.format('QUERY UserID:%s',googleHome.userObj.id))
    sendRespons(payload)
end

googleHome["action.devices.commands.OnOff"] = function(deviceId,params)
    -- __debugMsg("googleHome.action.devices.commands.OnOff::deviceId::" .. to_json(deviceId))
    local ret = {
        ids = {deviceId}
    }
    --TODO use refactored decodeSNAndModelFromApplianceId method
    local data = decodeSNAndModelFromApplianceId(deviceId)
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    local userID = googleHome.userObj.id

    if data == nil then
        ret["id"] = deviceId
        ret["status"] = "ERROR"
        ret["errorCode"] = "unknownError"
        return ret
    end

    local switchValue = "on"
    if params.on ~= nil and params.on == false then
        switchValue = "off"
    end
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    if not HamvModel.isConnected(deviceSn) then
        ret["status"] = "OFFLINE"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end
    local this_Device_EI = googleHome.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)

    local deviceOnOffAttributes = this_Device_EI_trait:getTraitAttributes("on_off")
    local code = deviceOnOffAttributes.key
    local setValue = deviceOnOffAttributes.values[switchValue]
    sendRequestToDevice(91,deviceSn,code,setValue)

    if switchValue == "on" then
        ret["states"] ={
            on = true,
            online = true
        }
    else
        ret["states"] ={
            on = false,
            online = true
        }
    end
    ret["status"]= "SUCCESS"
    logger:notice(string.format('OnOff UserID:%s',googleHome.userObj.id))
    return ret
end

googleHome["action.devices.commands.BrightnessAbsolute"] = function(deviceId,params)
    -- __debugMsg("googleHome.action.devices.commands.BrightnessAbsolute::deviceId::" .. to_json(deviceId))
    local ret = {
        ids = {deviceId}
    }
    local data = decodeSNAndModelFromApplianceId(deviceId)
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    local userID = googleHome.userObj.id
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    if not HamvModel.isConnected(deviceSn) then
        ret["status"] = "OFFLINE"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end

    local this_Device_EI = googleHome.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)

    local Percentage = this_Device_EI_trait:getTraitAttributes("brightness")
    if Percentage == nil then
        Percentage = this_Device_EI_trait:getTraitAttributes("percentage")
    end

    local mergedSetValue ={}
    if Percentage.before ~= nil and #Percentage.before > 0 then
        R(Percentage.before)
            :each(function(_, setValueBefore)
              mergedSetValue[setValueBefore.key] = setValueBefore.value
            end)
    end
    local setValue = params.brightness
    local valueMin = Percentage.min
    local valueMax = Percentage.max
    if setValue > valueMax then
        setValue = valueMax
    end
    if setValue < valueMin then
        setValue = valueMin
    end
    -- id=92 here is not meaningful, cloud be random number
    mergedSetValue[Percentage.key] = setValue
    HamvModel.sendSetAction(deviceSn, mergedSetValue, 'voiceControlToken_'..92)

    ret["states"] ={
        on = true,
        online = true
    }
    ret["status"]= "SUCCESS"
    logger:notice(string.format('Brightness UserID:%s',googleHome.userObj.id))
    return ret
end

return googleHome

end

package.preload['lodash'] = function()
--[[--
lodash
@module lodash
]]
local R = require 'modules_moses'

local lodash = {}

local NAN = 0 / 0

--[[--
Casts `value` as an array if it's not one.

@tparam any value The value to inspect.
@treturn table Returns the cast array.
@usage

castArray(1)
-- => { 1 }

castArray({ a = 1 })
-- => { { a = 1 } }

castArray('abc')
-- => { 'abc' }

castArray()
-- => {}

local array = {1, 2, 3}
print(castArray(array) == array)
-- => true
]]
function lodash.castArray(...)
	local args = { ... }
	if (#args == 0) then
		return setmetatable({}, { __type = 'slice' })
	end
	local value = args[1]
	if (not R.isArray(value)) then
		return setmetatable({ value }, { __type = 'slice' })
	end
	if (#value == 0) then
		return setmetatable({}, { __type = 'slice' })
	end
	return value
end

--[[--
Clamps `number` within the inclusive `lower` and `upper` bounds.

@tparam number number The number to clamp.
@tparam number lower The lower bound.
@tparam number upper The upper bound.
@treturn number Returns the clamped number.
@usage

clamp(-10, -5, 5)
-- => -5

clamp(10, -5, 5)
-- => 5
]]
function lodash.clamp(number, lower, upper)
	number = tonumber(number)
	lower = tonumber(lower) or NAN
	upper = tonumber(upper) or NAN
	lower = lower == lower and lower or 0
	upper = upper == upper and upper or 0
	if (number == number) then
		number = number <= upper and number or upper
		number = number >= lower and number or lower
	end
	return number
end

--[[--
Checks if `string` ends with the given target string.

@tparam string str The string to inspect.
@tparam string target The string to search for.
@tparam[opt=#str] int position The position to search up to.
@treturn bool Returns `true` if `string` ends with `target`, else `false`.
@usage

endsWith('abc', 'c')
-- => true

endsWith('abc', 'b')
-- => false

endsWith('abc', 'b', 2)
-- => true
]]
function lodash.endsWith(str, target, position)
	local length = #str
	position = not position and length or tonumber(position) or NAN
	if (position < 0 or position ~= position) then
		position = 0
	elseif (position > length) then
		position = length
	end
	local last = position
	position = position - #target
	return position >= 0 and str:sub(position + 1, last) == target
end

--[[--
Converts the characters "&", "<", ">", '"', and "'" in `string` to their
corresponding HTML entities.

Though the ">" character is escaped for symmetry, characters like
">" and "/" don't need escaping in HTML and have no special meaning
unless they're part of a tag or unquoted attribute value. See
<a href="https://mathiasbynens.be/notes/ambiguous-ampersands"
target="_blank">Mathias Bynens's article</a> (under "semi-related fun fact") for
more details.

When working with HTML you should always
<a href="http://wonko.com/post/html-escaping"
target="_blank">quote attribute values</a> to reduce XSS vectors.

@tparam string str The string to escape.
@treturn string Returns the escaped string.
@usage

escape('fred, barney, & pebbles')
-- => 'fred, barney, &amp pebbles'
]]
function lodash.escape(str)
	local htmlEscapes = {
		['&'] = '&amp;',
		['<'] = '&lt;',
		['>'] = '&gt;',
		['"'] = '&quot;',
		["'"] = '&#39;'
	}
	return str:gsub('[&<>"\']', htmlEscapes)
end

--[[
Checks if `value` is a safe integer. An integer is safe if it's an IEEE-754
double precision number which isn't the result of a rounded unsafe integer.

@tparam any value The value to check.
@treturn bool Returns `true` if `value` is a safe integer, else `false`.
@usage

isSafeInteger(3)
-- => true

isSafeInteger(math.huge)
-- => false

isSafeInteger('3')
-- => false
]]
function lodash.isSafeInteger(value)
	return R.isInteger(value) and R.isFinite(value)
end

--[[--
Computes `number` rounded to `precision`.

@tparam number number The number to round.
@tparam[opt=0] int precision The precision to round to.
@treturn number Returns the rounded number.
@usage

round(4.006)
-- => 4

round(4.006, 2)
-- => 4.01
]]
function lodash.round(number, precision)
	number = tonumber(number) or NAN
	if (number ~= number) then
		return number
	end
	precision = tonumber(precision) or NAN
	if (precision ~= precision) then
		precision = 0
	end
	precision = lodash.clamp(math.floor(precision), 0, 99)
	return tonumber(('%.' .. precision .. 'f'):format(number))
end

--[[--
Splits `string` by `separator`.

@tparam string str The string to split.
@tparam[opt] string separator The separator pattern to split by.
@treturn {table} Returns the string segments.
@usage

split('a-b-c', '-')
-- => { 'a', 'b', 'c' }
]]
function lodash.split(str, separator)
	if (not separator) then
		return lodash.castArray(str)
	end
	separator = separator == '' and '.' or ('([^%s]+)'):format(separator)
	local segments = {}
	str:gsub(separator, function(char)
		segments[#segments + 1] = char
	end)
	return segments
end

--[[--
Checks if `string` starts with the given target string.

@tparam string str The string to inspect.
@tparam string target The string to search for.
@tparam[opt=0] int position The position to search from.
@treturn bool Returns `true` if `string` starts with `target`, else `false`.
@usage

startsWith('abc', 'a')
-- => true

startsWith('abc', 'b')
-- => false

startsWith('abc', 'b', 1)
-- => true
]]
function lodash.startsWith(str, target, position)
	local length = #str
	position = tonumber(position) or 0
	if (position < 0 or position ~= position) then
		position = 0
	elseif (position > length) then
		position = length
	end
	target = tostring(target)
	return str:sub(position + 1, position + #target) == target
end

--[[--
Removes leading and trailing whitespace from `string`.

@tparam string str The string to trim.
@treturn string Returns the trimmed string.
@usage

trim('  abc  ')
-- => 'abc'
]]
function lodash.trim(str)
  return str:match('^%s*(.*%S)') or ''
end

--[[--
The inverse of `escape`this method converts the HTML entities `&amp;`, `&lt;`,
`&gt;`, `&quot;` and `&#39;` in `string` to their corresponding characters.

@tparam string str The string to unescape.
@treturn string Returns the unescaped string.
@usage

unescape('fred, barney, &amp; pebbles')
-- => 'fred, barney, & pebbles'
]]
function lodash.unescape(str)
	local htmlUnescapes = {
		['&lt;'] = '<',
		['&gt;'] = '>',
		['&quot;'] = '"',
		['&#39;'] = "'"
	}
	for entity, chr in pairs(htmlUnescapes) do
		str = str:gsub(entity, chr)
	end
	return str:gsub('&amp;', '&')
end

--[[--
This method is like `fromPairs` except that it accepts two arrays, one of
property identifiers and one of corresponding values.

@todo https://github.com/lodash/lodash/blob/master/zipObject.js
@tparam[opt={}] table props The property identifiers.
@tparam[opt={}] table values The property values.
@treturn table Returns the new object.
@usage

zipObject(['a', 'b'], [1, 2])
-- => { 'a': 1, 'b': 2 }
]]
function lodash.zipObject(props, values)
	local obj = {}
	for index, value in ipairs(props) do
		obj[value] = values[index]
	end
	return obj
end

return lodash

end

package.preload['base64'] = function()
-- Lua 5.1+ base64 v3.0 (c) 2009 by Alex Kloss <alexthkloss@web.de>
-- licensed under the terms of the LGPL2

-- character table string
local base64b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local base64 = {};

-- encoding
function base64.encode(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do
          r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0')
        end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do
          c = c + (x:sub(i,i) == '1' and 2 ^ (6 - i) or 0)
        end
        return base64b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data % 3 + 1])
end

-- decoding
function base64.decode(data)
    data = string.gsub(data, '[^'..base64b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (base64b:find(x) - 1)
        for i = 6, 1, -1 do
          r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0')
        end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then
          return ''
        end
        local c = 0
        for i = 1, 8 do
          c = c + (x:sub(i, i )== '1' and 2 ^ (8 - i) or 0)
        end
        return string.char(c)
    end))
end

return base64

end

package.preload['http-error'] = function()
--[[--
http-error
@module http-error
]]
local Error = require 'error'
local http = require 'http'

local STATUS_CODES = http.STATUS_CODES

--[[--
HttpError
@type HttpError
]]
local HttpError = Error:extend()

--[[--
new
@function HttpError:new
@tparam[opt=500] int code code
@tparam[opt='Internal Server Error'] any message message
@usage
HttpError:new()
HttpError:new(501)
HttpError:new(502, 'Bad Gateway')
HttpError:new(503, { 'Service Unavailable' })
]]
function HttpError:initialize(code, message)
	self.code = code or 500
	self.message = message or STATUS_CODES[self.code]
end

return HttpError

end

package.preload['http'] = function()
--[[--
http
@module http
]]
local http = {}

--[[--
STATUS_CODES
@table STATUS_CODES
@field 100 Continue
@field 101 Switching Protocols
@field 102 Processing
@field 200 OK
@field 201 Created
@field 202 Accepted
@field 203 Non-Authoritative Information
@field 204 No Content
@field 205 Reset Content
@field 206 Partial Content
@field 207 Multi-Status
@field 208 Already Reported
@field 226 IM Used
@field 300 Multiple Choices
@field 301 Moved Permanently
@field 302 Found
@field 303 See Other
@field 304 Not Modified
@field 305 Use Proxy
@field 307 Temporary Redirect
@field 308 Permanent Redirect
@field 400 Bad Request
@field 401 Unauthorized
@field 402 Payment Required
@field 403 Forbidden
@field 404 Not Found
@field 405 Method Not Allowed
@field 406 Not Acceptable
@field 407 Proxy Authentication Required
@field 408 Request Timeout
@field 409 Conflict
@field 410 Gone
@field 411 Length Required
@field 412 Precondition Failed
@field 413 Payload Too Large
@field 414 URI Too Long
@field 415 Unsupported Media Type
@field 416 Range Not Satisfiable
@field 417 Expectation Failed
@field 418 I'm a teapot
@field 421 Misdirected Request
@field 422 Unprocessable Entity
@field 423 Locked
@field 424 Failed Dependency
@field 425 Unordered Collection
@field 426 Upgrade Required
@field 428 Precondition Required
@field 429 Too Many Requests
@field 431 Request Header Fields Too Large
@field 451 Unavailable For Legal Reasons
@field 500 Internal Server Error
@field 501 Not Implemented
@field 502 Bad Gateway
@field 503 Service Unavailable
@field 504 Gateway Timeout
@field 505 HTTP Version Not Supported
@field 506 Variant Also Negotiates
@field 507 Insufficient Storage
@field 508 Loop Detected
@field 509 Bandwidth Limit Exceeded
@field 510 Not Extended
@field 511 Network Authentication Required
]]
http.STATUS_CODES = {
	[100] = 'Continue',
	[101] = 'Switching Protocols',
	[102] = 'Processing',
	[200] = 'OK',
	[201] = 'Created',
	[202] = 'Accepted',
	[203] = 'Non-Authoritative Information',
	[204] = 'No Content',
	[205] = 'Reset Content',
	[206] = 'Partial Content',
	[207] = 'Multi-Status',
	[208] = 'Already Reported',
	[226] = 'IM Used',
	[300] = 'Multiple Choices',
	[301] = 'Moved Permanently',
	[302] = 'Found',
	[303] = 'See Other',
	[304] = 'Not Modified',
	[305] = 'Use Proxy',
	[307] = 'Temporary Redirect',
	[308] = 'Permanent Redirect',
	[400] = 'Bad Request',
	[401] = 'Unauthorized',
	[402] = 'Payment Required',
	[403] = 'Forbidden',
	[404] = 'Not Found',
	[405] = 'Method Not Allowed',
	[406] = 'Not Acceptable',
	[407] = 'Proxy Authentication Required',
	[408] = 'Request Timeout',
	[409] = 'Conflict',
	[410] = 'Gone',
	[411] = 'Length Required',
	[412] = 'Precondition Failed',
	[413] = 'Payload Too Large',
	[414] = 'URI Too Long',
	[415] = 'Unsupported Media Type',
	[416] = 'Range Not Satisfiable',
	[417] = 'Expectation Failed',
	[418] = "I'm a teapot",
	[421] = 'Misdirected Request',
	[422] = 'Unprocessable Entity',
	[423] = 'Locked',
	[424] = 'Failed Dependency',
	[425] = 'Unordered Collection',
	[426] = 'Upgrade Required',
	[428] = 'Precondition Required',
	[429] = 'Too Many Requests',
	[431] = 'Request Header Fields Too Large',
	[451] = 'Unavailable For Legal Reasons',
	[500] = 'Internal Server Error',
	[501] = 'Not Implemented',
	[502] = 'Bad Gateway',
	[503] = 'Service Unavailable',
	[504] = 'Gateway Timeout',
	[505] = 'HTTP Version Not Supported',
	[506] = 'Variant Also Negotiates',
	[507] = 'Insufficient Storage',
	[508] = 'Loop Detected',
	[509] = 'Bandwidth Limit Exceeded',
	[510] = 'Not Extended',
	[511] = 'Network Authentication Required'
}

return http
end

package.preload['locker'] = function()
local M = {}
local EXPIRED_TIME = 10
local KV = require 'modules_kv'

function M:new(obj)
    obj = obj or {}
    self.__index = self
    if self.locked == nil then
        self.locked = {}
    end
    setmetatable(obj, self)
    return obj
end

function M:acquire(trycount)
    -- To ensure the locker without deadlock in the same script running
    local locked, key = self.locked, self.key
    if trycount == nil or trycount == 1 then
        if locked[key] == nil then
            locked[key] = 1
        else
            locked[key] = locked[key] +  1
            return true
        end
    end
    local ret = KV.setnx(key,'true')

    if ret == nil or ret == 0 then
        return false
    end
    -- set an expired time (10s) to lock
    local ret = KV.expire(key,EXPIRED_TIME)

    if ret == nil then
        print("set lock expire error,lock_key="..key)
        -- setting expire time error, abandom this lock
        KV.del(key)
        return false
    end
    return true
end

function M:acquire_retry()
    local kernel = require "kernel"
    params = params or {}
    local max_retry, sleep = params.max_retry or 12, params.sleep or 0.5
    local retry = 0
    for i = 1, max_retry do
      if self:acquire(i) == false then
        retry = retry + 1
        kernel.sleep(sleep)
      else
        break
      end
    end
    if retry == max_retry then
      local ttl = KV.ttl(self.key)
      if (ttl ~= nil) and (ttl < 0) then KV.expire(self.key,EXPIRED_TIME) end
      return false
    end
    return true
end

function M:release()
    -- release lock
    local locked, key = self.locked, self.key
    locked[key] = locked[key] - 1
    if locked[key] == 0 then
        locked[key] = nil
    end
    local ret = KV.delete(key)
    if ret == nil then
        return false
    end
    return true
end

return M

end

package.preload['information_alexa'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'
local L = require 'lodash'
local JSON = require 'modules_json'
local HamvModel = require 'hamv_model'
local DevicePermissionModel = require 'device_permission_model'

local informationAlexa = {}
informationAlexa.meta = { __index = Object }
informationAlexa.KVkey = 'im'
informationAlexa.imData = {}

local function checkBefore(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) == 0 then
        __debugMsg("informationAlexa.checkBefore fail 1" .. type(Obj) .. table.map_length(Obj))
        return false
    end
    for k,v in pairs(Obj) do
        if v.key == nil or type(v.key) ~= 'string' or v.key == "" or v.value == nil or v.value == "" then
            __debugMsg("informationAlexa.checkBefore ".. k .." fail 2::" .. to_json(v))
            return false
        end
    end
    return true
end

local function checkDescription(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 1 then
        __debugMsg("informationAlexa.checkDescription fail 1")
        return false
    end
    if Obj.value == nil and type(Obj.value) ~= 'string' then
        __debugMsg("informationAlexa.checkDescription fail 2")
        return false
    end
    return true
end

local function checkAppendname(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 1 then
        __debugMsg("informationAlexa.checkAppendname fail 1")
        return false
    end
    if Obj.value == nil and type(Obj.value) ~= 'string' then
        __debugMsg("informationAlexa.checkAppendname fail 2")
        return false
    end
    return true
end

local function checkPercentage(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 2 then
        __debugMsg("informationAlexa.checkPercentage fail 1")
        return false
    end
    if Obj.key == nil or Obj.values == nil or type(Obj.values) ~= 'table' then
        __debugMsg("informationAlexa.checkPercentage fail 2")
        return false
    end
    local values = Obj.values
    if values.min == nil or values.min == "" or values.max == nil or values.max == "" then
        __debugMsg("informationAlexa.checkPercentage ON fail 3")
        return false
    end

    --- check if is set before
    if Obj.before ~= nil and checkBefore(Obj.before) == false then
        __debugMsg("informationAlexa.checkPercentage fail 4")
        return false
    end
    return true
end

local function checkOnOff(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) ~= 2 then
        __debugMsg("informationAlexa.checkOnOff fail ON_OFF1")
        return false
    end
    if Obj.ON == nil or Obj.OFF == nil then
        __debugMsg("informationAlexa.checkOnOff fail ON_OFF1")
        return false
    end
    local on = Obj.ON
    if on.key == nil or type(on.key) ~= 'string' or on.key == "" or on.value == nil or on.value == "" then
        __debugMsg("informationAlexa.checkOnOff ON fail 1")
        return false
    end
    local off = Obj.OFF
    if off.key == nil or type(off.key) ~= 'string' or off.key == "" or off.value == nil or off.value == "" then
        __debugMsg("informationAlexa.checkOnOff OFF fail 2::" .. to_json(off))
        return false
    end
    return true
end

local function checkMapDefined(mapObj,mapItems)
    if type(mapObj) ~= 'table' or table.map_length(mapObj) == 0 then
        __debugMsg("informationAlexa.checkMapDefined fail1")
        return false
    end
    -- must have ON_OFF
    if type(mapObj["ON_OFF"]) ~= 'table' or table.map_length(mapObj["ON_OFF"]) == 0 then
        __debugMsg("informationAlexa.checkMapDefined fail2")
        return false
    end
    local appendName = nil

    for k,v in pairs(mapObj) do
        if k == 'ON_OFF' and checkOnOff(v) == false then
            __debugMsg("informationAlexa.checkMapDefined fail ON_OFF ::" .. to_json(v))
            return false
        elseif k == 'PERCENTAGE' and checkPercentage(v) == false then
            __debugMsg("informationAlexa.checkMapDefined fail PERCENTAGE::" .. to_json(v))
            return false
        elseif k == 'DESCRIPTION' and checkDescription(v) == false then
            __debugMsg("informationAlexa.checkMapDefined fail DESCRIPTION::" .. to_json(v))
            return false
        elseif k == 'APPEND_NAME' then
            appendName = checkAppendname(v)
            if appendName == false then
                __debugMsg("informationAlexa.checkMapDefined fail APPEND_NAME::" .. to_json(v))
                return false
            end
        end
    end

    if mapItems > 1 and appendName == nil then
        __debugMsg("informationAlexa.checkMapDefined fail can't find any APPEND_NAME")
        return false
    end
    return true
end

function informationAlexa.verify(jsonObject)
    if jsonObject.externalIntegration.alexa == nil or type(jsonObject.externalIntegration.alexa) ~= 'table' or table.map_length(jsonObject.externalIntegration.alexa) == 0 then
        return false
    end
    local alexa = jsonObject.externalIntegration.alexa
    local mapItems = table.map_length(alexa)
    for k,v in pairs(alexa) do
        __debugMsg("informationAlexa.checkMapDefined::" .. k)
        if checkMapDefined(v,mapItems) == false then
            __debugMsg("informationAlexa.checkMapDefined fail::" .. k)
            return false
        end
    end
    return true
end

function informationAlexa.loadAllModel(imData)
    if imData == nil or table.map_length(imData) < 1 then
        return false
    end
    __debugMsg("informationAlexa.loadAllModel::imData::" .. to_json(imData))
    local ret = {}
    for k,v in pairs(imData) do
        if informationAlexa.verify(v) == false then
            __debugMsg("informationAlexa.loadAllModel::fail::" .. k)
            return false
        elseif v.externalIntegration.alexa ~= nil then
            table.insert(ret, v)
        end
    end
    if table.map_length(ret) < 1 then
        return false
    end
    informationAlexa.imData = ret
    return true
end

local function getMapModel(DeviceModel)
    for key,value in pairs(informationAlexa.imData) do
        for key2,value2 in pairs(value.familyMembers) do
            if string.match(DeviceModel, value2) ~= nil then
                return key
            end
        end
    end
end

local function sendRequestToDevice(id, deviceSn, code, value)
  HamvModel.sendSetAction(deviceSn, {[code] = value})
end
local function sendRequestToDeviceBefore(deviceSn,before)
    local id = 99
    for key,value in pairs(before) do
        sendRequestToDevice(id,deviceSn, value.key, value.value)
        id = id + 1
    end
end

local function getDeviceLatestCodeValue(deviceSn,code)
    local status = HamvModel.getInfo(deviceSn).status
    return status[code] or 0
end

local function getDiscoverDevice(mapModel,deviceSn,alexaDeviceName)
    local data = informationAlexa.imData[mapModel].externalIntegration.alexa
    -- __debugMsg("informationAlexa.getDiscoverDevice::" .. to_json(data))
    local ret = L.castArray()
    for key,value in pairs(data) do
        local actions = L.castArray()
        if value.ON_OFF ~= nil then
            R.push(actions, "turnOn", "turnOff")
        end
        if value.PERCENTAGE ~= nil then
            R.push(actions, "setPercentage", "incrementPercentage", "decrementPercentage")
        end
        local applianceId = deviceSn .. "::" .. key
        local friendlyDescription = ""
        if value.DESCRIPTION ~= nil and value.DESCRIPTION.value ~= nil then
            friendlyDescription = friendlyDescription .. value.DESCRIPTION.value
        end
        local friendlyName = alexaDeviceName
        if value.APPEND_NAME ~= nil and value.APPEND_NAME.value ~= nil then
            friendlyName = friendlyName .. value.APPEND_NAME.value
        end
        local device = HamvModel.getInfo(deviceSn)
        local data = {
            ["actions"] = actions,
            ["additionalApplianceDetails"] = {},
            ["applianceId"] = applianceId,
            ["friendlyDescription"] =  friendlyDescription,
            ["friendlyName"] = friendlyName,
            ["isReachable"] = true,
            ["manufacturerName"]= device.profile.esh.brand,
            ["modelName"]= device.profile.esh.model,
            ["version"]= device.profile.esh.esh_version
        }
        R.push(ret, data)
    end
    return ret
end

function informationAlexa.getDeviceSNandModel(applianceId)
    if string.match(applianceId, '.*::.*') == applianceId then
        return {
            ["deviceSn"] = string.match(applianceId, '(.*)::.*'),
            ["deviceModel"] = string.match(applianceId, '.*::(.*)')
        }
    end
end

function informationAlexa.TurnOnOffRequest(deviceModel,deviceSn,userID,response,message,OnOff)
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        AlexaErrorMessage('NoSuchTargetError',response,message.header)
        return false
    end
    if not HamvModel.getInfo(deviceSn).connected then
        AlexaErrorMessage('TargetOfflineError',response,message.header)
    end

    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    -- __debugMsg("informationAlexa.TurnOnOffRequest::model::" .. to_json(model))
    local mapModel = getMapModel(model)
    -- __debugMsg("informationAlexa.TurnOnOffRequest::mapModel::" .. to_json(mapModel))
    local data = informationAlexa.imData[mapModel].externalIntegration.alexa
    if data[deviceModel].ON_OFF == nil then
        AlexaErrorMessage('DriverInternalError',response,message.header)
    end
    local code = data[deviceModel].ON_OFF[string.upper(OnOff)].key
    local setValue = data[deviceModel].ON_OFF[string.upper(OnOff)].value
    sendRequestToDevice(91,deviceSn,code,setValue)
    __debugMsg("informationAlexa.TurnOnOffRequest::sendRequestToDevice")
    local header = {
        ["messageId"] = message.header.messageId,
        ["name"] = "Turn".. OnOff .."Confirmation",
        ["namespace"] = message.header.namespace,
        ["payloadVersion"] = message.payloadVersion
    }
    local ret = {
        ["header"] = header,
        ["payload"] = {}
    }
    response.message = to_json(ret)
    __debugMsg("informationAlexa.TurnOnOffRequest::message::" .. to_json(ret))
    return true
end

function informationAlexa.SetPercentageRequest(deviceModel,deviceSn,userID,response,message)
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        AlexaErrorMessage('NoSuchTargetError',response,message.header)
        return false
    end
    if not HamvModel.getInfo(deviceSn).connected then
        AlexaErrorMessage('TargetOfflineError',response,message.header)
    end

    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    local mapModel = getMapModel(model)
    local data = informationAlexa.imData[mapModel].externalIntegration.alexa
    if data[deviceModel].PERCENTAGE == nil then
        AlexaErrorMessage('DriverInternalError',response,message.header)
    end
    local setValue = message.payload.percentageState.value
    local code = data[deviceModel].PERCENTAGE.key
    local valueMin = data[deviceModel].PERCENTAGE.values.min
    local valueMax = data[deviceModel].PERCENTAGE.values.max
    if setValue < valueMin or setValue > valueMax then
        AlexaErrorMessage('ValueOutOfRangeError',response,message.header)
    end
    if data[deviceModel].PERCENTAGE.before ~= nil and #data[deviceModel].PERCENTAGE.before > 0 then
        sendRequestToDeviceBefore(deviceSn,data[deviceModel].PERCENTAGE.before)
    end
    __debugMsg("informationAlexa.SetPercentageRequest::sendRequestToDevice")
    sendRequestToDevice(92,deviceSn,code,setValue)
    local header = {
        ["messageId"] = message.header.messageId,
        ["name"] = "SetPercentageConfirmation",
        ["namespace"] = message.header.namespace,
        ["payloadVersion"] = message.payloadVersion
    }
    local ret = {
        ["header"] = header,
        ["payload"] = {}
    }
    response.message = to_json(ret)
    __debugMsg("informationAlexa.SetPercentageRequest::message::" .. to_json(ret))
    return true
end

function informationAlexa.IncrementDecrementPercentageRequest(deviceModel,deviceSn,userID,response,message,IncrementDecrement)
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        AlexaErrorMessage('NoSuchTargetError',response,message.header)
        return false
    end
    if not HamvModel.getInfo(deviceSn).connected then
        AlexaErrorMessage('TargetOfflineError',response,message.header)
    end

    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    local mapModel = getMapModel(model)
    local data = informationAlexa.imData[mapModel].externalIntegration.alexa
    if data[deviceModel].PERCENTAGE == nil then
        AlexaErrorMessage('DriverInternalError',response,message.header)
    end

    local code = data[deviceModel].PERCENTAGE.key
    local valueMin = data[deviceModel].PERCENTAGE.values.min
    local valueMax = data[deviceModel].PERCENTAGE.values.max
    local nowValue = getDeviceLatestCodeValue(deviceSn,code)
    local setValue = message.payload.deltaPercentage.value
    if IncrementDecrement == "Increment" then
        setValue = nowValue + setValue
    elseif IncrementDecrement == "Decrement" then
        setValue = nowValue - setValue
    end
    if setValue < valueMin or setValue > valueMax then
        setValue = valueMin
    end
    if setValue > valueMax then
        setValue = valueMax
    end
    if data[deviceModel].PERCENTAGE.before ~= nil and #data[deviceModel].PERCENTAGE.before > 0 then
        sendRequestToDeviceBefore(deviceSn,data[deviceModel].PERCENTAGE.before)
    end
    __debugMsg("informationAlexa.IncrementDecrementPercentageRequest::sendRequestToDevice")
    sendRequestToDevice(93,deviceSn,code,setValue)
    local header = {
        ["messageId"] = message.header.messageId,
        ["name"] = IncrementDecrement .. "PercentageConfirmation",
        ["namespace"] = message.header.namespace,
        ["payloadVersion"] = message.payloadVersion
    }
    local ret = {
        ["header"] = header,
        ["payload"] = {}
    }
    response.message = to_json(ret)
    __debugMsg("informationAlexa.IncrementDecrementPercentageRequest::message::" .. to_json(ret))
    return true
end

function informationAlexa.discoverDevice(userID)
    local list  = getUserDevicelist(userID)
    if #list == 0 then
        return false
    end
    local ret = L.castArray()
    if #list > 0 then
        for key,value in pairs(list) do
            -- __debugMsg("informationAlexa.discoverDevice::device::".. to_json(value) )
            local device = value.device
            local model = HamvModel.getInfo(deviceSn).profile.esh.model
            if model ~= nil then
                local mapModel = getMapModel(model)
                -- __debugMsg("informationAlexa.discoverDevice::device::".. device .. "::" .. model .. "::" .. to_json(mapModel))
                if mapModel ~= nil and value.properties ~= nil and value.properties.alexaDeviceName ~= nil then
                    local data = getDiscoverDevice(mapModel,device,value.properties.alexaDeviceName)
                    __debugMsg("informationAlexa.getDiscoverDevice::data::" .. to_json(data))
                    for key2,value2 in pairs(data) do
                        R.push(ret, value2)
                    end
                end
            end
        end
        if #ret > 0 then
            return ret
        end
    end
    return false
end

return informationAlexa

end

package.preload['modules_device'] = function()
--[[--
device
@module device
]]
-- luacheck: globals Tsdb
local DeviceGateway = require 'device_gateway'
local DevicePermissionModel = require 'device_permission_model'
local DevicePropertyModel = require 'device_property_model'
local HamvModel = require 'hamv_model'
local HamvUniqueModel = require 'hamv_unique_model'
local KV = require 'modules_kv'
local L = require 'lodash'
local R = require 'modules_moses'
local UserGroupModel = require 'user_group_model'
local UserPermissionModel = require 'user_permission_model'
local DeviceEventModel = require 'device_events_model'
local IftttTriggersModel = require 'ifttt_triggers_model'
local InformationModel = require 'information_model'

local Device = {}

function Device:new(sn)
  local o = {
    sn = sn,
  }
  setmetatable(o, { __index = self })
  return o
end

function Device:getDisplayName(userID)
  local sn = self.sn
  local deviceProperty = DevicePropertyModel.get(userID, sn)
  if deviceProperty and deviceProperty.displayName then
    return deviceProperty.displayName
  else
    return sn
  end
end

function Device:delete()
  local sn = self.sn
  if HamvModel.isProvisioned(sn) then
    local owners = DevicePermissionModel.getDeviceOwners(sn)
    local owner
    if owners and #(owners) ~= 0 then
      owner = getUser(owners[1])
    end

    if owner then
      HamvModel.notifyUser(owner.id, 'del_device', {
        ['device'] = sn,
        ['owner'] = owner.email
      })
      UserPermissionModel.removeOwnDevice(owner.id, sn)
      DevicePropertyModel.remove(owner.id, sn)
      DevicePermissionModel.removeDeviceOwner(sn, owner.id)
    end

    local guests = DevicePermissionModel.getDeviceGuests(sn)
    for _, userId in ipairs(guests) do
      if UserPermissionModel.removeShareDevice(userId, sn) and owner then
        HamvModel.notifyUser(userId, 'del_device', {
          ['device'] = sn,
          ['owner'] = owner.email
        })
      end
      DevicePermissionModel.removeDeviceGuest(sn, userId)
      DevicePropertyModel.remove(userId, sn)
    end

    R(owners)
      :append(guests)
      :each(function(_, userId)
        R(UserGroupModel.removeDeviceFromGroups(userId, sn))
          :each(function(_, group)
            HamvModel.notifyUser(userId, 'set_group', group)
          end)
      end)

    HamvModel.sendResetAction(sn)
    HamvModel.remove(sn)

    if R.all(self:getAllDeviceEvents(), function(eventId, _)
      return IftttTriggersModel.del(eventId)
    end) then
      DeviceEventModel.destroy(self.sn)
    end

    HamvUniqueModel.setDisconnect(HamvModel.getDeviceId(self.sn))
    return HamvUniqueModel.lock(HamvModel.getDeviceId(self.sn))
  end
end

function Device:isConnected()
  return HamvModel.isConnected(self.sn)
end

function Device:isDeleted()
  local ret = Hamv.listIdentities({
    identity = self.sn,
  })

  if ret.error then return end

  local product = ret.devices[1]
  if product then
    return product.locked
  end
end

function Device:kv()
  if not R.isNil(self._kv) then
    return self._kv
  end

  local resp = Keystore.get({key = "sn_" .. self.sn})
  local device
  if type(resp) == "table" and resp.value ~= nil and type(resp.value) == "string" then
    -- device has written. Get the latest written values
    device = from_json(resp.value)
    self._kv = device
    return device
  else
    return
  end
end

function Device:profile()
  local ret = Tsdb.query({
    limit = 1,
    metrics = { 'profile' },
    mode = 'split',
    start_time = START_TIME,
    tags = { device_sn = self.sn },
  })

  if R.isNil(ret.values) then return end
  if R.isEmpty(ret.values.profile) then return {} end
  return from_json(ret.values.profile[1][2])
end

function Device:info()
  local deviceInfo = HamvModel.getInfo(self.sn)
  local newDeviceInfo = R.pick(deviceInfo, 'device', 'profile', 'status', 'connected', 'device_state', 'fields')
  newDeviceInfo.connected = newDeviceInfo.connected and 1 or 0
  newDeviceInfo.calendar = deviceInfo.schedules
  newDeviceInfo.users = L.castArray(HamvModel.getDetailedDeviceUserList(self.sn))
  return newDeviceInfo
end

function Device:addDeviceEvent(eventId, event)
  if not HamvModel.isProvisioned(self.sn) then
    return
  end
  if IftttTriggersModel.setnx(eventId, self.sn) then
    return DeviceEventModel.setEvent(self.sn, eventId, event)
  end
end

function Device:getAllDeviceEvents()
  return DeviceEventModel.getAllEvents(self.sn)
end

function Device:getInformationModel()
  return InformationModel.filterByModel(HamvModel.getModel(self.sn), InformationModel.LoadAll())
end

function Device:updateDeviceEvent(eventId, event)
  return DeviceEventModel.setEvent(self.sn, eventId, event)
end

function Device:removeDeviceEvent(eventId)
  return DeviceEventModel.removeEvent(self.sn, eventId) and IftttTriggersModel.del(eventId)
end

function Device.listKey()
  return R.select(KV.list(), function(_, key)
    return string.match(key, '^sn_.*')
  end)
end

function Device.listSn()
  return R.map(Device.listKey(), function(_, snKey)
    return string.sub(snKey, 4)
  end)
end

function Device.AddtoADC(deivceSN)
  local HamvGateway = DeviceGateway.get('Hamv')
  return HamvGateway.addIdentity({
      identity = deivceSN
  })
end

function Device.StoreInfo(deivceSN, deviceInfo)
  local profile = deviceInfo.profile
  local fields = deviceInfo.fields

  local metrics = {
    ['profile'] = to_json(profile),
    ['fields'] = to_json(fields)
  }

  local tags = {
    device_sn = deivceSN
  }
  local out = Tsdb.write({
    metrics = metrics,
    tags = tags
  })
  return out
end

function Device.products(...)
  local res = Hamv.listIdentities(...)
  return L.castArray(res.devices)
end

return Device

end

package.preload['modules_kv'] = function()
-- luacheck: globals Keystore
--[[--
kv
@module kv
]]
local JSON = require('modules_json')
local R = require('modules_moses')

local KV = {}

local commands = {
	'append',
	'bitcount',
	'bitpos',
	'decr',
	'decrby',
	'del',
	'exists',
	'expire',
	'expireat',
	'get',
	'getbit',
	'getrange',
	'getset',
	'hdel',
	'hexists',
	'hget',
	'hgetall',
	'hincrby',
	'hincrbyfloat',
	'hkeys',
	'hlen',
	'hmget',
	'hmset',
	'hscan',
	'hset',
	'hsetnx',
	'hstrlen',
	'hvals',
	'incr',
	'incrby',
	'incrbyfloat',
	'lindex',
	'linsert',
	'llen',
	'lpop',
	'lpush',
	'lpushx',
	'lrange',
	'lrem',
	'lset',
	'ltrim',
	'persist',
	'pexpire',
	'pexpireat',
	'psetex',
	'pttl',
	'rpop',
	'rpush',
	'rpushx',
	'sadd',
	'scard',
	'set',
	'setbit',
	'setex',
	'setnx',
	'sismember',
	'smembers',
	'spop',
	'srandmember',
	'srem',
	'strlen',
	'ttl',
	'type',
	'zadd',
	'zcard',
	'zcount',
	'zincrby',
	'zlexcount',
	'zrange',
	'zrangebylex',
	'zrangebyscore',
	'zrank',
	'zrem',
	'zremrangebylex',
	'zremrangebyrank',
	'zremrangebyscore',
	'zrevrange',
	'zrevrangebylex',
	'zrevrangebyscore',
	'zrevrank',
	'zscore'
}

KV.commandOptionBuilder = {}

for _, command in ipairs(commands) do
	KV.commandOptionBuilder[command] = function(key, ...)
    local options = {
      command = command,
      key = key
    }

    local args = { ... }
    if (#args > 0) then
      options.args = args
    end

    return options
  end
end

local function buildCommand(command)
	local function retryCommand(key, retry, ...)

    local options = KV.commandOptionBuilder[command](key, ...)

		local res = Keystore.command(options)
		retry = retry - 1
    if (res.error and res.status >= 500 and retry > 0) then
      local degree = 10 - retry
      degree = math.min(1, degree)
      local count = 1
      for _ = 1, degree do
        count = count * 2
      end
      for _ = 1, count do end
			return retryCommand(key, retry, ...)
		end
		assert(not res.error or res.status < 400, res.error or 'kv retry exceeded')

		return res.value
	end

	return function(key, ...)
		return retryCommand(key, 5, ...)
	end
end

for _, command in ipairs(commands) do
	KV[command] = buildCommand(command)
end

--[[--
Delete all the keys.
@treturn bool Returns TRUE on success or FALSE on failure.
]]
function KV.clear()
	local res = Keystore.clear()
	return res.status == 204
end

--[[--
Removes the specified key.
@tparam string key Key to be deleted.
@treturn bool Returns TRUE on success or FALSE on failure.
]]
function KV.delete(key)
	assert(R.isString(key) and not R.isEmpty(key))

	local res = Keystore.delete({ key = key })
	return res.status == 204
end

--[[--
Get the value of key.
@tparam string key Key to be retrieved.
@treturn any The value of key.
]]
function KV.get(key)
	assert(R.isString(key) and not R.isEmpty(key))

	local res = Keystore.get({ key = key })
	return JSON.parse(res.value)
end

--[[--
Returns all keys.
@treturn table List of keys.
]]
function KV.list()
	local res = Keystore.list()
	return res.keys or {}
end

--[[--
Set key to hold the string value.
@tparam string key Key to be set.
@tparam any value Value to be set.
@treturn bool Returns TRUE on success or FALSE on failure.
]]
function KV.set(key, value)
	assert(R.isString(key) and not R.isEmpty(key))

	local res = Keystore.set({ key = key, value = JSON.stringify(value) })
	return res.status == 204
end

return KV

end

package.preload['solution_logger'] = function()
local R = require 'modules_moses'

local SolutionLogger = {}
local supportedMethod = {
 'error',
 'warn',
 'notice',
 'info',
 'debug',
}

R.forEach(supportedMethod, function(_, method)
  SolutionLogger[method] = function(self, value)
    local object = self:sanitizeValue(value)
    return log[method](to_json(object))
  end
end)

function SolutionLogger:new(default)
  local o = {
    default = default,
  }
  setmetatable(o, { __index = self })
  return o
end

function SolutionLogger.convertToObject(value)
  if R.isArray(value) then
    return { message = R.concat(value, ',') }
  elseif R.isTable(value) then
    return value
  else
    return { message = tostring(value) }
  end
end

function SolutionLogger:sanitizeValue(value)
  local object = self.convertToObject(value)
  return R.extend({}, self.default, object)
end

return SolutionLogger

end

package.preload['constant'] = function()
--[[--
constant
@module constant
]]
local Constant = {
  GOOGLEHOME_TOKEN_MAX_EXPIRES_IN_SECONDS = 950400,
  KEYSTORE_COMMAND_PAYLOAD_LIMIT = 95000
}


return Constant



end

package.preload['alexav3'] = function()
-- luacheck: globals __debugMsg
-- luacheck: globals getUserByToken
-- luacheck: globals getUserDevicelist
local informationModel = require "information_model"
local HamvModel = require 'hamv_model'
local DevicePermissionModel = require 'device_permission_model'
local UserPermissionModel = require 'user_permission_model'
local DevicePropertyModel = require 'device_property_model'
local R = require 'modules_moses'
local SolutionLogger = require 'solution_logger'


local logger = SolutionLogger:new({functionName = "alexav3"})
local Alexa = {}
Alexa.uncertaintyInMilliseconds = 500

local function time8601_format()
    local dec = ".00"
    local format = '!%Y-%m-%dT%T'..dec..'Z'
	local str = os.date(format,os.time())
    return str
end
local function checkItems(object,item)
    if object == nil then
        return
	end
	if object[item] ~= nil then
		return object[item]
	end
end

local function getEndpointId(object)
    return checkItems(object,"endpointId")
end

local function getEndpoint(object)
    return checkItems(object,"endpoint")
end

local function getPayload(object)
    return checkItems(object,"payload")
end

local function getPayloadScope(payload)
    return checkItems(payload,"scope")
end

local function getScopeToken(scope)
    return checkItems(scope,"token")
end

local function getUserFT(token)
    if token == nil and type(token) ~= "string" then
        return
	end
	return getUserByToken(token)
end

-- local function getEndpointId(endpoint)
--     if endpoint == nil and type(token) ~= "table" then
--         return
--     end
--     if endpoint.endpointId ~= nil and type(endpoint.endpointId) == "string" then
--         return endpoint.endpointId
--     end
-- end

local function errorMessage(errorType,errorMsg,validRange)
    local header = {
        ["namespace"] = "Alexa",
        ["messageId"] = Alexa.header.messageId,
        ["name"] = "ErrorResponse",
        ["payloadVersion"] = Alexa.header.payloadVersion
    }
    if Alexa.correlationToken ~= nil then
        header.correlationToken = Alexa.correlationToken
    end
    local payload = {
        type = errorType,
        message = errorMsg
    }
    if validRange ~= nil and type(validRange) == "table" then
        payload["validRange"] = validRange
    end
    local error = {
        event = {
            header = header,
            endpoint = {
                scope = Alexa.scope
            },
            payload = payload
        }
    }

    local AlexaErrorMessage = to_json(error)
    __debugMsg("AlexaErrorMessage::" .. AlexaErrorMessage)
    -- response.code= 400
    Alexa.response.message = AlexaErrorMessage
end
local function getPowerController()
    return {
        type = "AlexaInterface",
        interface = "Alexa.PowerController",
        version =  "3",
        properties = {
            supported = {
                {
                name = "powerState"
                }
            },
            proactivelyReported = false,
            retrievable = true
        }
    }
end
local function getPercentageController()
    return {
        type = "AlexaInterface",
        interface = "Alexa.PercentageController",
        version =  "3",
        properties = {
            supported = {
                {
                name = "percentage"
                }
            },
            proactivelyReported = false,
            retrievable = true
        }
    }
end

local function getBrightnessController()
    return {
        type = "AlexaInterface",
        interface = "Alexa.BrightnessController",
        version =  "3",
        properties = {
            supported = {
                {
                name = "brightness"
                }
            },
            proactivelyReported = false,
            retrievable = true
        }
    }
end

local function getEndpointHealth()
    return {
        type = "AlexaInterface",
        interface = "Alexa.EndpointHealth",
        version =  "3",
        properties = {
            supported = {
                {
                name = "connectivity"
                }
            },
            proactivelyReported = false,
            retrievable = true
        }
    }
end

local function getDeviceCapabilities(deviceTrait)
    local data = {
        {
            type = "AlexaInterface",
            interface = "Alexa",
            version =  "3"
        }
    }
    if deviceTrait:getTraitAttributes("on_off") ~= nil then
        table.insert( data, getPowerController() )
    end
    if deviceTrait:getTraitAttributes("brightness") ~= nil then
        table.insert( data, getPercentageController() )
        table.insert( data, getBrightnessController() )
    elseif deviceTrait:getTraitAttributes("percentage") ~= nil then
        table.insert( data, getPercentageController() )
    end
    table.insert( data, getEndpointHealth() )
    return data
end

function Alexa.request(requestBody,response)
    __debugMsg('amazon::AlexaV3::requestBody::' .. to_json(requestBody))
    logger:notice({message = 'input', payload = requestBody})
    Alexa.response = response
    if requestBody.directive ~= nil then
        Alexa.handleDirective(requestBody.directive)
    end
end

local function getDisplayCategories(deviceTrait)
    local type = deviceTrait:getTraitType()
    local _map = {
        light = "LIGHT",
        switch = "SWITCH",
        smartplug = "SMARTPLUG",
        thermostat = "THERMOSTAT",
        smartlock = "SMARTLOCK"
    }
    if _map[type] ~= nil then
        return _map[type]
    else
        return "OTHER"
    end
end

local function handleGrantAuthorization()
    local header = {
        namespace = Alexa.header.namespace,
        name = "AcceptGrant.Response",
        payloadVersion = Alexa.header.payloadVersion,
        messageId = Alexa.header.messageId
    }
    local payload = {}
    local AlexaMessage = to_json({event = {header = header, payload = payload}})
    Alexa.response.message = AlexaMessage
end

local function handleDiscover()
    --TODO update Alexa.directive coding style, data flow
    Alexa.scope = getPayloadScope(getPayload(Alexa.directive))
    local user = getUserFT(getScopeToken(Alexa.scope))
    if user ~= nil and user.error ~= nil then
        logger:error('Discover Auth fail!')
        errorMessage("INVALID_AUTHORIZATION_CREDENTIAL","Auth fail.")
        return
    end
    Alexa.user = user
    __debugMsg('amazon::AlexaV3::user' .. to_json(Alexa.user))
    --TODO refactor here
    --local list  = getUserDevicelist(user.id)
    local list = UserPermissionModel.getDevices(user.id)
    local v3Data = setmetatable({}, { __type = 'slice' })
    if #list ~= 0 and Alexa.externalIntegration ~= nil then
        for _,deviceSn in pairs(list) do
            local this_Device_EI = Alexa.externalIntegration:getMapModelByDeviceSn(deviceSn)
            if this_Device_EI then
                if #this_Device_EI:getTraitsIds() ~= 0 then
                    for _,_value in pairs(this_Device_EI:getTraitsIds()) do
                        local this_Device_EI_trait = this_Device_EI:getTraits(_value)
                        __debugMsg('amazon::AlexaV3::handleDiscover::this_Device_EI_trait::' .. to_json(_value))
                        local friendlyDescription = ""
                        if this_Device_EI_trait:getTraitDescription() ~= nil then
                            friendlyDescription = friendlyDescription .. this_Device_EI_trait:getTraitDescription()
                        end
                        local friendlyName = ""
                        --TODO
                        --need to get property here
                        local deviceProperty = DevicePropertyModel.get(user.id, deviceSn)
                        if deviceProperty and deviceProperty.displayName then
                            friendlyName = deviceProperty.displayName
                        end
                        local APPEND_NAME = this_Device_EI_trait:getTraitAppendName()
                        if APPEND_NAME ~= nil then
                            friendlyName = friendlyName .. APPEND_NAME
                        end
                        --TODO remove comment
                        local esh = HamvModel.getInfo(deviceSn).profile.esh
                        --local esh = getDeviceEsh(deviceSn)
                        local newData = {
                            endpointId = deviceSn .. "::" .. _value,
                            manufacturerName = esh.brand,
                            friendlyName = friendlyName,
                            description = friendlyDescription,
                            displayCategories = { getDisplayCategories(this_Device_EI_trait) },
                            cookie = {},
                            capabilities = getDeviceCapabilities(this_Device_EI_trait)
                        }
                        table.insert( v3Data, newData )
                    end
                end
            end
        end
    end
    -- __debugMsg('amazon::AlexaV3::getUserDevicelist::' .. to_json(list))
    local header = {
        namespace = Alexa.header.namespace,
        name = "Discover.Response",
        payloadVersion = Alexa.header.payloadVersion,
        messageId = Alexa.header.messageId
    }
    local payload = {endpoints = v3Data}
    local AlexaMessage = to_json({event = {header = header, payload = payload}})
    __debugMsg('amazon::AlexaV3::handleDiscover::' .. AlexaMessage)
    logger:notice(string.format('Discover UserID:%s',Alexa.user.id))
    Alexa.response.message = AlexaMessage
end

local function getPowerStateContext(status)
    return {
        namespace = "Alexa.PowerController",
        name =  "powerState",
        value = status,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = Alexa.uncertaintyInMilliseconds
    }
end

local function getBrightnessControllerContext(value)
    return {
        namespace = "Alexa.BrightnessController",
        name =  "brightness",
        value = value,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = Alexa.uncertaintyInMilliseconds
    }
end

-- local function getPowerLevelContext(value)
--     return {
--         namespace = "Alexa.PowerLevelController",
--         name =  "powerLevel",
--         value = value,
--         timeOfSample = time8601_format(),
--         uncertaintyInMilliseconds = Alexa.uncertaintyInMilliseconds
--     }
-- end

local function getPercentageContext(value)
    return {
        namespace = "Alexa.PercentageController",
        name =  "percentage",
        value = value,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = Alexa.uncertaintyInMilliseconds
    }
end

local function getConnectivityContext(connectivity)
    local status = "UNREACHABLE"
    if connectivity == true then
        status = "OK"
    end

    return {
        namespace = "Alexa.EndpointHealth",
        name =  "connectivity",
        value = {value = status},
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = Alexa.uncertaintyInMilliseconds
    }
end

local function sendRequestToDevice(id,deviceSn,code,value)
    HamvModel.sendSetAction(deviceSn, {[code] = value}, "voiceControlToken_"..id)
end

--TODO checking whether still need when doing refactor
-- local function sendRequestToDeviceBefore(deviceSn,before)
--     local id = 99
--     for _,value in pairs(before) do
--         sendRequestToDevice(id,deviceSn, value.key, value.value)
--         id = id + 1
--     end
-- end

local function getDevicePercentage(deviceSn,Percentage)
    local code = Percentage.key
    local status = HamvModel.getDeviceStatus(deviceSn)
    if status[code] ~= nil then
        return status[code]
    end
    return 0
end

local function setDevicePercentage(deviceSn,Percentage,setValue)
    local mergedSetValue={}
    if Percentage.before ~= nil and #Percentage.before > 0 then
        R(Percentage.before)
            :each(function(_, setValueBefore)
              mergedSetValue[setValueBefore.key] = setValueBefore.value
            end)
    end
    local valueMin = Percentage.min
    local valueMax = Percentage.max
    if setValue > valueMax then
        setValue = valueMax
    end
    if setValue < valueMin then
        setValue = valueMin
    end
    mergedSetValue[Percentage.key]=setValue
    HamvModel.sendSetAction(deviceSn, mergedSetValue, 'voiceControlToken_'..92)
    __debugMsg("amazon::AlexaV3::setDevicePercentage")
    return setValue
end

local function getDeviceOnOff(deviceSn,On_Off)
    local onCode = On_Off.key
    local onValue = On_Off.values.on
    local status = HamvModel.getDeviceStatus(deviceSn)
    if status[onCode] == onValue then
        return "ON"
    end
    return "OFF"
end

local function changeDeviceOnOff(deviceSn,On_Off,Turn)
    local code = On_Off.key
    local setValue = On_Off.values[Turn]
    sendRequestToDevice(91,deviceSn,code,setValue)
    __debugMsg("amazon::AlexaV3::sendRequestToDevice")
end

--TODO connon function with GoogleHome
local function decodeSNAndModelFromApplianceId(applianceId)
    if string.match(applianceId, '.*::.*') == applianceId then
        return {
            ["deviceSn"] = string.match(applianceId, '(.*)::.*'),
            ["deviceModel"] = string.match(applianceId, '.*::(.*)')
        }
    end
end

local function handleReportState()
    Alexa.endpoint = getEndpoint(Alexa.directive)
    Alexa.scope = getPayloadScope(Alexa.endpoint)
    local header = checkItems(Alexa.directive,"header")
    Alexa.correlationToken = header.correlationToken
    local user = getUserFT(getScopeToken(Alexa.scope))
    if user ~= nil and user.error ~= nil then
        errorMessage("INVALID_AUTHORIZATION_CREDENTIAL","Auth fail.")
        logger:error('ReportState Auth fail!')
        return
    end
    local endpointId = getEndpointId(Alexa.endpoint)
    -- __debugMsg('amazon::AlexaV3::handleReportState::endpointId::' .. to_json(endpointId))
    local data = decodeSNAndModelFromApplianceId(endpointId)
    if data == nil then
        return nil
    end
    -- __debugMsg('amazon::AlexaV3::handleReportState::data::' .. to_json(data))
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, user.id) then
        errorMessage("NO_SUCH_ENDPOINT", "Unable to get endpoint " .. endpointId .. "not exist")
        return false
    end
    local this_Device_EI = Alexa.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        errorMessage("INTERNAL_ERROR", "could not get model of "..deviceSn)
        return false
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)


    local event = {
        header = {
            name = "StateReport",
            namespace = header.namespace,
            payloadVersion = header.payloadVersion,
            messageId = header.messageId,
            correlationToken = header.correlationToken
        },
        endpoint = {
            scope = Alexa.scope,
            endpointId = endpointId
        },
        payload = {}
    }
    local properties = setmetatable({}, { __type = 'slice' })
    table.insert( properties, getConnectivityContext(HamvModel.isConnected(deviceSn)) )

    if this_Device_EI_trait:getTraitAttributes("on_off") ~= nil then
        table.insert( properties,
          getPowerStateContext(getDeviceOnOff(deviceSn,this_Device_EI_trait:getTraitAttributes("on_off"))) )
    end

    if this_Device_EI_trait:getTraitAttributes("brightness") ~= nil
      and this_Device_EI_trait:getTraitAttributes("percentage") == nil then
        local percentageStatus = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("brightness"))
        table.insert( properties, getPercentageContext(percentageStatus) )
        table.insert( properties, getBrightnessControllerContext(percentageStatus) )
    elseif this_Device_EI_trait:getTraitAttributes("brightness") ~= nil
      and this_Device_EI_trait:getTraitAttributes("percentage") ~= nil then
        local percentageStatus = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("percentage"))
        table.insert( properties, getPercentageContext(percentageStatus) )
        local brightnessStatus = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("brightness"))
        table.insert( properties, getBrightnessControllerContext(brightnessStatus) )
    elseif this_Device_EI_trait:getTraitAttributes("percentage") ~= nil then
        local percentageStatus = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("percentage"))
        table.insert( properties, getPercentageContext(percentageStatus) )
    end

    local AlexaMessage = to_json({event = event, context = {properties = properties}})
    __debugMsg('amazon::AlexaV3::handleReportState::' .. AlexaMessage)
    logger:notice(string.format('ReportState UserID:%s',user.id))
    Alexa.response.message = AlexaMessage
end

local function handlePowerController()
    Alexa.endpoint = getEndpoint(Alexa.directive)
    Alexa.scope = getPayloadScope(Alexa.endpoint)
    local header = checkItems(Alexa.directive,"header")
    Alexa.correlationToken = header.correlationToken
    local user = getUserFT(getScopeToken(Alexa.scope))
    if user ~= nil and user.error ~= nil then
        errorMessage("INVALID_AUTHORIZATION_CREDENTIAL","Auth fail.")
        logger:error('PowerController Auth fail!')
        return
    end
    local endpointId = getEndpointId(Alexa.endpoint)
    -- __debugMsg('amazon::AlexaV3::handlePowerController::endpointId::' .. to_json(endpointId))
    local data = decodeSNAndModelFromApplianceId(endpointId)
    if data == nil then
        return nil
    end
    -- __debugMsg('amazon::AlexaV3::handlePowerController::data::' .. to_json(data))
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, user.id) then
        errorMessage("NO_SUCH_ENDPOINT", "Unable to get endpoint ".. endpointId .. "not exist")
        return false
    end
    if not HamvModel.isConnected(deviceSn) then
        errorMessage("ENDPOINT_UNREACHABLE",
          "Unable to reach endpoint ".. endpointId .. "because it appears to be offline")
    end
    local Turn = "off"
    if header.name == "TurnOn" then
        Turn = "on"
    end

    local this_Device_EI = Alexa.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        errorMessage("INTERNAL_ERROR", "could not get model of "..deviceSn)
        return false
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)
    changeDeviceOnOff(deviceSn,this_Device_EI_trait:getTraitAttributes("on_off"),Turn)
    local event = {
        header = {
            name = "Response",
            namespace = "Alexa",
            payloadVersion = header.payloadVersion,
            messageId = header.messageId,
            correlationToken = header.correlationToken
        },
        endpoint = {
            scope = Alexa.scope,
            endpointId = endpointId
        },
        payload = {}
    }
    local properties = setmetatable({}, { __type = 'slice' })
    table.insert( properties, {
        namespace = "Alexa.PowerController",
        name = "powerState",
        value =  Turn,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = 500
      } )
    table.insert( properties, getConnectivityContext(true) )
    local AlexaMessage = to_json({event = event, context = {properties = properties}})
    __debugMsg('amazon::AlexaV3::handlePowerController::' .. AlexaMessage)
    logger:notice(string.format('PowerController UserID:%s', user.id))
    Alexa.response.message = AlexaMessage
end

local function handleBrightnessController()
    Alexa.endpoint = getEndpoint(Alexa.directive)
    Alexa.scope = getPayloadScope(Alexa.endpoint)
    local header = checkItems(Alexa.directive,"header")
    Alexa.correlationToken = header.correlationToken
    local user = getUserFT(getScopeToken(Alexa.scope))
    if user ~= nil and user.error ~= nil then
        errorMessage("INVALID_AUTHORIZATION_CREDENTIAL","Auth fail.")
        logger:error('BrightnessController Auth fail!')
        return
    end
    local endpointId = getEndpointId(Alexa.endpoint)
    -- __debugMsg('amazon::AlexaV3::handleBrightnessController::endpointId::' .. to_json(endpointId))
    local data = decodeSNAndModelFromApplianceId(endpointId)
    if data == nil then
        return nil
    end
    -- __debugMsg('amazon::AlexaV3::handleBrightnessController::data::' .. to_json(data))
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    local this_Device_EI = Alexa.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        errorMessage("INTERNAL_ERROR", "could not get model of "..deviceSn)
        return false
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, user.id) then
        errorMessage("NO_SUCH_ENDPOINT", "Unable to get endpoint ".. endpointId .. "not exist")
        return false
    end
    if not HamvModel.isConnected(deviceSn) then
        errorMessage("ENDPOINT_UNREACHABLE",
          "Unable to reach endpoint ".. endpointId .. "because it appears to be offline")
    end
    local payload = getPayload(Alexa.directive)
    local brightness = payload.brightness or 0
    if header.name == "AdjustBrightness" then
        local pValue = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("brightness"))
        brightness = payload.brightnessDelta + pValue
    end

    local setValue = setDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("brightness"),brightness)

    local event = {
        header = {
            name = "Response",
            namespace = "Alexa",
            payloadVersion = header.payloadVersion,
            messageId = header.messageId,
            correlationToken = header.correlationToken
        },
        endpoint = {
            scope = Alexa.scope,
            endpointId = endpointId
        },
        payload = {}
    }
    local properties = setmetatable({}, { __type = 'slice' })
    table.insert( properties, {
        namespace = "Alexa.BrightnessController",
        name = "brightness",
        value =  setValue,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = 500
      } )
    table.insert( properties, getConnectivityContext(true) )
    local AlexaMessage = to_json({event = event, context = {properties = properties}})
    __debugMsg('amazon::AlexaV3::handleBrightnessController::' .. AlexaMessage)
    logger:notice(string.format('BrightnessController UserID:%s', user.id))
    Alexa.response.message = AlexaMessage
end

local function handlePercentageController()
    Alexa.endpoint = getEndpoint(Alexa.directive)
    Alexa.scope = getPayloadScope(Alexa.endpoint)
    local header = checkItems(Alexa.directive,"header")
    Alexa.correlationToken = header.correlationToken
    local user = getUserFT(getScopeToken(Alexa.scope))
    if user ~= nil and user.error ~= nil then
        errorMessage("INVALID_AUTHORIZATION_CREDENTIAL","Auth fail.")
        logger:error('PercentageController Auth fail!')
        return
    end
    local endpointId = getEndpointId(Alexa.endpoint)
    -- __debugMsg('amazon::AlexaV3::handlePercentageController::endpointId::' .. to_json(endpointId))
    local data = decodeSNAndModelFromApplianceId(endpointId)
    if data == nil then
        return nil
    end
    -- __debugMsg('amazon::AlexaV3::handlePercentageController::data::' .. to_json(data))
    local deviceSn = data.deviceSn
    local deviceModel = data.deviceModel
    local this_Device_EI = Alexa.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not this_Device_EI then
        errorMessage("INTERNAL_ERROR", "could not get model of "..deviceSn)
        return false
    end
    local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)
    if not DevicePermissionModel.checkUserHasAccess(deviceSn, user.id) then
        errorMessage("NO_SUCH_ENDPOINT", "Unable to get endpoint ".. endpointId .. "not exist")
        return false
    end
    if not HamvModel.isConnected(deviceSn) then
        errorMessage("ENDPOINT_UNREACHABLE",
          "Unable to reach endpoint ".. endpointId .. "because it appears to be offline")
    end
    local payload = getPayload(Alexa.directive)
    local percentage = payload.percentage
    if header.name == "AdjustPercentage" then
        local pValue = getDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("percentage"))
        percentage = payload.percentageDelta + pValue
    end

    local setValue = setDevicePercentage(deviceSn,this_Device_EI_trait:getTraitAttributes("percentage"),percentage)

    local event = {
        header = {
            name = "Response",
            namespace = "Alexa",
            payloadVersion = header.payloadVersion,
            messageId = header.messageId,
            correlationToken = header.correlationToken
        },
        endpoint = {
            scope = Alexa.scope,
            endpointId = endpointId
        },
        payload = {}
    }
    local properties = setmetatable({}, { __type = 'slice' })
    table.insert( properties, {
        namespace = "Alexa.PercentageController",
        name = "percentage",
        value =  setValue,
        timeOfSample = time8601_format(),
        uncertaintyInMilliseconds = 500
      } )
    table.insert( properties, getConnectivityContext(true) )
    local AlexaMessage = to_json({event = event, context = {properties = properties}})
    __debugMsg('amazon::AlexaV3::handlePercentageController::' .. AlexaMessage)
    logger:notice(string.format('PercentageController UserID:%s', user.id))
    Alexa.response.message = AlexaMessage
end

function Alexa.handleDirective(directive)
    Alexa.directive = directive
    Alexa.header = Alexa.directive.header
    --TODO coding style and check functionality
    --ok, Alexa.externalIntegration = pcall(
    local success, result = pcall(
      function()
        return informationModel:new():loadExternalIntegration():getExternalIntegration()
      end)
    if not success then
        __debugMsg('amazon::AlexaV3:: Error!! informationModel not fund.')
        logger:error('InformationModel not fund!')
        return
    end
    Alexa.externalIntegration = result
    if Alexa.header.name == "AcceptGrant" then
        handleGrantAuthorization()
    end
    if Alexa.header.name == "Discover" then
        handleDiscover()
    end

    if Alexa.header.name == "ReportState" then
        handleReportState()
    end

    if Alexa.header.namespace == "Alexa.PowerController" then
        handlePowerController()
    end

    if Alexa.header.namespace == "Alexa.BrightnessController" then
        handleBrightnessController()
    end

    if Alexa.header.namespace == "Alexa.PercentageController" then
        handlePercentageController()
    end
    logger:notice({message = 'response', payload = from_json(Alexa.response.message)})
end

return Alexa

end

package.preload['controllers.geolocation'] = function()
local HttpError = require 'http-error'
local L = require('lodash')
local R = require('modules_moses')

local GeolocationController = {}

function GeolocationController.serviceCall(req, _, nxt)
  local res = Analytics.geoLocation({ip = req.parameters.ip})
  if res.error then
    nxt(HttpError:new(res.status, res.error))
  end
  req.geolocation = res
  nxt()
end

function GeolocationController.filterFields(req, res, nxt)
  local output = req.geolocation

  local fields = req.parameters.fields
  if fields then
    output = R.pick(req.geolocation, L.split(fields, ','))
  end

  res:send(output)
  nxt()
end

return GeolocationController

end

package.preload['integration_model'] = function()
local R = require "modules_moses"
local Object = require "modules_object"
local HamvModel = require "hamv_model"

local integration = Object:extend()
-- integration.meta = { __index = integration }

function integration:initialize(externalIntegration)
    self.externalIntegration = externalIntegration
end

function integration:getMapModelByDeviceSn(deviceSn)
    --TODO coding style here
    local success, model = pcall(function () return HamvModel.getModel(deviceSn) end)
    if success then
      return self:getMapModel(model)
    else
      return nil
    end
end

function integration:getMapModel(DeviceModel)
    -- return self.externalIntegration
    for key,value in pairs(self.externalIntegration) do
        for _,value2 in pairs(value.familyMembers) do
            if string.match(DeviceModel, value2) ~= nil then
                local newObj = integration:new(self.externalIntegration)
                newObj._MapModel = value
                newObj._MapModelName = key
                return newObj
            end
        end
    end
end

function integration:getTraitsIds()
    if self._MapModel == nil or self._MapModelName == nil or self._MapModel.traits == nil then return end
    return R.pluck(self._MapModel.traits ,'id')
end

function integration:getTraits(id)
    if self._MapModel == nil or self._MapModelName == nil or self._MapModel.traits == nil then return end
    local newObj = integration:new(self.externalIntegration)
    newObj._MapModel = self._MapModel
    newObj._MapModelName = self._MapModelName
    newObj._Trait = R.select(self._MapModel.traits, function(_,value)
        return (value.id == id)
    end)[1]
    return newObj
end

local function getTraitItem(trait,item)
    if trait == nil or R.isEmpty(trait[item]) == nil then return end
    return trait[item]
end
function integration:getTraitDescription()
    return getTraitItem(self._Trait,'description')
end
function integration:getTraitType()
    return getTraitItem(self._Trait,'type')
end
function integration:getTraitAppendName()
    return getTraitItem(self._Trait,'append_name')
end

function integration:getTraitAttributes(name)
    local _s = {'on_off','percentage','ac_mode','temperature','target_temperature','low_target_temperature',
        'high_target_temperature','humidity','color','color_temperature','brightness'}
    if R.find(_s,name) then
        local ret = getTraitItem(self._Trait,'attributes')
        if ret ~= nil and ret[name] ~= nil then return ret[name] end
    end
end


function integration:getAllTraitAttributes()
  return  self._Trait.attributes
end

return integration

end

package.preload['phone_actions'] = function()
-- luacheck: globals __debugMsg
-- luacheck: globals User
-- luacheck: globals getUserData getUserByEmail
-- luacheck: globals getUserDevicelist getUser

local TsdbLogger = require 'modules_logger'
local D = require 'modules_device'
local R = require 'modules_moses'
local L = require 'lodash'
local HamvModel = require 'hamv_model'
local HamvError = require 'hamv_error'
local UserGroupModel = require 'user_group_model'
local DevicePropertyModel = require 'device_property_model'
local UserPermissionModel = require 'user_permission_model'
local DevicePermissionModel = require 'device_permission_model'
local UserIntegrationModel = require 'user_integration_model'
local SolutionLogger = require 'solution_logger'

local logger = SolutionLogger:new({functionName = "phone_actions"})
local DEVICE_USER_LIMIT = 10

local PHONE_ACTIONS = {}

PHONE_ACTIONS['provision_token'] = function(ws, user, message)
  __debugMsg('PhoneRequest::provision_token' .. ' :: ' .. to_json(message.data))

  local UserO = require 'user_object'

  local tokenOptions = message.data
  local setUser = UserO.findById(user.id)

  if tokenOptions.expires_in == nil
      or type(tokenOptions.expires_in) ~= 'number'
      or tokenOptions.expires_in < 5*60 -- 5 minutes
      or tokenOptions.expires_in > 30*24*60*60 -- 30 days
  then
    error(HamvError.instance(300))
  end

  local Provision = require 'provision'
  local expires_in = os.time() + tokenOptions.expires_in
  local response = {
    ['id'] = message.id,
    ['response'] = message.request,
    ['data'] = {
      ['token'] = Provision.createProvisionToken(setUser.id, tokenOptions.expires_in),
      ['expires_in'] = expires_in
    },
    ['status'] = 'ok'
  }
  ws.send(response)
  logger:notice({message = string.format('provision_token UserID:%s',user.id), payload = response})

  return true
end

PHONE_ACTIONS['listen'] = function(ws, user, _)
  local devices = UserPermissionModel.getDevices(user.id)

  HamvModel.subscribeDeviceEvent(devices, ws.socket_id)
  return true
end

PHONE_ACTIONS['listen_stop'] = function(ws, user, _)
  local devices = UserPermissionModel.getDevices(user.id)

  HamvModel.unsubscribeDeviceEvent(devices, ws.socket_id)
  return true
end

PHONE_ACTIONS['ping'] = function(ws, _, message)
  __debugMsg('PhoneRequest::ping')
  local res = {
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok'
  }
  ws.send(res)

  return true
end

PHONE_ACTIONS['config'] = function(ws, user, message)
  __debugMsg('PhoneRequest::config')

  local sn = message.device
  local config = message.data

  if sn == nil or config == nil or config.fields == nil then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    error(HamvError.instance(102))
  end

  if not HamvModel.isConnected(sn) then
    error(HamvError.instance(206))
  end

  logger:notice({message = string.format('config UserID:%s',user.id), payload = {sn = sn, config = config }})
  local identifier = HamvModel.createActionIdentifier(ws, message.id, 'config')
  HamvModel.sendConfigAction(sn, config, identifier)

  return true
end

PHONE_ACTIONS['set'] = function(ws, user, message)
  __debugMsg('PhoneRequest::set')
  local ip = ws.headers['x-forwarded-for'] or "unknown"

  local sn = message.device
  local stateChanges = message.data

  if not sn or not stateChanges then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  local deviceInfo = HamvModel.getInfo(sn)

  if not deviceInfo.connected then
    error(HamvError.instance(206))
  end

  stateChanges = R.pick(stateChanges, deviceInfo.fields)

  local identifier = HamvModel.createActionIdentifier(ws, message.id, 'set')
  HamvModel.sendSetAction(sn, stateChanges, identifier)

  R.each(stateChanges, function(key, value)
    local logType = 'event'
    local action = {
      email = user.email,
      key = key,
      label = 'User set',
      value = value,
    }
    local msg = TsdbLogger.parseMessage(sn, key, value)
    if msg then
      logType = msg.type
      action.content = msg.text
    end

    TsdbLogger.log(logType, user.email, action, {
        device_sn = sn,
        field = key,
      },
      ip
    )
  end)

  return true
end

PHONE_ACTIONS['get'] = function(ws, user, message)
  __debugMsg('PhoneRequest::get')

  local sn = message.device

  if not sn then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  local deviceInfo = HamvModel.getInfo(sn)
  local newDeviceInfo = R.pick(deviceInfo, 'device', 'profile', 'status', 'connected', 'device_state', 'fields')
  newDeviceInfo.connected = deviceInfo.connected and 1 or 0
  newDeviceInfo.calendar = deviceInfo.schedules
  newDeviceInfo.users = L.castArray(HamvModel.getDetailedDeviceUserList(sn))

  local response = {
    id = message.id,
    response = message.request,
    data = newDeviceInfo,
    status = 'ok'
  }
  ws.send(response)

  return true
end

PHONE_ACTIONS['reset'] = function(ws, user, message)
  __debugMsg('PhoneRequest::reset')

  local sn = message.device

  if not sn then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    error(HamvError.instance(102))
  end

  if not HamvModel.isConnected(sn) then
    error(HamvError.instance(206))
  end

  local identifier = HamvModel.createActionIdentifier(ws, message.id, 'reset')
  HamvModel.sendResetAction(sn, identifier)

  return true
end

PHONE_ACTIONS['ota'] = function(ws, user, message)
  __debugMsg('PhoneRequest::ota')

  local sn = message.device
  local firmwareInfo = message.data

  if not sn or not firmwareInfo or not firmwareInfo.url then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    error(HamvError.instance(102))
  end

  if not HamvModel.isConnected(sn) then
    error(HamvError.instance(206))
  end

  logger:notice({message = string.format('ota UserID:%s',user.id), payload = {sn = sn, firmwareInfo = firmwareInfo }})
  local identifier = HamvModel.createActionIdentifier(ws, message.id, 'ota')
  HamvModel.sendOTAAction(sn, firmwareInfo, identifier)

  return true
end

PHONE_ACTIONS['calendar'] = function(ws, user, message)
  __debugMsg('PhoneRequest::calendar')

  local sn = message.device
  local schedules = message.data

  local HAMV_SCHEDULE_LIMIT = 10

  if not sn or not schedules then
    error(HamvError.instance(300))
  end

  if #schedules > HAMV_SCHEDULE_LIMIT then
    error(HamvError.instance(200))
  end

  if not HamvModel.isValidSchedules(schedules) then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  if not HamvModel.setSchedules(sn, schedules) then
    error(HamvError.instance(300))
  end

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  HamvModel.publishCalendarEvent(sn, L.castArray(schedules))

  return true
end

PHONE_ACTIONS['add_user'] = function(ws, user, message)
  __debugMsg('PhoneRequest::add_user')

  local UserShare = require 'user_share'

  local sn = message.device
  local data = message.data

  if not sn or not data then
    error(HamvError.instance(300))
  end

  if data.role ~= 'guest' or (data.email and data.email == user.email) then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    error(HamvError.instance(102))
  end

  local deviceUsers = DevicePermissionModel.list(sn)
  if #deviceUsers > DEVICE_USER_LIMIT then
    error(HamvError.instance(101))
  end

  if data.email then
    -- add user by email
    local addUser = getUserByEmail(data.email)
    if not addUser then
      error(HamvError.instance(103))
    end
    if addUser.id == user.id then
      error(HamvError.instance(102))
    end
    -- If add duplicate device guest currently response success.
    local deviceSuccess = DevicePermissionModel.addDeviceGuest(sn, addUser.id)
    local userSuccess = UserPermissionModel.addShareDevice(addUser.id, sn)

    if deviceSuccess and userSuccess then
      ws.send({
        ['id'] = message.id,
        ['response'] = message.request,
        ['status'] = 'ok'
      })

      local owners = DevicePermissionModel.getDeviceOwners(sn)

      HamvModel.subscribeDeviceEvent(sn, unpack(HamvModel.listUserSockets(addUser.id)))

      DevicePropertyModel.set(addUser.id, sn, {
        displayName = HamvModel.getDeviceId(sn),
      })

      HamvModel.notifyUser(addUser.id, 'add_device', {
        ['device'] = sn,
        ['owner'] = getUser(owners[1]).email
      })

      return true
    end

  else
    -- add user by share token
    -- TODO this feature is not necessary in websocket and should not mixed the command usage here
    local tokenObject = UserShare.requestToken(user, sn)
    if not tokenObject then
      error(HamvError.instance(300))
    end

    ws.send({
      ['id'] = message.id,
      ['response'] = message.request,
      ['status'] = 'ok',
      ['data'] = tokenObject
    })

    return true
  end

end

PHONE_ACTIONS['add_user_verify'] = function(ws, user, message)
  __debugMsg('PhoneRequest::add_user_verify')
  local UserShare = require 'user_share'
  local KV = require 'modules_kv'
  local JSON = require 'modules_json'

  local data = message.data
  local token = data.token

  if not data or not token then
    error(HamvError.instance(300))
  end

  local res = KV.hget(UserShare.KVkey, token)
  if not res then
    error(HamvError.instance(301))
  end

  local info = JSON.parse(res)
  assert(info.deviceSn)

  if os.time() >= info.expTTL then
    UserShare.removeToken(token)
    error(HamvError.instance(300))
  end

  local deviceUsers = DevicePermissionModel.list(info.deviceSn)

  if #deviceUsers > DEVICE_USER_LIMIT then
    error(HamvError.instance(101))
  end

  -- weird
  -- TODO check user sceneriao here.   -> The following process should use add_user to replace.
  if DevicePermissionModel.checkUserHasAccess(info.deviceSn, user.id) then
    error(HamvError.instance(300))
  end

  if not (DevicePermissionModel.addDeviceGuest(info.deviceSn, user.id)
    and UserPermissionModel.addShareDevice(user.id, info.deviceSn)) then
    error(HamvError.instance(300))
  end

  local owners = DevicePermissionModel.getDeviceOwners(info.deviceSn)

  HamvModel.subscribeDeviceEvent(info.deviceSn, unpack(HamvModel.listUserSockets(user.id)))

  DevicePropertyModel.set(user.id, info.deviceSn, {
    displayName = HamvModel.getDeviceId(info.deviceSn),
  })

  HamvModel.notifyUser(user.id, 'add_device', {
    ['device'] = info.deviceSn,
    ['owner'] = getUser(owners[1]).email
  })
  UserShare.removeToken(token)

  ws.send({
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok'
  })

  return true
end

PHONE_ACTIONS['rem_user'] = function(ws, user, message)
  __debugMsg('PhoneRequest::rem_user')

  local sn = message.device
  local data = message.data

  if not sn or not data or not data.email then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  -- Owner should be able to remove anyone But not self. But guest should only be able to remove self.
  -- Email is used for checking remUser.id
  local remUser = getUserByEmail(data.email)
  local owners = DevicePermissionModel.getDeviceOwners(sn)

  -- remUser checking
  if not remUser
      or not DevicePermissionModel.checkUserHasAccess(sn, remUser.id) then
    error(HamvError.instance(103))
  end

  -- Permission checking.
  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  -- owner can not remove himself
  if R.contains(owners, user.id) and remUser.id == user.id then
    error(HamvError.instance(103))
  end

  -- guest can only remove himself
  if not R.contains(owners, user.id) and remUser.id ~= user.id then
    error(HamvError.instance(102))
  end

  __debugMsg('PhoneRequest::rem_user::'..remUser.id)
  if DevicePropertyModel.remove(remUser.id, sn) then
    HamvModel.notifyUser(remUser.id, 'device_change', {
      device = sn,
      changes = {
        properties = {}
      }
    })
  end

  local updatedGroups = UserGroupModel.removeDeviceFromGroups(remUser.id, sn)
  R(updatedGroups)
    :each(function(_, group)
      HamvModel.notifyUser(remUser.id, 'set_group', group)
    end)

  if not DevicePermissionModel.removeDeviceGuest(sn, remUser.id)
    or not UserPermissionModel.removeShareDevice(remUser.id, sn) then
    -- no error?
    return false
  end

  ws.send({
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok'
  })

  HamvModel.unsubscribeDeviceEvent(sn, unpack(HamvModel.listUserSockets(user.id)))

  HamvModel.notifyUser(remUser.id, 'del_device', {
    ['device'] = sn,
    ['owner'] = getUser(owners[1]).email
  })

  return true
end

PHONE_ACTIONS['lst_user'] = function(ws, user, message)
  __debugMsg('PhoneRequest::lst_user')

  local sn = message.device

  if not sn then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    error(HamvError.instance(102))
  end

  local users = HamvModel.getDetailedDeviceUserList(sn)
  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok',
    data = L.castArray(users)
  })

  return true
end

PHONE_ACTIONS['lst_device'] = function(ws, user, message)
  __debugMsg('PhoneRequest::lst_device')

  local list = getUserDevicelist(user.id)

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok',
    data = list
  })

  return true
end

PHONE_ACTIONS['del_device'] = function(ws, user, message)
  __debugMsg('PhoneRequest::del_device' .. message.device .. ' ' .. user.id)

  local sn = message.device

  if not sn then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkOwnerPermission(sn, user.id) then
    if DevicePermissionModel.checkGuestPermission(sn, user.id) then
      message.data = {
        email =  User.getUser({id=user.id}).email
      }
      return PHONE_ACTIONS['rem_user'](ws, user, message)
    else
      error(HamvError.instance(102))
    end
  end

  local response = {
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok'
  }
  ws.send(response)

  return D:new(sn):delete()
end

PHONE_ACTIONS['set_group'] = function(ws, user, message)
  __debugMsg('PhoneRequest::set_group')

  local group = message.data

  if not group or not group.name or not R.isArray(group.devices) then
    error(HamvError.instance(300))
  end

  R(group.devices)
    :map(function(_, sn)
      if not UserPermissionModel.checkAnyPermission(user.id, sn) then
        error(HamvError.instance(102))
      end
    end)

  -- set gruop
  UserGroupModel.set(user.id, group)
  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  HamvModel.notifyUser(user.id, 'set_group', group)

  return true
end

PHONE_ACTIONS['get_group'] = function(ws, user, message)
  __debugMsg('PhoneRequest::get_group')

  local data = message.data

  if not data or not data.name then
    error(HamvError.instance(300))
  end

  -- get gruop
  local group = UserGroupModel.get(user.id, data.name)
  if not group then
    error(HamvError.instance(104))
  end

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok',
    data = group
  })

  return true
end

PHONE_ACTIONS['del_group'] = function(ws, user, message)
  __debugMsg('PhoneRequest::del_group')

  local group = message.data

  if not group or not group.name then
    error(HamvError.instance(300))
  end

  -- delete gruop
  if not UserGroupModel.remove(user.id, group.name) then
    error(HamvError.instance(104))
  end

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  HamvModel.notifyUser(user.id, 'del_group', {
    name = group.name
  })

  return true
end

PHONE_ACTIONS['lst_group'] = function(ws, user, message)
  __debugMsg('PhoneRequest::lst_group')

  local groupList = UserGroupModel.list(user.id)

  ws.send({
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok',
    ['data'] = L.castArray(groupList)
  })

  return true
end

PHONE_ACTIONS['set_properties'] = function(ws, user, message)
  __debugMsg('PhoneRequest::set_properties')

  local sn = message.device
  local properties = message.data

  if not sn or not R.isTable(properties) then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  DevicePropertyModel.set(user.id, sn, properties)

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  HamvModel.notifyUser(user.id, 'device_change', {
    device = sn,
    changes = {
      properties = properties
    }
  })

  return true
end

PHONE_ACTIONS['del_properties'] = function(ws, user, message)
  __debugMsg('PhoneRequest::del_properties')

  local sn = message.device
  local properties = message.data

  if not sn or not R.isArray(properties) then
    error(HamvError.instance(300))
  end

  if not HamvModel.isProvisioned(sn) then
    error(HamvError.instance(201))
  end

  if not DevicePermissionModel.checkUserHasAccess(sn, user.id) then
    error(HamvError.instance(102))
  end

  -- TODO modify the return data here can decrease one more service call to keystore for notification
  if not DevicePropertyModel.deletePropertiesFromDevice(user.id, message.device, properties) then
    error(HamvError.instance(208))
  end

  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  HamvModel.notifyUser(user.id, 'device_change', {
    device = sn,
    changes = {
      properties = DevicePropertyModel.get(user.id, sn)
    }
  })

  return true
end

PHONE_ACTIONS['set_user_data'] = function(ws, user, message)
  __debugMsg('PhoneRequest::set_user_data' .. type(message.data))

  local data = message.data

  if not R.isTable(data) then
    error(HamvError.instance(300))
  end

  for key, value in pairs(data) do
    local userData = User.getUserData({id = user.id, key = key})
    if userData.error then
      User.createUserData({id = user.id, [key] = to_json(value)})
    else
      User.updateUserData({id = user.id, [key] = to_json(value)})
    end
  end

  ws.send({
    ['id'] = message.id,
    ['response'] = message.request,
    ['status'] = 'ok'
  })

  local userData = getUserData(user.id)

  HamvModel.notifyUser(user.id, 'user_data_change', userData)

  return true
end

PHONE_ACTIONS['del_user_data'] = function(ws, user, message)
  __debugMsg('PhoneRequest::del_user_data')

  local data = message.data

  if not data or not R.isArray(data) then
    error(HamvError.instance(300))
  end

  User.deleteUserData({id = user.id, keys = data})
  ws.send({
    id = message.id,
    response = message.request,
    status = 'ok'
  })

  local userData = getUserData(user.id)
  HamvModel.notifyUser(user.id, 'user_data_change', userData)

  return true
end

PHONE_ACTIONS['get_user_data'] = function(ws, user, message)
  __debugMsg('PhoneRequest::get_user_data')
  local userData = getUserData(user.id)
  ws.send({
    id = message.id,
    response = message.request,
    data = userData,
    status = 'ok'
  })
end

PHONE_ACTIONS['get_me'] = function(ws, user, message)
  __debugMsg('PhoneRequest::get_me')
  local integrationStatus = UserIntegrationModel.get(user.id)

  user['alexa_link'] = {['status'] = integrationStatus.alexa and 1 or 0}
  user['googlehome_link'] = {['status'] = integrationStatus.google and 1 or 0}
  user['ifttt_link'] = {['status'] = integrationStatus.ifttt and 1 or 0}

  user.creation_date = nil
  ws.send({
    id = message.id,
    response = message.request,
    data = user,
    status = 'ok'
  })
  return true
end

PHONE_ACTIONS['__NOT_IMPLEMENTED__'] = function(_, _, message)
  print(('`%s` not implemented'):format(message.request))
  error(HamvError.instance(300))
end

return PHONE_ACTIONS

end

package.preload['hamv_model'] = function()
-- luacheck: globals Keystore Tsdb Websocket
-- luacheck: globals getUser

local L = require 'lodash'
local R = require 'modules_moses'
local JSON = require 'modules_json'
local DeviceGateway = require 'device_gateway'
local DevicePermissionModel = require 'device_permission_model'
local HamvChannel = require 'hamv_channel'

local HamvGateway = DeviceGateway.get('Hamv')
local HamvModel = {}

-- return {owners=[],guests=[]}
function HamvModel.getDetailedDeviceUserList(sn)
  local owners = R(DevicePermissionModel.getDeviceOwners(sn))
                  :map(function(_, userId) return getUser(userId) end)
                  :compact()
                  :map(function(_, user) return {email = user.email, role = 'owner'} end)
                  :value()

  local guests = R(DevicePermissionModel.getDeviceGuests(sn))
                  :map(function(_, userId) return getUser(userId) end)
                  :compact()
                  :map(function(_, user) return {email = user.email, role = 'guest'} end)
                  :value()

  local list = R(L.castArray())
                :append(owners)
                :append(guests)
                :value()

  return list
end

function HamvModel.init(sn)
  return HamvModel.update(sn, {})
end

function HamvModel.update(sn, model)
  return Keystore.set({key = 'sn_' .. sn, value = JSON.stringify(model)}).error == nil
end

function HamvModel.remove(sn)
  Keystore.delete({key = 'sn_' .. sn})
  HamvChannel.drop(sn)
  Hamv.removeIdentity({
    identity = sn,
  })
end

local getGatewayProfile = R.memoize(function(sn)
  local result = HamvGateway.getIdentity({identity=sn})

  local defaults = {}
  defaults.state = {}
  defaults.state.owner = {}
  defaults.state.esh = {}
  defaults.state.module = {}
  defaults.state.cert = {}
  defaults.state.states = {}
  defaults.state.ota = {}
  defaults.state.fields = {}
  defaults.state.schedules = {}

  if result.error then
    return defaults
  end

  R.extend(defaults.state, result.state)
  defaults.online = result.online
  defaults.locked = result.locked

  return defaults
end)

function HamvModel.setProvisioned(sn, userId)
  local opt = {identity = sn, owner = tostring(userId)}
  return HamvGateway.setIdentityState(opt).error == nil
end

function HamvModel.isProvisioned(sn)
  return not R.isEmpty((getGatewayProfile(sn).state or {}).owner)
end

function HamvModel.removeGatewayProfile(sn)
  return HamvGateway.removeIdentity({identity=sn}).error == nil
end

function HamvModel.isConnected(sn)
  return getGatewayProfile(sn).online
end

function HamvModel.isReadyToProvision(sn)
  local info = HamvModel.getInfo(sn)
  return R.isTable(info.profile.esh)
      and R.isTable(info.profile.module)
      and R.isTable(info.profile.cert)
      and R.isTable(info.status)
      and R.isArray(info.fields)
      and R.isArray(info.schedules)
end

HamvModel.getInfo = R.memoize(function(sn)
  local profile = getGatewayProfile(sn)

  local info = {}

  info.device = sn

  local owner = profile.state.owner or {}
  info.owner = tonumber(owner.set)

  -- not safe, easily broke when device malfunction and send corrupt data
  info.profile = {
    esh = JSON.parse(profile.state.esh.reported),
    module = JSON.parse(profile.state.module.reported),
    cert = JSON.parse(profile.state.cert.reported)
  }

  info.status = JSON.parse(profile.state.states.reported)

  info.connected = profile.online

  info.locked = profile.locked

  if profile.state.ota.reported then
    info.device_state = JSON.parse(profile.state.ota.reported).state or 'idle'
  else
    info.device_state = 'idle'
  end

  info.fields = L.castArray(JSON.parse(profile.state.fields.set) or {})

  info.schedules = L.castArray(JSON.parse(profile.state.schedules.set) or {})

  return info
end)

function HamvModel.addInfoHisotry(sn, info)
  local profile = info.profile
  local fields = info.fields

  local opt = {
    metrics = {
      ['profile'] = JSON.stringify(profile),
      ['fields'] = JSON.stringify(fields)
    },
    tags = {
      device_sn = sn
    }
  }
  return Tsdb.write(opt).error == nil
end

function HamvModel.addStatusHisotry(sn, states)
  local opt = {
    metrics = {},
    tags = {
      device_sn = sn,
    }
  }
  for key,value in pairs(states) do
    opt.metrics[key] = value
  end
  return Tsdb.write(opt).error == nil
end

function HamvModel.isValidSchedules(calendars)
  for _, value in pairs(calendars) do
    if value.name == nil or value.start == nil or value['end'] == nil
        or value.days == nil or value.active == nil or value.esh ==nil then
      return false
    end
  end
  return true
end

function HamvModel.sendAction(sn, name, data, identifier)
  local action = R.extend({
    id = identifier or tostring(os.time()),
    request = name,
  }, data)
  local opt = {identity = sn, action = JSON.stringify(action)}
  return HamvGateway.setIdentityState(opt).error == nil
end

function HamvModel.sendConfigAction(sn, config, identifier)
  return HamvModel.sendAction(sn, 'config', { data = config }, identifier)
end

function HamvModel.sendSetAction(sn, stateChanges, identifier)
  return HamvModel.sendAction(sn, 'set', { data = stateChanges }, identifier)
end

function HamvModel.sendOTAAction(sn, firmwareInfo, identifier)
  return HamvModel.sendAction(sn, 'ota', { data = firmwareInfo }, identifier)
end

function HamvModel.sendResetAction(sn, identifier)
  return HamvModel.sendAction(sn, 'reset', nil, identifier)
end

function HamvModel.sendReconnectAction(sn)
  return HamvModel.sendAction(sn, 'reconnect')
end

function HamvModel.setFields(sn, fields)
  local opt = {identity = sn, fields = JSON.stringify(fields)}
  return HamvGateway.setIdentityState(opt).error == nil
end

function HamvModel.setSchedules(sn, schedules)
  local opt = {identity = sn, schedules = JSON.stringify(schedules)}
  return HamvGateway.setIdentityState(opt).error == nil
end

function HamvModel.getSchedules(sn)
  return HamvModel.getInfo(sn).schedules
end

function HamvModel.getEsh(sn)
  return HamvModel.getInfo(sn).profile.esh or {}
end

function HamvModel.getModel(sn)
  return assert(HamvModel.getEsh(sn).model, ('Device failed to getModel, sn=%s'):format(sn))
end

function HamvModel.getDeviceId(sn)
  local module = HamvModel.getModule(sn)
  return module.id or module.mac_address
end

function HamvModel.getModule(sn)
  return HamvModel.getInfo(sn).profile.module or {}
end

function HamvModel.getFirmwareVersion(sn)
  return HamvModel.getModule(sn).firmware_version
end

function HamvModel.getStates(sn)
  return HamvModel.getInfo(sn).status
end

-- TODO: move this out
function HamvModel.createActionIdentifier(ws, requestId, requestName, opt)
  local JWT = require 'jwt'

  local payload = {
    opt = opt,
    iat = os.time(),
    sid = ws.socket_id,
    rid = requestId,
    rqn = requestName
  }

  local PRIVATE_KEY = require 'action_identifier_secret'
  return JWT.encode(payload, PRIVATE_KEY, 'HS256')
end

function HamvModel.decodeActionResult(result)
  if R.isNumber(result.id) then
    return
  end

  local JWT = require 'jwt'
  local PRIVATE_KEY = require 'action_identifier_secret'

  local payload, err = JWT.decode(result.id, PRIVATE_KEY, true, 'HS256')
  if err then
    print(JSON.stringify(err))
    return nil
  end

  if payload.rqn ~= result.response then
    print('response from device does not match action identifier')
    return
  end

  return payload
end

function HamvModel.responseByActionResult(result)
  local payload = HamvModel.decodeActionResult(result)

  if not R.isTable(payload) then
    return payload
  end

  if R.isNil(payload.sid) then
    return true
  end

  local response = {
    id = payload.rid,
    response = payload.rqn
  }

  if result.code then
    response.code = result.code
    response.status = result.status
    response.message = result.message
  else
    response.status = result.status
    if result.data then
      response.data = result.data
    end
  end

  local opt = {
    message = JSON.stringify(response),
    socket_id = payload.sid,
    type = 'data-text'
  }

  return Websocket.send(opt).error == nil
end

local function buildEventPaylod(eventName, eventData)

  local event = {
    event = eventName
  }
  if eventData then
    event.data = eventData
  end

  return JSON.stringify(event)
end

-- TODO: move this out to user model
function HamvModel.listUserSockets(userId)
  assert(R.isNumber(userId), 'invalid userId to listUserSockets: '..JSON.stringify(userId))

  return HamvChannel.list(userId)
end

-- TODO: move this out to user model
function HamvModel.subscribeUserSocket(userId, socketId)
  assert(R.isNumber(userId), 'invalid userId to subscribeUserSocket: '..JSON.stringify(userId))

  return HamvChannel.subscribe(userId, socketId)
end

-- TODO: move this out to user model
function HamvModel.unsubscribeUserSocket(userId, socketId)
  assert(R.isNumber(userId), 'invalid userId to unsubscribeUserSocket: '..JSON.stringify(userId))

  return HamvChannel.unsubscribe(userId, socketId)
end

-- TODO: move this out to user model
function HamvModel.pruneUserSockets(userId)
  assert(R.isNumber(userId), 'invalid userId to pruneUserSockets: '..JSON.stringify(userId))

  return HamvChannel.prune(userId)
end

-- TODO: move this out to user model
function HamvModel.notifyUser(userId, eventName, eventData)
  assert(R.isNumber(userId), 'invalid userId to notifyUser: '..JSON.stringify(userId))

  local payload = buildEventPaylod(eventName, eventData)

  HamvChannel.publish(userId, payload)
end

-- @tdescription Subscribe
-- @tparam sn string|array(string) device sn
-- @tparam changes dictionary changes to device profile
function HamvModel.subscribeDeviceEvent(sn, ...)
  assert(R.isString(sn) or R.isArray(sn), 'invalid sn to subscribeDeviceEvent: '..JSON.stringify(sn))
  HamvChannel.subscribe(sn, ...)
end

-- @tdescription Subscribe
-- @tparam sn string|array(string) device sn
-- @tparam changes dictionary changes to device profile
function HamvModel.unsubscribeDeviceEvent(sn, ...)
  assert(R.isString(sn) or R.isArray(sn), 'invalid sn to unsubscribeDeviceEvent: '..JSON.stringify(sn))
  HamvChannel.unsubscribe(sn, ...)
end

-- @tdescription Send device change event to subscribers of the device
-- @tparam sn string device sn
-- @tparam changes dictionary changes to device profile
function HamvModel.publishDeviceChangeEvent(sn, changes)
  assert(R.isString(sn), 'invalid sn to publishDeviceChangeEvent: '..JSON.stringify(sn))

  local eventData = {
    device = sn,
    changes = changes or {}
  }

  local payload = buildEventPaylod('device_change', eventData)

  HamvChannel.publish(sn, payload)
end

-- @tdescription Send device change event to subscribers of the device
-- @tparam sn string device sn
-- @tparam schedules array new schedules
function HamvModel.publishCalendarEvent(sn, schedules)
  assert(R.isString(sn), 'can not publish calendar event to '..JSON.stringify(sn))

  local eventData = {
    device = sn,
    schedules = schedules or {}
  }

  local payload = buildEventPaylod('calendar', eventData)

  HamvChannel.publish(sn, payload)
end

-- @tdescription clean up closed sockets listening to device
function HamvModel.pruneListeners(sn)
  HamvChannel.prune(sn)
end

function HamvModel.getDeviceStatus(deviceSn, options)
  options = options or {}
  local ret = Tsdb.listMetrics()
  if ret.total == 0 then
    return {}
  end
  local metrics = {}
  local counts = 0
  for _, value in pairs(ret.metrics) do
    if string.sub(value,1, 1) == "H" then
      table.insert(metrics, value)
      counts = counts + 1
    end
  end
  if counts == 0 then
    return {}
  end

  ret = Tsdb.query({
    metrics = metrics,
    mode = "split",
    start_time = options.start_time or "2016-01-01T00:00:01+00:00",
    end_time = options.end_time,
    tags = { device_sn = deviceSn },
    limit = 1
  })

  if ret.values == nil then
    return {}
  end

  local statusInfo = {}
  for key, value in pairs(ret.values) do
    if #value > 0 then
      statusInfo[key] = value[1][2]
    end
  end

  return statusInfo
end

function HamvModel.getDeviceStatusHistory(deviceSn, options)
  options = options or {}
  local ret = Tsdb.listMetrics()
  if ret.total == 0 then
    return {}
  end
  local deviceFieldMetrics = {}
  local counts = 0
  for _, value in pairs(ret.metrics) do
    if string.sub(value,1, 1) == "H" then
      table.insert(deviceFieldMetrics, value)
      counts = counts + 1
    end
  end
  if counts == 0 then
    return {}
  end

  ret = Tsdb.query({
    metrics = deviceFieldMetrics,
    mode = "merge",
    start_time = options.start_time or "2017-01-01T00:00:01+00:00",
    end_time = options.end_time,
    tags = { device_sn = deviceSn },
    limit = options.limit or 1
  })

  if ret.values == nil then
    return {}
  end
  local historyData = L.castArray()
  R(ret.values)
    :each(function(_, fieldValueArray)
      local dataPoint = {}
      R(fieldValueArray)
        :each(function(key, value)
          --TODO use pcall
          dataPoint[ret.columns[key]]=value
        end)
      --print("dataPoint="..to_json(dataPoint))
      R.push(historyData,dataPoint)
    end)
  --print("in history query **1 = "..to_json(historyData))
  return historyData
end

function HamvModel.validateSn(deviceSn)
  if #deviceSn ~= 24 then return end
  if deviceSn ~= string.match(deviceSn, '[%l%u%d]+') then return end
  return deviceSn
end

return HamvModel

end

package.preload['events'] = function()
--[[--
events
@module events
]]
local Object = require 'modules_object'
local R = require 'modules_moses'

local EventEmitter = Object:extend()

function EventEmitter:initialize()
	self.events = {}
end

function EventEmitter:emit(name, ...)
	local events = self.events
	local listeners = events[name]
	if (name == 'error' and not listeners) then
		local args = { ... }
		if (#args > 0) then
			error(args[1])
		end
		return false
	end
	if (not listeners) then
		return false
	end
	for index = 1, #listeners do
		listeners[index](...)
	end
	return true
end

function EventEmitter:on(name, listener)
	assert(R.isCallable(listener), '"listener" argument must be callable')
	local events = self.events
	local listeners = events[name] or {}
	events[name] = listeners
	table.insert(listeners, listener)
	return self
end

function EventEmitter:once(name, listener)
	assert(R.isCallable(listener), '"listener" argument must be callable')
	local function wrapper(...)
		self:removeListener(name, wrapper)
		listener(...)
	end
	return self:on(name, wrapper)
end

function EventEmitter:removeAllListeners(name)
	if (not name) then
		self.events = {}
	else
		self.events[name] = nil
	end
	return self
end

function EventEmitter:removeListener(name, listener)
	assert(R.isCallable(listener), '"listener" argument must be callable')
	local events = self.events
	local listeners = events[name]
	if (not listeners) then
		return self
	end
	for index = 1, #listeners do
		if (listeners[index] == listener) then
			table.remove(listeners, index)
			break
		end
	end
	if (#listeners == 0) then
		events[name] = nil
	end
	return self
end

return EventEmitter

end

package.preload['user_integration_model'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'

local UserIntegrationModel = {}
local primaryKey = 'User_Data'

function UserIntegrationModel.genStoreKey(userId)
  return userId..'_integration'
end
function UserIntegrationModel.genLockId(userId)
  return 'uim_' .. userId
end

function UserIntegrationModel.get(userId)
  return from_json(
    KV.hget(primaryKey, UserIntegrationModel.genStoreKey(userId)) or '{}'
  )
end

function UserIntegrationModel.add(userId, value)
  local _, res = sync_call(UserIntegrationModel.genLockId(userId), function()
    return R.isNumber(
      KV.hset(primaryKey, UserIntegrationModel.genStoreKey(userId), to_json(
        R.extend(UserIntegrationModel.get(userId), value)
      ))
    )
  end)
  return res
end

function UserIntegrationModel.set(userId, value)
  local _, res = sync_call(UserIntegrationModel.genLockId(userId), function()
    return R.isNumber(
      KV.hset(primaryKey, UserIntegrationModel.genStoreKey(userId), to_json(value))
    )
  end)
  return res
end

function UserIntegrationModel.remove(userId)
  return R.isNumber(
    KV.hdel(primaryKey, UserIntegrationModel.genStoreKey(userId))
  )
end

return UserIntegrationModel

end

package.preload['device_events_model'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'

local DeviceEventModel = {}

function DeviceEventModel.genStoreKey(sn)
  return 'device_' .. sn .. '_events'
end

function DeviceEventModel.getAllEvents(sn)
  return R.map(KV.hgetall(
    DeviceEventModel.genStoreKey(sn)
  ) or {},
  function(_, jsonEvent)
    return from_json(jsonEvent)
  end)
end

function DeviceEventModel.setEvent(sn, eventId, event)
  return R.isNumber(
    KV.hset(
      DeviceEventModel.genStoreKey(sn),
      eventId,
      to_json(event)
    )
  )
end

function DeviceEventModel.checkEventExist(sn, eventId)
  return KV.hget(
    DeviceEventModel.genStoreKey(sn),
    eventId
  ) ~= nil
end

function DeviceEventModel.removeEvent(sn, eventId)
  return R.isNumber(
    KV.hdel(
      DeviceEventModel.genStoreKey(sn),
      eventId
    )
  )
end

function DeviceEventModel.destroy(sn)
  return R.isNumber(
    KV.del(
      DeviceEventModel.genStoreKey(sn)
    )
  )
end

return DeviceEventModel

end

package.preload['phone_session'] = function()
-- luacheck: globals Keystore
-- luacheck: globals __debugMsg

local R = require 'modules_moses'
local KV = require 'modules_kv'

local PhoneSession = {}

local SESSION_KEY = 'phoneSession'

-- Get the phone session information
local sessionInfo = R.memoize(function(socket_id)
  local result = KV.hget(SESSION_KEY, socket_id)
  return from_json(result)
end)

-- Init phone session
function PhoneSession.sessionInit(wsInfo, data)
  local session = R(wsInfo)
    :pick('socket_id', 'parameters', 'timestamp', 'route')
    :extend({
      data = data
    })
    :value()

  return KV.hset(SESSION_KEY, wsInfo.socket_id, to_json(session)) == 1
end

-- Set phone session data
function PhoneSession.setSessionData(wsInfo, sessionData)
  local session = sessionInfo(wsInfo.socket_id)
  session.data = sessionData
  return KV.hset(SESSION_KEY, wsInfo.socket_id, to_json(session)) == 1
end

-- Get phone session data
function PhoneSession.getSessionData(wsInfo)
  local session = sessionInfo(wsInfo.socket_id) or {}
  return session.data or {}
end

-- Clear the phone session
function PhoneSession.sessionDelete(wsInfo)
  return KV.hdel(SESSION_KEY, wsInfo.socket_id) == 1
end

return PhoneSession

end

package.preload['device_permission_model'] = function()
local KV = require 'modules_kv'
local L = require 'lodash'
local R = require 'modules_moses'
local DevicePermissionModel = {}
local OWNER="owner"
local GUEST="guest"

function DevicePermissionModel.genStoreKey(sn)
  return "device_"..sn.."_permissions"
end

function DevicePermissionModel.genUserRole(userId, role)
  return role.."_"..userId
end

function DevicePermissionModel.checkOwnerPermission(sn, userId)
  return DevicePermissionModel.checkPermission(sn, DevicePermissionModel.genUserRole(userId, OWNER))
end

function DevicePermissionModel.checkGuestPermission(sn, userId)
  return DevicePermissionModel.checkPermission(sn, DevicePermissionModel.genUserRole(userId, GUEST))
end

function DevicePermissionModel.checkPermission(sn, userRole)
  return KV.sismember(DevicePermissionModel.genStoreKey(sn), userRole) == 1
end

function DevicePermissionModel.checkUserHasAccess(sn, userId)
  local permissionSet={
    DevicePermissionModel.genUserRole(userId, OWNER),
    DevicePermissionModel.genUserRole(userId, GUEST)
  }
  return (R.size(R.intersection(DevicePermissionModel.list(sn), permissionSet)) > 0)
end

function DevicePermissionModel.getUserDevicePermission(sn, userId)
  local permissionSet={
    DevicePermissionModel.genUserRole(userId, OWNER),
    DevicePermissionModel.genUserRole(userId, GUEST)
  }
  return R.intersection(DevicePermissionModel.list(sn), permissionSet)
end

function DevicePermissionModel.getDeviceUsers(sn, noCache)
  return R.union(
    DevicePermissionModel.getDeviceWithRole(sn, OWNER, noCache),
    DevicePermissionModel.getDeviceWithRole(sn, GUEST, noCache)
  )
end

function DevicePermissionModel.getDeviceOwners(sn, noCache)
  return DevicePermissionModel.getDeviceWithRole(sn, OWNER, noCache)
end

function DevicePermissionModel.getDeviceGuests(sn, noCache)
  return DevicePermissionModel.getDeviceWithRole(sn, GUEST, noCache)
end

function DevicePermissionModel.getDeviceWithRole(sn, role, noCache)
  local permissions = DevicePermissionModel.list(sn, noCache)
  local users = L.castArray()
  R(permissions)
    :each(function(_, permission)
      local splitResult = L.split(permission,"_")
      if splitResult[1] == role then
        R.push(users,tonumber(splitResult[2]))
      end
    end)
  return users
end

local function listWithoutCache(sn)
  return KV.smembers(DevicePermissionModel.genStoreKey(sn))
end
local listWithCache = R.memoize(listWithoutCache)
function DevicePermissionModel.list(sn, noCache)
  return noCache and listWithoutCache(sn) or listWithCache(sn)
end

function DevicePermissionModel.remove(sn, userRole)
  return KV.srem(DevicePermissionModel.genStoreKey(sn), userRole) ~= nil
end

function DevicePermissionModel.removeDeviceOwner(sn, userId)
  return DevicePermissionModel.remove(sn, DevicePermissionModel.genUserRole(userId, OWNER))
end

function DevicePermissionModel.removeDeviceGuest(sn, userId)
  return DevicePermissionModel.remove(sn, DevicePermissionModel.genUserRole(userId, GUEST))
end

function DevicePermissionModel.removeAnyUser(sn, userId)
  return DevicePermissionModel.removeOwnDevice(sn, userId) or DevicePermissionModel.removeShareDevice(sn, userId)
end

function DevicePermissionModel.add(sn, userRole)
  return KV.sadd(DevicePermissionModel.genStoreKey(sn), userRole) ~= nil
end

function DevicePermissionModel.addDeviceOwner(sn, userId)
  return DevicePermissionModel.add(sn, DevicePermissionModel.genUserRole(userId, OWNER))
end

function DevicePermissionModel.addDeviceGuest(sn, userId)
  return DevicePermissionModel.add(sn, DevicePermissionModel.genUserRole(userId, GUEST))
end

return DevicePermissionModel

end

package.preload['information_model'] = function()
local KV = require "modules_kv"
local L = require "lodash"
local R = require "modules_moses"
local JSON = require "modules_json"
local yaml = require 'yaml'
local integration = require "integration_model"

local InformationModel = {}
InformationModel.meta = { __index = InformationModel }
InformationModel.KVkey = "infoModelList"
InformationModel.MappingKVkey = "infoModelMap"

local errors = {
    [100] = "file format error."
}
function InformationModel.decodeInformationModel(rawText)
    local ok, ret
    ret = from_json(rawText)
    if ret then return ret end
    ok, ret = pcall(function() return yaml.eval(rawText) end)
    if ok then return ret end
end

local function checkMapId(map)
    if map.id == nil or R.isString(map.id) ~= true or map.id == "" then
        return false,"\"id\" is empty or not string"
    end
    return true
end

local function checkMapType(map)
    if map.type == nil or R.isString(map.type) ~= true or map.type == "" then
        return false,"\"type\" is empty or not string"
    end
    return true
end

local function checkMapAppendName(map,total)
    if total > 1 and (map.append_name == nil or R.isString(map.append_name) ~= true or map.append_name == "") then
        return false,"\"append_name\" must defiend and it is not string or empty string"
    elseif map.append_name ~= nil and R.isString(map.append_name) ~= true and map.append_name == "" then
        return false,"\"append_name\" is not string or empty string"
    end
    return true
end

local function checkMapDescription(map)
    if map.description ~= nil and R.isString(map.description) ~= true and map.description == "" then
        return false,"\"description\" is not string or empty string"
    end
    return true
end

local function checkAttributesOnOff(attributes)
    if attributes.on_off == nil or type(attributes.on_off) ~= "table" or R.isEmpty(attributes.on_off) then
        return false,"Can't find \"on_off\" on Attributes"
    end
    local on_off = attributes.on_off
    if on_off.key == nil or R.isString(on_off.key) ~= true then
        return false,"\"on_off\" missing the key"
    end
    if on_off.values == nil or R.isTable(on_off.values) ~= true then
        return false,"\"on_off\" missing the values"
    end
    local values = on_off.values
    if values.on == nil then
        return false,"\"on_off\" values missing the on"
    end
    if values.off == nil then
        return false,"\"on_off\" values missing the off"
    end
    return true
end
local function checkAttributesLockState(attributes)
    if attributes.lock_state == nil or type(attributes.lock_state) ~= "table" or R.isEmpty(attributes.lock_state) then
        return true
    end
    local lock_state = attributes.lock_state
    if lock_state.key == nil or R.isString(lock_state.key) ~= true then
        return false,"\"lock_state\" missing the key"
    end
    if lock_state.values == nil or R.isTable(lock_state.values) ~= true then
        return false,"\"lock_state\" missing the values"
    end
    local values = lock_state.values
    if values.locked == nil or R.isEmpty(values.locked) then
        return false,"\"lock_state\" values missing the locked"
    end
    if values.unlocked == nil or R.isEmpty(values.unlocked) then
        return false,"\"lock_state\" values missing the unlocked"
    end
    return true
end
local function checkAttributesPercentage(attributes)
    if attributes.percentage == nil or type(attributes.percentage) ~= "table" or R.isEmpty(attributes.percentage) then
        return true
    end
    local percentage = attributes.percentage
    if percentage.key == nil or R.isString(percentage.key) ~= true then
        return false,"\"percentage\" missing the key"
    end
    if percentage.max == nil or R.isNaN(percentage.max) or percentage.max > 100 then
        return false,"\"percentage\" max is worng"
    end
    if percentage.min == nil or R.isNaN(percentage.min) or percentage.min < 0 then
        return false,"\"percentage\" min is worng"
    end
    return true
end
local function checkAttributesAcMode(attributes)
    if attributes.ac_mode == nil or type(attributes.ac_mode) ~= "table" or R.isEmpty(attributes.ac_mode) then
        return true
    end
    local ac_mode = attributes.ac_mode
    if ac_mode.key == nil or R.isString(ac_mode.key) ~= true then
        return false,"\"ac_mode\" missing the key"
    end
    if ac_mode.values == nil or R.isTable(ac_mode.values) ~= true then
        return false,"\"ac_mode\" missing the values"
    end
    local values = ac_mode.values
    if values.off ~= nil and (R.isEmpty(values.off) or R.isNaN(values.off)) then
        return false,"\"ac_mode\" off is wrong"
    end
    if values.heat ~= nil and (R.isEmpty(values.heat) or R.isNaN(values.heat)) then
        return false,"\"ac_mode\" heat is wrong"
    end
    if values.cool ~= nil and (R.isEmpty(values.cool) or R.isNaN(values.cool)) then
        return false,"\"ac_mode\" cool is wrong"
    end
    if values.auto ~= nil and (R.isEmpty(values.auto) or R.isNaN(values.auto)) then
        return false,"\"ac_mode\" auto is wrong"
    end
    if values.eco ~= nil and (R.isEmpty(values.eco) or R.isNaN(values.eco)) then
        return false,"\"ac_mode\" eco is wrong"
    end
    return true
end

local function checkAttributesTemperatureTemplete(item,attributes)
    if attributes[item] == nil or type(attributes[item]) ~= "table"
        or R.isEmpty(attributes[item]) then
        return true
    end
    local obj = attributes[item]
    if obj.key == nil or R.isString(obj.key) ~= true then
        return false,'"' .. item .. "\" missing the key"
    end
    if obj.unit == nil or R.isEmpty( obj.unit) or
        (obj.unit ~= "celsius" and obj.unit ~= "fahrenheit") then
        return false,'"' .. item .. "\" unit is worng"
    end
    return true
end

local function checkAttributesHumidity(attributes)
    if attributes.humidity == nil or type(attributes.humidity) ~= "table" or R.isEmpty(attributes.humidity) then
        return true
    end
    local humidity = attributes.humidity
    if humidity.key == nil or R.isString(humidity.key) ~= true then
        return false,"\"humidity\" missing the key"
    end
    return true
end

local function checkAttributesColor(attributes)
    if attributes.color == nil or type(attributes.color) ~= "table" or R.isEmpty(attributes.color) then
        return true
    end
    local color = attributes.color
    if color.key == nil or R.isString(color.key) ~= true then
        return false,"\"color\" missing the key"
    end
    if color.unit == nil or R.isEmpty(color.unit) or color.unit ~= "rgb" then
        return false,"\"color\" unit is worng"
    end
    return true
end

local function checkAttributesColorTemperature(attributes)
    if attributes.color_temperature == nil or type(attributes.color_temperature) ~= "table" or R.isEmpty(attributes.color_temperature) then
        return true
    end
    local color_temperature = attributes.color_temperature
    if color_temperature.key == nil or R.isString(color_temperature.key) ~= true then
        return false,"\"color_temperature\" missing the key"
    end
    if color_temperature.unit == nil or R.isEmpty(color_temperature.unit) or
        (color_temperature.unit ~= "kelvin") then
        return false,"\"color_temperature\" unit is worng"
    end
    if color_temperature.max == nil or R.isEmpty(color_temperature.max) or R.isNaN(color_temperature.max) or color_temperature.max > 100 then
        return false,"\"color_temperature\" max is worng"
    end
    if color_temperature.min == nil or R.isEmpty(color_temperature.min) or R.isNaN(color_temperature.min) or color_temperature.min < 0 then
        return false,"\"color_temperature\" min is worng"
    end
    return true
end

local function checkAttributesBrightness(attributes)
    if attributes.brightness == nil or type(attributes.brightness) ~= "table" or R.isEmpty(attributes.brightness) then
        return true
    end
    local brightness = attributes.brightness
    if brightness.key == nil or R.isString(brightness.key) ~= true then
        return false,"\"brightness\" missing the key"
    end
    if brightness.max == nil or R.isNaN(brightness.max) or brightness.max > 100 then
        return false,"\"brightness\" max is worng"
    end
    if brightness.min == nil or R.isNaN(brightness.min) or brightness.min < 0 then
        return false,"\"brightness\" min is worng"
    end
    return true
end

local function checkErrorMessgae(_error,__ok,__error)
    if not __ok and __error ~= nil then
        _error = _error .. __error .."\n"
    end
    return _error
end
local function checkMapAttributes(map)
    if map.attributes == nil or type(map.attributes) ~= "table" or R.isEmpty(map.attributes) then
        return false,"Can't find any \"attributes\"."
    end
    local attributes = map.attributes
    local _error = ""
    local __ok, __error = checkAttributesOnOff(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesPercentage(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesAcMode(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesTemperatureTemplete("temperature",attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesTemperatureTemplete("target_temperature",attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesTemperatureTemplete("low_target_temperature",attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesTemperatureTemplete("high_target_temperature",attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesHumidity(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesColor(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesColorTemperature(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesBrightness(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkAttributesLockState(attributes)
    _error = checkErrorMessgae(_error,__ok,__error)
    if _error ~= "" then
        return false,_error
    end
    return true
end

local function checkTraitsMap(map,total)
    if R.isEmpty(map) then
        return false,"Can't find any map"
    end
    local _error = ""
    local __ok, __error = checkMapId(map)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkMapType(map)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkMapAppendName(map,total)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkMapDescription(map)
    _error = checkErrorMessgae(_error,__ok,__error)
    __ok, __error = checkMapAttributes(map)
    _error = checkErrorMessgae(_error,__ok,__error)

    if _error ~= "" then
        return false,_error
    end
    return true
end

local function checkIntegrationTraits(obj)
    if R.isEmpty(obj) then
        return false,"traits is empty"
    end
    local _error = ""
    for k,map in pairs(obj) do
        local __ok, __error = checkTraitsMap(map,#obj)
        if not __ok and __error ~= nil then
            _error = _error .. "\n[" .. k .. "]" .. __error
        end
    end
    if _error ~= "" then
        return false, ",traits errors =>" .. _error
    end
    return true
end
local function checkExternalIntegration(obj)
    __debugMsg("checkExternalIntegration::" .. to_json(obj))
    if obj.traits == nil then
        return false,"Can't find any Traits"
    end
    local _ok, _error = checkIntegrationTraits(obj.traits)
    if not _ok then
        return _ok, "integration errors" .. _error
    end
    return true
end

function InformationModel:new()
    local meta = rawget(self, 'meta')
  	if not meta then
      error('Cannot inherit from instance object')
    end
    local i = {
        KV = InformationModel.LoadAll()
    }
    return setmetatable(i, meta)
end

function InformationModel:loadExternalIntegration()
    local _data =  R.select(self.KV or {} , function(index, value)
        return R.has(value,'integration')
    end)
    if R.isEmpty(_data) then return end
    _data = R.map(_data,function(k,v)
        local _v = v.integration
        _v.familyMembers = v.familyMembers
        return v.familyName,_v
    end)
    if R.isEmpty(_data) then return end
    self.externalIntegration = _data
    return self
end

function InformationModel:getExternalIntegration()
    return integration:new(self.externalIntegration)
end

InformationModel.LoadAll = R.memoize(function()
  return L.castArray(
    R(Keystore.get({key=InformationModel.KVkey}).value or {})
      :map(function(familyName, text)
        local ok, ret
        ret = from_json(text)
        if ret then return ret end

        ok, ret = pcall(function() return yaml.eval(text) end)
        if ok then return ret end
      end)
      :select(function(_, value)
        return R.isIterable(value)
      end)
      :value()
  )
end, function() return '' end)

function InformationModel.getModel(familyName)
    local res = KV.hget(InformationModel.KVkey,familyName)
    __debugMsg("InformationModel.getModel::" .. to_json(res))
    return JSON.parse(res) or nil
end

function InformationModel.setModel(familyName, model)
    if type(model) ~= 'string' then
      model = to_json(model)
    end
    local _, res = sync_call(string.format('%s_%s', InformationModel.KVkey, familyName), function()
      return KV.hset(InformationModel.KVkey,familyName, model)
    end)
    __debugMsg("InformationModel.setModel::" .. to_json(res))
    return {
      listRes = res,
      mapRes = InformationModel.updateMappingTime(familyName)
    }
end

function InformationModel.updateMappingTime(familyName)
    local _, res = sync_call(InformationModel.MappingKVkey, function()
      local mapping = KV.get(InformationModel.MappingKVkey) or {}
      local model = mapping[familyName]
      if not model then return end
      local ts = tonumber(os.time(os.date('!*t')) .. '000')
      model.timestamp = ts
      model.lastModified = ts
      local res = KV.set(InformationModel.MappingKVkey, mapping)
      __debugMsg("InformationModel.updateMappingTime::" .. to_json(res))
      return JSON.parse(res) or nil
    end)
    return res
end

function InformationModel.verify(rawText)
    local data = InformationModel.decodeInformationModel(rawText)
    if data == nil then return false, errors[100] end
    if data.integration ~= nil then
        local _ok, _error = checkExternalIntegration(data.integration)
        if not _ok then
            return _ok, _error
        end
    end
    return true
end

function InformationModel.filterByModel(model, infoModels)
  return R(infoModels)
    :select(function(_, im)
      return R(im.familyMembers)
        :include(function(regex)
          return string.match(model, regex)
        end)
        :value()
    end)
    :value()
end

function InformationModel.checkCondition(conditions, states)
  return R.all(conditions, function(_, condition)
    local value = states[condition.key]

    if R.isNil(value) then
      return false
    end

    if not (type(value) == type(condition.target)) then
      print(string.format("Error, please check triggerEvent with device key %s and device data", condition.key))
      return false
    end

    if condition.op == 'eq' then
      return value == condition.target
    end
    if condition.op == 'neq' then
      return value ~= condition.target
    end
    if condition.op == 'lt' then
      return value < condition.target
    end
    if condition.op == 'lte' then
      return value <= condition.target
    end
    if condition.op == 'gt' then
      return value > condition.target
    end
    if condition.op == 'gte' then
      return value >= condition.target
    end
  end)
end

return InformationModel

end

package.preload['modules_logger'] = function()
--[[--
logger
@module logger
]]
local InformationModel = require 'information_model'
local R = require 'modules_moses'
local yaml = require 'yaml'
local HamvModel = require 'hamv_model'
local Logger = {}
local infoModels = InformationModel.LoadAll()

function Logger.findKeyValueInFields(key, value, fields)
  if fields[key] then
    if fields[key][value] then
      local field = fields[key][value]
      return {
        key = key,
        text = field.text,
        value = value,
      }
    end
  end
end

function Logger.fromToTag(from)
  return string.find(from or '', '@') and 'email' or 'device_sn'
end

function Logger.getErrorMapping(ims)
  return R(ims)
    :pluck('errorFields')
    :reduce(function(result, errors)
      local mapping = Logger.modelsToFieldsMapping(errors)
      R.each(mapping, function(esh, obj)
        result[esh] = R.extend(result[esh] or {}, obj)
      end)
      return result
    end, {})
    :value()
end

function Logger.getComponentMapping(ims)
  return R(ims)
    :reduce(function(result, im)
      return R.extend(
        result,
        R(im.components)
          :reduce(function(result, component)
            return R.extend(
              result,
              Logger.modelsToFieldsMapping(component.models, component.title)
            )
          end, {})
          :value()
      )
    end, {})
    :value()
end

function Logger.log(type, from, action, tags, ip)
  local tag = Logger.fromToTag(from)
  local defaultTags = {
    [tag] = from,
    log_type = type,
  }
  R.extend(defaultTags, tags)

  local device_unique_id
  if defaultTags.device_sn then
    action.sn = defaultTags.device_sn

    local uniqueId = HamvModel.getDeviceId(defaultTags.device_sn)
    defaultTags.device_unique_id = uniqueId
    action.device_unique_id = uniqueId
  end

  Tsdb.write({
    metrics = {
      from = from,
      ip = ip,
      log = to_json(action),
      log_type = type,
    },
    tags = defaultTags
  })
end

function Logger.modelsToFieldsMapping(array, title)
  return R(array)
    :reduce(function(result, model)
      result[model.key] = R(model.values)
        :reduce(function(model, value)
          if not R.isTable(value) then return model end
          local key = value.value
          if not key then return model end
          model[key] = {
            text = R({title, value.text}):compact():concat(' '):value(),
          }
          return model
        end, {})
        :value()

      if R.isEmpty(result[model.key]) then
        result[model.key] = nil
      end

      return result
    end, {})
    :value()
end

function Logger.parseMessage(sn, key, value)
  local success, model = pcall(function () return HamvModel.getModel(sn) end)
  if not success then return nil end
  local ims = InformationModel.filterByModel(model, infoModels)
  local fields, obj

  fields = Logger.getErrorMapping(ims)
  obj = Logger.findKeyValueInFields(key, value, fields)
  if obj then obj.type = 'error' return obj end

  local getComponentMappingSuccess, fields = pcall(function () return Logger.getComponentMapping(ims) end)
  if not getComponentMappingSuccess then
    print(("Error, getComponentMapping fail, please check information model for model %s"):format(model))
    return nil
  end
  obj = Logger.findKeyValueInFields(key, value, fields)
  if obj then obj.type = 'event' return obj end
end

return Logger

end

package.preload['modules_moses'] = function()
--- Utility-belt library for functional programming in Lua ([source](http://github.com/Yonaba/Moses))
-- @author [Roland Yonaba](http://github.com/Yonaba)
-- @copyright 2012-2017
-- @license [MIT](http://www.opensource.org/licenses/mit-license.php)
-- @release 1.6.0
-- @module moses
-- Ref: Parker-FTP-Api/blob/develop/src/modules/moses.lua

local _MODULEVERSION = '1.6.0'

-- Internalisation
local next, type, select, pcall = next, type, select, pcall
local setmetatable, getmetatable = setmetatable, getmetatable
local t_insert, t_sort = table.insert, table.sort
local t_remove,t_concat = table.remove, table.concat
local randomseed, random, huge = math.randomseed, math.random, math.huge
local floor, max, min = math.floor, math.max, math.min
local rawget = rawget
local unpack = table.unpack or unpack
local pairs,ipairs = pairs,ipairs
local _ = {}


-- ======== Private helpers

local function f_max(a,b) return a>b end
local function f_min(a,b) return a<b end
local function clamp(var,a,b) return (var<a) and a or (var>b and b or var) end
local function isTrue(_,value) return value and true end
local function iNot(value) return not value end

local function count(t)  -- raw count of items in an map-table
  local i = 0
    for k,v in pairs(t) do i = i + 1 end
  return i
end

local function extract(list,comp,transform,...) -- extracts value from a list
  local _ans
  local transform = transform or _.identity
  for index,value in pairs(list) do
    if not _ans then _ans = transform(value,...)
    else
      local value = transform(value,...)
      _ans = comp(_ans,value) and _ans or value
    end
  end
  return _ans
end

local function partgen(t, n, f, pad) -- generates array partitions
  for i = 0, #t, n do
    local s = _.slice(t, i+1, i+n)
    if #s>0 then
			while (#s < n and pad) do s[#s+1] = pad end
			f(s)
		end
  end
end

local function partgen2(t, n, f, pad) -- generates sliding array partitions
  for i = 0, #t, n-1 do
    local s = _.slice(t, i+1, i+n)
    if #s>0 and i+1<#t then
			while (#s < n and pad) do s[#s+1] = pad end
			f(s)
		end
  end
end

local function permgen(t, n, f) -- taken from PiL: http://www.lua.org/pil/9.3.html
  if n == 0 then f(t) end
  for i = 1,n do
    t[n], t[i] = t[i], t[n]
    permgen(t, n-1, f)
    t[n], t[i] = t[i], t[n]
  end
end

-- Internal counter for unique ids generation
local unique_id_counter = -1

--- Table functions
-- @section Table

--- Iterates on key-value pairs, calling `f (k, v)` at every step.
-- <br/><em>Aliased as `forEach`</em>.
-- @function each
-- @param t a table
-- @param f a function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @see eachi
function _.each(t, f, ...)
  for index,value in pairs(t) do
    f(index,value,...)
  end
end

--- Iterates on integer key-value pairs, calling `f(k, v)` every step.
-- Only applies to values located at integer keys. The table can be a sparse array.
-- Iteration will start from the lowest integer key found to the highest one.
-- <br/><em>Aliased as `forEachi`</em>.
-- @function eachi
-- @param t a table
-- @param f a function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @see each
function _.eachi(t, f, ...)
  local lkeys = _.sort(_.select(_.keys(t), function(k,v)
    return _.isInteger(v)
  end))
  for k, key in ipairs(lkeys) do
    f(key, t[key],...)
  end
end

--- Collects values at given keys and return them wrapped in an array.
-- @function at
-- @param t a table
-- @param ... A variable number of keys to collect values
-- @return an array-list of values
function _.at(t, ...)
  local values = {}
  for i, key in ipairs({...}) do
    if _.has(t, key) then values[#values+1] = t[key] end
  end
  return values
end

--- Counts occurrences of a given value in a table. Uses @{isEqual} to compare values.
-- @function count
-- @param t a table
-- @param[opt] value a value to be searched in the table. If not given, the @{size} of the table will be returned
-- @return the count of occurrences of the given value
-- @see countf
-- @see size
function _.count(t, value)
  if _.isNil(value) then return _.size(t) end
  local count = 0
  _.each(t, function(k,v)
    if _.isEqual(v, value) then count = count + 1 end
  end)
  return count
end

--- Counts occurrences validating a predicate. Same as @{count}, but uses an iterator.
-- Returns the count for values passing the test `f (k, v, ...)`
-- @function countf
-- @param t a table
-- @param f an iterator function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return the count of values validating the predicate
-- @see count
-- @see size
function _.countf(t, f, ...)
  return _.count(_.map(t, f, ...), true)
end

--- Loops `n` times through a table. In case `n` is omitted, it will loop forever.
-- In case `n` is lower or equal to 0, it returns an empty function.
-- <br/><em>Aliased as `loop`</em>.
-- @function cycle
-- @param t a table
-- @param n the number of loops
-- @return an iterator function yielding key-value pairs from the passed-in table.
function _.cycle(t, n)
  n = n or 1
  if n<=0 then return _.noop end
  local k, fk
  local i = 0
  while true do
    return function()
      k = k and next(t,k) or next(t)
      fk = not fk and k or fk
      if n then
        i = (k==fk) and i+1 or i
        if i > n then
          return
        end
      end
      return k, t[k]
    end
  end
end

--- Maps `f (k, v)` on key-value pairs, collects and returns the results.
-- <br/><em>Aliased as `collect`</em>.
-- @function map
-- @param t a table
-- @param f  an iterator function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return a table of results
function _.map(t, f, ...)
  local _t = {}
  for index,value in pairs(t) do
    local k, kv, v = index, f(index,value,...)
    _t[v and kv or k] = v or kv
  end
  return _t
end

--- Reduces a table, left-to-right. Folds the table from the first element to the last element
-- to a single value, using a given iterator and an initial state.
-- The iterator takes a state and a value and returns a new state.
-- <br/><em>Aliased as `inject`, `foldl`</em>.
-- @function reduce
-- @param t a table
-- @param f an iterator function, prototyped as `f (state, value)`
-- @param[opt] state an initial state of reduction. Defaults to the first value in the table.
-- @return the final state of reduction
-- @see reduceRight
-- @see reduceby
function _.reduce(t, f, state)
  for __,value in pairs(t) do
    if state == nil then state = value
    else state = f(state,value)
    end
  end
  return state
end

--- Reduces values in a table passing a given predicate. Folds the table left-to-right, considering
-- only values validating a given predicate.
-- @function reduceby
-- @param t a table
-- @param f an iterator function, prototyped as `f (state, value)`
-- @param state an initial state of reduction.
-- @param pred a predicate function `pred (k, v, ...)` to select values to be considered for reduction
-- @param[opt] ... optional args to be passed to `pred`
-- @return the final state of reduction
-- @see reduce
function _.reduceby(t, f, state, pred, ...)
	return _.reduce(_.select(t, pred, ...), f, state)
end

--- Reduces a table, right-to-left. Folds the table from the last element to the first element
-- to single value, using a given iterator and an initial state.
-- The iterator takes a state and a value, and returns a new state.
-- <br/><em>Aliased as `injectr`, `foldr`</em>.
-- @function reduceRight
-- @param t a table
-- @param f an iterator function, prototyped as `f (state, value)`
-- @param[opt] state an initial state of reduction. Defaults to the last value in the table.
-- @return the final state of reduction
-- @see reduce
function _.reduceRight(t, f, state)
  return _.reduce(_.reverse(t),f,state)
end

--- Reduces a table while saving intermediate states. Folds the table left-to-right
-- using a given iterator and an initial state. The iterator takes a state and a value,
-- and returns a new state. The result is an array of intermediate states.
-- <br/><em>Aliased as `mapr`</em>
-- @function mapReduce
-- @param t a table
-- @param f an iterator function, prototyped as `f (state, value)`
-- @param[opt] state an initial state of reduction. Defaults to the first value in the table.
-- @return an array of states
-- @see mapReduceRight
function _.mapReduce(t, f, state)
  local _t = {}
  for i,value in pairs(t) do
    _t[i] = not state and value or f(state,value)
    state = _t[i]
  end
  return _t
end

--- Reduces a table while saving intermediate states. Folds the table right-to-left
-- using a given iterator and an initial state. The iterator takes a state and a value,
-- and returns a new state. The result is an array of intermediate states.
-- <br/><em>Aliased as `maprr`</em>
-- @function mapReduceRight
-- @param t a table
-- @param f an iterator function, prototyped as `f (state, value)`
-- @param[opt] state an initial state of reduction. Defaults to the last value in the table.
-- @return an array of states
-- @see mapReduce
function _.mapReduceRight(t, f, state)
  return _.mapReduce(_.reverse(t),f,state)
end

--- Performs a linear search for a value in a table. It does not work for nested tables.
-- The given value can be a function prototyped as `f (v, value)` which should return true when
-- any v in the table equals the value being searched.
-- <br/><em>Aliased as `any`, `some`, `contains`</em>
-- @function include
-- @param t a table
-- @param value a value to search for
-- @return a boolean : `true` when found, `false` otherwise
-- @see detect
function _.include(t, value)
  local _iter = _.isFunction(value) and value or _.isEqual
  for __,v in pairs(t) do
    if _iter(v,value) then return true end
  end
  return false
end

--- Performs a linear search for a value in a table. Returns the key of the value if found.
-- The given value can be a function prototyped as `f (v, value)` which should return true when
-- any v in the table equals the value being searched.
-- @function detect
-- @param t a table
-- @param value a value to search for
-- @return the key of the value when found or __nil__
-- @see include
function _.detect(t, value)
  local _iter = _.isFunction(value) and value or _.isEqual
  for key,arg in pairs(t) do
    if _iter(arg,value) then return key end
  end
end

--- Returns all values having specified keys `props`.
-- @function where
-- @param t a table
-- @param props a set of keys
-- @return an array of values from the passed-in table
-- @see findWhere
function _.where(t, props)
	local r = _.select(t, function(__,v)
		for key in pairs(props) do
			if v[key] ~= props[key] then return false end
		end
		return true
	end)
	return #r > 0 and r or nil
end

--- Returns the first value having specified keys `props`.
-- @function findWhere
-- @param t a table
-- @param props a set of keys
-- @return a value from the passed-in table
-- @see where
function _.findWhere(t, props)
  local index = _.detect(t, function(v)
    for key in pairs(props) do
      if props[key] ~= v[key] then return false end
    end
    return true
  end)
  return index and t[index]
end

--- Selects and returns values passing an iterator test.
-- <br/><em>Aliased as `filter`</em>.
-- @function select
-- @param t a table
-- @param f an iterator function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return the selected values
-- @see reject
function _.select(t, f, ...)
  local _t = {}
  for index,value in pairs(t) do
    if f(index, value,...) then _t[#_t+1] = value end
  end
  return _t
end

--- Clones a table while dropping values passing an iterator test.
-- <br/><em>Aliased as `discard`</em>
-- @function reject
-- @param t a table
-- @param f an iterator function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return the remaining values
-- @see select
function _.reject(t, f, ...)
  local _mapped = _.map(t,f,...)
  local _t = {}
  for index,value in pairs (_mapped) do
    if not value then _t[#_t+1] = t[index] end
  end
  return _t
end

--- Checks if all values in a table are passing an iterator test.
-- <br/><em>Aliased as `every`</em>
-- @function all
-- @param t a table
-- @param f an iterator function, prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return `true` if all values passes the predicate, `false` otherwise
function _.all(t, f, ...)
  return ((#_.select(_.map(t,f,...), isTrue)) == count(t))
end

--- Invokes a method on each value in a table.
-- @function invoke
-- @param t a table
-- @param method a function, prototyped as `f (v, ...)`
-- @param[opt] ... Optional args to be passed to `method`
-- @return the result of the call `f (v, ...)`
-- @see pluck
function _.invoke(t, method, ...)
  local args = {...}
  return _.map(t, function(__,v)
    if _.isTable(v) then
      if _.has(v,method) then
        if _.isCallable(v[method]) then
          return v[method](v,unpack(args))
        else
          return v[method]
        end
      else
        if _.isCallable(method) then
          return method(v,unpack(args))
        end
      end
    elseif _.isCallable(method) then
      return method(v,unpack(args))
    end
  end)
end

--- Extracts values in a table having a given key.
-- @function pluck
-- @param t a table
-- @param key a key, will be used to index in each value: `value[key]`
-- @return an array of values having the given key
function _.pluck(t, key)
  return _.reject(_.map(t,function(__,value)
      return value[key]
    end), iNot)
end

--- Returns the max value in a collection. If an transformation function is passed, it will
-- be used to evaluate values by which all objects will be sorted.
-- @function max
-- @param t a table
-- @param[opt] transform a transformation function, prototyped as `transform (v, ...)`, defaults to @{identity}
-- @param[optchain] ... Optional args to be passed to `transform`
-- @return the max value found
-- @see min
function _.max(t, transform, ...)
  return extract(t, f_max, transform, ...)
end

--- Returns the min value in a collection. If an transformation function is passed, it will
-- be used to evaluate values by which all objects will be sorted.
-- @function min
-- @param t a table
-- @param[opt] transform a transformation function, prototyped as `transform (v, ...)`, defaults to @{identity}
-- @param[optchain] ... Optional args to be passed to `transform`
-- @return the min value found
-- @see max
function _.min(t, transform, ...)
  return extract(t, f_min, transform, ...)
end

--- Returns a shuffled copy of a given collection. If a seed is provided, it will
-- be used to init the pseudo random number generator (using `math.randomseed`).
-- @function shuffle
-- @param t a table
-- @param[opt] seed a seed
-- @return a shuffled copy of the given table
function _.shuffle(t, seed)
  if seed then randomseed(seed) end
  local _shuffled = {}
  _.each(t,function(index,value)
     local randPos = floor(random()*index)+1
    _shuffled[index] = _shuffled[randPos]
    _shuffled[randPos] = value
  end)
  return _shuffled
end

--- Checks if two tables are the same. It compares if both tables features the same values,
-- but not necessarily at the same keys.
-- @function same
-- @param a a table
-- @param b another table
-- @return `true` or `false`
function _.same(a, b)
  return _.all(a, function (i,v) return _.include(b,v) end)
     and _.all(b, function (i,v) return _.include(a,v) end)
end

--- Sorts a table, in-place. If a comparison function is given, it will be used to sort values.
-- @function sort
-- @param t a table
-- @param[opt] comp a comparison function prototyped as `comp (a, b)`, defaults to <tt><</tt> operator.
-- @return the initial table, sorted.
-- @see sortBy
function _.sort(t, comp)
  t_sort(t, comp)
  return t
end

--- Sorts a table in-place using a transform. Values are ranked in a custom order of the results of
-- running `transform (v)` on all values. `transform` may also be a string name property  sort by.
-- `comp` is a comparison function.
-- @function sortBy
-- @param t a table
-- @param[opt] transform a `transform` function to sort elements prototyped as `transform (v)`. Defaults to @{identity}
-- @param[optchain] comp a comparision function, defaults to the `<` operator
-- @return a new array of sorted values
-- @see sort
function _.sortBy(t, transform, comp)
	local f = transform or _.identity
	if _.isString(transform) then
		f = function(t) return t[transform] end
	end
	comp = comp or f_min
	local _t = {}
	_.each(t, function(__,v)
		_t[#_t+1] = {value = v, transform = f(v)}
	end)
	t_sort(_t, function(a,b) return comp(a.transform, b.transform) end)
	return _.pluck(_t, 'value')
end

--- Splits a table into subsets groups.
-- @function groupBy
-- @param t a table
-- @param iter an iterator function, prototyped as `iter (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `iter`
-- @return a table of subsets groups
function _.groupBy(t, iter, ...)
  local vararg = {...}
  local _t = {}
  _.each(t, function(i,v)
      local _key = iter(i,v, unpack(vararg))
      if _t[_key] then _t[_key][#_t[_key]+1] = v
      else _t[_key] = {v}
      end
    end)
  return _t
end

--- Groups values in a collection and counts them.
-- @function countBy
-- @param t a table
-- @param iter an iterator function, prototyped as `iter (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `iter`
-- @return a table of subsets groups names paired with their count
function _.countBy(t, iter, ...)
  local vararg = {...}
  local stats = {}
  _.each(t,function(i,v)
      local key = iter(i,v,unpack(vararg))
      stats[key] = (stats[key] or 0) +1
    end)
  return stats
end

--- Counts the number of values in a collection. If being passed more than one argument
-- it will return the count of all passed-in arguments.
-- @function size
-- @param[opt] ... Optional variable number of arguments
-- @return a count
-- @see count
-- @see countf
function _.size(...)
  local args = {...}
  local arg1 = args[1]
  if _.isTable(arg1) then
    return count(args[1])
  else
    return count(args)
  end
end

--- Checks if all the keys of `other` table exists in table `t`. It does not
-- compares values. The test is not commutative, i.e table `t` may contains keys
-- not existing in `other`.
-- @function containsKeys
-- @param t a table
-- @param other another table
-- @return `true` or `false`
-- @see sameKeys
function _.containsKeys(t, other)
  for key in pairs(other) do
    if not t[key] then return false end
  end
  return true
end

--- Checks if both given tables have the same keys. It does not compares values.
-- @function sameKeys
-- @param tA a table
-- @param tB another table
-- @return `true` or `false`
-- @see containsKeys
function _.sameKeys(tA, tB)
  for key in pairs(tA) do
    if not tB[key] then return false end
  end
  for key in pairs(tB) do
    if not tA[key] then return false end
  end
  return true
end

--- Array functions
-- @section Array

--- Samples `n` random values from an array. If `n` is not specified, returns a single element.
-- It uses internally @{shuffle} to shuffle the array before sampling values. If `seed` is passed,
-- it will be used for shuffling.
-- @function sample
-- @param array an array
-- @param[opt] n a number of elements to be sampled. Defaults to 1.
-- @param[optchain] seed an optional seed for shuffling
-- @return an array of selected values or a single value when `n` == 1
-- @see sampleProb
function _.sample(array, n, seed)
	n = n or 1
	if n < 1 then return end
	if n == 1 then
		if seed then randomseed(seed) end
		return array[random(1, #array)]
	end
	return _.slice(_.shuffle(array, seed), 1, n)
end

--- Return elements from a sequence with a given probability. It considers each value independently.
-- Providing a seed will result in deterministic sampling. Given the same seed it will return the same sample
-- every time.
-- @function sampleProb
-- @param array an array
-- @param prob a probability for each element in array to be selected
-- @param[opt] seed an optional seed for deterministic sampling
-- @return an array of selected values
-- @see sample
function _.sampleProb(array, prob, seed)
	if seed then randomseed(seed) end
	return _.select(array, function(_,v) return random() < prob end)
end

--- Converts a list of arguments to an array.
-- @function toArray
-- @param ... a list of arguments
-- @return an array of all passed-in args
function _.toArray(...) return {...} end

--- Looks for the first occurrence of a given value in an array. Returns the value index if found.
-- Uses @{isEqual} to compare values.
-- @function find
-- @param array an array of values
-- @param value a value to lookup for
-- @param[opt] from the index from where the search will start. Defaults to 1.
-- @return the index of the value if found in the array, `nil` otherwise.
function _.find(array, value, from)
  for i = from or 1, #array do
    if _.isEqual(array[i], value) then return i end
  end
end

--- Returns an array where values are in reverse order. The passed-in array should not be sparse.
-- @function reverse
-- @param array an array
-- @return a reversed array
function _.reverse(array)
  local _array = {}
  for i = #array,1,-1 do
    _array[#_array+1] = array[i]
  end
  return _array
end

--- Replaces elements in a given array with a given value. In case `i` and `j` are given
-- it will only replaces values at indexes between `[i,j]`. In case `j` is greather than the array
-- size, it will append new values, increasing the array.
-- @function fill
-- @param array an array
-- @param value a value
-- @param[opt] i the index from which to start replacing values. Defaults to 1.
-- @param[optchain] j the index where to stop replacing values. Defaults to the array size.
-- @return the original array with values changed
function _.fill(array, value, i, j)
	j = j or _.size(array)
	for i = i or 1, j do array[i] = value end
	return array
end

--- Collects values from a given array. The passed-in array should not be sparse.
-- This function collects values as long as they satisfy a given predicate and returns on the first falsy test.
-- <br/><em>Aliased as `takeWhile`</em>
-- @function selectWhile
-- @param array an array
-- @param f an iterator function prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return a new table containing all values collected
-- @see dropWhile
function _.selectWhile(array, f, ...)
  local t = {}
  for i,v in ipairs(array) do
    if f(i,v,...) then t[i] = v else break end
  end
  return t
end

--- Collects values from a given array. The passed-in array should not be sparse.
-- This function collects values as long as they do not satisfy a given predicate and returns on the first truthy test.
-- <br/><em>Aliased as `rejectWhile`</em>
-- @function dropWhile
-- @param array an array
-- @param f an iterator function prototyped as `f (k,v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return a new table containing all values collected
-- @see selectWhile
function _.dropWhile(array, f, ...)
  local _i
  for i,v in ipairs(array) do
    if not f(i,v,...) then
      _i = i
      break
    end
  end
  if _.isNil(_i) then return {} end
  return _.rest(array,_i)
end

--- Returns the index at which a value should be inserted. This index is evaluated so
-- that it maintains the sort. If a comparison function is passed, it will be used to sort
-- values.
-- @function sortedIndex
-- @param array an array
-- @param the value to be inserted
-- @param[opt] comp an comparison function prototyped as `f (a, b)`, defaults to <tt><</tt> operator.
-- @param[optchain] sort whether or not the passed-in array should be sorted
-- @return number the index at which the passed-in value should be inserted
function _.sortedIndex(array, value, comp, sort)
  local _comp = comp or f_min
  if sort then _.sort(array,_comp) end
  for i = 1,#array do
    if not _comp(array[i],value) then return i end
  end
  return #array+1
end

--- Returns the index of the first occurence of value in an array.
-- @function indexOf
-- @param array an array
-- @param value the value to search for
-- @return the index of the passed-in value
-- @see lastIndexOf
function _.indexOf(array, value)
  for k = 1,#array do
    if array[k] == value then return k end
  end
end

--- Returns the index of the last occurrence of value in an array.
-- @function lastIndexOf
-- @param array an array
-- @param value the value to search for
-- @return the index of the last occurrence of the passed-in value or __nil__
-- @see indexOf
function _.lastIndexOf(array, value)
  local key = _.indexOf(_.reverse(array),value)
  if key then return #array-key+1 end
end

--- Returns the first index at which a predicate returns true.
-- @function findIndex
-- @param array an array
-- @param predicate a predicate function prototyped as `predicate (k, v, ...)`
-- @param[opt] ... optional arguments to `pred`
-- @return the index found or __nil__
-- @see findLastIndex
function _.findIndex(array, predicate, ...)
	for k = 1, #array do
		if predicate(k,array[k],...) then return k end
	end
end

--- Returns the last index at which a predicate returns true.
-- @function findLastIndex
-- @param array an array
-- @param predicate a predicate function prototyped as `predicate (k, v, ...)`
-- @param[opt] ... optional arguments to `pred`
-- @return the index found or __nil__
-- @see findIndex
function _.findLastIndex(array, predicate, ...)
  local key = _.findIndex(_.reverse(array),predicate,...)
  if key then return #array-key+1 end
end

--- Adds all passed-in values at the top of an array. The last elements will bubble to the
-- top of the given array.
-- @function addTop
-- @param array an array
-- @param ... a variable number of arguments
-- @return the passed-in array with new values added
-- @see push
function _.addTop(array, ...)
  _.each({...},function(i,v) t_insert(array,1,v) end)
  return array
end

--- Pushes all passed-in values at the end of an array.
-- @function push
-- @param array an array
-- @param ... a variable number of arguments
-- @return the passed-in array with new added values
-- @see addTop
function _.push(array, ...)
  _.each({...}, function(i,v) array[#array+1] = v end)
  return array
end

--- Removes and returns the values at the top of a given array.
-- <br/><em>Aliased as `shift`</em>
-- @function pop
-- @param array an array
-- @param[opt] n the number of values to be popped. Defaults to 1.
-- @return the popped values
-- @see unshift
function _.pop(array, n)
  n = min(n or 1, #array)
  local ret = {}
  for i = 1, n do
    local retValue = array[1]
    ret[#ret + 1] = retValue
    t_remove(array,1)
  end
  return unpack(ret)
end

--- Removes and returns the values at the end of a given array.
-- @function unshift
-- @param array an array
-- @param[opt] n the number of values to be unshifted. Defaults to 1.
-- @return the values
-- @see pop
function _.unshift(array, n)
  n = min(n or 1, #array)
  local ret = {}
  for i = 1, n do
    local retValue = array[#array]
    ret[#ret + 1] = retValue
    t_remove(array)
  end
  return unpack(ret)
end

--- Removes all provided values in a given array.
-- <br/><em>Aliased as `remove`</em>
-- @function pull
-- @param array an array
-- @param ... a variable number of values to be removed from the array
-- @return the passed-in array with values removed
function _.pull(array, ...)
  for __, rmValue in ipairs({...}) do
    for i = #array, 1, -1 do
      if _.isEqual(array[i], rmValue) then
        t_remove(array, i)
      end
    end
  end
  return array
end

--- Removes values at index within the range `[start, finish]`.
-- <br/><em>Aliased as `rmRange`, `chop`</em>
-- @function removeRange
-- @param array an array
-- @param[opt] start the lower bound index, defaults to the first index in the array.
-- @param[optchain] finish the upper bound index, defaults to the array length.
-- @return the passed-in array with values removed
function _.removeRange(array, start, finish)
  local array = _.clone(array)
  local i,n = (next(array)),#array
  if n < 1 then return array end

  start = clamp(start or i,i,n)
  finish = clamp(finish or n,i,n)

  if finish < start then return array end

  local count = finish - start + 1
  local i = start
  while count > 0 do
    t_remove(array,i)
    count = count - 1
  end
  return array
end

--- Chunks together consecutive values. Values are chunked on the basis of the return
-- value of a provided predicate `f (k, v, ...)`. Consecutive elements which return
-- the same value are chunked together. Leaves the first argument untouched if it is not an array.
-- @function chunk
-- @param array an array
-- @param f an iterator function prototyped as `f (k, v, ...)`
-- @param[opt] ... Optional args to be passed to `f`
-- @return a table of chunks (arrays)
-- @see zip
function _.chunk(array, f, ...)
  if not _.isArray(array) then return array end
  local ch, ck, prev = {}, 0
  local mask = _.map(array, f,...)
  _.each(mask, function(k,v)
    prev = (prev==nil) and v or prev
    ck = ((v~=prev) and (ck+1) or ck)
    if not ch[ck] then
      ch[ck] = {array[k]}
    else
      ch[ck][#ch[ck]+1] = array[k]
    end
    prev = v
  end)
  return ch
end

--- Slices values indexed within `[start, finish]` range.
-- <br/><em>Aliased as `_.sub`</em>
-- @function slice
-- @param array an array
-- @param[opt] start the lower bound index, defaults to the first index in the array.
-- @param[optchain] finish the upper bound index, defaults to the array length.
-- @return a new array of sliced values
function _.slice(array, start, finish)
  return _.select(array, function(index)
      return (index >= (start or next(array)) and index <= (finish or #array))
    end)
end

--- Returns the first N values in an array.
-- <br/><em>Aliased as `head`, `take`</em>
-- @function first
-- @param array an array
-- @param[opt] n the number of values to be collected, defaults to 1.
-- @return a new array
-- @see initial
-- @see last
-- @see rest
function _.first(array, n)
  local n = n or 1
  return _.slice(array,1, min(n,#array))
end

--- Returns all values in an array excluding the last N values.
-- @function initial
-- @param array an array
-- @param[opt] n the number of values to be left, defaults to the array length.
-- @return a new array
-- @see first
-- @see last
-- @see rest
function _.initial(array, n)
  if n and n < 0 then return end
  return _.slice(array,1, n and #array-(min(n,#array)) or #array-1)
end

--- Returns the last N values in an array.
-- @function last
-- @param array an array
-- @param[opt] n the number of values to be collected, defaults to the array length.
-- @return a new array
-- @see first
-- @see initial
-- @see rest
function _.last(array, n)
  if n and n <= 0 then return end
  return _.slice(array,n and #array-min(n-1,#array-1) or 2,#array)
end

--- Removes all values before index.
-- <br/><em>Aliased as `tail`</em>
-- @function rest
-- @param array an array
-- @param[opt] index an index, defaults to 1
-- @return a new array
-- @see first
-- @see initial
-- @see last
function _.rest(array,index)
  if index and index > #array then return {} end
  return _.slice(array,index and max(1,min(index,#array)) or 1,#array)
end

--- Returns the value at a given index.
-- @function nth
-- @param array an array
-- @param index an index
-- @return the value at the given index
function _.nth(array, index)
  return array[index]
end

--- Removes all falsy (false and nil) values.
-- @function compact
-- @param array an array
-- @return a new array
function _.compact(array)
  return _.reject(array, function (_,value)
    return not value
  end)
end

--- Flattens a nested array. Passing `shallow` will only flatten at the first level.
-- @function flatten
-- @param array an array
-- @param[opt] shallow specifies the flattening depth
-- @return a new array, flattened
function _.flatten(array, shallow)
  local shallow = shallow or false
  local new_flattened
  local _flat = {}
  for key,value in pairs(array) do
    if _.isTable(value) then
      new_flattened = shallow and value or _.flatten (value)
      _.each(new_flattened, function(_,item) _flat[#_flat+1] = item end)
    else _flat[#_flat+1] = value
    end
  end
  return _flat
end

--- Returns values from an array not present in all passed-in args.
-- <br/><em>Aliased as `without` and `diff`</em>
-- @function difference
-- @param array an array
-- @param another array
-- @return a new array
-- @see union
-- @see intersection
-- @see symmetricDifference
function _.difference(array, array2)
  if not array2 then return _.clone(array) end
  return _.select(array,function(i,value)
      return not _.include(array2,value)
    end)
end

--- Returns the duplicate-free union of all passed in arrays.
-- @function union
-- @param ... a variable number of arrays arguments
-- @return a new array
-- @see difference
-- @see intersection
-- @see symmetricDifference
function _.union(...)
  return _.uniq(_.flatten({...}))
end

--- Returns the  intersection of all passed-in arrays.
-- Each value in the result is present in each of the passed-in arrays.
-- @function intersection
-- @param array an array
-- @param ... a variable number of array arguments
-- @return a new array
-- @see difference
-- @see union
-- @see symmetricDifference
function _.intersection(array, ...)
  local arg = {...}
  local _intersect = {}
  for i,value in ipairs(array) do
    if _.all(arg,function(i,v)
          return _.include(v,value)
        end) then
      t_insert(_intersect,value)
    end
  end
  return _intersect
end

--- Performs a symmetric difference. Returns values from `array` not present in `array2` and also values
-- from `array2` not present in `array`.
-- <br/><em>Aliased as `symdiff`</em>
-- @function symmetricDifference
-- @param array an array
-- @param array2 another array
-- @return a new array
-- @see difference
-- @see union
-- @see intersection
function _.symmetricDifference(array, array2)
  return _.difference(
    _.union(array, array2),
    _.intersection(array,array2)
  )
end

--- Produces a duplicate-free version of a given array.
-- <br/><em>Aliased as `uniq`</em>
-- @function unique
-- @param array an array
-- @return a new array, duplicate-free
-- @see isunique
function _.unique(array)
  local ret = {}
  for i = 1, #array do
    if not _.find(ret, array[i]) then
      ret[#ret+1] = array[i]
    end
  end
  return ret
end

--- Checks if a given array contains distinct values. Such an array is made of distinct elements,
-- which only occur once in this array.
-- <br/><em>Aliased as `isuniq`</em>
-- @function isunique
-- @param array an array
-- @return `true` if the given array is unique, `false` otherwise.
-- @see unique
function _.isunique(array)
  return _.isEqual(array, _.unique(array))
end

--- Merges values of each of the passed-in arrays in subsets.
-- Only values indexed with the same key in the given arrays are merged in the same subset.
-- <br/><em>Aliased as `transpose`</em>
-- @function zip
-- @param ... a variable number of array arguments
-- @return a new array
function _.zip(...)
  local arg = {...}
  local _len = _.max(_.map(arg,function(i,v)
      return #v
    end))
  local _ans = {}
  for i = 1,_len do
    _ans[i] = _.pluck(arg,i)
  end
  return _ans
end

--- Clones `array` and appends `other` values.
-- @function append
-- @param array an array
-- @param other an array
-- @return a new array
function _.append(array, other)
  local t = {}
  for i,v in ipairs(array) do t[i] = v end
  for i,v in ipairs(other) do t[#t+1] = v end
  return t
end

--- Interleaves arrays. It returns a single array made of values from all
-- passed in arrays in their given order, interleaved.
-- @function interleave
-- @param ... a variable list of arrays
-- @return a new array
-- @see interpose
function _.interleave(...) return _.flatten(_.zip(...)) end

--- Interposes value in-between consecutive pair of values in `array`.
-- @function interpose
-- @param value a value
-- @param array an array
-- @return a new array
-- @see interleave
function _.interpose(value, array)
  return _.flatten(_.zip(array, _.rep(value, #array-1)))
end

--- Produces a flexible list of numbers. If one positive value is passed, will count from 0 to that value,
-- with a default step of 1. If two values are passed, will count from the first one to the second one, with the
-- same default step of 1. A third value passed will be considered a step value.
-- @function range
-- @param[opt] from the initial value of the range
-- @param[optchain] to the final value of the range
-- @param[optchain] step the step of count
-- @return a new array of numbers
function _.range(...)
  local arg = {...}
  local _start,_stop,_step
  if #arg==0 then return {}
  elseif #arg==1 then _stop,_start,_step = arg[1],0,1
  elseif #arg==2 then _start,_stop,_step = arg[1],arg[2],1
  elseif #arg == 3 then _start,_stop,_step = arg[1],arg[2],arg[3]
  end
  if (_step and _step==0) then return {} end
  local _ranged = {}
  local _steps = max(floor((_stop-_start)/_step),0)
  for i=1,_steps do _ranged[#_ranged+1] = _start+_step*i end
  if #_ranged>0 then t_insert(_ranged,1,_start) end
  return _ranged
end

--- Creates an array list of `n` values, repeated.
-- @function rep
-- @param value a value to be repeated
-- @param n the number of repetitions of value.
-- @return a new array of `n` values
function _.rep(value, n)
  local ret = {}
  for i = 1, n do ret[#ret+1] = value end
  return ret
end

--- Iterator returning partitions of an array. It returns arrays of length `n`
-- made of values from the given array. If the last partition has lower elements than `n` and
-- `pad` is supplied, it will be adjusted to `n` of elements with `pad` value.
-- @function partition
-- @param array an array
-- @param[opt] n the size of partitions. Should be greater than 0. Defaults to 1.
-- @param[optchain] pad a value to adjust the last subsequence to the `n` elements
-- @return an iterator function
function _.partition(array, n, pad)
	if n<=0 then return end
  return coroutine.wrap(function()
    partgen(array, n or 1, coroutine.yield, pad)
  end)
end

--- Iterator returning sliding partitions of an array. It returns overlapping subsequences
-- of length `n`. If the last subsequence has lower elements than `n` and `pad` is
-- supplied, it will be adjusted to `n` elements with `pad` value.
-- @function sliding.
-- @param array an array
-- @param[opt] n the size of partitions. Should be greater than 1. Defaults to 2.
-- @param[optchain] pad a value to adjust the last subsequence to the `n` elements
-- @return an iterator function
function _.sliding(array, n, pad)
	if n<=1 then return end
  return coroutine.wrap(function()
    partgen2(array, n or 2, coroutine.yield, pad)
  end)
end

--- Iterator returning the permutations of an array. It returns arrays made of all values
-- from the passed-in array, with values permuted.
-- @function permutation
-- @param array an array
-- @return an iterator function
function _.permutation(array)
  return coroutine.wrap(function()
    permgen(array, #array, coroutine.yield)
  end)
end

--- Swaps keys with values. Produces a new array where previous keys are now values,
-- while previous values are now keys.
-- <br/><em>Aliased as `mirror`</em>
-- @function invert
-- @param array a given array
-- @return a new array
function _.invert(array)
  local _ret = {}
  _.each(array,function(i,v) _ret[v] = i end)
  return _ret
end

--- Concatenates values in a given array. Handles booleans as well. If `sep` string is
-- passed, it will be used as a separator. Passing `i` and `j` will result in concatenating
-- only values within `[i, j]` range.
-- <br/><em>Aliased as `join`</em>
-- @function concat
-- @param array a given array
-- @param[opt] sep a separator string, defaults to the empty string `''`.
-- @param[optchain] i the starting index, defaults to 1.
-- @param[optchain] j the final index, defaults to the array length.
-- @return a string
function _.concat(array, sep, i, j)
  local _array = _.map(array,function(i,v)
    return tostring(v)
  end)
  return t_concat(_array,sep,i or 1,j or #array)

end


--- Utility functions
-- @section Utility

--- The no-operation function.
-- @function noop
-- @return nothing
function _.noop() return end

--- Returns the passed-in value. This function is used internally
-- as a default iterator.
-- @function identity
-- @param value a value
-- @return the passed-in value
function _.identity(value) return value end

--- Creates a constant function which returns the same output on every call.
-- @function constant
-- @param value a constant value
-- @return a constant function
function _.constant(value) return function() return value end end

--- Returns a version of `f` that runs only once. Successive calls to `f`
-- will keep yielding the same output, no matter what the passed-in arguments are.
-- It can be used to initialize variables.
-- @function once
-- @param f a function
-- @return a new function
-- @see after
function _.once(f)
  local _internal = 0
  local _args = {}
  return function(...)
      _internal = _internal+1
      if _internal<=1 then _args = {...} end
      return f(unpack(_args))
    end
end

--- Memoizes a given function by caching the computed result.
-- Useful for speeding-up slow-running functions. If a `hash` function is passed,
-- it will be used to compute hash keys for a set of input values for caching.
-- <br/><em>Aliased as `cache`</em>
-- @function memoize
-- @param f a function
-- @param[opt] hash a hash function, defaults to @{identity}
-- @return a new function
function _.memoize(f, hash)
  local _cache = setmetatable({},{__mode = 'k'})
  local _hasher = hash or _.identity
  return function (...)
      local _hashKey = _hasher(...)
      local _result = _cache[_hashKey]
      if not _result then _cache[_hashKey] = f(...) end
      return _cache[_hashKey]
    end
end

--- Returns a version of `f` that runs on the `count-th` call.
-- Useful when dealing with asynchronous tasks.
-- @function after
-- @param f a function
-- @param count the number of calls before `f` will start running.
-- @return a new function
-- @see once
function _.after(f, count)
  local _limit,_internal = count, 0
  return function(...)
      _internal = _internal+1
      if _internal >= _limit then return f(...) end
    end
end

--- Composes functions. Each passed-in function consumes the return value of the function that follows.
-- In math terms, composing the functions `f`, `g`, and `h` produces the function `f(g(h(...)))`.
-- @function compose
-- @param ... a variable number of functions
-- @return a new function
-- @see pipe
function _.compose(...)
	-- See: https://github.com/Yonaba/Moses/pull/15#issuecomment-139038895
  local f = _.reverse {...}
  return function (...)
		local first, _temp = true
		for i, func in ipairs(f) do
			if first then
				first = false
				_temp = func(...)
			else
				_temp = func(_temp)
			end
		end
		return _temp
	end
end

--- Pipes a value through a series of functions. In math terms,
-- given some functions `f`, `g`, and `h` in that order, it returns `f(g(h(value)))`.
-- @function pipe
-- @param value a value
-- @param ... a variable number of functions
-- @return the result of the composition of function calls.
-- @see compose
function _.pipe(value, ...)
  return _.compose(...)(value)
end

--- Returns the logical complement of a given function. For a given input, the returned
-- function will output `false` if the original function would have returned `true`,
-- and vice-versa.
-- @function complement
-- @param f a function
-- @return  the logical complement of the given function `f`.
function _.complement(f)
  return function(...) return not f(...) end
end

--- Calls a sequence of passed-in functions with the same argument.
-- Returns a sequence of results.
-- <br/><em>Aliased as `juxt`</em>
-- @function juxtapose
-- @param value a value
-- @param ... a variable number of functions
-- @return a list of results
function _.juxtapose(value, ...)
  local res = {}
  _.each({...}, function(_,f) res[#res+1] = f(value) end)
  return unpack(res)
end

--- Wraps `f` inside of the `wrapper` function. It passes `f` as the first argument to `wrapper`.
-- This allows the wrapper to execute code before and after `f` runs,
-- adjust the arguments, and execute it conditionally.
-- @function wrap
-- @param f a function to be wrapped, prototyped as `f (...)`
-- @param wrapper a wrapper function, prototyped as `wrapper (f, ...)`
-- @return the results
function _.wrap(f, wrapper)
  return function (...) return  wrapper(f,...) end
end

--- Runs `iter` function `n` times. Collects the results of each run and returns them in an array.
-- @function times
-- @param n the number of times `iter` should be called
-- @param  iter an iterator function, prototyped as `iter (i, ...)`
-- @param ... args to be passed to `iter` function
-- @return table an array of results
function _.times(n, iter, ...)
  local results = {}
  for i = 1,n do
    results[i] = iter(i,...)
  end
  return results
end

--- Binds `v` to be the first argument to `f`. Calling `f (...)` will result to `f (v, ...)`.
-- @function bind
-- @param f a function
-- @param v a value
-- @return a function
-- @see bind2
-- @see bindn
-- @see bindAll
function _.bind(f, v)
  return function (...)
      return f(v,...)
    end
end

--- Binds `v` to be the second argument to `f`. Calling `f (a, ...)` will result to `f (a, v, ...)`.
-- @function bind2
-- @param f a function
-- @param v a value
-- @return a function
-- @see bind
-- @see bindn
-- @see bindAll
function _.bind2(f, v)
  return function (t, ...)
    return f(t, v, ...)
  end
end

--- Binds `...` to be the N-first arguments to function `f`.
-- Calling `f (a1, a2, ..., aN)` will result to `f (..., a1, a2, ...,aN)`.
-- @function bindn
-- @param f a function
-- @param ... a variable number of arguments
-- @return a function
-- @see bind
-- @see bind2
-- @see bindAll
function _.bindn(f, ...)
  local iArg = {...}
  return function (...)
      return f(unpack(_.append(iArg,{...})))
    end
end

--- Binds methods to object. As such, whenever any of these methods is invoked, it
-- always receives the object as its first argument.
-- @function bindAll
-- @param obj an abject
-- @param ... a variable number of method names
-- @return the passed-in object with all methods bound to the object itself.
-- @see bind
-- @see bind2
-- @see bindn
function _.bindAll(obj, ...)
	local methodNames = {...}
	for __, methodName in ipairs(methodNames) do
		local method = obj[methodName]
		if method then obj[methodName] = _.bind(method, obj) end
	end
	return obj
end

--- Generates an unique ID for the current session. If given a string `template`, it
-- will use this template for output formatting. Otherwise, if `template` is a function, it
-- will evaluate `template (id, ...)`.
-- <br/><em>Aliased as `uid`</em>.
-- @function uniqueId
-- @param[opt] template either a string or a function template to format the ID
-- @param[optchain] ... a variable number of arguments to be passed to `template`, in case it is a function.
-- @return value an ID
function _.uniqueId(template, ...)
  unique_id_counter = unique_id_counter + 1
  if template then
    if _.isString(template) then
      return template:format(unique_id_counter)
    elseif _.isFunction(template) then
      return template(unique_id_counter,...)
    end
  end
  return unique_id_counter
end

--- Produces an iterator which repeatedly apply a function `f` onto an input.
-- Yields x, then f(x), then f(f(x)), continuously.
-- @function iterate
-- @param f a function
-- @param x an initial input to `f`
-- @return an iterator fnction
-- <br/><em>Aliased as `iter`</em>.
function _.iterator(f, x)
	return function()
		x = f(x)
		return x
	end
end

--- Creates a function of `f` with arguments flipped in reverse order.
-- @function flip
-- @param f a function
-- @return a function
function _.flip(f)
	return function(...)
		return f(unpack(_.reverse({...})))
	end
end

--- Creates a function that runs transforms on all arguments it receives.
-- @function over
-- @param ... a set of functions which will receive all arguments to the returned function
-- @return a function
-- @see overEvery
-- @see overSome
-- @see overArgs
function _.over(...)
	local transforms = {...}
	return function(...)
		local r = {}
		for __,transform in ipairs(transforms) do
			r[#r+1] = transform(...)
		end
		return r
	end
end

--- Creates a validation function. The returned function checks if *all* of the given predicates return
-- truthy when invoked with the arguments it receives.
-- @function overEvery
-- @param ... a list of predicate functions
-- @return a new function
-- @see over
-- @see overSome
-- @see overArgs
function _.overEvery(...)
	local f = _.over(...)
	return function(...)
		return _.reduce(f(...),function(state,v) return state and v end)
	end
end

--- Creates a validation function. The return function checks if *any* of a given predicates return
-- truthy when invoked with the arguments it receives.
-- @function overSome
-- @param ... a list of predicate functions
-- @return a new function
-- @see over
-- @see overEvery
-- @see overArgs
function _.overSome(...)
	local f = _.over(...)
	return function(...)
		return _.reduce(f(...),function(state,v) return state or v end)
	end
end

--- Creates a function that invokes `f` with its arguments transformed. 1rst arguments will be passed to
-- the 1rst transform, 2nd arg to the 2nd transform, etc. Remaining arguments will not be transformed.
-- @function overArgs
-- @param f a function
-- @param ... a list of transforms funcs prototyped as `f (v)`
-- @return the result of running `f` with its transformed arguments
-- @see over
-- @see overEvery
-- @see overSome
function _.overArgs(f,...)
	local _argf = {...}
	return function(...)
		local _args = {...}
		for i = 1,#_argf do
			local f = _argf[i]
			if _args[i] then _args[i] = f(_args[i]) end
		end
		return f(unpack(_args))
	end
end

--- Partially apply a function by filling in any number of its arguments.
-- One may pass a string `'_'` as a placeholder in the list of arguments to specify an argument
-- that should not be pre-filled, but left open to be supplied at call-time.
-- @function partial
-- @param f a function
-- @param ... a list of partial arguments to `f`
-- @return a new version of function f having some of it original arguments filled
-- @see partialRight
-- @see curry
function _.partial(f,...)
	local partial_args = {...}
	return function (...)
		local n_args = {...}
		local f_args = {}
		for k,v in ipairs(partial_args) do
			f_args[k] = (v == '_') and _.pop(n_args) or v
		end
		return f(unpack(_.append(f_args,n_args)))
	end
end

--- Similar to @{partial}, but from the right.
-- @function partialRight
-- @param f a function
-- @param ... a list of partial arguments to `f`
-- @return a new version of function f having some of it original arguments filled
-- @see partialRight
-- @see curry
function _.partialRight(f,...)
	local partial_args = {...}
	return function (...)
		local n_args = {...}
		local f_args = {}
		for k = 1,#partial_args do
			f_args[k] = (partial_args[k] == '_') and _.pop(n_args) or partial_args[k]
		end
		return f(unpack(_.append(n_args, f_args)))
	end
end

--- Curries a function. If the given function `f` takes multiple arguments, it returns another version of
-- `f` that takes a single argument (the first of the arguments to the original function) and returns a new
-- function that takes the remainder of the arguments and returns the result.
-- @function curry
-- @param f a function
-- @param[opt] n_args the number of arguments expected for `f`. Defaults to 2.
-- @return a curried version of `f`
-- @see partial
-- @see partialRight
function _.curry(f, n_args)
	n_args = n_args or 2
	local _args = {}
	local function scurry(v)
		if n_args == 1 then return f(v) end
		if v ~= nil then _args[#_args+1] = v end
		if #_args < n_args then
			return scurry
		else
			local r = {f(unpack(_args))}
			_args = {}
			return unpack(r)
		end
	end
	return scurry
end

--- Object functions
--@section Object

--- Returns the keys of the object properties.
-- @function keys
-- @param obj an object
-- @return an array
function _.keys(obj)
  local _oKeys = {}
  _.each(obj,function(key) _oKeys[#_oKeys+1]=key end)
  return _oKeys
end

--- Returns the values of the object properties.
-- @function values
-- @param obj an object
-- @return an array
function _.values(obj)
  local _oValues = {}
  _.each(obj,function(_,value) _oValues[#_oValues+1]=value end)
  return _oValues
end

--- Converts keys and values a an array-list of [k, v].
-- @function kvpairs
-- @param obj an object
-- @return an array list of key-values pairs
-- @see toObj
function _.kvpairs(obj)
	local t = {}
	_.each(obj, function(k,v) t[#t+1] = {k,v} end)
	return t
end

--- Converts an array list of `kvpairs` to an object. Keys are taken
-- from the 1rst column in the `kvpairs` sequence, associated with values in the 2nd
-- column
-- @function toObj
-- @param kvpairs an array-list of `kvpairs`
-- @return an object
-- @see kvpairs
function _.toObj(kvpairs)
	local obj = {}
	for __, v in ipairs(kvpairs) do
		obj[v[1]] = v[2]
	end
	return obj
end

--- Returns a function that will return the key property of any passed-in object.
-- @function property
-- @param key a key property name
-- @return a function which should accept an object as argument
-- @see propertyOf
function _.property(key)
	return function(obj) return obj[key] end
end

--- Returns a function which will return the value of an object property.
-- @function propertyOf
-- @param obj an object
-- @return a function which should accept a key property argument
-- @see property
function _.propertyOf(obj)
	return function(key) return obj[key] end
end

--- Converts any given value to a boolean
-- @function toBoolean
-- @param value a value. Can be of any type
-- @return `true` if value is true, `false` otherwise (false or nil).
function _.toBoolean(value)
  return not not value
end

--- Extends an object properties. It copies the properties of extra passed-in objects
-- into the destination object, and returns the destination object. The last objects
-- will override properties of the same name.
-- @function extend
-- @param destObj a destination object
-- @param ... a list of objects
-- @return the destination object extended
function _.extend(destObj, ...)
  local sources = {...}
  _.each(sources,function(__,source)
    if _.isTable(source) then
      _.each(source,function(key,value)
        destObj[key] = value
      end)
    end
  end)
  return destObj
end

--- Returns a sorted list of all methods names found in an object. If the given object
-- has a metatable implementing an `__index` field pointing to another table, will also recurse on this
-- table if `recurseMt` is provided. If `obj` is omitted, it defaults to the library functions.
-- <br/><em>Aliased as `methods`</em>.
-- @function functions
-- @param[opt] obj an object. Defaults to Moses library functions.
-- @return an array-list of methods names
function _.functions(obj, recurseMt)
  obj = obj or _
  local _methods = {}
  _.each(obj,function(key,value)
    if _.isFunction(value) then
      _methods[#_methods+1]=key
    end
  end)
  if not recurseMt then
    return _.sort(_methods)
  end
  local mt = getmetatable(obj)
  if mt and mt.__index then
    local mt_methods = _.functions(mt.__index)
    _.each(mt_methods, function(k,fn)
      _methods[#_methods+1] = fn
    end)
  end
  return _.sort(_methods)
end

--- Clones a given object properties. If `shallow` is passed will also clone nested array properties.
-- @function clone
-- @param obj an object
-- @param[opt] shallow whether or not nested array-properties should be cloned, defaults to false.
-- @return a copy of the passed-in object
function _.clone(obj, shallow)
  if not _.isTable(obj) then return obj end
  local _obj = {}
  _.each(obj,function(i,v)
    if _.isTable(v) then
      if not shallow then
        _obj[i] = _.clone(v,shallow)
      else _obj[i] = v
      end
    else
      _obj[i] = v
    end
  end)
  return _obj
end

--- Invokes interceptor with the object, and then returns object.
-- The primary purpose of this method is to "tap into" a method chain, in order to perform operations
-- on intermediate results within the chain.
-- @function tap
-- @param obj an object
-- @param f an interceptor function, should be prototyped as `f (obj, ...)`
-- @param[opt] ... args to be passed to `f`
-- @return the passed-in object
function _.tap(obj, f, ...)
  f(obj,...)
  return obj
end

--- Checks if a given object implements a property.
-- @function has
-- @param obj an object
-- @param key a key property to be checked
-- @return `true` or `false`
function _.has(obj, key)
  return obj[key]~=nil
end

--- Returns an object copy having white-listed properties.
-- <br/><em>Aliased as `choose`</em>.
-- @function pick
-- @param obj an object
-- @param ... a variable number of string keys
-- @return the filtered object
function _.pick(obj, ...)
  local whitelist = _.flatten {...}
  local _picked = {}
  _.each(whitelist,function(key,property)
      if not _.isNil(obj[property]) then
        _picked[property] = obj[property]
      end
    end)
  return _picked
end

--- Returns an object copy without black-listed properties.
-- <br/><em>Aliased as `drop`</em>.
-- @function omit
-- @param obj an object
-- @param ... a variable number of string keys
-- @return the filtered object
function _.omit(obj, ...)
  local blacklist = _.flatten {...}
  local _picked = {}
  _.each(obj,function(key,value)
      if not _.include(blacklist,key) then
        _picked[key] = value
      end
    end)
  return _picked
end

--- Applies a template to an object, preserving non-nil properties.
-- <br/><em>Aliased as `defaults`</em>.
-- @function template
-- @param obj an object
-- @param[opt] template a template object. Defaults to an empty table `{}`.
-- @return the passed-in object filled
function _.template(obj, template)
  _.each(template or {},function(i,v)
  if not obj[i] then obj[i] = v end
  end)
  return obj
end

--- Performs a deep comparison test between two objects. Can compare strings, functions
-- (by reference), nil, booleans. Compares tables by reference or by values. If `useMt`
-- is passed, the equality operator `==` will be used if one of the given objects has a
-- metatable implementing `__eq`.
-- <br/><em>Aliased as `_.compare`</em>
-- @function isEqual
-- @param objA an object
-- @param objB another object
-- @param[opt] useMt whether or not `__eq` should be used, defaults to false.
-- @return `true` or `false`
function _.isEqual(objA, objB, useMt)
  local typeObjA = type(objA)
  local typeObjB = type(objB)

  if typeObjA~=typeObjB then return false end
  if typeObjA~='table' then return (objA==objB) end

  local mtA = getmetatable(objA)
  local mtB = getmetatable(objB)

  if useMt then
    if (mtA or mtB) and (mtA.__eq or mtB.__eq) then
      return mtA.__eq(objA, objB) or mtB.__eq(objB, objA) or (objA==objB)
    end
  end

  if _.size(objA)~=_.size(objB) then return false end

  for i,v1 in pairs(objA) do
    local v2 = objB[i]
    if _.isNil(v2) or not _.isEqual(v1,v2,useMt) then return false end
  end

  for i,v1 in pairs(objB) do
    local v2 = objA[i]
    if _.isNil(v2) then return false end
  end

  return true
end

--- Invokes an object method. It passes the object itself as the first argument. if `method` is not
-- callable, will return `obj[method]`.
-- @function result
-- @param obj an object
-- @param method a string key to index in object `obj`.
-- @param[opt] ... Optional args to be passed to `method`
-- @return the returned value of `method (obj, ...)` call
function _.result(obj, method, ...)
  if obj[method] then
    if _.isCallable(obj[method]) then
      return obj[method](obj,...)
    else return obj[method]
    end
  end
  if _.isCallable(method) then
    return method(obj,...)
  end
end

--- Checks if the given arg is a table.
-- @function isTable
-- @param t a value to be tested
-- @return `true` or `false`
function _.isTable(t)
  return type(t) == 'table'
end

--- Checks if the given argument is callable. Assumes `obj` is callable if
-- it is either a function or a table having a metatable implementing `__call` metamethod.
-- @function isCallable
-- @param obj an object
-- @return `true` or `false`
function _.isCallable(obj)
  return (_.isFunction(obj) or
     (_.isTable(obj) and getmetatable(obj)
                   and getmetatable(obj).__call~=nil) or false)
end

--- Checks if the given argument is an array. Assumes `obj` is an array
-- if is a table with consecutive integer keys starting at 1.
-- @function isArray
-- @param obj an object
-- @return `true` or `false`
function _.isArray(obj)
  if not _.isTable(obj) then return false end
  -- Thanks @Wojak and @Enrique García Cota for suggesting this
  -- See : http://love2d.org/forums/viewtopic.php?f=3&t=77255&start=40#p163624
  local i = 0
  for __ in pairs(obj) do
     i = i + 1
     if _.isNil(obj[i]) then return false end
  end
  return true
end

--- Checks if the given object is iterable with `pairs` (or `ipairs`).
-- @function isIterable
-- @param obj an object
-- @return `true` if the object can be iterated with `pairs` (or `ipairs`), `false` otherwise
function _.isIterable(obj)
  return _.toBoolean((pcall(pairs, obj)))
end

--- Checks if the given pbject is empty. If `obj` is a string, will return `true`
-- if `#obj == 0`. Otherwise, if `obj` is a table, will return whether or not this table
-- is empty. If `obj` is `nil`, it will return true.
-- @function isEmpty
-- @param[opt] obj an object
-- @return `true` or `false`
function _.isEmpty(obj)
  if _.isNil(obj) then return true end
  if _.isString(obj) then return #obj==0 end
  if _.isTable(obj) then return next(obj)==nil end
  return true
end

--- Checks if the given argument is a string.
-- @function isString
-- @param obj an object
-- @return `true` or `false`
function _.isString(obj)
  return type(obj) == 'string'
end

--- Checks if the given argument is a function.
-- @function isFunction
-- @param obj an object
-- @return `true` or `false`
function _.isFunction(obj)
   return type(obj) == 'function'
end

--- Checks if the given argument is nil.
-- @function isNil
-- @param obj an object
-- @return `true` or `false`
function _.isNil(obj)
  return obj==nil
end

--- Checks if the given argument is a number.
-- @function isNumber
-- @param obj an object
-- @return `true` or `false`
-- @see isNaN
function _.isNumber(obj)
  return type(obj) == 'number'
end

--- Checks if the given argument is NaN (see [Not-A-Number](http://en.wikipedia.org/wiki/NaN)).
-- @function isNaN
-- @param obj an object
-- @return `true` or `false`
-- @see isNumber
function _.isNaN(obj)
  return _.isNumber(obj) and obj~=obj
end

--- Checks if the given argument is a finite number.
-- @function isFinite
-- @param obj an object
-- @return `true` or `false`
function _.isFinite(obj)
  if not _.isNumber(obj) then return false end
  return obj > -huge and obj < huge
end

--- Checks if the given argument is a boolean.
-- @function isBoolean
-- @param obj an object
-- @return `true` or `false`
function _.isBoolean(obj)
  return type(obj) == 'boolean'
end

--- Checks if the given argument is an integer.
-- @function isInteger
-- @param obj an object
-- @return `true` or `false`
function _.isInteger(obj)
  return _.isNumber(obj) and floor(obj)==obj
end

-- Aliases

do

  -- Table functions aliases
  _.forEach     = _.each
  _.forEachi    = _.eachi
  _.loop        = _.cycle
  _.collect     = _.map
  _.inject      = _.reduce
  _.foldl       = _.reduce
  _.injectr     = _.reduceRight
  _.foldr       = _.reduceRight
  _.mapr        = _.mapReduce
  _.maprr       = _.mapReduceRight
  _.any         = _.include
  _.some        = _.include
  _.contains    = _.include
  _.filter      = _.select
  _.discard     = _.reject
  _.every       = _.all

  -- Array functions aliases
  _.takeWhile   = _.selectWhile
  _.rejectWhile = _.dropWhile
  _.shift       = _.pop
  _.remove      = _.pull
  _.rmRange     = _.removeRange
  _.chop        = _.removeRange
  _.sub         = _.slice
  _.head        = _.first
  _.take        = _.first
  _.tail        = _.rest
  _.skip        = _.last
  _.without     = _.difference
  _.diff        = _.difference
  _.symdiff     = _.symmetricDifference
  _.xor         = _.symmetricDifference
  _.uniq        = _.unique
  _.isuniq      = _.isunique
	_.transpose   = _.zip
  _.part        = _.partition
  _.perm        = _.permutation
  _.mirror      = _.invert
  _.join        = _.concat

  -- Utility functions aliases
  _.cache       = _.memoize
  _.juxt        = _.juxtapose
  _.uid         = _.uniqueId
  _.iter        = _.iterator

  -- Object functions aliases
  _.methods     = _.functions
  _.choose      = _.pick
  _.drop        = _.omit
  _.defaults    = _.template
  _.compare     = _.isEqual

end

-- Setting chaining and building interface

do

  -- Wrapper to Moses
  local f = {}

  -- Will be returned upon requiring, indexes into the wrapper
  local __ = {}
  __.__index = f

  -- Wraps a value into an instance, and returns the wrapped object
  local function new(value)
    local i = {_value = value, _wrapped = true}
    return setmetatable(i, __)
  end

  setmetatable(__,{
    __call  = function(self,v) return new(v) end, -- Calls returns to instantiation
    __index = function(t,key,...) return f[key] end  -- Redirects to the wrapper
  })

  --- Returns a wrapped object. Calling library functions as methods on this object
  -- will continue to return wrapped objects until @{obj:value} is used. Can be aliased as `_(value)`.
  -- @class function
  -- @name chain
  -- @param value a value to be wrapped
  -- @return a wrapped object
  function __.chain(value)
    return new(value)
  end

  --- Extracts the value of a wrapped object. Must be called on an chained object (see @{chain}).
  -- @class function
  -- @name obj:value
  -- @return the value previously wrapped
  function __:value()
    return self._value
  end

  -- Register chaining methods into the wrapper
  f.chain, f.value = __.chain, __.value

  -- Register all functions into the wrapper
  for fname,fct in pairs(_) do
    f[fname] = function(v, ...)
      local wrapped = _.isTable(v) and v._wrapped or false
      if wrapped then
        local _arg = v._value
        local _rslt = fct(_arg,...)
        return new(_rslt)
      else
        return fct(v,...)
      end
    end
  end

  --- Imports all library functions into a context.
  -- @function import
  -- @param[opt] context a context. Defaults to `_G` (global environment) when not given.
  -- @param[optchain] noConflict if supplied, will not import functions having a key existing in the destination context.
  -- @return the passed-in context
  f.import = function(context, noConflict)
    context = context or _ENV or _G
    local funcs = _.functions()
    _.each(funcs, function(k, fname)
      if rawget(context, fname) then
        if not noConflict then
          context[fname] = _[fname]
        end
      else
        context[fname] = _[fname]
      end
    end)
    return context
  end

  -- Descriptive tags
  __._VERSION     = 'Moses v'.._MODULEVERSION
  __._URL         = 'http://github.com/Yonaba/Moses'
  __._LICENSE     = 'MIT <http://raw.githubusercontent.com/Yonaba/Moses/master/LICENSE>'
  __._DESCRIPTION = 'utility-belt library for functional programming in Lua'

  return __

end

end

package.preload['jsonschema'] = function()
-- luacheck: ignore
local store = require 'jsonschema_store'
local tostring = tostring
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local sformat = string.format
local mmax, mmodf = math.max, math.modf
local tconcat = table.concat
local coro_wrap = coroutine.wrap
local coro_yield = coroutine.yield
local DEBUG = os and os.getenv and os.getenv('DEBUG') == '1'

-- default null token
-- local default_null = nil
-- do
--   local ok, cjson = pcall(require, 'cjson')
--   if ok then default_null = cjson.null end
-- end

--
-- Code generation
--

local generate_validator -- forward declaration

local codectx_mt = {}
codectx_mt.__index = codectx_mt

function codectx_mt:libfunc(globalname)
  local root = self._root
  local localname = root._globals[globalname]
  if not localname then
    localname = globalname:gsub('%.', '_')
    root._globals[globalname] = localname
    root:preface(sformat('local %s = %s', localname, globalname))
  end
  return localname
end

function codectx_mt:localvar(init, nres)
  local names = {}
  local nloc = self._nloc
  nres = nres or 1
  for i=1, nres do
    names[i] = sformat('var_%d_%d', self._idx, nloc+i)
  end

  self:stmt(sformat('local %s = ', tconcat(names, ', ')), init or 'nil')
  self._nloc = nloc + nres
  return unpack(names)
end

function codectx_mt:param(n)
  self._nparams = mmax(n, self._nparams)
  return 'p_' .. n
end

function codectx_mt:label()
  local nlabel = self._nlabels + 1
  self._nlabels = nlabel
  return 'label_' .. nlabel
end

-- Returns an expression that will result in passed value.
-- Currently user vlaues are stored in an array to avoid consuming a lot of local
-- and upvalue slots. Array accesses are still decently fast.
function codectx_mt:uservalue(val)
  local slot = #self._root._uservalues + 1
  self._root._uservalues[slot] = val
  return sformat('uservalues[%d]', slot)
end






local function q(s) return sformat('%q', s) end

function codectx_mt:validator(path, schema)
  local ref = self._schema:child(path)
  local resolved = ref:resolve()
  local root = self._root
  local var = root._validators[resolved]
  if not var then
    var = root:localvar('nil')
    root._validators[resolved] = var
    root:stmt(sformat('%s = ', var), generate_validator(root:child(ref), resolved))
  end
  return var
end

function codectx_mt:preface(...)
  assert(self._preface, 'preface is only available for root contexts')
  local n = #self._preface
  for i=1, select('#', ...) do
    self._preface[n+i] = select(i, ...)
  end
  self._preface[#self._preface+1] = '\n'
end

function codectx_mt:stmt(...)
  local n = #self._body
  for i=1, select('#', ...) do
    self._body[n+i] = select(i, ...)
  end
  self._body[#self._body+1] = '\n'
end

-- load doesn't like at all empty string, but sometimes it is easier to add
-- some in the chunk buffer
local function yield_chunk(chunk)
  if chunk and chunk ~= '' then
    coro_yield(chunk)
  end
end

function codectx_mt:_generate()
  local indent = ''
  if self._root == self then
    for _, stmt in ipairs(self._preface) do
      yield_chunk(indent)
      if getmetatable(stmt) == codectx_mt then
        stmt:_generate()
      else
        yield_chunk(stmt)
      end
    end
  else
    coro_yield('function(')
    for i=1, self._nparams do
      yield_chunk('p_' .. i)
      if i ~= self._nparams then yield_chunk(', ') end
    end
    yield_chunk(')\n')
    indent = string.rep('  ', self._idx)
  end

  for _, stmt in ipairs(self._body) do
    yield_chunk(indent)
    if getmetatable(stmt) == codectx_mt then
      stmt:_generate()
    else
      yield_chunk(stmt)
    end
  end

  if self._root ~= self then
    yield_chunk('end')
  end
end

function codectx_mt:_get_loader()
  return coro_wrap(function()
    self:_generate()
  end)
end

function codectx_mt:as_string()
  local buf, n = {}, 0
  for chunk in self:_get_loader() do
    n = n+1
    buf[n] = chunk
  end
  return table.concat(buf)
end

function codectx_mt:as_func(name, ...)
  local loader, err = load(self:_get_loader(), 'jsonschema:' .. (name or 'anonymous'))
  if loader then
    local validator
    validator, err = loader(self._uservalues, ...)
    if validator then return validator end
  end

  -- something went really wrong
  if DEBUG then
    local line=1
    print('------------------------------')
    print('FAILED to generate validator: ', err)
    print('generated code:')
    print('0001: ' .. self:as_string():gsub('\n', function()
      line = line + 1
      return sformat('\n%04d: ', line)
    end))
    print('------------------------------')
  end
  error(err)
end

-- returns a child code context with the current context as parent
function codectx_mt:child(ref)
  return setmetatable({
    _schema = ref,
    _idx = self._idx+1,
    _nloc = 0,
    _nlabels = 0,
    _body = {},
    _root = self._root,
    _nparams = 0,
  }, codectx_mt)
end

-- returns a root code context. A root code context holds the library function
-- cache (as upvalues for the child contexts), a preface, and no named params
local function codectx(schema, options)
  local self = setmetatable({
    _schema = store.new(schema, options.external_resolver),
    _id = schema.id,
    _path = '',
    _idx = 0,
    -- code generation
    _nloc = 0,
    _nlabels = 0,
    _preface = {},
    _body = {},
    _globals = {},
    _uservalues = {},
    -- schema management
    _validators = {}, -- maps paths to local variable validators
    _external_resolver = options.external_resolver,
  }, codectx_mt)
  self._root = self
  return self
end


--
-- Validator util functions (available in the validator context
--
local validatorlib = {}

-- TODO: this function is critical for performance, optimize it
-- Returns:
--  0 for objects
--  1 for empty object/table (these two are indistinguishable in Lua)
--  2 for arrays
function validatorlib.tablekind(t)
  local length = #t
  if length == 0 then
    if next(t) == nil then
      return 1 -- empty table
    else
      return 0 -- pure hash
    end
  end

  -- not empty, check if the number of items is the same as the length
  local items = 0
  for k, v in pairs(t) do items = items + 1 end
  if items == #t then
    return 2 -- array
  else
    return 0 -- mixed array/object
  end
end

-- used for unique items in arrays (not fast at all)
-- from: http://stackoverflow.com/questions/25922437
-- If we consider only the JSON case, this function could be simplified:
-- no loops, keys are only strings. But this library might also be used in
-- other cases.
local function deepeq(table1, table2)
   local avoid_loops = {}
   local function recurse(t1, t2)
      -- compare value types
      if type(t1) ~= type(t2) then return false end
      -- Base case: compare simple values
      if type(t1) ~= "table" then return t1 == t2 end
      -- Now, on to tables.
      -- First, let's avoid looping forever.
      if avoid_loops[t1] then return avoid_loops[t1] == t2 end
      avoid_loops[t1] = t2
      -- Copy keys from t2
      local t2keys = {}
      local t2tablekeys = {}
      for k, _ in pairs(t2) do
         if type(k) == "table" then table.insert(t2tablekeys, k) end
         t2keys[k] = true
      end
      -- Let's iterate keys from t1
      for k1, v1 in pairs(t1) do
         local v2 = t2[k1]
         if type(k1) == "table" then
            -- if key is a table, we need to find an equivalent one.
            local ok = false
            for i, tk in ipairs(t2tablekeys) do
               if deepeq(k1, tk) and recurse(v1, t2[tk]) then
                  table.remove(t2tablekeys, i)
                  t2keys[tk] = nil
                  ok = true
                  break
               end
            end
            if not ok then return false end
         else
            -- t1 has a key which t2 doesn't have, fail.
            if v2 == nil then return false end
            t2keys[k1] = nil
            if not recurse(v1, v2) then return false end
         end
      end
      -- if t2 has a key which t1 doesn't have, fail.
      if next(t2keys) then return false end
      return true
   end
   return recurse(table1, table2)
end
validatorlib.deepeq = deepeq


--
-- Validation generator
--

-- generate an expression to check a JSON type
local function typeexpr(ctx, jsontype, datatype, tablekind)
  -- TODO: optimize the type check for arays/objects (using NaN as kind?)
  if jsontype == 'object' then
    return sformat(' %s == "table" and %s <= 1 ', datatype, tablekind)
  elseif jsontype == 'array' then
    return sformat(' %s == "table" and %s >= 1 ', datatype, tablekind)
  elseif jsontype == 'table' then
    return sformat(' %s == "table" ', datatype)
  elseif jsontype == 'integer' then
    return sformat(' (%s == "number" and %s(%s, 1.0) == 0.0) ',
      datatype, ctx:libfunc('math.fmod'), ctx:param(1))
  elseif jsontype == 'string' or jsontype == 'boolean' or jsontype == 'number' then
    return sformat('%s == %q', datatype, jsontype)
  elseif jsontype == 'null' then
    return sformat('%s == %s', ctx:param(1), ctx:libfunc('custom.null'))
  elseif jsontype == 'function' then
    return sformat(' %s == "function" ', datatype)
  else
    error('invalid JSON type: ' .. jsontype)
  end
end

generate_validator = function(ctx, schema)
  -- get type informations as they will be necessary anyway
  local datatype = ctx:localvar(sformat('%s(%s)',
    ctx:libfunc('type'), ctx:param(1)))
  local datakind = ctx:localvar(sformat('%s == "table" and %s(%s)',
    datatype, ctx:libfunc('lib.tablekind'), ctx:param(1)))

  -- type check
  local tt = type(schema.type)
  if tt == 'string' then
    -- only one type allowed
    ctx:stmt('if not (', typeexpr(ctx, schema.type, datatype, datakind), ') then')
    ctx:stmt(sformat('  return false, "wrong type: expected %s, got " .. %s', schema.type, datatype))
    ctx:stmt('end')
  elseif tt == 'table' then
    -- multiple types allowed
    ctx:stmt('if not (')
    for _, t in ipairs(schema.type) do
      ctx:stmt('  ', typeexpr(ctx, t, datatype, datakind), ' or')
    end
    ctx:stmt('false) then') -- close the last "or" statement
    ctx:stmt(sformat('  return false, "wrong type: expected one of %s, got " .. %s', table.concat(schema.type, ', '),  datatype))
    ctx:stmt('end')
  elseif tt ~= 'nil' then error('invalid "type" type: got ' .. tt) end

  -- properties check
  if schema.properties or
     schema.additionalProperties or
     schema.patternProperties or
     schema.minProperties or
     schema.maxProperties or
     schema.dependencies
  then
    -- check properties, this differs from the spec as empty arrays are
    -- considered as object
    ctx:stmt(sformat('if %s == "table" and %s <= 1 then', datatype, datakind))

    -- switch the required keys list to a set
    local required = {}
    local dependencies = schema.dependencies or {}
    local properties = schema.properties or {}
    if schema.required then
      for _, k in ipairs(schema.required) do required[k] = true end
    end

    -- opportunistically count keys if we walk the table
    local needcount = schema.minProperties or schema.maxProperties
    if needcount then
      ctx:stmt(          '  local propcount = 0')
    end

    for prop, subschema in pairs(properties) do
      -- generate validator
      local propvalidator = ctx:validator({ 'properties', prop }, subschema)
      ctx:stmt(          '  do')
      ctx:stmt(sformat(  '    local propvalue = %s[%q]', ctx:param(1), prop))
      ctx:stmt(          '    if propvalue ~= nil then')
      ctx:stmt(sformat(  '      local ok, err = %s(propvalue)', propvalidator))
      ctx:stmt(          '      if not ok then')
      ctx:stmt(sformat(  "        return false, 'property %q validation failed: ' .. err", prop))
      ctx:stmt(          '      end')

      if dependencies[prop] then
        local d = dependencies[prop]
        if #d > 0 then
          -- dependency is a list of properties
          for _, depprop in ipairs(d) do
            ctx:stmt(sformat('      if %s[%q] == nil then', ctx:param(1), depprop))
            ctx:stmt(sformat("        return false, 'property %q is required when %q is set'", depprop, prop))
            ctx:stmt(        '      end')
          end
        else
          -- dependency is a schema
          local depvalidator = ctx:validator({ 'dependencies', prop }, d)
          -- ok and err are already defined in this block
          ctx:stmt(sformat('      ok, err = %s(%s)', depvalidator, ctx:param(1)))
          ctx:stmt(        '      if not ok then')
          ctx:stmt(sformat("        return false, 'failed to validate dependent schema for %q: ' .. err", prop))
          ctx:stmt(        '      end')
        end
      end

      if required[prop] then
        ctx:stmt(        '    else')
        ctx:stmt(sformat("      return false, 'property %q is required'", prop))
        required[prop] = nil
      end
      ctx:stmt(          '    end') -- if prop
      ctx:stmt(          '  end') -- do
    end

    -- check the rest of required fields
    for prop, _ in pairs(required) do
      ctx:stmt(sformat('  if %s[%q] == nil then', ctx:param(1), prop))
      ctx:stmt(sformat("      return false, 'property %q is required'", prop))
      ctx:stmt(        '  end')
    end

    -- check the rest of dependencies
    for prop, d in pairs(dependencies) do
      if not properties[prop] then
        if #d > 0 then
          -- dependencies are a list of properties
          for _, depprop in ipairs(d) do
            ctx:stmt(sformat('  if %s[%q] ~= nil and %s[%q] == nil then', ctx:param(1), prop, ctx:param(1), depprop))
            ctx:stmt(sformat("    return false, 'property %q is required when %q is set'", depprop, prop))
            ctx:stmt(        '  end')
          end
        else
          -- dependency is a schema
          local depvalidator = ctx:validator({ 'dependencies', prop }, d)
          ctx:stmt(sformat('  if %s[%q] ~= nil then', ctx:param(1), prop))
          ctx:stmt(sformat('    local ok, err = %s(%s)', depvalidator, ctx:param(1)))
          ctx:stmt(        '    if not ok then')
          ctx:stmt(sformat("      return false, 'failed to validate dependent schema for %q: ' .. err", prop))
          ctx:stmt(        '    end')
          ctx:stmt(        '  end')
        end
      end
    end

    -- patternProperties and additionalProperties
    local propset, addprop_validator -- all properties defined in the object
    if schema.additionalProperties ~= nil and schema.additionalProperties ~= true then
      -- TODO: can be optimized with a static table expression
      propset = ctx._root:localvar('{}')
      if schema.properties then
        for prop, _ in pairs(schema.properties) do
          ctx._root:stmt(sformat('%s[%q] = true', propset, prop))
        end
      end

      if type(schema.additionalProperties) == 'table' then
        addprop_validator = ctx:validator({ 'additionalProperties' }, schema.additionalProperties)
      end
    end

    -- patternProperties and additionalProperties are matched together whenever
    -- possible in order to walk the table only once
    if schema.patternProperties then
      local patterns = {}
      for patt, patt_schema in pairs(schema.patternProperties) do
        patterns[patt] = ctx:validator({ 'patternProperties', patt }, patt_schema )
      end

      ctx:stmt(sformat(    '  for prop, value in %s(%s) do', ctx:libfunc('pairs'), ctx:param(1)))
      if propset then
        ctx:stmt(          '    local matched = false')
        for patt, validator in pairs(patterns) do
          ctx:stmt(sformat('    if %s(prop, %q) then', ctx:libfunc('custom.match_pattern'), patt))
          ctx:stmt(sformat('      local ok, err = %s(value)', validator))
          ctx:stmt(        '      if not ok then')
          ctx:stmt(sformat("        return false, 'failed to validate '..prop..' (matching %q): '..err", patt))
          ctx:stmt(        '      end')
          ctx:stmt(        '      matched = true')
          ctx:stmt(        '    end')
        end
        -- additional properties check
        ctx:stmt(sformat(  '    if not (%s[prop] or matched) then', propset))
        if addprop_validator then
          -- the additional properties must match a schema
          ctx:stmt(sformat('      local ok, err = %s(value)', addprop_validator))
          ctx:stmt(        '      if not ok then')
          ctx:stmt(        "        return false, 'failed to validate additional property '..prop..': '..err")
          ctx:stmt(        '      end')
        else
          -- additional properties are forbidden
          ctx:stmt(        '      return false, "additional properties forbidden, found " .. prop')
        end
        ctx:stmt(          '    end') -- if not (%s[prop] or matched)
      else
        for patt, validator in pairs(patterns) do
          ctx:stmt(sformat('    if %s(prop, %q) then', ctx:libfunc('custom.match_pattern'), patt))
          ctx:stmt(sformat('      local ok, err = %s(value)', validator))
          ctx:stmt(        '      if not ok then')
          ctx:stmt(sformat("        return false, 'failed to validate '..prop..' (matching %q): '..err", patt))
          ctx:stmt(        '      end')
          ctx:stmt(        '    end')
        end
      end
      if needcount then
        ctx:stmt(          '    propcount = propcount + 1')
      end
      ctx:stmt(            '  end') -- for
    elseif propset then
      -- additionalProperties alone
      ctx:stmt(sformat(  '  for prop, value in %s(%s) do', ctx:libfunc('pairs'), ctx:param(1)))
      ctx:stmt(sformat(  '    if not %s[prop] then', propset))
      if addprop_validator then
        -- the additional properties must match a schema
        ctx:stmt(sformat('      local ok, err = %s(value)', addprop_validator))
        ctx:stmt(        '      if not ok then')
        ctx:stmt(        "        return false, 'failed to validate additional property '..prop..': '..err")
        ctx:stmt(        '      end')
      else
        -- additional properties are forbidden
        ctx:stmt(        '      return false, "additional properties forbidden, found " .. prop')
      end
      ctx:stmt(          '    end') -- if not %s[prop]
      if needcount then
        ctx:stmt(        '    propcount = propcount + 1')
      end
      ctx:stmt(          '  end') -- for prop
    elseif needcount then
      -- we might still need to walk the table to get the number of properties
      ctx:stmt(sformat(  '  for _, _  in %s(%s) do', ctx:libfunc('pairs'), ctx:param(1)))
      ctx:stmt(          '    propcount = propcount + 1')
      ctx:stmt(          '  end')
    end

    if schema.minProperties then
      ctx:stmt(sformat('  if propcount < %d then', schema.minProperties))
      ctx:stmt(sformat('    return false, "expect object to have at least %s properties"', schema.minProperties))
      ctx:stmt(        '  end')
    end
    if schema.maxProperties then
      ctx:stmt(sformat('  if propcount > %d then', schema.maxProperties))
      ctx:stmt(sformat('    return false, "expect object to have at most %s properties"', schema.maxProperties))
      ctx:stmt(        '  end')
    end

    ctx:stmt('end') -- if object
  end

  -- array checks
  if schema.items or schema.minItems or schema.maxItems or schema.uniqueItems then
    ctx:stmt(sformat('if %s == "table" and %s >= 1 then', datatype, datakind))

    -- this check is rather cheap so do it before validating the items
    -- NOTE: getting the size could be avoided in the list validation case, but
    --       this would mean validating items beforehand
    if schema.minItems or schema.maxItems then
      ctx:stmt(sformat(  '  local itemcount = #%s', ctx:param(1)))
      if schema.minItems then
        ctx:stmt(sformat('  if itemcount < %d then', schema.minItems))
        ctx:stmt(sformat('    return false, "expect array to have at least %s items"', schema.minItems))
        ctx:stmt(        '  end')
      end
      if schema.maxItems then
        ctx:stmt(sformat('  if itemcount > %d then', schema.maxItems))
        ctx:stmt(sformat('    return false, "expect array to have at least %s items"', schema.maxItems))
        ctx:stmt(        '  end')
      end
    end

    if schema.items and #schema.items > 0 then
      -- each item has a specific schema applied (tuple validation)

      -- From the section 5.1.3.2, missing an array with missing items is
      -- still valid, because... Well because! So we have to jump after
      -- validations whenever we meet a nil value
      local after = ctx:label()
      for i, ischema in ipairs(schema.items) do
        -- JSON arrays are zero-indexed: remove 1 for URI path
        local ivalidator = ctx:validator({ 'items', tostring(i-1) }, ischema)
        ctx:stmt(        '  do')
        ctx:stmt(sformat('    local item = %s[%d]', ctx:param(1), i))
        ctx:stmt(sformat('    if item == nil then goto %s end', after))
        ctx:stmt(sformat('    local ok, err = %s(item)', ivalidator))
        ctx:stmt(sformat('    if not ok then'))
        ctx:stmt(sformat('      return false, "failed to validate item %d: " .. err', i))
        ctx:stmt(        '    end')
        ctx:stmt(        '  end')
      end

      -- additional items check
      if schema.additionalItems == false then
        ctx:stmt(sformat('  if %s[%d] ~= nil then', ctx:param(1), #schema.items+1))
        ctx:stmt(        '      return false, "found unexpected extra items in array"')
        ctx:stmt(        '  end')
      elseif type(schema.additionalItems) == 'table' then
        local validator = ctx:validator({ 'additionalItems' }, schema.additionalItems)
        ctx:stmt(sformat('  for i=%d, #%s do', #schema.items+1, ctx:param(1)))
        ctx:stmt(sformat('    local ok, err = %s(%s[i])', validator, ctx:param(1)))
        ctx:stmt(sformat('    if not ok then'))
        ctx:stmt(sformat('      return false, %s("failed to validate additional item %%d: %%s", i, err)', ctx:libfunc('string.format')))
        ctx:stmt(        '    end')
        ctx:stmt(        '  end')
      end

      ctx:stmt(sformat(  '::%s::', after))
    elseif schema.items then
      -- all of the items has to match the same schema (list validation)
      local validator = ctx:validator({ 'items' }, schema.items)
      ctx:stmt(sformat('  for i, item in %s(%s) do', ctx:libfunc('ipairs'), ctx:param(1)))
      ctx:stmt(sformat('    local ok, err = %s(item)', validator))
      ctx:stmt(sformat('    if not ok then'))
      ctx:stmt(sformat('      return false, %s("failed to validate item %%d: %%s", i, err)', ctx:libfunc('string.format')))
      ctx:stmt(        '    end')
      ctx:stmt(        '  end')
    end

    -- TODO: this is slow as hell, could be optimized by storing value items
    -- in a spearate set, and calling deepeq only for references.
    if schema.uniqueItems then
      ctx:stmt(sformat('  for i=2, #%s do', ctx:param(1)))
      ctx:stmt(        '    for j=1, i-1 do')
      ctx:stmt(sformat('      if %s(%s[i], %s[j]) then', ctx:libfunc('lib.deepeq'), ctx:param(1), ctx:param(1)))
      ctx:stmt(sformat('        return false, %s("expected unique items but items %%d and %%d are equal", i, j)', ctx:libfunc('string.format')))
      ctx:stmt(        '      end')
      ctx:stmt(        '    end')
      ctx:stmt(        '  end')
    end
    ctx:stmt('end') -- if array
  end

  if schema.minLength or schema.maxLength or schema.pattern then
    ctx:stmt(sformat('if %s == "string" then', datatype))
    if schema.minLength then
      ctx:stmt(sformat('  if #%s < %d then', ctx:param(1), schema.minLength))
      ctx:stmt(sformat('    return false, %s("string too short, expected at least %d, got %%d", #%s)',
                       ctx:libfunc('string.format'), schema.minLength, ctx:param(1)))
      ctx:stmt(        '  end')
    end
    if schema.maxLength then
      ctx:stmt(sformat('  if #%s > %d then', ctx:param(1), schema.maxLength))
      ctx:stmt(sformat('    return false, %s("string too long, expected at most %d, got %%d", #%s)',
                       ctx:libfunc('string.format'), schema.maxLength, ctx:param(1)))
      ctx:stmt(        '  end')
    end
    if schema.pattern then
      ctx:stmt(sformat('  if not %s(%s, %q) then', ctx:libfunc('custom.match_pattern'), ctx:param(1), schema.pattern))
      ctx:stmt(sformat('    return false, %s([[failed to match pattern %q with %%q]], %s)', ctx:libfunc('string.format'), schema.pattern, ctx:param(1)))
      ctx:stmt(        '  end')
    end
    ctx:stmt('end') -- if string
  end

  if schema.minimum or schema.maximum or schema.multipleOf then
    ctx:stmt(sformat('if %s == "number" then', datatype))

    if schema.minimum then
      local op = schema.exclusiveMinimum and '<=' or '<'
      local msg = schema.exclusiveMinimum and 'sctrictly greater' or 'greater'
      ctx:stmt(sformat('  if %s %s %s then', ctx:param(1), op, schema.minimum))
      ctx:stmt(sformat('    return false, %s("expected %%s to be %s than %s", %s)',
                       ctx:libfunc('string.format'), msg, schema.minimum, ctx:param(1)))
      ctx:stmt(        '  end')
    end

    if schema.maximum then
      local op = schema.exclusiveMaximum and '>=' or '>'
      local msg = schema.exclusiveMaximum and 'sctrictly smaller' or 'smaller'
      ctx:stmt(sformat('  if %s %s %s then', ctx:param(1), op, schema.maximum))
      ctx:stmt(sformat('    return false, %s("expected %%s to be %s than %s", %s)',
                       ctx:libfunc('string.format'), msg, schema.maximum, ctx:param(1)))
      ctx:stmt(        '  end')
    end

    local mof = schema.multipleOf
    if mof then
      -- TODO: optimize integer case
      if mmodf(mof) == mof then
        -- integer multipleOf: modulo is enough
        ctx:stmt(sformat('  if %s %% %d ~= 0 then', ctx:param(1), mof))
      else
          -- float multipleOf: it's a bit more hacky and slow
        ctx:stmt(sformat('  local quotient = %s / %s', ctx:param(1), mof))
        ctx:stmt(sformat('  if %s(quotient) ~= quotient then', ctx:libfunc('math.modf')))
      end
      ctx:stmt(sformat(  '    return false, %s("expected %%s to be a multiple of %s", %s)',
                       ctx:libfunc('string.format'), mof, ctx:param(1)))
      ctx:stmt(          '  end')
    end
    ctx:stmt('end') -- if number
  end

  -- enum values
  -- TODO: for big sets of hashable values (> 16 or so), it might be intersing to create a
  --       table beforehand
  if schema.enum then
    ctx:stmt('if not (')
    local lasti = #schema.enum
    for i, val in ipairs(schema.enum) do
      local tval = type(val)
      local op = i == lasti and '' or ' or'

      if tval == 'number' or tval == 'boolean' then
        ctx:stmt(sformat('  %s == %s', ctx:param(1), val), op)
      elseif tval == 'string' then
        ctx:stmt(sformat('  %s == %q', ctx:param(1), val), op)
      elseif tval == 'table' then
        ctx:stmt(sformat('  %s(%s, %s)', ctx:libfunc('lib.deepeq'), ctx:param(1), ctx:uservalue(val)), op)
      else
        error('unsupported enum type: ' .. tval) -- TODO: null
      end
    end
    ctx:stmt(') then')
    ctx:stmt('  return false, "matches non of the enum values"')
    ctx:stmt('end')
  end

  -- compound schemas
  -- (very naive implementation for now, can be optimized a lot)
  if schema.allOf then
    for i, subschema in ipairs(schema.allOf) do
      local validator = ctx:validator({ 'allOf', tostring(i-1) }, subschema)
      ctx:stmt(        'do')
      ctx:stmt(sformat('  local ok, err = %s(%s)', validator, ctx:param(1)))
      ctx:stmt(sformat('  if not ok then'))
      ctx:stmt(sformat('    return false, "allOf %d failed: " .. err', i))
      ctx:stmt(        '  end')
      ctx:stmt(        'end')
    end
  end

  if schema.anyOf then
    local lasti = #schema.anyOf
    ctx:stmt('if not (')
    for i, subschema in ipairs(schema.anyOf) do
      local op = i == lasti and '' or ' or'
      local validator = ctx:validator({ 'anyOf', tostring(i-1) }, subschema)
      ctx:stmt(sformat('  %s(%s)', validator, ctx:param(1)), op)
    end
    ctx:stmt(') then')
    ctx:stmt('  return false, "object matches none of the alternatives"')
    ctx:stmt('end')
  end

  if schema.oneOf then
    ctx:stmt('do')
    ctx:stmt('  local matched')
    for i, subschema in ipairs(schema.oneOf) do
      local validator = ctx:validator({ 'oneOf', tostring(i-1) }, subschema)
      ctx:stmt(sformat('  if %s(%s) then', validator, ctx:param(1)))
      ctx:stmt(        '    if matched then')
      ctx:stmt(sformat('      return false, %s("value sould match only one schema, but matches both schemas %%d and %%d", matched, %d)',
                       ctx:libfunc('string.format'), i))
      ctx:stmt(        '    end')
      ctx:stmt(        '    matched = ', tostring(i))
      ctx:stmt(        '  end')
    end
    ctx:stmt('  if not matched then')
    ctx:stmt('    return false, "value sould match only one schema, but matches none"')
    ctx:stmt('  end')
    ctx:stmt('end')
  end

  if schema['not'] then
    local validator = ctx:validator({ 'not' }, schema['not'])
    ctx:stmt(sformat('if %s(%s) then', validator, ctx:param(1)))
    ctx:stmt(        '  return false, "value wasn\'t supposed to match schema"')
    ctx:stmt(        'end')
  end

  ctx:stmt('return true')
  return ctx
end

local function generate_main_validator_ctx(schema, options)
  local ctx = codectx(schema, options or {})
  -- the root function takes two parameters:
  --  * the validation library (auxiliary function used during validation)
  --  * the custom callbacks (used to customize various aspects of validation
  --    or for dependency injection)
  ctx:preface('local uservalues, lib, custom = ...')
  ctx:stmt('return ', ctx:validator(nil, schema))
  return ctx
end

return {
  generate_validator = function(schema, custom)
    local customlib = {
      null = custom and custom.null or default_null,
      match_pattern = custom and custom.match_pattern or string.find
    }
    local name = custom and custom.name
    return generate_main_validator_ctx(schema, custom):as_func(name, validatorlib, customlib)
  end,
  -- debug only
  generate_validator_code = function(schema, custom)
    return generate_main_validator_ctx(schema, custom):as_string()
  end,
}

end

package.preload['device_ifttt_hooks'] = function()
local Bus = require 'event_bus'
local D = require 'modules_device'
local R = require 'modules_moses'
local TriggerEventsModel = require 'trigger_events_model'
local SolutionLogger = require 'solution_logger'


local logger = SolutionLogger:new({functionName = "IftttHook"})
local DeviceIftttEventBus = Bus('DeviceIftttEvent')

DeviceIftttEventBus:on('data_in:states', function(sn, states)
  local device = D:new(sn)
  local events = device:getAllDeviceEvents()
  local matchedEvents = TriggerEventsModel.getMatchedEvents(
    states,
    device:getInformationModel()
  )
  print('ASDFASDFASDf')
  R.each(states, function(key, value)
	  T4wnaka8.postCacheIdKey({
		  id = sn,
		  key = key,
		  body = {
			  value = value
		  }
	  })
	  print(key)
	  print(value)
  end)
  print('ASDFASDFASDf')


  local eventIds = R(events)
    :map(function(eventId, event)
      local isMatched = R.include(matchedEvents, event.name)
      if isMatched == event.lastMatchedStatus then
        return false
      end

      device:updateDeviceEvent(eventId, R.extend(
        {},
        event,
        { lastMatchedStatus = isMatched }
      ))

      return isMatched and eventId or false
    end)
    :compact()
    :value()

  if not R.isEmpty(eventIds) then
    local Ifttt = require 'ifttt'
    logger:notice({message = string.format('Emitting Realtime API DeviceSN:%s', device.sn), payload = eventIds})
    if not Ifttt.realtime(eventIds) then
      logger:error({message = string.format('Error!! DeviceSN:%s', device.sn), payload = eventIds})
    end
  end

end)

end

package.preload['controllers.device_model_info'] = function()
local DeviceModelInfo = require 'device_model_info'
local HttpError = require 'http-error'
local DeviceModelInfoController = {}

function DeviceModelInfoController.getFieldsByModel(req, res, nxt)
  local fields = DeviceModelInfo.getModelFields(req.parameters.model)
  if fields == nil then
    nxt(HttpError:new(404))
  else
    res:send(fields)
    nxt()
  end
end

return DeviceModelInfoController

end

package.preload['controllers.term_of_service'] = function()
local KV = require "modules_kv"
local R = require 'modules_moses'
local HttpError = require 'http-error'
local TemplateModel = require 'template_model'

local TermOfServiceController = {}
TermOfServiceController.keyName = 'term_of_service'

function TermOfServiceController.getContent(req, res, nxt)
  local domain = string.gsub(req.uri, 'https?://(.-)(/.*)', '%1')
  local data = KV.get(TermOfServiceController.keyName) or nil
  if data == nil then
    data = {
      title = TemplateModel.getTermOfServicesDefaultTitle(),
      body = TemplateModel.getTermOfServicesDefaultBody(domain),
      last_update = os.time()
    }
  end
  res:send(data)
  nxt()
end

function TermOfServiceController.setContent(req, res, nxt)
  local data = req.body
  if R.isEmpty(data.title) or R.isEmpty(data.body) then
    nxt(HttpError:new(400,{status =  "invalid"}))
    return
  end
  data.last_update = req.timestamp
  KV.set(TermOfServiceController.keyName, data)
  res:send(data)
  nxt()
end
return TermOfServiceController

end

package.preload['hamv_error'] = function()
local ERROR_MAPPING = {
  [100] = 'Invalid Token',
  [101] = 'Limit Reached',
  [102] = 'Forbidden',
  [103] = 'Account does not exist',
  [104] = 'Group does not exist',
  [105] = 'Empty groups',
  [200] = 'Too many entries',
  [201] = 'Device doesn’t exist',
  [202] = 'Device exist',
  [203] = 'Device is not provisioned',
  [204] = 'Device is provisioned',
  [205] = 'Invalid provision token',
  [206] = 'Device is offline',
  [207] = 'No device information',
  [208] = 'Property doesn’t exist',
  [300] = 'Bad request',
  [301] = 'Ack fail',
  [302] = 'Auth fail',
  [503] = 'Raced request blocked',
}

local HamvError = {}

function HamvError.instance(code)
  code = tonumber(code)
  local error = {
    status = 'error',
    code = code,
    message = ERROR_MAPPING[code]
  }
  return error
end

return HamvError

end

package.preload['controllers.image'] = function()
local FileManager = require 'file_manager'
local HttpError = require 'http-error'
local InformationModel = require 'information_model'
local KV = require "modules_kv"
local R = require 'modules_moses'
local ImageController = {}

function ImageController.checkImageType(req, _, nxt)
  local valid = R(req.files)
    :map(function(_, file) return ImageController.parseFieldname(file.fieldname) end)
    :all(function(_, object)
      if ImageController.isImageTypeValid(object.imageType) then return true end
      local whitelist = R.concat(ImageController.imageTypeList(), ', ')
      local message = string.format(
        '%s is not valid image type. Only support [%s].',
        object.imageType,
        whitelist
      )
      nxt(HttpError:new(406, message))
    end)
    :value()
  nxt()
  return valid
end

function ImageController.checkFileSize(req, _, nxt)
  local valid = R(req.files)
    :all(function(_, file)
      local limit = 2
      if file.size <= limit * 1024 * 1024 then return true end
      local message = string.format(
        'file size can not greater than %dMB',
        limit
      )
      nxt(HttpError:new(406, message))
    end)
    :value()
  nxt()
  return valid
end

function ImageController.checkFamilyName(req, _, nxt)
  local infoModelMap = KV.get('infoModelMap') or {}
  local index = ImageController.getInvalidFileIndex(req, infoModelMap)
  if index then
    local message = string.format(
      '%s familyName not matched any information model',
      req.files[index].fieldname
    )
    nxt(HttpError:new(406, message))
  end
  nxt()
end

function ImageController.getInvalidFileIndex(req, infoModelMap)
  return R(req.files)
    :map(function(_, file) return ImageController.parseFieldname(file.fieldname) end)
    :findIndex(function(_, object)
      return not infoModelMap[object.familyName]
    end)
    :value()
end

function ImageController.parseFieldname(name)
  local imageType = string.match(name, '%-%w+$') or ''
  local familyName = string.gsub(name, imageType, '')
  return {
    imageType = string.gsub(imageType, '-', ''),
    familyName = familyName,
    fieldname = name,
  }
end

function ImageController.parseUri(uri)
  local regex = 'https?://(.-)/file_manager/(.*)'
  local domain = string.gsub(uri, regex, '%1')
  local filename = string.gsub(uri, regex, '%2')
  local fieldname = FileManager.getFilenameWithoutTimestamp(filename)
  local parsedFieldname = ImageController.parseFieldname(fieldname)
  return R.extend(parsedFieldname, {
    domain = domain,
  })
end

function ImageController.filterAssetsByFamilyName(assets, familyName)
  local regex = string.format('%s-%%w+', familyName)
  return FileManager.filterAssetsByName(assets, regex)
end

function ImageController.removeOldAssets(req, _, nxt)
  local assets = Asset.list({
    path = string.format( '%s/*', FileManager.getDiretoryPath()),
  })
  local fieldnames = R.pluck(req.files, 'fieldname')
  R(fieldnames)
    :map(function(_, fieldname)
      return FileManager.filterAssetsByName(assets, fieldname)
    end)
    :flatten()
    :map(function(_, path)
      return Asset.delete({ path = path })
    end)
  nxt()
end

function ImageController.addNewAssets(req, _, nxt)
  req._pathMapping = {}
  R.forEach(req.files, function(_, file)
    local newFileName = FileManager.appendTimestamp(file.fieldname)
    local path = string.format(
      '%s/%s',
      FileManager.getDiretoryPath(),
      newFileName
    )
    Asset.store({
      path = path,
      file_id = file.file_id,
      request_id = req.request_id,
    })
    req._pathMapping[file.fieldname] = path
  end)
  nxt()
end

function ImageController.updateInformationModels(req, _, nxt)
  sync_call('updateInformationModels', function()
    local infoModels = InformationModel.LoadAll()
    local newInfoModels = ImageController.getUpdatedInformationModels(req, infoModels)
    R.forEach(newInfoModels, function(familyName, infoModel)
      InformationModel.setModel(familyName, infoModel)
    end)
    nxt()
  end)
end

function ImageController.updateInformationModel(infoModel, uri, force)
  local parsedUri = ImageController.parseUri(uri)
  if not infoModel.images then
    infoModel.images = {}
  end
  if not infoModel.images[parsedUri.imageType] then
    infoModel.images[parsedUri.imageType] = {}
  end
  local currentValue = infoModel.images[parsedUri.imageType].uri
  local regex = string.gsub(parsedUri.domain, '%-', '%%-')
  if R.isEmpty(currentValue) or string.match(currentValue, regex) or force then
    infoModel.images[parsedUri.imageType].uri = uri
    return infoModel
  end
end

function ImageController.getUpdatedInformationModels(req, infoModels)
  return R(req.files)
    :reduce(function(acc, file)
      local object = ImageController.parseFieldname(file.fieldname)
      local infoModel = R.findWhere(infoModels, {
        familyName = object.familyName,
      })
      local domain = string.gsub(req.uri, 'https?://(.-)(/.*)', '%1')
      local uri = string.format(
        'https://%s%s',
        domain,
        req._pathMapping[object.fieldname]
      )
      local newInfoModel = ImageController.updateInformationModel(infoModel, uri, true)
      if newInfoModel then
        acc[object.familyName] = newInfoModel
      end
      return acc
    end, {})
    :value()
end

function ImageController.imageTypeList()
  return {
    'banner',
    'thumbnail',
  }
end

function ImageController.isImageTypeValid(imageType)
  local whitelist = ImageController.imageTypeList()
  return R.include(whitelist, imageType)
end

function ImageController.deleteImages(req, _, nxt)
  local assets = Asset.list({
    path = string.format( '%s/*', FileManager.getDiretoryPath()),
  })
  R(assets)
    :filter(function(_, asset)
      local pattern = string.format('^%s/%s-%s',
        FileManager.getDiretoryPath(),
        req.body.familyName,
        req.body.imageType
      )
      pattern = pattern:gsub('-', '%%-')
      return string.match(asset.path, pattern)
    end)
    :reduce(function(acc, asset)
      local path = asset.path
      acc[path] = Asset.delete({ path = path })
      return acc
    end, {})
    :value()
  nxt()
end

function ImageController.removeImageInInformationModel(req, _, nxt)
  sync_call('updateInformationModels', function()
    local familyName = req.body.familyName
    local imageType = req.body.imageType
    local infoModel = InformationModel.getModel(familyName)
    if not infoModel then return end
    infoModel.images = infoModel.images or {}
    infoModel.images[imageType] = nil
    InformationModel.setModel(familyName, infoModel)
    nxt()
  end)
end

return ImageController

end

package.preload['hamv_channel'] = function()
-- luacheck: globals Bulknotify Websocket

--[[--
HamvChannel
@module HamvChannel
]]
local KV = require 'modules_kv'
local R = require 'modules_moses'
local L = require 'lodash'

local HamvChannel = {}

local KEY_PREFIX = 'channel_'

local channelItems = R.memoize(function(key)
  return KV.smembers(key)
end)

local function batch(service, fnName, options)
  if R.isEmpty(options) then
    return
  end

  if #options == 1 then
    local option = options[1]
    return _G[service][fnName](option)
  end

  local serviceFunction = service .. '.' .. fnName

  R(options)
    :chunk(function(i)
      return math.floor((i-1)/20)
    end)
    :each(function(_, chuckedOptions)
      Bulknotify.send({
        service_function = serviceFunction,
        parameters = chuckedOptions
      })
    end)
end

local function getKey(id)
  return KEY_PREFIX .. id
end

--[[--
Posts a message to the given channel(s).

@tparam string channel
@tparam string message message to send
]]
function HamvChannel.publish(channel, message)
  local socketIds = HamvChannel.list(channel) or {}
  local options = R(socketIds)
    :map(function(_, socketId)
      return {
        socket_id = socketId,
        message = message,
        type = 'data-text'
      }
    end)
    :value()

	return batch('Websocket', 'send', options)
end

--[[--
Subscribes the client to the given channel(s).

@tparam string channel one or more channel names
@tparam ... string websocket id
]]
function HamvChannel.subscribe(channel, ...)
  local socketIds = {...}

  if R.isEmpty(socketIds) then
    return
  end

  channel = L.castArray(channel)

  local options = R(channel)
    :map(function(_, _channel)
      return getKey(_channel)
    end)
    :map(function(_, key)
      return KV.commandOptionBuilder.sadd(key, unpack(socketIds))
    end)
    :value()

  batch('Keystore', 'command', options)
end

--[[--
Unsubscribes the client from the given channel(s).

@tparam string channel one or more channel names
@tparam ... string websocket id
]]
function HamvChannel.unsubscribe(channel, ...)
  local socketIds = {...}

  if R.isEmpty(socketIds) then
    return
  end

  channel = L.castArray(channel)

  local options = R(channel)
    :map(function(_, _channel)
      return getKey(_channel)
    end)
    :map(function(_, key)
      return KV.commandOptionBuilder.srem(key, unpack(socketIds))
    end)
    :value()

  batch('Keystore', 'command', options)
end

--[[--
Drop channel(s)

@tparam string channel one or more channel names
]]
function HamvChannel.drop(channel)

  channel = L.castArray(channel)

  local options = R(channel)
    :map(function(_, _channel)
      return getKey(_channel)
    end)
    :map(function(_, key)
      return KV.commandOptionBuilder.del(key)
    end)
    :value()

  batch('Keystore', 'command', options)
end

--[[--
List all socketIds in the channel(s)

@tparam string channel one or more channel names
]]
function HamvChannel.list(channel)
  channel = L.castArray(channel)
  local socketIds = R(channel)
    :map(function(_, _channel)
      return getKey(_channel)
    end)
    :map(function(_, key)
      return L.castArray(channelItems(key))
    end)
    :flatten()
    :value()

  return socketIds
end

--[[--
Clean up closed sockets in a channel

@tparam string channel channel name
@treturn array list of subscribers closed
]]
function HamvChannel.prune(channel)
  local key = getKey(channel)

  local socketIds = channelItems(key)
  socketIds = L.castArray(socketIds)

  socketIds = R(socketIds)
    :filter(function(_, socketId)
      return Websocket.info({
        socket_id = socketId
      }).status == 404
    end)
    :value()

  if not R.isEmpty(socketIds) then
    KV.srem(key, unpack(socketIds))
  end

  return socketIds
end

return HamvChannel

end

package.preload['neturl'] = function()
-- luacheck: ignore
-- neturl.lua - a robust url parser and builder
--
-- Bertrand Mansion, 2011-2013; License MIT
-- @module neturl
-- @alias	M

local M = {}
M.version = "0.9.0"

--- url options
-- separator is set to `&` by default but could be anything like `&amp;amp;` or `;`
-- @todo Add an option to limit the size of the argument table
M.options = {
	separator = '&'
}

--- list of known and common scheme ports
-- as documented in <a href="http://www.iana.org/assignments/uri-schemes.html">IANA URI scheme list</a>
M.services = {
	acap     = 674,
	cap      = 1026,
	dict     = 2628,
	ftp      = 21,
	gopher   = 70,
	http     = 80,
	https    = 443,
	iax      = 4569,
	icap     = 1344,
	imap     = 143,
	ipp      = 631,
	ldap     = 389,
	mtqp     = 1038,
	mupdate  = 3905,
	news     = 2009,
	nfs      = 2049,
	nntp     = 119,
	rtsp     = 554,
	sip      = 5060,
	snmp     = 161,
	telnet   = 23,
	tftp     = 69,
	vemmi    = 575,
	afs      = 1483,
	jms      = 5673,
	rsync    = 873,
	prospero = 191,
	videotex = 516
}

local legal = {
	["-"] = true, ["_"] = true, ["."] = true, ["!"] = true,
	["~"] = true, ["*"] = true, ["'"] = true, ["("] = true,
	[")"] = true, [":"] = true, ["@"] = true, ["&"] = true,
	["="] = true, ["+"] = true, ["$"] = true, [","] = true,
	[";"] = true -- can be used for parameters in path
}

local function decode(str)
	local str = str:gsub('+', ' ')
	return (str:gsub("%%(%x%x)", function(c)
			return string.char(tonumber(c, 16))
	end))
end

local function encode(str)
	return (str:gsub("([^A-Za-z0-9%_%.%-%~])", function(v)
			return string.upper(string.format("%%%02x", string.byte(v)))
	end))
end

-- for query values, prefer + instead of %20 for spaces
local function encodeValue(str)
	local str = encode(str)
	return str:gsub('%%20', '+')
end

local function encodeSegment(s)
	local legalEncode = function(c)
		if legal[c] then
			return c
		end
		return encode(c)
	end
	return s:gsub('([^a-zA-Z0-9])', legalEncode)
end

--- builds the url
-- @return a string representing the built url
function M:build()
	local url = ''
	if self.path then
		local path = self.path
		path:gsub("([^/]+)", function (s) return encodeSegment(s) end)
		url = url .. tostring(path)
	end
	if self.query then
		local qstring = tostring(self.query)
		if qstring ~= "" then
			url = url .. '?' .. qstring
		end
	end
	if self.host then
		local authority = self.host
		if self.port and self.scheme and M.services[self.scheme] ~= self.port then
			authority = authority .. ':' .. self.port
		end
		local userinfo
		if self.user and self.user ~= "" then
			userinfo = self.user
			if self.password then
				userinfo = userinfo .. ':' .. self.password
			end
		end
		if userinfo and userinfo ~= "" then
			authority = userinfo .. '@' .. authority
		end
		if authority then
			if url ~= "" then
				url = '//' .. authority .. '/' .. url:gsub('^/+', '')
			else
				url = '//' .. authority
			end
		end
	end
	if self.scheme then
		url = self.scheme .. ':' .. url
	end
	if self.fragment then
		url = url .. '#' .. self.fragment
	end
	return url
end

--- builds the querystring
-- @param tab The key/value parameters
-- @param sep The separator to use (optional)
-- @param key The parent key if the value is multi-dimensional (optional)
-- @return a string representing the built querystring
function M.buildQuery(tab, sep, key)
	local query = {}
	if not sep then
		sep = M.options.separator or '&'
	end
	local keys = {}
	for k in pairs(tab) do
		keys[#keys+1] = k
	end
	table.sort(keys)
	for _,name in ipairs(keys) do
		local value = tab[name]
		name = encode(tostring(name))
		if key then
			name = string.format('%s[%s]', tostring(key), tostring(name))
		end
		if type(value) == 'table' then
			query[#query+1] = M.buildQuery(value, sep, name)
		else
			local value = encodeValue(tostring(value))
			if value ~= "" then
				query[#query+1] = string.format('%s=%s', name, value)
			else
				query[#query+1] = name
			end
		end
	end
	return table.concat(query, sep)
end

--- Parses the querystring to a table
-- This function can parse multidimensional pairs and is mostly compatible
-- with PHP usage of brackets in key names like ?param[key]=value
-- @param str The querystring to parse
-- @param sep The separator between key/value pairs, defaults to `&`
-- @todo limit the max number of parameters with M.options.max_parameters
-- @return a table representing the query key/value pairs
function M.parseQuery(str, sep)
	if not sep then
		sep = M.options.separator or '&'
	end

	local values = {}
	for key,val in str:gmatch(string.format('([^%q=]+)(=*[^%q=]*)', sep, sep)) do
		local key = decode(key)
		local keys = {}
		key = key:gsub('%[([^%]]*)%]', function(v)
				-- extract keys between balanced brackets
				if string.find(v, "^-?%d+$") then
					v = tonumber(v)
				else
					v = decode(v)
				end
				table.insert(keys, v)
				return "="
		end)
		key = key:gsub('=+.*$', "")
		key = key:gsub('%s', "_") -- remove spaces in parameter name
		val = val:gsub('^=+', "")

		if not values[key] then
			values[key] = {}
		end
		if #keys > 0 and type(values[key]) ~= 'table' then
			values[key] = {}
		elseif #keys == 0 and type(values[key]) == 'table' then
			values[key] = decode(val)
		end

		local t = values[key]
		for i,k in ipairs(keys) do
			if type(t) ~= 'table' then
				t = {}
			end
			if k == "" then
				k = #t+1
			end
			if not t[k] then
				t[k] = {}
			end
			if i == #keys then
				t[k] = decode(val)
			end
			t = t[k]
		end
	end
	setmetatable(values, { __tostring = M.buildQuery })
	return values
end

--- set the url query
-- @param query Can be a string to parse or a table of key/value pairs
-- @return a table representing the query key/value pairs
function M:setQuery(query)
	local query = query
	if type(query) == 'table' then
		query = M.buildQuery(query)
	end
	self.query = M.parseQuery(query)
	return query
end

--- set the authority part of the url
-- The authority is parsed to find the user, password, port and host if available.
-- @param authority The string representing the authority
-- @return a string with what remains after the authority was parsed
function M:setAuthority(authority)
	self.authority = authority
	self.port = nil
	self.host = nil
	self.userinfo = nil
	self.user = nil
	self.password = nil

	authority = authority:gsub('^([^@]*)@', function(v)
		self.userinfo = v
		return ''
	end)
	authority = authority:gsub("^%[[^%]]+%]", function(v)
		-- ipv6
		self.host = v
		return ''
	end)
	authority = authority:gsub(':([^:]*)$', function(v)
		self.port = tonumber(v)
		return ''
	end)
	if authority ~= '' and not self.host then
		self.host = authority:lower()
	end
	if self.userinfo then
		local userinfo = self.userinfo
		userinfo = userinfo:gsub(':([^:]*)$', function(v)
				self.password = v
				return ''
		end)
		self.user = userinfo
	end
	return authority
end

--- Parse the url into the designated parts.
-- Depending on the url, the following parts can be available:
-- scheme, userinfo, user, password, authority, host, port, path,
-- query, fragment
-- @param url Url string
-- @return a table with the different parts and a few other functions
function M.parse(url)
	local comp = {}
	M.setAuthority(comp, "")
	M.setQuery(comp, "")

	local url = tostring(url or '')
	url = url:gsub('#(.*)$', function(v)
		comp.fragment = v
		return ''
	end)
	url =url:gsub('^([%w][%w%+%-%.]*)%:', function(v)
		comp.scheme = v:lower()
		return ''
	end)
	url = url:gsub('%?(.*)', function(v)
		M.setQuery(comp, v)
		return ''
	end)
	url = url:gsub('^//([^/]*)', function(v)
		M.setAuthority(comp, v)
		return ''
	end)
	comp.path = decode(url)

	setmetatable(comp, {
		__index = M,
		__tostring = M.build}
	)
	return comp
end

--- removes dots and slashes in urls when possible
-- This function will also remove multiple slashes
-- @param path The string representing the path to clean
-- @return a string of the path without unnecessary dots and segments
function M.removeDotSegments(path)
	local fields = {}
	if string.len(path) == 0 then
		return ""
	end
	local startslash = false
	local endslash = false
	if string.sub(path, 1, 1) == "/" then
		startslash = true
	end
	if (string.len(path) > 1 or startslash == false) and string.sub(path, -1) == "/" then
		endslash = true
	end

	path:gsub('[^/]+', function(c) table.insert(fields, c) end)

	local new = {}
	local j = 0

	for i,c in ipairs(fields) do
		if c == '..' then
			if j > 0 then
				j = j - 1
			end
		elseif c ~= "." then
			j = j + 1
			new[j] = c
		end
	end
	local ret = ""
	if #new > 0 and j > 0 then
		ret = table.concat(new, '/', 1, j)
	else
		ret = ""
	end
	if startslash then
		ret = '/'..ret
	end
	if endslash then
		ret = ret..'/'
	end
	return ret
end

local function absolutePath(base_path, relative_path)
	if string.sub(relative_path, 1, 1) == "/" then
		return '/' .. string.gsub(relative_path, '^[%./]+', '')
	end
	local path = base_path
	if relative_path ~= "" then
		path = '/'..path:gsub("[^/]*$", "")
	end
	path = path .. relative_path
	path = path:gsub("([^/]*%./)", function (s)
		if s ~= "./" then return s else return "" end
	end)
	path = string.gsub(path, "/%.$", "/")
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, "([^/]*/%.%./)", function (s)
			if s ~= "../../" then return "" else return s end
		end)
	end
	path = string.gsub(path, "([^/]*/%.%.?)$", function (s)
		if s ~= "../.." then return "" else return s end
	end)
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, '^/?%.%./', '')
	end
	return '/' .. path
end

--- builds a new url by using the one given as parameter and resolving paths
-- @param other A string or a table representing a url
-- @return a new url table
function M:resolve(other)
	if type(self) == "string" then
		self = M.parse(self)
	end
	if type(other) == "string" then
		other = M.parse(other)
	end
	if other.scheme then
		return other
	else
		other.scheme = self.scheme
		if not other.authority or other.authority == "" then
			other:setAuthority(self.authority)
			if not other.path or other.path == "" then
				other.path = self.path
				local query = other.query
				if not query or not next(query) then
					other.query = self.query
				end
			else
				other.path = absolutePath(self.path, other.path)
			end
		end
		return other
	end
end

--- normalize a url path following some common normalization rules
-- described on <a href="http://en.wikipedia.org/wiki/URL_normalization">The URL normalization page of Wikipedia</a>
-- @return the normalized path
function M:normalize()
	if type(self) == 'string' then
		self = M.parse(self)
	end
	if self.path then
		local path = self.path
		path = absolutePath(path, "")
		-- normalize multiple slashes
		path = string.gsub(path, "//+", "/")
		self.path = path
	end
	return self
end

return M

end

package.preload['controllers.theme'] = function()
local R = require 'modules_moses'
local Solution = require 'modules_solution'

local ThemeController = {}

function ThemeController.whitelistKeys()
  return {
    'app_name',
    'app_url_scheme',
    'apple_store',
    'company_address',
    'company_contact',
    'company_name',
    'company_url',
    'google_play',
    'primary_color',
    'product_name',
    'timestamp',
    'solution_version',
    'welcome_email_body',
    'welcome_email_headline',
    'welcome_email_subject',
    'welcome_web_body',
    'welcome_web_headline',
    'wifi_name',
  }
end

function ThemeController.getConfig(_, res, nxt)
  local config = Solution.getSolutionConfig() or {}

  config = R.pick(config, ThemeController.whitelistKeys())

	res:json(config)
	nxt()
end

function ThemeController.setConfig(req, _, nxt)
  req.body.timestamp = req.timestamp

  R(req.body)
    :pick(ThemeController.whitelistKeys())
    :map(function(key, value)
      return Solution.setSolutionConfig(key, value)
    end)
    :value()
  nxt()
end

function ThemeController.removeAssets(req, _, nxt)
  R(req.body)
    :keys()
    :filter(function(_, key)
      return string.match(key, '^remove_')
    end)
    :map(function(_, key)
      return req.body[key]
    end)
    :filter(function(_, value)
      return not R.isNil(value)
    end)
    :map(function(_, value)
      return Asset.delete({
        path = '/theme/' .. value,
      })
    end)
    :value()
  nxt()
end

function ThemeController.storeAssets(req, _, nxt)
  R.map(req.files, function(_, file)
    return Asset.store({
      file_id = file.file_id,
      path = '/theme/' .. file.fieldname,
      request_id = req.request_id,
    })
  end)
  nxt()
end

return ThemeController

end

package.preload['routers.api'] = function()
--[[--
api-router
@module api-router
]]
local Router = require('router')

local ApiRouter = Router:new()

return ApiRouter

end

package.preload['controllers.historical'] = function()
local DevicePermissionModel = require 'device_permission_model'
local HttpError = require 'http-error'
local L = require 'lodash'
local R = require 'modules_moses'
local HistoricalController = {}

function HistoricalController.checkDeviceAccess(req, _, nxt)
  local user = _G.currentUser(req)
  local p = req.parameters
  local hasAccess = DevicePermissionModel.checkUserHasAccess(p.deviceId, user.id)
  if not hasAccess then
    nxt(HttpError:new(403))
  end
  nxt()
end

function HistoricalController.queryData(req, res, nxt)
  local p = req.parameters
  local tsdb = Tsdb.query({
    aggregate = p.aggregate,
    end_time = p.end_time,
    limit = p.limit,
    metrics = {
      p.field,
    },
    order_by = p.order_by,
    sampling_size = p.sampling_size,
    start_time = p.start_time,
    tags = {
      device_sn = p.deviceId,
    },
  })
  if tsdb.error then
    nxt(HttpError:new(tsdb.status, tsdb.error))
  end
  local output = R.map(tsdb.values or {}, function(_, data)
    return {
      time = data[1],
      value = data[2],
    }
  end)
  res:json(L.castArray(output))
  nxt()
end

return HistoricalController

end

package.preload['router'] = function()
--[[--
router
@module router
]]
local finalHandler = require 'final-handler'
local HttpError = require 'http-error'
local initialHandler = require 'initial-handler'
local JSON = require 'modules_json'
local Object = require 'modules_object'
local R = require 'modules_moses'
local SolutionLogger = require 'solution_logger'

--[[--
Router
@type Router
]]
local Router = Object:extend()

function Router:initialize()
	self.stack = {}
	self:use(initialHandler)
  self.pos = #self.stack
end

--[[--
use
@tparam func fn middleware
@treturn Router self
@usage
Router:new():use(function(req, res, nxt) ... end)
]]
function Router:use(fn)
	assert(R.isCallable(fn), '"fn" argument must be callable')
	self.stack[#self.stack + 1] = fn
	return self
end

--[[--
use
@tparam is object check the SolutionLogger
@treturn Router self
@usage
Router:new():enableLogger({functionName = "IftttController", severity = 5})
]]
function Router:enableLogger(parameter)
  self.logger = SolutionLogger:new(parameter)
  return self
end

--[[--
handle
@tparam userdata req request
@tparam userdata res response
@tparam[opt=finalHandler] func out finalHandler
@treturn Router self
@usage
Router:new():handle(request, response, function(err, req, res) ... end)
]]
function Router:handle(req, res, out)
	local idx = 0
	local pos = self.pos
	local function nxt(err)
		idx = idx + 1
		local fn = self.stack[idx]
		if not fn then
			local ok, msg = pcall(out, err, req, res)
			if not ok then
				res:status(500):send('#final ' .. JSON.stringify(err or msg))
			end
			return
		end
		if err then
			return nxt(err)
		end
		local ok, msg = pcall(fn, req, res, nxt)
		if not ok then
			nxt(HttpError:new(500, ('#%d %s'):format(idx - pos, JSON.stringify(msg))))
		end
	end
  out = out or finalHandler
  -- log input one time only.
  if self.logger ~= nil then
    self.logger:notice({message = 'input', payload = req})
  end
	nxt()
	if idx <= #self.stack then
		res:status(501):send(('#%d unhandled middleware'):format(idx - pos))
	end
	return self
end

return Router

end

package.preload['modules_solution'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'
local Solution = {}

Solution.keyName = "SolutionConfig"
Solution.__defaultConfig = {
  solution_version = '2.2.1',
  debug = false,
  migration = 0.1,
  app_url_scheme = "myProduct://",
  app_name = "myProduct",
  product_name = "My Product",
  company_name = "My Company",
  company_address = "275 Market St, Suite 535, Minneapolis, MN 55405",
  company_contact = "1-612-353-2161",
  company_url = "https://mycompany.com",
  apple_store = "https://itunes.apple.com/us/app/exosite-excite/id1090866808",
  google_play = "https://play.google.com/store/apps/details?id=com.exosite.excite",
  primary_color = "#00BAFF",
  welcome_email_body = "Thanks for creating a {{product_name}} account. With the {{app_name}} "
    .."app, you can control your smart AC from anywhere and set schedules to fit your daily routine.",
  welcome_email_headline = "Welcome to {{product_name}}!",
  welcome_email_subject = "Welcome to {{product_name}}!",
  welcome_web_body = "With the {{app_name}} app, you can control your smart AC from anywhere "
    .. "and set schedules to fit your daily routine. If you haven’t yet, make sure to download "
    .. "the {{app_name}} app on any device you wish to use.",
  welcome_web_headline = "Welcome to {{product_name}}!",
  o_auth_expires_in = 0,
  o_auth_expires_in_default = 1296000,
  ifttt_trigger_tsdb_query_limit = 60
}

local function _readSolutionWithoutCache()
  return KV.get(Solution.keyName)
end

local _readSolutionWithCache = R.memoize(_readSolutionWithoutCache, function() return 'hashkey' end)

local function _readSolution(withCache)
  return withCache and _readSolutionWithCache() or _readSolutionWithoutCache()
end

local function _writeSolution(values)
  return KV.set(Solution.keyName, values)
end

function Solution.getSolutionConfig(key, withCache)
  local config = _readSolution(withCache)
  if config == nil then
    print('Error, missing solution config, reply default value')
    config = Solution.__defaultConfig
  end

  config.solution_version = Solution.__defaultConfig.solution_version
  if key == nil then return config end

  local value = config[key]
  if value == nil then
    print(('Error, missing solution config key:%s'):format(key))
  end
  return value
end

function Solution.setSolutionConfig(key, value)
  assert(key and type(key) == 'string', 'Error, set solution config with missing key')
  local config = assert(_readSolution(), ('Error, set solution config error key:%s'):format(key))
  config[key] = value
  return _writeSolution(config)
end

function Solution.initSolutionConfig()
  local config = _readSolution()
  -- set solution default config
  if config == nil then
    config = Solution.__defaultConfig
    return assert(_writeSolution(config), 'Error, init solution config fail')
  end
end

return Solution

end

package.preload['controllers.init'] = function()
local DeviceGateway = require 'device_gateway'
local HamvGateway = DeviceGateway.get('Hamv')
local HamvUniqueGateway = DeviceGateway.get('HamvUnique')
local R = require 'modules_moses'
local InitController = {}

function InitController.initResponseMessage(_, res, nxt)
  res.message = {}
  nxt()
end

function InitController.initSolutionConfig(_, res, nxt)
  local Solution = require 'modules_solution'
  res.message['Solution.initSolutionConfig'] = Solution.initSolutionConfig()
  nxt()
end

function InitController.initAdminRole(_, res, nxt)
  local parameters = {
    role_id = 'admin',
    body = {
      {
        name = 'customRoleName',
      },
    },
  }
  res.message['User.createRole'] = User.createRole(parameters)
  res.message['User.addRoleParam'] = User.addRoleParam(parameters)
  nxt()
end

function InitController.initGatewaySettings(_, res, nxt)
  local parameters = {
    protocol = {
      name = 'mqtt',
    },
  }
  res.message['HamvGateway.updateGatewaySettings'] = HamvGateway.updateGatewaySettings(parameters)
  nxt()
end

function InitController.initGatewayResource(_, res, nxt)
  local hamv = {
    {
      alias = 'action',
      format = 'string',
      settable = true,
    },
    {
      alias = 'cert',
      format = 'string',
      settable = false,
    },
    {
      alias = 'esh',
      format = 'string',
      settable = false,
    },
    {
      alias = 'fields',
      format = 'string',
      settable = true,
    },
    {
      alias = 'module',
      format = 'string',
      settable = false,
    },
    {
      alias = 'ota',
      format = 'string',
      settable = false,
    },
    {
      alias = 'owner',
      format = 'string',
      settable = true,
    },
    {
      alias = 'profile',
      format = 'string',
      settable = true,
    },
    {
      alias = 'result',
      format = 'string',
      settable = false,
    },
    {
      alias = 'schedules',
      format = 'string',
      settable = true,
    },
    {
      alias = 'states',
      format = 'string',
      settable = false,
    },
    {
      alias = 'token',
      format = 'string',
      settable = false,
    },
    {
      alias = 'debug',
      format = 'string',
      settable = false,
    },
  }
  res.message['HamvGateway.addGatewayResource'] = R.map(hamv, function(_, parameters)
    return HamvGateway.addGatewayResource(parameters)
  end)

  local hamvUnique = {
    {
      alias = 'debug_mode',
      format = 'boolean',
      settable = true,
    },
    {
      alias = 'connected',
      format = 'boolean',
      settable = true,
    },
    {
      alias = 'firmware_version',
      format = 'string',
      settable = true,
    },
    {
      alias = 'guest_emails',
      format = 'string',
      settable = true,
    },
    {
      alias = 'model',
      format = 'string',
      settable = true,
    },
    {
      alias = 'owner_email',
      format = 'string',
      settable = true,
    },
    {
      alias = 'sn',
      format = 'string',
      settable = true,
    },
  }
  res.message['HamvUniqueGateway.addGatewayResource'] = R.map(hamvUnique, function(_, parameters)
    return HamvUniqueGateway.addGatewayResource(parameters)
  end)
  nxt()
end

return InitController

end

package.preload['controllers.device_action'] = function()
local HamvModel = require 'hamv_model'
local HttpError = require 'http-error'
local R = require('modules_moses')
local DeviceActionController = {}


function DeviceActionController.filterAction(req, _, nxt)
  local whitelist = {
    'debug',
  }
  if not R.include(whitelist, req.parameters.action) then
    nxt(HttpError:new(405))
  end
  nxt()
end

function DeviceActionController.verifyAction(req, _, nxt)
  local verifyFunction = {
    debug = DeviceActionController.verifyDebugAction,
  }
  if not verifyFunction[req.parameters.action](req.body) then
    nxt(HttpError:new(400))
  end
  nxt()
end

function DeviceActionController.doAction(req, res, nxt)
  local sn = req.parameters.sn
  local name = req.parameters.action
  local data = req.body
  local identifier = HamvModel.createActionIdentifier({}, req.request_id, name, data)
  res:send(HamvModel.sendAction(sn, name, data, identifier))
  nxt()
end

function DeviceActionController.verifyDebugAction(payload)
  if not R.isTable(payload) then return end
  local mode = payload.mode
  if not R.isNumber(mode) then return end
  if mode > 1 or mode < 0 then return end
  return true
end

return DeviceActionController

end

package.preload['modules_json'] = function()
-- luacheck: globals from_json to_json
--[[--
json
@module json
]]
local JSON = {}

--[[--
This method parses a JSON string, constructing the Lua value or object described
by the string.

@function JSON.parse
@tparam any value
@treturn[1] any result
@treturn[1] nil error message
@treturn[2] nil result
@treturn[2] string error message
@usage

JSON.parse('{}')
-- => {}, nil

JSON.parse('')
-- => nil, 'message'
]]
JSON.parse = from_json or function(value)
	return value
end

--[[--
This method converts a Lua value to a JSON string.

@function JSON.stringify
@tparam any value
@treturn[1] string result
@treturn[1] nil error message
@treturn[2] nil result
@treturn[2] string error message
@usage

JSON.stringify({})
-- => '{}', nil

JSON.stringify(_G)
-- => nil, 'message'
]]
JSON.stringify = to_json or function(value)
	return value ~= nil and tostring(value) or nil
end

return JSON

end

package.preload['jsonschema_store'] = function()
-- luacheck: ignore
-- This module is a store for all schemas unsed in a code context.
-- It is meant to deal with the id and $ref madness that JSON schema authors
-- managed to put together. Resolving JSON references involves full URI
-- parsing, absolute/relative URLs, scope management, id aliases, multipass
-- parsing (as you have to walk the document a first time to discover all ids)
-- and other niceties.
--
-- Don't try to find any logic in this code, there isn't: this is just an
-- implementation of [1] which is foreign to the concept of *logic*.
--
-- [1] http://json-schema.org/latest/json-schema-core.html#rfc.section.8

-- I gave up (for now) on doing a stripped down URI parser only for JSON schema
-- needs
local url = require 'neturl'
local schar = string.char

-- the net.url is kinda weird when some uri parts are missing (sometimes it is
-- nil, sometimes it is an empty string)
local function noe(s) return s == nil or s == '' end

-- fetching and parsing external schemas requires a lot of dependencies, and
-- depends a lot on the application ecosystem (e.g. piping curl,  LuaSocket,
-- cqueues, ...). Moreover, most sane schemas are self contained, so it is not
-- even useful.
-- So it is up to the user to provide a resolver if it's really needed
local function default_resolver(uri)
  error('an external resolver is required to fetch ' .. uri)
end

local function percent_unescape(x)
  return schar(tonumber(x, 16))
end
local tilde_unescape = { ['~0']='~', ['~1']='/' }
local function urlunescape(fragment)
  return fragment:gsub('%%(%x%x)', percent_unescape):gsub('~[01]', tilde_unescape)
end

-- attempt to translate a URI fragemnt part to a valid table index:
-- * if the part can be converted to number, that number+1 is returned to
--   compensate with Lua 1-based indices
-- * otherwise, the part is returned URL-escaped
local function decodepart(part)
  local n = tonumber(part)
  return n and (n+1) or urlunescape(part)
end


-- a reference points to a particular node of a particular schema in the store
local ref_mt = {}
ref_mt.__index = ref_mt

function ref_mt:child(items)
  if not (items and items[1]) then return self end
  local schema = self:resolve()
  for _, node in ipairs(items) do
    schema = assert(schema[decodepart(node)])
  end
  return setmetatable({ store=self.store, schema=schema }, ref_mt)
end

function ref_mt:resolve()
  local schema = self.schema

  -- resolve references
  while schema['$ref'] do
    -- ok, this is a ref, but what kind of ref?!?
    local ctx = self.store:ctx(schema)
    local ref = url.parse(ctx.base.id):resolve(schema['$ref'])
    local fragment = ref.fragment

    -- get the target schema
    ref.fragment = nil
    schema = self.store:fetch(tostring(ref:normalize()))

    -- no fragment? just retrun the root
    if not fragment then
      return schema
    end

    -- maybe the fragment is a id alias
    local by_id = self.store:ctx(ctx.base).map[fragment]
    if by_id then
      schema = by_id
    else
      -- maybe not after all, walk the schema
      -- TODO: notrmalize path (if there is people mean enough to put '.' or
      -- '..' components)
      for part in fragment:gmatch('[^/]+') do
        part = decodepart(part)
        local new = schema[part]
        if not new then
          error(string.format('reference not found: %s#%s (at %q)',
                              ref, fragment, part))
        end
        schema = new
      end
    end
  end

  return schema
end


-- a store manage all currently required schemas
-- it is not exposed directly
local store_mt = {}
store_mt.__index = store_mt

function store_mt:ref(schema)
  return setmetatable({
    store = self,
    schema = schema,
  }, ref_mt)
end

-- store of additional metadata by schema table part, this is to avoid
-- modifying schema tables themselves. For now, we have
--
-- * `base`: refers to the base schema (e.g. for a nested subschema to find
--   its parent schema
-- * `map`: only for "root" schemas, maps indetifiers to subschemas
function store_mt:ctx(t)
  local c = self.ctx_store[t]
  if not c then
    c = {}
    self.ctx_store[t] = c
  end
  return c
end

function store_mt:fetch(uri)
  local schema = self.schemas[uri]
  if schema then return schema end

  -- schema not yet known
  schema = self.resolver(uri)
  if not schema then
    error('faild to fetch schema for: ' .. uri)
  end
  if not schema.id then
    schema.id = uri
  end
  self:insert(schema)
  return schema
end


-- functions used to walk a schema
local function is_schema(path)
  local n = #path
  local parent, grandparent = path[n], path[n-1]

  return n == 0 or -- root node
     parent == 'additionalItems' or
     parent == 'additionalProperties' or
     parent == 'items' or
     parent == 'not' or
     (type(parent) == 'number' and (
        grandparent == 'items' or
        grandparent == 'allOf' or
        grandparent == 'anyOf' or
        grandparent == 'oneOf'
     )) or
     grandparent == 'properties' or
     grandparent == 'patternProperties' or
     grandparent == 'definitions' or
     grandparent == 'dependencies'
end

function store_mt:insert(schema)
  local id = url.parse(assert(schema.id, 'id is required'))
  assert(noe(id.fragment), 'schema ids should not have fragments')
  schema.id = tostring(id:normalize())
  self.schemas[schema.id] = schema
  local base_id = id

  -- walk the schema to collect the ids and populate the base field in context
  local map = {}

  local function walk(s, p)
    local id = s.id
    if id and s ~= schema and is_schema(p) then
      -- there is an id, but it is not over: we have 2 different cases (!)
      --  1. the id is a fragment: it is some kind of an internal alias
      --  2. the id is an url (relative or absolute): resolve it using the
      --     current base and use that as a new base.
      if id:sub(1,1) == '#' then
        -- fragment (case 1)
        map[id.fragment] = self:ref(s)
      else
        -- relative url (case 2)
        -- FIXME: I'm sure it's broken bacasue resolution scopes could be
        -- nested... but at the same time, who the hell would do this and it
        -- passes the tests so ¯\_(ツ)_/¯
        local resolved = base_id:resolve(id)
        assert(noe(resolved.fragment), 'fragment in relative id')
        s.id = tostring(resolved:normalize())
        return self:insert(s)
      end
    end

    self:ctx(s).base = schema
    for k, v in pairs(s) do
      if type(v) == 'table' and
        (type(k) == 'number' or (
          k ~= 'enum' and
          k:sub(1,1) ~= '_'
        ))
      then
        table.insert(p, k)
        walk(v, p)
        table.remove(p)
      end
    end
  end
  walk(schema, {})
  self:ctx(schema).map = map
  return self:ref(schema)
end

local function new(schema, resolver)
  local self = setmetatable({
    ctx_store = {}, -- used to store metadata aobut schema parts
    schemas = {},
    resolver = resolver or default_resolver,
  }, store_mt)

  schema.id = schema.id or 'root:'
  return self:insert(schema)
end

return {
  new = new,
}

end

package.preload['file_manager'] = function()
local R = require 'modules_moses'

local FileManager = {}

function FileManager.appendTimestamp (name)
  local ts = os.time(os.date('!*t'))
  return string.format('%s-%s', tostring(name), ts)
end

function FileManager.getDiretoryPath ()
  return '/file_manager'
end

function FileManager.filterAssetsByName (assets, name)
  local regex = string.gsub(name, '%-', '%%-')
  regex = string.format('^%s/%s%%-%%d+$', FileManager.getDiretoryPath(), regex)
  return R(assets)
    :pluck('path')
    :filter(function(_, path) return string.match(path, regex) end)
    :value()
end

function FileManager.getFilenameWithoutTimestamp (name)
  return string.gsub(name, '%-%d+$', '')
end

return FileManager

end

package.preload['device_property_model'] = function()
local R = require 'modules_moses'
local JSON = require 'modules_json'
local KV = require 'modules_kv'
local DevicePropertyModel = {}

function DevicePropertyModel.get(userId, sn)
  return JSON.parse(KV.hget(DevicePropertyModel.getStoreKey(userId), sn))
end

function DevicePropertyModel.list(userId)
  return KV.hkeys(DevicePropertyModel.getStoreKey(userId))
end

-- TODO: add lock to this function, return logic definition
function DevicePropertyModel.deletePropertiesFromDevice(userId, sn, keys)
  local deviceProperties = DevicePropertyModel.get(userId, sn)
  if deviceProperties and R.size(R.intersection(R.keys(deviceProperties), keys)) > 0 then
    local newDeviceProperties = R(deviceProperties)
      :map(function(key, value) if not R.contains(keys,key) then return value end end)
      :value()
    DevicePropertyModel.set(userId, sn, newDeviceProperties)
    return true
  else
    return false
  end
end

function DevicePropertyModel.remove(userId, sn)
  return KV.hdel(DevicePropertyModel.getStoreKey(userId), sn) == 1
end

function DevicePropertyModel.set(userId, sn, properties)
  return KV.hset(DevicePropertyModel.getStoreKey(userId), sn, JSON.stringify(properties))
end

function DevicePropertyModel.getStoreKey(userId)
  return "user_"..userId.."_properties"
end

return DevicePropertyModel

end

package.preload['controllers.unique_device'] = function()
local D = require 'modules_device'
local HamvUniqueModel = require 'hamv_unique_model'
local HttpError = require 'http-error'

local UniqueDeviceController = {}

function UniqueDeviceController.deleteDevice(req, res, nxt)
  local id = req.parameters.id

  local device = HamvUniqueModel.getById(id)

  if not device then
    return nxt(HttpError:new(404))
  end

  local sn = HamvUniqueModel.getState(id, 'sn')
  if not sn then
    return nxt(HttpError:new(404))
  end

  if not D:new(sn):delete() then
    return nxt(HttpError:new(500))
  end

  res:status(204)
  nxt()
end

return UniqueDeviceController

end

package.preload['kv_list'] = function()
local KV = require "modules_kv"
local R = require "modules_moses"
local JSON = require "modules_json"
local Object = require "modules_object"
local Constant = require "constant"

local KVObject = Object:extend()
KVObject.KVkey = {}

function KVObject:initialize(KV_Key)
    if KV_Key ~= nil and KV_Key ~= "" then
        KVObject.KVkey = KV_Key
    end
end

local function setToList(ListKey,value)
    return KV.hset(KVObject.KVkey,ListKey,JSON.stringify(value))
end

local function getFromList(ListKey)
    local res = KV.hget(KVObject.KVkey,ListKey)
    return JSON.parse(res) or nil
end

local function delFromList(ListKey)
    return KV.hdel(KVObject.KVkey,ListKey)
end

local function getKeysList()
    return KV.hkeys(KVObject.KVkey)
end

local function addToListValue(ListKey,value)
    local data = getFromList(ListKey)
    if data == nil then
        data = setmetatable({}, { __type = 'slice' })
    end
    if R.find(data, value) == nil then
        table.insert(data,value)
        if string.len(JSON.stringify(data)) > Constant.KEYSTORE_COMMAND_PAYLOAD_LIMIT then
          --remove 5 object to make sure not to meet payload limit
          R.unshift(data,5)
        end
        return KV.hset(KVObject.KVkey,ListKey,JSON.stringify(data))
    end
end

local function delFromListValue(ListKey,value)
    local data = getFromList(ListKey)
    if data == nil then
        return nil
    end
    if R.find(data, value) ~= nil then
        data = R.pull(data, value)
        return KV.hset(KVObject.KVkey,ListKey,JSON.stringify(data))
    end
end

local function getItemsFromListValue(ListKey)
    return getFromList(ListKey)
end

KVObject.setToList = setToList
KVObject.getFromList = getFromList
KVObject.delFromList = delFromList
KVObject.getKeysList = getKeysList
KVObject.addToListValue = addToListValue
KVObject.delFromListValue = delFromListValue
KVObject.getItemsFromListValue = getItemsFromListValue
return KVObject

end

package.preload['hamv_unique_model'] = function()
local DeviceGateway = require 'device_gateway'
local R = require 'modules_moses'

local HamvUniqueModel = {}
local HamvUniqueGateway = DeviceGateway.get('HamvUnique')

local function setState(identity, state)
  state.identity = identity
  return HamvUniqueGateway.setIdentityState(state).error == nil
end

local function updateConnection(identity, connected)
  return setState(identity, {
    connected = connected,
  })
end

local function updateLock(identity, locked)
  return HamvUniqueGateway.updateIdentity({
    identity = identity,
    locked = locked,
  }).error == nil
end

local function updateDebugoMode(identity, mode)
  return setState(identity, {
    debug_mode = mode,
  })
end

function HamvUniqueModel.add(identity, state)
  HamvUniqueGateway.addIdentity({
    identity = identity,
  })
  setState(identity, state)
  HamvUniqueModel.unlock(identity)
end

HamvUniqueModel.getById = R.memoize(function (identity)
  local ret = HamvUniqueGateway.listIdentities({
    identity = '^' .. identity .. '$',
  })

  local list = assert(ret.devices, ret.error)

  return list[1]
end)

function HamvUniqueModel.getState(identity, key)
  local device = HamvUniqueModel.getById(identity) or {}
  local state = device.state or {}
  local obj = state[key] or {}
  return obj.set
end

function HamvUniqueModel.list(...)
  local ret = HamvUniqueGateway.listIdentities(...)
  if ret.error then error(ret.error) end
  return ret
end

function HamvUniqueModel.lock(identity)
  return updateLock(identity, true)
end

function HamvUniqueModel.setConnect(identity)
  return updateConnection(identity, true)
end

function HamvUniqueModel.setDisconnect(identity)
  return updateConnection(identity, false)
end

function HamvUniqueModel.setFirmwareVersion(identity, firmwareVersion)
  return setState(identity, {
    firmware_version = firmwareVersion,
  })
end

function HamvUniqueModel.setGuestEmails(identity, guestEmails)
  return setState(identity, {
    guest_emails = to_json(guestEmails),
  })
end

function HamvUniqueModel.setModel(identity, model)
  return setState(identity, {
    model = model,
  })
end

function HamvUniqueModel.unlock(identity)
  return updateLock(identity, false)
end

function HamvUniqueModel.disableDebugMode(identity)
  return updateDebugoMode(identity, false)
end

function HamvUniqueModel.enableDebugMode(identity)
  return updateDebugoMode(identity, true)
end

return HamvUniqueModel

end

package.preload['kernel'] = function()
local M = {}

function M.sleep(n)
    local t0 = os.clock()
    while os.clock() - t0 <= n do end
end

return M

end

package.preload['controllers.device'] = function()
local HamvModel = require 'hamv_model'
--[[--
device-controller
@module device-controller
]]
local DeviceController = {}

function DeviceController.findById(req, res, nxt)
  local sn = req.parameters.sn

  local info = HamvModel.getInfo(sn)

	res:json(info)
	nxt()
end

return DeviceController

end

package.preload['provision_private_token'] = function()
return 'DoNotTryToModifyThisLikeAVariable.MakeThisAEnvironmentVariablePlz'

end

package.preload['action_identifier_secret'] = function()
return 'ThisIsForActionIdentifier.ChangingThisWillCausePhoneWebsocketFailingToGeResponse'

end

package.preload['phone_hooks'] = function()
-- luacheck: globals __debugMsg
-- luacheck: globals getUserByToken getTokenExp
-- luacheck: globals bench
local Bus = require 'event_bus'
local PhoneSession = require 'phone_session'
local HamvModel = require 'hamv_model'
local HamvError = require 'hamv_error'
local R = require 'modules_moses'
local JSON = require 'modules_json'

local PhoneBus = Bus('Phone')

PhoneBus:on('open', function(_)
  __debugMsg('phone connection success.')
end)

PhoneBus:on('close', function(ws)
  __debugMsg('close the connection')
  local sessionData = PhoneSession.getSessionData(ws)

  if sessionData.auth == 1 and sessionData.token and R.isTable(sessionData.user) then

    HamvModel.unsubscribeUserSocket(sessionData.user.id, ws.socket_id)

    -- mimic calling listen action to subscribe to all device permission
    PhoneBus:emit('auth', ws, {request='listen_stop'}, sessionData)
  end

  PhoneSession.sessionDelete(ws)
end)

PhoneBus:on('data', function(ws)

  local message = JSON.parse(ws.message)
  if not R.isTable(message) then
    return
  end

  local sessionData = PhoneSession.getSessionData(ws)

  if not R.isNumber(message.id) or not R.isString(message.request) then
    return PhoneBus:emit('error', ws, HamvError.instance(300), sessionData)
  end

  if sessionData.auth ~= 1 then
    return PhoneBus:emit('noauth', ws, message)
  end

  return PhoneBus:emit('auth', ws, message, sessionData)
end)

PhoneBus:on('noauth', function(ws, message)
  __debugMsg('handlePhoneNoAuthMessage')

  if message.request ~= 'login' then
    return PhoneBus:emit('error', ws, HamvError.instance(300))
  end

  if not message.data or not message.data.token then
    return PhoneBus:emit('error', ws, HamvError.instance(300))
  end

  __debugMsg('handlePhonerequest')

  local user = getUserByToken(message.data.token)

  if user ~= nil and user.error ~= nil then
    return PhoneBus:emit('error', ws, HamvError.instance(100))
  end

  local sessionData = {}
  sessionData.auth = 1
  sessionData.user = user

  sessionData.token_exp = getTokenExp(message.data.token)

  HamvModel.pruneUserSockets(user.id)
  HamvModel.subscribeUserSocket(user.id, ws.socket_id)
  PhoneSession.sessionInit(ws, sessionData)

  local result = {
    id = message.id,
    response = message.request,
    status = 'ok'
  }
  ws.send(result)

  -- mimic calling listen action to subscribe to all device permission
  PhoneBus:emit('auth', ws, {request='listen'}, sessionData)

  __debugMsg(JSON.stringify(result))
end)

PhoneBus:on('auth', function(ws, message, sessionData)
  __debugMsg('handlePhoneAuthMessage')

  if sessionData.token_exp <= os.time() then
    PhoneBus:emit('error', ws, HamvError.instance(100), sessionData)
    ws.close()
    return
  end

  local actions = require 'phone_actions'
  local LockedActions = require 'locked_actions'
  local locker = require 'locker'

  local requestCall = actions[message.request] or actions['__NOT_IMPLEMENTED__']
  local needUserLock = LockedActions.phoneNeedUserLockActions[message.request] or false
  local needDeviceLock = LockedActions.phoneNeedDeviceLockActions[message.request] or false
  local user = sessionData.user

  local userLock = nil
  local deviceLock = nil
  if needUserLock then
    userLock = locker:new({ key = "user_lock_" .. sessionData.user.id})
    if userLock:acquire_retry() == false then
      print("{error_code=503,msg=acquire user lock fail in phone auth}")
      return PhoneBus:emit('error', ws, HamvError.instance(503), sessionData)
    end
  end
  if needDeviceLock then
    deviceLock = locker:new({ key = "device_lock_" .. message.device})
    if deviceLock:acquire_retry() == false then
      print("{error_code=503,msg=acquire device lock fail in phone auth}")
      return PhoneBus:emit('error', ws, HamvError.instance(503), sessionData)
    end
  end
  local success, result, time = bench.measure(function()
    local success, result = pcall(requestCall, ws, user, message)
    return success, result
  end)
  if deviceLock then
    deviceLock:release()
  end
  if userLock then
    userLock:release()
  end

  if not success then
    local error = HamvError.instance(300)
    if R.isString(result) then
      local errMsg = string.match(result, '.*:%d+: (.*)')
      if R.isNumber(errMsg) then
        error = HamvError.instance(tonumber(errMsg))
      else
        print(result)
      end
    elseif result.status == 'error' then
      error = result
    end

    return PhoneBus:emit('error', ws, error, sessionData)
  end

  if success and not result then
    print(('Phone Action `%s` from user `%s` finished with bad result (%s). [%s]')
        :format(message.request, user.id, tostring(result), time))
  end

  if success and _G.log_level == 'verbose' then
    print(('Phone Action `%s` from user `%s` finished. [%s]')
        :format(message.request, user.id, time))
  end
end)

PhoneBus:on('error', function(ws, error, _)
  local message = JSON.parse(ws.message) or {}
  error.id = message.id
  error.response = message.request

  ws.send(error)
end)

-- move error_disconnect to enviroment variable
if _G.error_disconnect then
  PhoneBus:on('error', function(ws, _, sessionData)
    if not sessionData or sessionData.auth ~= 1 then
      return ws.close()
    end

    sessionData.error_count = (sessionData.error_count or 0) + 1

    if sessionData.error_count > 3 then
      return ws.close()
    end

    PhoneSession.setSessionData(ws, sessionData)
  end)
end

end

package.preload['controllers.ifttt'] = function()
local D = require 'modules_device'
local L = require 'lodash'
local R = require 'modules_moses'
local Http = require 'http'
local HttpError = require 'http-error'
local Ifttt = require 'ifttt'
local HamvModel = require 'hamv_model'
local InformationModel = require 'information_model'
local TriggerEventsModel = require 'trigger_events_model'
local IftttTriggersModel = require 'ifttt_triggers_model'
local SolutionLogger = require 'solution_logger'
local Solution = require 'modules_solution'

local logger = SolutionLogger:new({functionName = "IftttController"})
local IftttController = {}

function IftttController.getSetupInfo(_, res, nxt)
  res:send(Ifttt.getSetupInfo())
  nxt()
end

function IftttController.getActionsOptions(req, res, nxt)
  local traitAttribute = req.parameters.traitAttribute
  local type = req.parameters.type
  res:send(Ifttt.getActionsOptions(traitAttribute,type))
  nxt()
end

function IftttController.runActions(req, res, nxt)
  local traitAttribute = req.parameters.traitAttribute
  local actionReq = req.body
  if R.isEmpty(actionReq.actionFields) or R.isEmpty(actionReq.actionFields.device) then
    logger:error('Bad Request!')
    nxt(HttpError:new(400,Ifttt.errorMessage("The requisition is Bad.")))
    return
  end
  res:send(Ifttt.runActions(actionReq,traitAttribute))
  nxt()
end

function IftttController.processTrigger(req, res, nxt)
  local limit = tonumber(req.body.limit) or 3
  local deviceSn = req.body.triggerFields.device
  local device = D:new(deviceSn)
  local triggerId = req.body.trigger_identity
  local getModelSuccess, model = pcall(function () return HamvModel.getModel(deviceSn) end)
  if not getModelSuccess then
    logger:error('GetModel Fail!')
    nxt(HttpError:new(500,Ifttt.errorMessage(Http.STATUS_CODES[500])))
  end
  local infromationModels = InformationModel.filterByModel(model, InformationModel.LoadAll())
  --TODO check device in IMS and user has permission
  local statusHistory = HamvModel.getDeviceStatusHistory(device.sn,
    {limit = Solution.__defaultConfig.ifttt_trigger_tsdb_query_limit})
  local matchStatus = R.map(statusHistory, function(_, value)
      local matchedEvents = TriggerEventsModel.getMatchedEvents(value,infromationModels)
      matchedEvents = R.intersection(matchedEvents, {req.parameters.name})
      return #matchedEvents > 0
    end)

  local notRealtimeStatus = R.isEmpty(tonumber(req.headers["x-ifttt-realtime"]))
  if notRealtimeStatus then
    local event = {
      lastMatchedStatus = matchStatus[1],
      name = req.parameters.name,
      type = 'triggerEvent',
    }
    device:addDeviceEvent(triggerId, event)
  end

  local triggerDataPoints = R.filter(statusHistory, function(index, _)
    local current = matchStatus[index]
    local older = matchStatus[index + 1]
    return current == true and older == false
  end)
  local responseData = Ifttt.formatTriggerDataPoints(triggerDataPoints, limit)
  res:send(responseData)
  logger:notice(string.format('TriggerDataPoints UserID:%s', Ifttt.user.id))
  nxt()
end

function IftttController.processTriggerOptions(req, res, nxt)
  local userDevicesWithTriggerEvents = Ifttt.getUserDevicesWithTriggerEvents(req.parameters.name)
  local deviceSnArray = L.castArray(
    R(userDevicesWithTriggerEvents)
      :pluck('sn')
      :flatten(1)
      :value()
    )

  local responseData = Ifttt.formatDeviceNames(deviceSnArray)
  logger:notice(string.format('TriggerOptions UserID:%s', Ifttt.user.id))
  res:send(responseData)
  nxt()
end

function IftttController.checkUser(req, _, nxt)
  local user = _G.currentUser(req)
  if user ~= nil and user.id ~= nil then
    Ifttt.user = user
    nxt()
  else
    logger:error(('InvalidToken Fail. Router:%s Reqs:%s'):format(req.route,to_json(req)))
    nxt(HttpError:new(401,Ifttt.errorMessage("Invalid access token.")))
  end
end

function IftttController.checkTriggerParameter(req, _, nxt)
  if not req.body.triggerFields or not req.body.triggerFields.device then
    logger:error('Invalid TriggerParamete')
    nxt(HttpError:new(400,Ifttt.errorMessage(Http.STATUS_CODES[400])))
  else
    nxt()
  end
end

function IftttController.checkTriggerFieldsParameter(req, _, nxt)
  if not req.parameters.name then
    logger:error('Invalid TriggerFieldsParameter')
    nxt(HttpError:new(400,Ifttt.errorMessage(Http.STATUS_CODES[400])))
  else
    nxt()
  end
end

function IftttController.verify(req, _, nxt)
  if req.headers["ifttt-channel-key"] ~= nil and req.headers["ifttt-service-key"] ~= nil and
  req.headers["ifttt-service-key"] == req.headers["ifttt-channel-key"] then
    local serviceKey = req.headers["ifttt-service-key"]
    local iftttServiceKey = Ifttt.serviceKey
    if serviceKey == iftttServiceKey then
      nxt()
      return
    end
  end
  nxt(HttpError:new(401))
  return
end

function IftttController.removeTrigger(req, res, nxt)
  local triggerId = req.parameters.id

  local sn = IftttTriggersModel.get(triggerId)
  if sn then
    D:new(sn):removeDeviceEvent(sn, triggerId)
    res:status(204)
    nxt()
  else
    nxt(HttpError:new(404))
  end
end

return IftttController

end

package.preload['ifttt'] = function()
local InformationModel = require "information_model"
local UserPermissionModel = require 'user_permission_model'
local UserGroupModel = require 'user_group_model'
local DevicePermissionModel = require 'device_permission_model'
local DevicePropertyModel = require 'device_property_model'
local HamvModel = require 'hamv_model'
local R = require 'modules_moses'
local L = require 'lodash'
local JSON = require 'modules_json'
local Solution = require 'modules_solution'
local TriggerEventsModel = require 'trigger_events_model'
local SolutionLogger = require 'solution_logger'

local logger = SolutionLogger:new({functionName = "Ifttt"})
local Ifttt = {}
Ifttt.serviceKey = Solution.getSolutionConfig("ifttt_service_key", true)
Ifttt.testingAccount = Solution.getSolutionConfig("external_integration_testing_account", true)
Ifttt.testingAccountPassword = Solution.getSolutionConfig("external_integration_testing_account_password", true)
Ifttt.user = {}

local success, result = pcall(
  function()
    return InformationModel:new():loadExternalIntegration():getExternalIntegration()
  end)
if not success then
  _G.__debugMsg('IFTTT:: Error!! InformationModel not fund.')
  logger:error('InformationModel not fund.')
  return
end
Ifttt.externalIntegration = result

local function decodeSNAndModelFromactionReq(deviceId)
  if string.match(deviceId, '.*::.*') == deviceId then
      return {
          ["deviceSn"] = string.match(deviceId, '(.*)::.*'),
          ["deviceModel"] = string.match(deviceId, '.*::(.*)')
      }
  end
end

local function discoverUserDevice(user)
  local list = UserPermissionModel.getDevices(user.id)

  local devicesData = L.castArray()
  if #list ~= 0 and Ifttt.externalIntegration ~= nil then
    for _,deviceSn in pairs(list) do
      local this_Device_EI = Ifttt.externalIntegration:getMapModelByDeviceSn(deviceSn)
      if this_Device_EI then
        if #this_Device_EI:getTraitsIds() ~= 0 then
          for _,_value in pairs(this_Device_EI:getTraitsIds()) do
            local this_Device_EI_trait = this_Device_EI:getTraits(_value)
            local friendlyName = ""
            local deviceProperty = DevicePropertyModel.get(user.id, deviceSn)
            if deviceProperty and deviceProperty.displayName then
              friendlyName = deviceProperty.displayName
            end
            local APPEND_NAME = this_Device_EI_trait:getTraitAppendName()
            if APPEND_NAME ~= nil then
                friendlyName = friendlyName .. APPEND_NAME
            end
            local newData = {
                endpointId = deviceSn .. "::" .. _value,
                friendlyName = friendlyName,
                capabilities = this_Device_EI_trait:getAllTraitAttributes()
            }
            table.insert( devicesData, newData )
          end
        end
      end
    end
  end
  return devicesData
end

function Ifttt.errorMessage(message)
  local error = {
    status = "SKIP",
    message = message
  }
  return { errors = {error}}
end

function Ifttt.getTriggersSetupInfo()
  local triggerRequestSampleData = {}
  local userDevicesWithTriggerEvents = Ifttt.getUserDevicesWithTriggerEvents()
  R(userDevicesWithTriggerEvents)
    :each(function(_, event)
      triggerRequestSampleData[event.eventName] = { device = event.sn }
    end)
  return triggerRequestSampleData
end

function Ifttt.getSetupInfo()
  local ret = User.getUserToken({
    email = Ifttt.testingAccount,
    password = Ifttt.testingAccountPassword,
    time_to_live = 43200
  })

  if ret ~= nil and ret.status == nil then
    local token = ret
    local user = _G.getUserByToken(ret)
    Ifttt.user = user
    local userDevices = discoverUserDevice(user)

    local actions = {}

    R(userDevices)
    :each(function(_, devicesData)
      R(devicesData.capabilities)
        :each(function(traitAttributes, _set)
          if actions[traitAttributes] == nil then
            actions[traitAttributes] = L.castArray({})
          end
          local sampleActions = "on"
          if traitAttributes == "brightness" or traitAttributes == "percentage" then
            math.randomseed(os.time())
            sampleActions = math.random(_set["min"],_set["max"])
          end
          actions[traitAttributes] = {device = devicesData.endpointId ,[traitAttributes] = sampleActions}
        end)
    end)
    local triggers = Ifttt.getTriggersSetupInfo()

    return {data = {
      accessToken = token,
      samples = {
        actions = actions,
        triggers = triggers,
        actionRecordSkipping = {}
        }
      }
    }
  end
end

function Ifttt.getActionsOptions(traitAttribute,type)
  if type == "device" then
    local userDevices = discoverUserDevice(Ifttt.user)
    local data = L.castArray({})
    R(userDevices)
    :each(function(_, devicesData)
      R(devicesData.capabilities)
        :each(function(deviceTraitAttributes, _)
          if traitAttribute == deviceTraitAttributes then
            R.push(data,{label = devicesData.friendlyName,value = devicesData.endpointId})
          end
        end)
    end)

    if traitAttribute == "on_off" then
      local groupData = {
        label = "Groups",
        values= L.castArray({})
      }
      local groups = UserGroupModel.getAllUserGroups(Ifttt.user.id) or {}
      R(groups)
      :each(function(_, groupInfo)
        R.push(groupData.values,{
          label = string.format('%s', groupInfo.properties.displayName or groupInfo.name ),
          value = groupInfo.name .. "::Groups"})
      end)
      if not R.isEmpty(groupData.values) then
        R.push(data,groupData)
      end
    end
    logger:notice(string.format('getActionsOptions OnOff UserID:%s',Ifttt.user.id))
    return { data = data }
  end

  if type == "percentage" or type == "brightness" then
    local data = L.castArray({})
    for i = 0,100,1 do
      R.push(data,{label = tostring(i),value = i})
    end
    logger:notice(string.format('getActionsOptions %s UserID:%s',type,Ifttt.user.id))
    return { data = data }
  end
end

local function sendRequestToDevice(id,deviceSn,code,value)
  HamvModel.sendSetAction(deviceSn, {[code] = value}, "iftttControlToken_"..id)
end

local function changeDeviceOnOff(deviceSn,On_Off,Turn)
  local code = On_Off.key
  local setValue = On_Off.values[Turn]
  sendRequestToDevice(91,deviceSn,code,setValue)
  _G.__debugMsg("IFTTT::changeDeviceOnOff::".. Turn)
  logger:notice(string.format('OnOff UserID:%s DeviceSn:%s',Ifttt.user.id,deviceSn))
end

local function setDevicePercentage(deviceSn,Percentage,setValue)
  local mergedSetValue={}
  if Percentage.before ~= nil and #Percentage.before > 0 then
    R(Percentage.before)
    :each(function(_, setValueBefore)
      mergedSetValue[setValueBefore.key] = setValueBefore.value
    end)
  end
  local valueMin = Percentage.min
  local valueMax = Percentage.max
  if setValue > valueMax then
    setValue = valueMax
  end
  if setValue < valueMin then
    setValue = valueMin
  end
  mergedSetValue[Percentage.key]=setValue
  HamvModel.sendSetAction(deviceSn, mergedSetValue, 'iftttControlToken_'..92)
  _G.__debugMsg("IFTTT::setDevicePercentage::" .. JSON.stringify(mergedSetValue))
  logger:notice(string.format('Percentage UserID:%s DeviceSn:%s',Ifttt.user.id,deviceSn))
end

local function handelActions(deviceSn,trait,traitAttribute,action)
  if traitAttribute == "on_off" then
    changeDeviceOnOff(deviceSn,trait:getTraitAttributes(traitAttribute),action)
  end
  if traitAttribute == "percentage" or traitAttribute == "brightness" then
    -- action variable should be numbers if not the default value is 0
    setDevicePercentage(deviceSn,trait:getTraitAttributes(traitAttribute),tonumber(action) or 0)
  end
  local response = {data = {{id = tostring(os.time())}}}
  logger:notice({message = 'response', payload = response})
  return response
end

local function handelGroupActions(groupName,traitAttribute,action)
  local group = UserGroupModel.get(Ifttt.user.id,groupName) or {}
  if R.isEmpty(group.devices) then
    return Ifttt.errorMessage("The Group is empty.")
  end
  R(group.devices)
  :each(function(_, deviceSn)
    local this_Device_EI = Ifttt.externalIntegration:getMapModelByDeviceSn(deviceSn)
    if not HamvModel.isConnected(deviceSn) then
      return
    end
    local mergedSetValue={}
    R(this_Device_EI:getTraitsIds())
    :each(function(_, traitsId)
      local this_Device_EI_trait = this_Device_EI:getTraits(traitsId)
      local On_Off = this_Device_EI_trait:getTraitAttributes(traitAttribute)
      local code = On_Off.key
      local setValue = On_Off.values[action]
      mergedSetValue[code] = setValue
    end)
    logger:notice(string.format('GroupActions Group:%s UserID:%s',groupName,Ifttt.user.id))
    HamvModel.sendSetAction(deviceSn, mergedSetValue, 'iftttControlToken_'..98)
  end)
  return {data = {{id = tostring(os.time())}}}
end

function Ifttt.runActions(actionReq,traitAttribute)
  local device = actionReq.actionFields.device
  local action = actionReq.actionFields[traitAttribute]
  local data = decodeSNAndModelFromactionReq(device)
  if data == nil then
      return nil
  end

  local deviceSn = data.deviceSn
  local deviceModel = data.deviceModel

  if deviceModel == "Groups" and traitAttribute == "on_off" then
    return handelGroupActions(deviceSn,traitAttribute,action)
  end
  local this_Device_EI = Ifttt.externalIntegration:getMapModelByDeviceSn(deviceSn)
  if not this_Device_EI then
    logger:error('Could not get model of device.')
    return Ifttt.errorMessage("Could not get model of device.")
  end
  local this_Device_EI_trait = this_Device_EI:getTraits(deviceModel)
  if not DevicePermissionModel.checkUserHasAccess(deviceSn, Ifttt.user.id) then
    logger:error('Device Not Found.')
    return Ifttt.errorMessage("Device Not Found.")
  end
  if not HamvModel.isConnected(deviceSn) then
    logger:notice(string.format('The device is unreachable. UserID:%s DeviceSn:%s',Ifttt.user.id,deviceSn))
    return Ifttt.errorMessage("The device is unreachable.")
  end
  return handelActions(deviceSn,this_Device_EI_trait,traitAttribute,action)
end

function Ifttt.getUserDevicesWithTriggerEvents(requestEventName)
  local userDeivces = UserPermissionModel.getDevices(Ifttt.user.id)
  local informationModels = InformationModel.LoadAll()
  local userDevicesWithTriggerEvents = L.castArray()
  R(userDeivces)
    :each(function(_, deviceSn)
      local getModelSuccess, model = pcall(function () return HamvModel.getModel(deviceSn) end)
        if getModelSuccess then
          local deviceInformationModels = InformationModel.filterByModel(model,informationModels)
          local triggerEvents = TriggerEventsModel.getEventsFromInformationModels(deviceInformationModels)
          R(triggerEvents)
            :each(function(_, event)
              if requestEventName == nil or requestEventName == event then
                R.push(userDevicesWithTriggerEvents,{eventName = event, sn = deviceSn})
              end
            end)
        end
    end)

    return userDevicesWithTriggerEvents
end

function Ifttt.formatTriggerDataPoints(dataPoints, limit)
  local formattedData = { data = L.castArray() }
  local pushCounter = 0
  if type(limit) == 'number' and limit >0 then
    R(dataPoints)
      :each(function(_, value)
        if pushCounter < limit then
          R.push(formattedData.data, {
            created_at = Ifttt.convertTimeToDate(value.time),
            meta = {
              id = value.time,
              timestamp = tostring(Ifttt.convertTimeToTimestamp(value.time))
            }
          })
          pushCounter = pushCounter + 1
        end
      end)
  end
  return formattedData
end

function Ifttt.formatDeviceNames(snArray)
  local devicesLabelArray = R(snArray)
    :map(function(_, sn)
      local D = require 'modules_device'
      return {
        label = D:new(sn):getDisplayName(Ifttt.user.id),
        value = sn
      }
    end)
    :compact()
    :unique()
    :value()
  local formattedData = { data = L.castArray({ label = "device", values =  L.castArray(devicesLabelArray)})}
  return formattedData
end

function Ifttt.convertTimeToTimestamp(timeToConvert)
  -- Assuming a date pattern like: yyyy-mm-dd hh:mm:ss.dddddd+00:00
  -- 2018-01-23T17:09:14.880734+00:00
  local pattern = "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)(.*)"
  local runyear, runmonth, runday, runhour, runminute, runseconds = timeToConvert:match(pattern)
  local convertedTimestamp = os.time({
    year = runyear,
    month = runmonth,
    day = runday,
    hour = runhour,
    min = runminute,
    sec = runseconds
  })
  return convertedTimestamp
end

function Ifttt.convertTimeToDate(timeToConvert)
  -- Assuming a date pattern like: yyyy-mm-dd hh:mm:ss.dddddd+00:00
  -- 2018-01-23T17:09:14.880734+00:00
  local pattern = "(%d+)-(%d+)-(%d+)(.*)"
  local runyear, runmonth, runday = timeToConvert:match(pattern)
  return runyear.."-"..runmonth.."-"..runday
end

function Ifttt.realtime(triggerIds)
  if R.isEmpty(triggerIds) then
    return true
  else
    return Http.post({
      url = 'https://realtime.ifttt.com/v1/notifications',
      headers = {
        ['Accept'] = 'application/json',
        ['Accept-Charset'] = 'utf-8',
        ['Accept-Encoding'] = 'gzip, deflate',
        ['Content-Type'] = 'application/json',
        ['IFTTT-Service-Key'] = Ifttt.serviceKey,
        ['X-Request-ID'] = tostring(os.time()),
      },
      body = to_json({
        data = R.map(triggerIds, function(_, triggerId)
          return {
            trigger_identity = triggerId,
          }
        end),
      }),
    })
    .status_code == 200
  end
end

return Ifttt

end

package.preload['trigger_events_model'] = function()
local InformationModel = require 'information_model'
local L = require 'lodash'
local R = require 'modules_moses'

local TriggerEventsModel = {}

function TriggerEventsModel.getMatchedEvents(states, infoModels)
  return L.castArray(
    R(infoModels)
      :pluck('eventCollections')
      :flatten(1)
      :select(function(_, event)
        return InformationModel.checkCondition(event.conditions, states)
      end)
      :pluck('name')
      :value()
  )
end

function TriggerEventsModel.getEventsFromInformationModels(infoModels)
  return L.castArray(
    R(infoModels)
      :pluck('eventCollections')
      :flatten(1)
      :pluck('name')
      :value()
  )
end

return TriggerEventsModel

end

package.preload['admin_hooks'] = function()
local Bus = require 'event_bus'
local DevicePermissionModel = require 'device_permission_model'
local HamvModel = require 'hamv_model'
local HamvUniqueModel = require 'hamv_unique_model'
local L = require 'lodash'
local R = require 'modules_moses'

local DevicePermissionBus = Bus('DevicePermission')

DevicePermissionBus:on('change', function(sn)
  local guests = L.castArray(R(DevicePermissionModel.getDeviceGuests(sn, true))
    :map(function(_, userId)
      return User.getUser({id = userId}).email
    end)
    :compact()
    :value()
  )

  HamvUniqueModel.setGuestEmails(HamvModel.getDeviceId(sn), guests)
end)

end

package.preload['template_model'] = function()
local TemplateModel = {}

--TODO move template.lua into here
function TemplateModel.updateTemplateWithSolutionConfig(template)
  template = template:gsubnil("{{company_name}}",getSolutionConfig("company_name"))
  template = template:gsubnil("{{company_url}}",getSolutionConfig("company_url"))
  template = template:gsubnil("{{company_address}}",getSolutionConfig("company_address"))
  template = template:gsubnil("{{company_contact}}",getSolutionConfig("company_contact"))
  template = template:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  template = template:gsubnil("{{product_name}}",getSolutionConfig("product_name"))
  return template
end

function TemplateModel.updateTemplateWithDomain(template, domain)
  return template:gsubnil("{{domain}}",domain)
end

function TemplateModel.getTermOfServicesDefaultTitle()
  return [[Terms & Conditions and Privacy Policy]]
end
function TemplateModel.getTermOfServicesDefaultBody(domain)
  local termOfServiceDefaultBody = [[THIS {{company_name}} USER ONLINE SERVICES AGREEMENT (“AGREEMENT”) GOVERNS YOUR USE OF OUR {{company_name}} ONLINE SERVICES (“SERVICES”).
  BY ACCEPTING THIS AGREEMENT, BY CREATING AN ACCOUNT USING OUR SERVICE, YOU AGREE TO THIS AGREEMENT. IF YOU ARE ENTERING INTO THIS AGREEMENT ON BEHALF OF A COMPANY OR OTHER LEGAL ENTITY, YOU REPRESENT THAT YOU HAVE THE AUTHORITY TO BIND SUCH ENTITY AND ITS AFFILIATES TO THIS AGREEMENT, IN WHICH CASE THE TERMS "YOU" OR "YOUR" SHALL REFER TO SUCH ENTITY AND ITS AFFILIATES. IF YOU DO NOT HAVE SUCH AUTHORITY, OR IF YOU DO NOT AGREE WITH THIS AGREEMENT, YOU MUST NOT ACCEPT THIS AGREEMENT AND MAY NOT USE THE SERVICES.
  You may not access the Services if You are Our direct competitor, except with Our prior written consent. In addition, You may not access the Services for purposes of monitoring its availability, performance or functionality, or for any other benchmarking or competitive purposes.
  This Agreement is effective between You and Us as of the date of Your acceptance of this Agreement.
  OUR PROPRIETARY RIGHTS
  Subject to the limited rights expressly granted hereunder, We reserve all rights, title and interest in and to the Services, including all related intellectual property rights subsisting therein. We grant no rights to You hereunder other than as expressly set forth herein.
  CONFIDENTIALITY
  Definition of Confidential Information. As used herein, " Confidential Information" means all confidential information disclosed by a party ("Disclosing Party") to the other party (" Receiving Party"), whether orally or in writing, that is designated as confidential or that reasonably should be understood to be confidential given the nature of the information and the circumstances of disclosure. Your Confidential Information shall include Your Data; Our Confidential Information shall include the Services; and Confidential Information of each party shall include the terms and conditions of this Agreement, as well as business and marketing plans, technology and technical information, product plans and designs, and business processes disclosed by such party. However, Confidential Information (other than Your Data) shall not include any information that (i) is or becomes generally known to the public without breach of any obligation owed to the Disclosing Party, (ii) was known to the Receiving Party prior to its disclosure by the Disclosing Party without breach of any obligation owed to the Disclosing Party, (iii) is received from a third party without breach of any obligation owed to the Disclosing Party, or (iv) was independently developed by the Receiving Party.
  Protection of Confidential Information. Except as otherwise permitted in writing by the Disclosing Party, (i) the Receiving Party shall use the same degree of care that it uses to protect the confidentiality of its own confidential information of like kind (but in no event less than reasonable care) not to disclose or use any Confidential Information of the Disclosing Party for any purpose outside the scope of this Agreement, and (ii) the Receiving Party shall limit access to Confidential Information of the Disclosing Party to those of its employees, contractors and agents who need such access for purposes consistent with this Agreement and who have signed confidentiality agreements with the Receiving Party containing protections no less stringent than those herein.
  Compelled Disclosure. The Receiving Party may disclose Confidential Information of the Disclosing Party if it is compelled by law to do so, provided the Receiving Party gives the Disclosing Party prior notice of such compelled disclosure (to the extent legally permitted) and reasonable assistance, at the Disclosing Party's cost, if the Disclosing Party wishes to contest the disclosure. If the Receiving Party is compelled by law to disclose the Disclosing Party’s Confidential Information as part of a civil proceeding to which the Disclosing Party is a party, and the Disclosing Party is not contesting the disclosure, the Disclosing Party will reimburse the Receiving Party for its reasonable cost of compiling and providing secure access to such Confidential Information.
  YOUR RESPONSIBILITIES
  You shall not (i) permit any third party to access the Services except as permitted herein, (ii) create derivative works based on the Services, (iii) copy, frame or mirror any part or content of the Services, other than copying or framing on Your own intranets or otherwise for Your own internal business purposes, (iv) reverse engineer the Services, (v) access the Services in order to build a competitive product or service or to copy any features, functions or graphics of the Services, (vi) sell, resell, rent or lease the Services, (vii) use the Services to store or transmit infringing, libelous, or otherwise unlawful or tortuous material, or to store or transmit material in violation of third-party privacy rights, (viii) use the Services to store or transmit malicious code or malware, or to engage in phishing or other fraudulent activity, (ix) interfere with or disrupt the integrity or performance of the Services or third-party data contained therein, or (x) attempt to gain unauthorized access to the Services or Our systems or Our data or networks.
  You shall (i) be responsible for Your compliance with this Agreement, (ii) be solely responsible for the accuracy, quality, integrity and legality of, and for the means by which You acquired, Your Data and Your Portal Resources, (iii) use commercially reasonable efforts to prevent unauthorized access to or use of the Services, and notify Us promptly of any such unauthorized access or use, (iv) use the Services only in accordance with applicable laws and government regulations, and (v) provide Us with complete and accurate contact information.
  WHAT WE LICENSE TO YOU
  We grant you a worldwide license during the term of this Agreement to use the Services to collect and view Your Data. Free Services are limited to personal, non-commercial use. We reserve the right to charge (or change our pricing) for all Services, including but not limited to monthly subscriptions to the Services, upon 30 days’ notice from us. Such notice may be provided at any time by an update to your application or via email or via the Services themselves.
  WHAT YOU LICENSE TO US
  You grant us a worldwide license to use, reproduce, transmit, display and adapt Your Data and Your Portal Resources solely as necessary for Us to provide the Services in accordance with this Agreement.
  You grant us a royalty-free, worldwide, transferable, sublicenseable, irrevocable, perpetual license to use or incorporate into our services any suggestions, enhancement requests, recommendations or other feedback provided by You relating to the operation of the Services.
  RELATIONSHIP TO THE PARTIES.
  You and We are independent contractors, and nothing in this Agreement will create any partnership, joint venture, agency, franchise, sales representative, or employment relationship between the parties. You are in no way authorized to make any license, contract, agreement, warranty or representation on behalf of Us, or to create any obligations expressed or inspired on behalf of Us except to the extent and for the purposes expressly provided for and set forth herein.
  EXCLUSION OF WARRANTIES
  WE MAKE NO WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, STATUTORY OR OTHERWISE, AND WE SPECIFICALLY DISCLAIM ALL IMPLIED WARRANTIES, INCLUDING ANY WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW. WITHOUT LIMITING THE GENERALITY OF THE FOREGOING, WE DO NOT REPRESENT OR WARRANT THAT YOUR USE OF THE SERVICES WILL MEET YOUR REQUIREMENTS OR THAT YOUR USE OF THE SERVICES WILL BE UNINTERRUPTED, TIMELY, SECURE OR FREE FROM ERROR. YOU will indemnify, defend and hold harmless US, and the underlying SERVICE PROVIDER, from and against any and all claims, damages and expenses (including reasonable attorneys' fees and costs of litigation) by any third party resulting from any acts or omissions of YOURS relating to its activities in connection with this Agreement, YOUR breach of this Agreement, or YOUR misrepresentations relating to US, the Services, or this Agreement, regardless of the form of action.
  LIMITATION OF LIABILITY
  IN NO EVENT SHALL WE HAVE ANY LIABILITY TO YOU FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL, CONSEQUENTIAL, COVER OR PUNITIVE DAMAGES, HOWEVER CAUSED, WHETHER IN CONTRACT, TORT OR UNDER ANY OTHER THEORY OF LIABILITY, AND WHETHER OR NOT YOU HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. WITHOUT LIMITING THE FOREGOING, WE SHALL HAVE NO LIABILITY FOR LOSS OF PROFITS, REVENUE OR DATA OR FOR INTERRUPTIONS IN SERVICE. THE FOREGOING DISCLAIMER SHALL NOT APPLY TO THE EXTENT PROHIBITED BY APPLICABLE LAW.
  TERM AND TERMINATION
  This Agreement commences on the date You accept it and continues until terminated by either party in accordance with this Agreement.
  You are solely responsible for properly cancelling your account. You may terminate Your subscription to the Services without cause at any time by logging in and clicking the Account link in the navigation bar at the top of the screen and following the cancellation links. An email or phone request to cancel your account is not considered cancellation.
  We may terminate Your subscription to the Services at any time without cause upon 7 days’ written notice to You, or (b) automatically if you fail to comply with any term or condition of this Agreement. Upon any termination of Your subscription to the Services, this Agreement shall also terminate, subject to the Surviving Provisions.
  UPON ANY TERMINATION OF YOUR SUBSCRIPTION TO THE SERVICES, YOUR INFORMATION, AND OTHER MATERIALS DEVELOPED BY YOU USING THE SERVICES WILL BE PERMANENTLY LOST.
  Surviving Provisions. The following sections shall survive any termination or expiration of this agreement: Our Proprietary Rights, Exclusion of Warranties, Limitation of Liability, and General Provisions.
  CHANGE TO TERMS
  We reserve the right at any time and from time to time to modify or discontinue, temporarily or permanently, the Service (or any part thereof) with or without notice.
  We may make changes to this Agreement from time to time. When these changes are made, We will make a new copy of the new Terms available at https://{{company_name}}.apps.exosite.io/#/legal. You understand and agree that if you use the Services after the date on which this Agreement has changed, We will treat Your use as acceptance of the updated Terms.
  GENERAL PROVISIONS
  Entire Agreement. This Agreement constitutes the entire agreement between the parties and supersedes all prior and contemporaneous agreements, proposals or representations, written or oral, concerning its subject matter.
  Governing Law. This Agreement, and any disputes arising out of or related hereto, shall be governed exclusively by the internal laws of the {{company_address}}, without regard to their conflicts of laws rules.
  Venue; Waiver of Jury Trial. The state and federal courts located in {{company_address}} shall have exclusive jurisdiction to adjudicate any dispute arising out of or relating to this Agreement.  Each party hereby consents to the exclusive jurisdiction of such courts.  Each party hereby waives any right to jury trial in connection with any action or litigation in any way arising out of or related to this Agreement.
  Export Compliance. Each party shall comply with the export laws and regulations of the United States and other applicable jurisdictions in providing and using the Services.
  Assignment. You may not assign any of the rights or obligations give You hereunder, whether by operation of law or otherwise, without the prior written consent of Us (not to be unreasonably withheld).
  DEFINITIONS
  "Affiliate" means any entity which directly or indirectly controls, is controlled by, or is under common control with the subject entity. "Control," for purposes of this definition, means direct or indirect ownership or control of more than 50% of the voting interests of the subject entity.
  "{{company_name}} Online Services" means the online services provided by Us as described in this Agreement that You access through {{domain}} and related sub-domains.
  "We", " Us" or " Our" means {{company_name}} with a principal place of business at {{company_address}}.
  "You" or "Your" means 1) the company or other legal entity for which you are accepting this Agreement, and Affiliates of that company or entity, or 2) an individual , in the case of a non-legal entity as defined in the registration information provided to Us.
  “Your Application Resources” means a web application and related configuration parameters that We, You, or a third party acting on Your behalf, create and that interoperates with the Services.
  "Your Data" means all electronic data or information submitted by You, or by devices owned by You, to the Services.

  PRIVACY POLICY
  {{company_name}} operates the {{app_name}} for the {{product_name}} as well as the resources required for the solution, which provides the SERVICE.
  This page is used to inform application users regarding our policies with the collection, use, and disclosure of Personal Information if anyone decided to use our Service.
  If you choose to use our Service, then you agree to the collection and use of information in relation with this policy. The Personal Information that we collect are used for providing and improving the Service. We will not use or share your information with anyone except as described in this Privacy Policy.
  The terms used in this Privacy Policy have the same meanings as in our Terms and Conditions, which is accessible at https://{{domain}}/#/legal, unless otherwise defined in this Privacy Policy.
  Information Collection and Use
  For a better experience while using our Service, we may require you to provide us with certain personally identifiable information, including but not limited to your name, phone number, and postal address. The information that we collect will be used to contact or identify you.
  Log Data
  We want to inform you that whenever you visit our Service, we collect information that your browser sends to us that is called Log Data. This Log Data may include information such as your computer’s Internet Protocol (“IP”) address, browser version, pages of our Service that you visit, the time and date of your visit, the time spent on those pages, and other statistics.
  Cookies
  Cookies are files with small amount of data that is commonly used an anonymous unique identifier. These are sent to your browser from the website/application that you visit and are stored on your computer’s hard drive.
  Our website/application uses these “cookies” to collection information and to improve our Service. You have the option to either accept or refuse these cookies, and know when a cookie is being sent to your computer. If you choose to refuse our cookies, you may not be able to use some portions of our Service.
  Service Providers
  We may employ third-party companies and individuals due to the following reasons:
  To facilitate our Service;
  To provide the Service on our behalf;
  To perform Service-related services; or
  To assist us in analyzing how our Service is used.
  We want to inform our Service users that these third parties have access to your Personal Information. The reason is to perform the tasks assigned to them on our behalf. However, they are obligated not to disclose or use the information for any other purpose.
  Security
  We value your trust in providing us your Personal Information, thus we are striving to use commercially acceptable means of protecting it. But remember that no method of transmission over the internet, or method of electronic storage is 100% secure and reliable, and we cannot guarantee its absolute security.
  Links to Other Sites
  Our Service may contain links to other sites. If you click on a third-party link, you will be directed to that site. Note that these external sites are not operated by us. Therefore, we strongly advise you to review the Privacy Policy of these websites. We have no control over, and assume no responsibility for the content, privacy policies, or practices of any third-party sites or services.
  Changes to This Privacy Policy
  We may update our Privacy Policy from time to time. Thus, we advise you to review this page periodically for any changes. We will notify you of any changes by posting the new Privacy Policy on this page. These changes are effective immediately, after they are posted on this page.
  Contact Us
  If you have any questions or suggestions about our Privacy Policy, do not hesitate to contact us at {{customer_support_email}}.
  ]]

  termOfServiceDefaultBody = TemplateModel.updateTemplateWithSolutionConfig(termOfServiceDefaultBody)
  return TemplateModel.updateTemplateWithDomain(termOfServiceDefaultBody, domain)
end

return TemplateModel

end

package.preload['locked_actions'] = function()
local locked_actions = {
  phoneNeedUserLockActions = {
    ['add_user'] = true,
    ['add_user_verify'] = true,
    ['rem_user'] = true,
    ['del_device'] = true,
    ['set_group'] = true,
    ['del_group'] = true,
    ['set_properties'] = true,
    ['del_properties'] = true,
    ['set_user_data'] = true,
    ['del_user_data'] = true,
    ['__NOT_LOCKED__'] = false
  },
  phoneNeedDeviceLockActions = {
    ['add_user'] = true,
    ['rem_user'] = true,
    ['del_device'] = true,
    ['__NOT_LOCKED__'] = false
  }
}
return locked_actions

end

package.preload['sha256'] = function()
--
--  Adaptation of the Secure Hashing Algorithm (SHA-244/256)
--  Found Here: http://lua-users.org/wiki/SecureHashAlgorithm
--
--  Using an adapted version of the bit library
--  Found Here: https://bitbucket.org/Boolsheet/bslf/src/1ee664885805/bit.lua
--

local MOD = 2^32
local MODM = MOD-1

local sha256 = {}

local function memoize(f)
	local mt = {}
	local t = setmetatable({}, mt)
	function mt.__index(_, k)
		local v = f(k)
		t[k] = v
		return v
	end
	return t
end

local function make_bitop_uncached(t, m)
	local function bitop(a, b)
		local res,p = 0,1
		while a ~= 0 and b ~= 0 do
			local am, bm = a % m, b % m
			res = res + t[am][bm] * p
			a = (a - am) / m
			b = (b - bm) / m
			p = p*m
		end
		res = res + (a + b) * p
		return res
	end
	return bitop
end

local function make_bitop(t)
	local op1 = make_bitop_uncached(t,2^1)
	local op2 = memoize(function(a) return memoize(function(b) return op1(a, b) end) end)
	return make_bitop_uncached(op2, 2 ^ (t.n or 1))
end

local bxor1 = make_bitop({[0] = {[0] = 0,[1] = 1}, [1] = {[0] = 1, [1] = 0}, n = 4})

local function bxor(a, b, c, ...)
	local z
	if b then
		a = a % MOD
		b = b % MOD
		z = bxor1(a, b)
    if c then
      z = bxor(z, c, ...)
    end
		return z
  elseif a then
    return a % MOD
  else
    return 0
  end
end

local function band(a, b, c, ...)
	local z
	if b then
		a = a % MOD
		b = b % MOD
		z = ((a + b) - bxor1(a,b)) / 2
		if c then z = band(z, c, ...) end
		return z
	elseif a then return a % MOD
	else return MODM end
end

local function bnot(x) return (-1 - x) % MOD end

local lshift, rshift, rshift1, rrotate

lshift = function (a, disp)
  if disp < 0 then return rshift(a,-disp) end
  return (a * 2 ^ disp) % 2 ^ 32
end

rshift = function(x, disp)
	if disp > 31 or disp < -31 then return 0 end
	return rshift1(x % MOD, disp)
end

rshift1 = function(a, disp)
	if disp < 0 then return lshift(a,-disp) end
	return math.floor(a % 2 ^ 32 / 2 ^ disp)
end

rrotate = function(x, disp)
    x = x % MOD
    disp = disp % 32
    local low = band(x, 2 ^ disp - 1)
    return rshift(x, disp) + lshift(low, 32 - disp)
end

local k = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function str2hexa(s)
	return (string.gsub(s, '.', function(c) return string.format('%02x', string.byte(c)) end))
end

local function num2s(l, n)
	local s = ''
	for _ = 1, n do
		local rem = l % 256
		s = string.char(rem) .. s
		l = (l - rem) / 256
	end
	return s
end

local function s232num(s, i)
	local n = 0
	for j = i, i + 3 do n = n*256 + string.byte(s, j) end
	return n
end

local function preproc(msg, len)
	local extra = 64 - ((len + 9) % 64)
	len = num2s(8 * len, 8)
	msg = msg .. '\128' .. string.rep('\0', extra) .. len
	-- assert(#msg % 64 == 0)
	return msg
end

local function initH256(H)
	H[1] = 0x6a09e667
	H[2] = 0xbb67ae85
	H[3] = 0x3c6ef372
	H[4] = 0xa54ff53a
	H[5] = 0x510e527f
	H[6] = 0x9b05688c
	H[7] = 0x1f83d9ab
	H[8] = 0x5be0cd19
	return H
end

local function digestblock(msg, i, H)
	local w = {}
	for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
	for j = 17, 64 do
		local v = w[j - 15]
		local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
		v = w[j - 2]
		w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
	end

	local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
	for j = 1, 64 do
		local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
		local maj = bxor(band(a, b), band(a, c), band(b, c))
		local t2 = s0 + maj
		local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
		local ch = bxor (band(e, f), band(bnot(e), g))
		local t1 = h + s1 + ch + k[j] + w[j]
		h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
	end

	H[1] = band(H[1] + a)
	H[2] = band(H[2] + b)
	H[3] = band(H[3] + c)
	H[4] = band(H[4] + d)
	H[5] = band(H[5] + e)
	H[6] = band(H[6] + f)
	H[7] = band(H[7] + g)
	H[8] = band(H[8] + h)
end

function sha256.sha256(msg)
	msg = preproc(msg, #msg)
	local H = initH256({})
	for i = 1, #msg, 64 do digestblock(msg, i, H) end
	return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) ..
		num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
end

local function hex_to_binary(hex)
  return hex:gsub('..', function(hexval)
    return string.char(tonumber(hexval, 16))
  end)
end

local BLOCK_SIZE = 64

local char = string.char

local xor_with_0x5c = {}
local xor_with_0x36 = {}
for i=0,0xff do
  xor_with_0x5c[char(i)] = char(bxor(i,0x5c))
  xor_with_0x36[char(i)] = char(bxor(i,0x36))
end

function sha256.binary(msg)
  return hex_to_binary(sha256.sha256(msg))
end

function sha256.hmac(key, text)
  assert(type(key)  == 'string', 'key passed to sha256.hmac should be a string')
  assert(type(text) == 'string', 'text passed to sha256.hmac should be a string')

  if #key > BLOCK_SIZE then
    key = sha256.binary(key)
  end

  local key_xord_with_0x36 = key:gsub('.', xor_with_0x36) .. string.rep(char(0x36), BLOCK_SIZE - #key)
  local key_xord_with_0x5c = key:gsub('.', xor_with_0x5c) .. string.rep(char(0x5c), BLOCK_SIZE - #key)

  return sha256.sha256(key_xord_with_0x5c .. sha256.binary(key_xord_with_0x36 .. text))
end

function sha256.hmac_binary(key, text)
  return hex_to_binary(sha256.hmac(key, text))
end

setmetatable(sha256, {__call = function(_,msg)
	return sha256.sha256(msg)
end })

return sha256

end

package.preload['user_object'] = function()
local KV = require "modules_kv"
local R = require "modules_moses"
local JSON = require "modules_json"
local Object = require "modules_object"
local UserGroupModel = require "user_group_model"
local UserPermissionModel = require "user_permission_model"
local kv_list = require 'kv_list'

local UserObject = Object:extend()
UserObject.Datakey = "User_Data"
UserObject.KVkey = "User_"
UserObject.PTkey = "ProvisionToken"

local function getUserFromKV(id)
    local key = UserObject.KVkey .. tostring(id)
    return KV.get(key)
end

local function setUserKV(id,value)
    local key = UserObject.KVkey .. tostring(id)
    return KV.set(key,value)
end

local function findById(id)
    assert(R.isInteger(id))
    local inforamtion = {
      KV = getUserFromKV(id),
      info = User.getUser({id = id}),
      id = id
    }
    local user = UserObject:new(inforamtion)
    return user
end
local function generatingPT(ttl)
    math.randomseed(os.time())
    local key = ""
    for i = 1, 32 do
        local __temp = math.random(1,10)
        if __temp > 5 then
            key = key .. string.char(math.random(48 ,57))
        else
            key = key .. string.char(math.random(65 ,90))
        end
    end
    local expires_in = os.time() + ttl
    return {token = key, expires_in = expires_in}
end
function UserObject:initialize(information)
    if information.KV ~= nil then
        self.KV = information.KV
    else
        self.KV = {}
    end
    if information.info ~= nil then
        self.info = information.info
    end
    if information.id ~= nil then
        self.id = information.id
    end
    if information.error ~= nil then
        self.error = information.error
    end
    self.userDataKv = kv_list:new(UserObject.Datakey)
end

function UserObject:getError()
    return self.error
end

function UserObject:getInfo()
    return self.info
end
function UserObject:getWS()
    local userWsKv = kv_list:new("User_ws_" .. self.id)
    return userWsKv.getKeysList()
end

local function createUser(email,name,password)
    local ret = User.createUser({
        email = email,
        name = name,
        password = password
    })
    if ret.status ~= nil then
        local error = from_json(ret.error)
        UserObject.status = ret.status
        UserObject.error = error
        return nil
    end

    local text = getWelcomeEmailTemplate("https://" .. domain .. "welcome",email,domain)
    local product_name = getSolutionConfig("product_name") or ""
    local ret2 = User.activateUser({code = ret})
    local guest = User.listUsers({filter = "email::like::" .. email})
    if #guest == 1 and guest[1].id ~= nil then
        setUserKV(guest[1].id,{})
        return UserObject.findById(guest[1].id)
    end
end

local function login(email,password)
    local ret = User.getUserToken({
        email = email,
        password = password,
        time_to_live = 43200
    })
    if ret.status ~= nil then
        local error = from_json(ret.error)
        UserObject.status = ret.status
        UserObject.error = error
        return nil
    end
    UserObject.token = ret
    return ret
end

local function removeUser(userId)
  UserGroupModel.drop(userId)

  UserPermissionModel.drop(userId)

  Keystore.delete({
    key = 'User_' .. userId,
  })

  return User.deleteUser({
    id = userId,
  })
end

UserObject.findById = findById
UserObject.createUser = createUser
UserObject.login = login
UserObject.removeUser = removeUser

return UserObject

end

package.preload['initial-handler'] = function()
--[[--
initial-handler
@module initial-handler
]]
local function initialHandler(req, res, nxt)
	function req:get(key)
		return self.headers[key:lower()]
	end

	function res:json(msg)
		return self:set('content-type', 'application/json'):send(msg)
	end

	function res:send(msg)
		self.message = msg
		return self
	end

	function res:set(key, val)
		self.headers = self.headers or {}
		self.headers[key] = val
		return self
	end

	function res:status(code)
		self.code = code
		return self
	end

	req.headers = req.headers or {}
	req.ip = req:get('x-forwarded-for') or req.server_ip
	res:status(200):send('')
	nxt()
end

return initialHandler

end

package.preload['controllers.device_log'] = function()
local HamvModel = require 'hamv_model'
local HttpError = require 'http-error'
local KeystoreLogger = require 'keystore_logger'
local DeviceLogController = {}

function DeviceLogController.isAdmin(req, _, nxt)
  if not _G.isAdmin(_G.currentUser(req)) then
    nxt(HttpError:new(403))
  else
    nxt()
  end
end

function DeviceLogController.genKeystoreLoggerName(sn)
  return 'device_' .. HamvModel.getDeviceId(sn)
end

function DeviceLogController.queryLogs(req, res, nxt)
  local name = DeviceLogController.genKeystoreLoggerName(req.parameters.sn)
  local option = {
    page = req.parameters.offset,
    querySize = req.parameters.querysize,
  }
  res:send(KeystoreLogger.get(name, option))
  nxt()
end

function DeviceLogController.addLog(sn, data)
  local name = DeviceLogController.genKeystoreLoggerName(sn)
  return KeystoreLogger.log(name, data)
end

function DeviceLogController.deleteLogs(req, res, nxt)
  local name = DeviceLogController.genKeystoreLoggerName(req.parameters.sn)
  res:send(KeystoreLogger.destroy(name))
  nxt()
end

return DeviceLogController

end

package.preload['event_bus'] = function()
local Emitter = require 'events'
local R = require 'modules_moses'

local emitters = {}

local instance
instance = function(namespace)
  namespace = namespace or ''
  if not emitters[namespace] then
    local newEmitter = Emitter:new()
    if namespace ~= '' then
      newEmitter.emit = R.wrap(newEmitter.emit, function(emit, self, eventName, ...)
        emit(self, eventName, ...)
        local globalEmitter = instance()
        globalEmitter:emit(namespace..':'..eventName, ...)
      end)
    end
    emitters[namespace] = newEmitter
  end
  return emitters[namespace]
end

return instance

end

package.preload['device_model_info'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'
local DeviceModelInfo = {}

function DeviceModelInfo.genStoreKey()
  return 'deviceModelInfo'
end

function DeviceModelInfo.getModelFields(model)
  return from_json(KV.hget(DeviceModelInfo.genStoreKey(), model))
end

function DeviceModelInfo.isFieldRange(fields)
  return R.include(fields, function(field)
    return R.isTable(field)
  end)
end

function DeviceModelInfo.fieldRangeToFields(fields)
  return R(fields)
    :map(function(_, field)
      return R.isTable(field) and R.keys(field) or field
    end)
    :flatten()
    :union()
    :value()
end

function DeviceModelInfo.setModelFields(model, fields)
  return KV.hset(DeviceModelInfo.genStoreKey(), model, to_json(fields))
end

return DeviceModelInfo

end

package.preload['modules_object'] = function()
--[[--
object
@module object
]]
local Object = {}

Object.meta = { __index = Object }

function Object.instanceof(obj, class)
	if type(obj) ~= 'table' or obj.meta == nil or not class then
		return false
	end
	if obj.meta.__index == class then
		return true
	end
	local meta = obj.meta
	while meta do
		if meta.super == class then
			return true
		elseif meta.super == nil then
			return false
		end
		meta = meta.super.meta
	end
	return false
end

function Object:create()
	local meta = rawget(self, 'meta')
	if not meta then
		error('Cannot inherit from instance object')
	end
	return setmetatable({}, meta)
end

function Object:extend()
	local obj = self:create()
	local meta = {}
	for k, v in pairs(self.meta) do
		meta[k] = v
	end
	meta.__index = obj
	meta.super = self
	obj.meta = meta
	return obj
end

function Object:new(...)
	local obj = self:create()
	if type(obj.initialize) == 'function' then
		obj:initialize(...)
	end
	return obj
end

return Object

end

package.preload['hamv_hooks'] = function()
-- luacheck: globals getUser
local Provision = require 'provision'
local HamvModel = require 'hamv_model'
local HamvUniqueModel = require 'hamv_unique_model'
local UserPermissionModel = require 'user_permission_model'
local DevicePermissionModel = require 'device_permission_model'
local DevicePropertyModel = require 'device_property_model'
local DeviceModelInfo = require 'device_model_info'
local D = require 'modules_device'
local R = require 'modules_moses'
local Bus = require 'event_bus'
local JSON = require 'modules_json'
local TsdbLogger = require 'modules_logger'
local DeviceLogController = require 'controllers.device_log'
local SolutionLogger = require 'solution_logger'

local logger = SolutionLogger:new({functionName = "hamv_hook"})
local HAMVBus = Bus('HAMV')
local DeviceIftttEventBus = Bus('DeviceIftttEvent')

HAMVBus:on('connect', function(event)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvUniqueModel.setConnect(HamvModel.getDeviceId(sn))

  HamvModel.publishDeviceChangeEvent(sn, {
    connected = 1
  })

  HamvModel.pruneListeners(sn)

end)

HAMVBus:on('disconnect', function(event)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvUniqueModel.setDisconnect(HamvModel.getDeviceId(sn))

  HamvModel.publishDeviceChangeEvent(sn, {
    connected = 0
  })
end)

HAMVBus:on('provisioned', function(event)
  local sn = event.identity

  HamvModel.init(sn)
  logger:notice(string.format('provisioned device SN:%s',sn))
end)

-- generate events for each of resources reported in the latest datapoints
HAMVBus:on('data_in', function(event)
	local map = {}

  local row = R.unshift(event.payload)

  local rawDataList = {'token', 'action', 'debug'}
  local logDataList = {'token', 'esh', 'module', 'ota'}
  R.each(row.values, function(alias, value)
    if R.include(rawDataList, alias) then
      map[alias] = value
    elseif alias == 'owner' then
      map[alias] = tonumber(value)
    else
      local parsed, error = JSON.parse(value)
      if error then
        print(string.format('device %s send a malformed value on alias `%s`.\n#####\n%s\n#####',
            event.identity, alias, value))
      end
      map[alias] = parsed
    end

    if R.include(logDataList, alias) then
      logger:notice({message = string.format('data_in:%s sn:%s', alias, event.identity), payload = map[alias]})
    end
  end)

  R.each(map, function(alias, datapoints)
    HAMVBus:emit('data_in:' .. alias, event, datapoints)
  end)

end)

-- Skeleton - comment off to use it
-- HAMVBus:on('data_in:action', function(event, dp)
--   print(JSON.stringify({event, dp}))
-- end)

HAMVBus:on('data_in:result', function(event, result)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  if result.response == 'debug' then
    local deviceId = HamvModel.getDeviceId(sn)
    local payload = HamvModel.decodeActionResult(result)
    if payload.opt.mode == 0 then
      HamvUniqueModel.disableDebugMode(deviceId)
    end
    if payload.opt.mode == 1 then
      HamvUniqueModel.enableDebugMode(deviceId)
    end
  else
    HamvModel.responseByActionResult(result)
  end
end)

HAMVBus:on('data_in:esh', function(event)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvUniqueModel.setModel(HamvModel.getDeviceId(sn), HamvModel.getModel(sn))

  local deviceInfo = HamvModel.getInfo(sn)

  HamvModel.publishDeviceChangeEvent(sn, {
    profile = deviceInfo.profile
  })

  -- HamvModel.addInfoHisotry(sn, deviceInfo)
end)

HAMVBus:on('data_in:module', function(event)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvUniqueModel.setFirmwareVersion(HamvModel.getDeviceId(sn), HamvModel.getFirmwareVersion(sn))

  local deviceInfo = HamvModel.getInfo(sn)

  HamvModel.publishDeviceChangeEvent(sn, {
    profile = deviceInfo.profile
  })

  -- HamvModel.addInfoHisotry(sn, deviceInfo)
end)

-- HAMVBus:on('data_in:cert', function(event)
--   local sn = event.identity

--   if not HamvModel.isProvisioned(sn) then
--     return
--   end

--   local deviceInfo = HamvModel.getInfo(sn)
--   -- HamvModel.addInfoHisotry(sn, deviceInfo)
-- end)

HAMVBus:on('data_in:ota', function(event, ota)
  local sn = event.identity

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvModel.publishDeviceChangeEvent(sn, {
    device_state = ota.state
  })

  -- HamvModel.addInfoHisotry(sn, deviceInfo)
end)

-- Skeleton - comment off to use it
HAMVBus:on('data_in:fields', function(event, fields)
  local sn = event.identity
  if DeviceModelInfo.isFieldRange(fields) then
    local model = HamvModel.getModel(sn)
    DeviceModelInfo.setModelFields(model, fields)
    fields = DeviceModelInfo.fieldRangeToFields(fields)
  end
  return HamvModel.setFields(sn, fields)
end)

-- Skeleton - comment off to use it
-- HAMVBus:on('data_in:schedules', function(event, dp)
--   print(JSON.stringify({event, dp}))
-- end)

-- Skeleton - comment off to use it
HAMVBus:on('data_in:states', function(event, states)
  local sn = event.identity
  local ip = event.ip or "unknown"

  if not HamvModel.isProvisioned(sn) then
    return
  end

  HamvModel.publishDeviceChangeEvent(sn, {
    status = states
  })

  local lastStates = HamvModel.getDeviceStatus(sn)
  local changedStates = R.toObj(
    R.difference(
      R.kvpairs(states),
      R.kvpairs(lastStates)
    )
  )

  local res = HamvModel.addStatusHisotry(sn, states)

  if not res then
    logger:error(string.format('Write device states to TSDB having error:%s',sn))
  end

  R.each(changedStates, function(key, value)
    local logType = 'event'
    local action = {
      key = key,
      label = 'Status changed',
      value = value,
    }
    local msg = TsdbLogger.parseMessage(sn, key, value)
    if msg then
      logType = msg.type
      action.content = msg.text
    end
    if logType == 'error' then
      action.label = 'Code'
    end
    TsdbLogger.log(logType, sn, action, {field = key}, ip)
  end)

  DeviceIftttEventBus:emit('data_in:states', sn, states)
end)

HAMVBus:on('data_in:token', function(event, token)
  local sn = event.identity
  local ip = event.ip or "unknown"

  if HamvModel.isProvisioned(sn) then
    local deviceInfo = HamvModel.getInfo(sn)
    HamvModel.setProvisioned(sn, deviceInfo.owner)
    return print(('%s device attempt recovery on provisioning'):format(sn))
  end

  if not HamvModel.isReadyToProvision(sn) or not HamvModel.validateSn(sn) then
    HamvModel.removeGatewayProfile(sn)
    return print(('%s device not inited properly to provision'):format(sn))
  end

  local userId = Provision.getUserIdFromProvisionToken(token)

  local user = getUser(userId)
  if not user then
    return print(('%s device failed to pair, user not found'):format(sn))
  end

  -- TODO priority here need to be discussed
  if not UserPermissionModel.addOwnDevice(user.id, sn)
      or not DevicePermissionModel.addDeviceOwner(sn, user.id) then
    return print(('%s device failed to pair'):format(sn))
  end
  print(('%s device paired with user (%s)'):format(sn, user.id))

  HamvModel.setProvisioned(sn, user.id)

  -- compatible to restructure
  HamvModel.sendAction(sn, 'provisioned')

  local oldSn = HamvUniqueModel.getState(HamvModel.getDeviceId(sn), 'sn')
  if oldSn then
    D:new(oldSn):delete()
  end
  HamvUniqueModel.add(HamvModel.getDeviceId(sn), {
    connected = true,
    firmware_version = HamvModel.getFirmwareVersion(sn),
    model = HamvModel.getModel(sn),
    owner_email = user.email,
    sn = sn,
  })

  HamvModel.subscribeDeviceEvent(sn, unpack(HamvModel.listUserSockets(user.id)))

  HamvModel.notifyUser(user.id, 'add_device', {
    ['device'] = sn,
    ['owner'] = user.email
  })

  DevicePropertyModel.set(user.id, sn, {
    displayName = HamvModel.getDeviceId(sn),
  })

  TsdbLogger.log('event', user.email,
    {
      email = user.email,
      label = 'Device provisioned',
    },
    {
      device_sn = sn,
      action = 'provision',
    },
    ip
  )

  -- local deviceInfo = HamvModel.getInfo(sn)
  -- HamvModel.addInfoHisotry(sn, deviceInfo)
end)

HAMVBus:on('data_in:debug', function(event, debugContent)
  DeviceLogController.addLog(event.identity, debugContent)
end)

end

package.preload['device_gateway'] = function()
local DeviceGateway = {}

function DeviceGateway.get(name)
  return _G[name:lower():gsub('^%l',string.upper)]
end

return DeviceGateway

end

package.preload['information_googlehome'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'
local JSON = require 'modules_json'
local HamvModel = require 'hamv_model'
local DevicePermissionModel = require 'device_permission_model'

local informationGoogleHome = {}
informationGoogleHome.meta = { __index = Object }
informationGoogleHome.KVkey = 'im'
informationGoogleHome.imData = {}

local function checkBefore(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) == 0 then
        __debugMsg("informationGoogleHome.checkBefore fail 1" .. type(Obj) .. table.map_length(Obj))
        return false
    end
    for k,v in pairs(Obj) do
        if v.key == nil or type(v.key) ~= 'string' or v.key == "" or v.value == nil or v.value == "" then
            __debugMsg("informationGoogleHome.checkBefore ".. k .." fail 2::" .. to_json(v))
            return false
        end
    end
    return true
end

local function checkDescription(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 1 then
        __debugMsg("informationGoogleHome.checkDescription fail 1")
        return false
    end
    if Obj.value == nil and type(Obj.value) ~= 'string' then
        __debugMsg("informationGoogleHome.checkDescription fail 2")
        return false
    end
    return true
end

local function checkAppendname(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 1 then
        __debugMsg("informationGoogleHome.checkAppendname fail 1")
        return false
    end
    if Obj.value == nil and type(Obj.value) ~= 'string' then
        __debugMsg("informationGoogleHome.checkAppendname fail 2")
        return false
    end
    return true
end

local function checkBrightness(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 2 then
        __debugMsg("informationGoogleHome.checkBrightness fail 1")
        return false
    end
    if Obj.key == nil or Obj.values == nil or type(Obj.values) ~= 'table' then
        __debugMsg("informationGoogleHome.checkBrightness fail 2")
        return false
    end
    local values = Obj.values
    if values.min == nil or values.min == "" or values.max == nil or values.max == "" then
        __debugMsg("informationGoogleHome.checkBrightness ON fail 3")
        return false
    end

    --- check if is set before
    if Obj.before ~= nil and checkBefore(Obj.before) == false then
        __debugMsg("informationGoogleHome.checkBrightness fail 4")
        return false
    end
    return true
end

local function checkType(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) < 1 then
        __debugMsg("informationGoogleHome.checkType fail 1")
        return false
    end
    if Obj.value == nil and type(Obj.value) ~= 'string' then
        __debugMsg("informationGoogleHome.checkType fail 2")
        return false
    end
    if Obj.value ~= "OUTLET" and Obj.value ~= "LIGHT" then
        __debugMsg("informationGoogleHome.checkType fail 3")
        return false
    end
    return true
end

local function checkOnOff(Obj)
    if type(Obj) ~= 'table' or table.map_length(Obj) ~= 2 then
        __debugMsg("informationGoogleHome.checkOnOff fail OnOff1")
        return false
    end
    if Obj.On == nil or Obj.Off == nil then
        __debugMsg("informationGoogleHome.checkOnOff fail OnOff1")
        return false
    end
    local on = Obj.On
    if on.key == nil or type(on.key) ~= 'string' or on.key == "" or on.value == nil or on.value == "" then
        __debugMsg("informationGoogleHome.checkOnOff ON fail 1")
        return false
    end
    local off = Obj.Off
    if off.key == nil or type(off.key) ~= 'string' or off.key == "" or off.value == nil or off.value == "" then
        __debugMsg("informationGoogleHome.checkOnOff OFF fail 2::" .. to_json(off))
        return false
    end
    return true
end

local function checkMapDefined(mapObj,mapItems)
    if type(mapObj) ~= 'table' or table.map_length(mapObj) == 0 then
        __debugMsg("informationGoogleHome.checkMapDefined fail1")
        return false
    end
    -- must have TYPE
    if type(mapObj["TYPE"]) ~= 'table' or table.map_length(mapObj["TYPE"]) == 0 then
        __debugMsg("informationGoogleHome.checkMapDefined fail2")
        return false
    end
    -- must have OnOff
    if type(mapObj["OnOff"]) ~= 'table' or table.map_length(mapObj["OnOff"]) == 0 then
        __debugMsg("informationGoogleHome.checkMapDefined fail3")
        return false
    end

    local appendName = nil

    for k,v in pairs(mapObj) do
        if k == 'OnOff' and checkOnOff(v) == false then
            __debugMsg("informationGoogleHome.checkMapDefined fail OnOff ::" .. to_json(v))
            return false
        elseif k == 'TYPE' and checkType(v) == false then
            __debugMsg("informationGoogleHome.checkMapDefined fail TYPE::" .. to_json(v))
            return false
        elseif k == 'Brightness' and checkBrightness(v) == false then
            __debugMsg("informationGoogleHome.checkMapDefined fail Brightness::" .. to_json(v))
            return false
        elseif k == 'APPEND_NAME' then
            appendName = checkAppendname(v)
            if appendName == false then
                __debugMsg("informationGoogleHome.checkMapDefined fail APPEND_NAME::" .. to_json(v))
                return false
            end
        end
    end

    -- must have TYPE
    if mapObj["TYPE"].value == "LIGHT" and mapObj["Brightness"] == nil then
        __debugMsg("informationGoogleHome.checkMapDefined fail type Light need Brightness")
        return false
    end

    if mapItems > 1 and appendName == nil then
        __debugMsg("informationGoogleHome.checkMapDefined fail can't find any APPEND_NAME")
        return false
    end
    return true
end

function informationGoogleHome.verify(jsonObject)
    if jsonObject.externalIntegration.googlehome == nil or type(jsonObject.externalIntegration.googlehome) ~= 'table' or table.map_length(jsonObject.externalIntegration.googlehome) == 0 then
        return false
    end
    local googlehome = jsonObject.externalIntegration.googlehome
    -- __debugMsg("informationGoogleHome.verify")
    local mapItems = table.map_length(googlehome)
    for k,v in pairs(googlehome) do
        -- __debugMsg("informationGoogleHome.checkMapDefined::" .. k)
        if checkMapDefined(v,mapItems) == false then
            -- __debugMsg("informationGoogleHome.checkMapDefined fail::" .. k)
            return false
        end
    end
    return true
end

function informationGoogleHome.loadAllModel(imData)
    if imData == nil or table.map_length(imData) < 1 then
        return false
    end
    local ret = {}
    -- __debugMsg("informationGoogleHome.loadAllModel::imData::" .. to_json(imData))
    for k,v in pairs(imData) do
        if v.externalIntegration.googlehome ~= nil and informationGoogleHome.verify(v) == false then
            -- __debugMsg("informationGoogleHome.loadAllModel::fail::" .. k)
            return false
        elseif v.externalIntegration.googlehome ~= nil then
            table.insert(ret, v)
        end
    end
    if table.map_length(ret) < 1 then
        return false
    end
    informationGoogleHome.imData = ret
    return true
end

local function getMapModel(DeviceModel)
    for key,value in pairs(informationGoogleHome.imData) do
        for key2,value2 in pairs(value.familyMembers) do
            if string.match(DeviceModel, value2) ~= nil then
                return key
            end
        end
    end
end

local function sendRequestToDevice(id,deviceSn,code,value)
  HamvModel.sendSetAction(deviceSn, {[code] = value})
end
local function sendRequestToDeviceBefore(deviceSn,before)
    local id = 99
    for key,value in pairs(before) do
        sendRequestToDevice(id,deviceSn, value.key, value.value)
        id = id + 1
    end
end

local function getDeviceLatestCodeValue(deviceSn,code)
    local status = HamvModel.getInfo(deviceSn).status
    return status[code] or 0
end

local function getDiscoverDevice(deviceModel,mapModel,deviceSn,googlehomeDeviceName)
    local data = informationGoogleHome.imData[mapModel].externalIntegration.googlehome
    -- __debugMsg("informationGoogleHome.getDiscoverDevice::" .. to_json(data))
    local ret = L.castArray()
    for key, value in pairs(data) do
        local traits = L.castArray()
        if value.TYPE.value == "OUTLET" then
            R.push(traits, "action.devices.traits.OnOff")
        end
        if value.TYPE.value == "LIGHT" then
            R.push(traits, "action.devices.traits.OnOff","action.devices.traits.Brightness")
        end

        local id = deviceSn .. "::" .. key
        local name = googlehomeDeviceName
        if value.APPEND_NAME ~= nil and value.APPEND_NAME.value ~= nil then
            name = name .. value.APPEND_NAME.value
        end
        local device = HamvModel.getInfo(deviceSn)
        local data = {
            ["id"] = id,
            ["traits"] = traits,
            ["type"] = "action.devices.types." .. value.TYPE.value,
            ["name"] = { name = name },
            ["willReportState"] = false,
            ["deviceInfo"]= {
                manufacturer = device.profile.esh.brand,
                model = deviceModel,
                hwVersion = device.profile.esh.esh_version
            }
        }
        R.push(ret, data)
    end
    return ret
end

function informationGoogleHome.getDeviceSNandModel(applianceId)
    if string.match(applianceId, '.*::.*') == applianceId then
        return {
            ["deviceSn"] = string.match(applianceId, '(.*)::.*'),
            ["deviceModel"] = string.match(applianceId, '.*::(.*)')
        }
    end
end

function informationGoogleHome.TurnOnOffRequest(deviceModel,deviceSn,userID,OnOff)
    -- __debugMsg("informationGoogleHome.TurnOnOffRequest")
    local ret = {}
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    if not HamvModel.getInfo(deviceSn).connected then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end

    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    local mapModel = getMapModel(model)
    -- __debugMsg("informationGoogleHome.TurnOnOffRequest::mapModel::" .. to_json(mapModel))
    local data = informationGoogleHome.imData[mapModel].externalIntegration.googlehome
    if data[deviceModel].OnOff == nil then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end
    local code = data[deviceModel].OnOff[OnOff].key
    local setValue = data[deviceModel].OnOff[OnOff].value
    sendRequestToDevice(91,deviceSn,code,setValue)
    -- __debugMsg("informationGoogleHome.TurnOnOffRequest::sendRequestToDevice")
    if OnOff == "On" then
        ret["states"] ={
            on = true,
            online = true
        }
    else
        ret["states"] ={
            on = false,
            online = true
        }
    end
    ret["status"]= "SUCCESS"
    __debugMsg("informationGoogleHome.TurnOnOffRequest::message::" .. to_json(ret))
    return ret
end

function informationGoogleHome.getDeviceStatus(deviceModel,deviceSn,userID)
    --  __debugMsg("informationGoogleHome.getDeviceStatus")
    local ret = {}
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    local mapModel = getMapModel(model)
    local data = informationGoogleHome.imData[mapModel].externalIntegration.googlehome
    if data[deviceModel].OnOff == nil then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end
    __debugMsg("informationGoogleHome.getDeviceStatus::online")
    local code = data[deviceModel].OnOff["On"].key
    if not HamvModel.getInfo(deviceSn).connected then
        ret["online"] = false
        code = data[deviceModel].OnOff["Off"].key
    else
        ret["online"] = true
    end
    -- __debugMsg("informationGoogleHome.getDeviceStatus::onoffValue")
    if tonumber(getDeviceLatestCodeValue(deviceSn,code)) ~= 0 then
        ret["on"] = true
    else
        ret["on"] = false
    end
    -- __debugMsg("informationGoogleHome.getDeviceStatus::LIGHT")
    if data[deviceModel].TYPE.value == "LIGHT" then
        ret["brightness"] = tonumber(getDeviceLatestCodeValue(deviceSn,data[deviceModel].Brightness.key)) or 0
    end
    __debugMsg("informationGoogleHome.getDeviceStatus::ret")
    return ret
end

function informationGoogleHome.BrightnessAbsolute(deviceModel,deviceSn,userID,targetValue)
    local ret = {}
    if DevicePermissionModel.checkUserHasAccess(deviceSn, userID) then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceNotFound"
        return ret
    end
    if not HamvModel.getInfo(deviceSn).connected then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end

    local model = HamvModel.getInfo(deviceSn).profile.esh.model
    local mapModel = getMapModel(model)
    local data = informationGoogleHome.imData[mapModel].externalIntegration.googlehome
    if data[deviceModel].Brightness == nil then
        ret["status"] = "ERROR"
        ret["errorCode"] = "deviceTurnedOff"
        return ret
    end

    local setValue = targetValue
    local code = data[deviceModel].Brightness.key
    local valueMin = data[deviceModel].Brightness.values.min
    local valueMax = data[deviceModel].Brightness.values.max
    if setValue < valueMin or setValue > valueMax then
        ret["status"] = "ERROR"
        ret["errorCode"] = "valueOutOfRange"
        return ret
    end
    if data[deviceModel].Brightness.before ~= nil and #data[deviceModel].Brightness.before > 0 then
        sendRequestToDeviceBefore(deviceSn,data[deviceModel].Brightness.before)
    end
    -- __debugMsg("informationGoogleHome.SetPercentageRequest::sendRequestToDevice")
    sendRequestToDevice(92,deviceSn,code,setValue)
    ret["states"] ={
        on = true,
        online = true
    }
    ret["status"]= "SUCCESS"
    __debugMsg("informationGoogleHome.SetPercentageRequest::message::" .. to_json(ret))
    return ret
end

function informationGoogleHome.discoverDevice(userID)
    local list  = getUserDevicelist(userID)
    if #list == 0 then
        return false
    end
    local ret = L.castArray()
    if #list > 0 then
        for key,value in pairs(list) do
            -- __debugMsg("informationGoogleHome.discoverDevice::device::".. to_json(value) )
            local deviceSn = value.device
            local model = HamvModel.getInfo(deviceSn).profile.esh.model
            if model ~= nil then
                local mapModel = getMapModel(model)
                __debugMsg("informationGoogleHome.discoverDevice::device::".. deviceSn .. "::" .. model .. "::" .. to_json(mapModel))
                if mapModel ~= nil then
                    local data = getDiscoverDevice(model,mapModel,deviceSn,"")
                    __debugMsg("informationGoogleHome.getDiscoverDevice::data::" .. to_json(data))
                    for key2,value2 in pairs(data) do
                        R.push(ret, value2)
                    end
                end
            end
        end
        if #ret > 0 then
            return ret
        end
    end
    return false
end

return informationGoogleHome

end

package.preload['jwt'] = function()
local base64 = require 'base64'
local sha256 = require 'sha256'
local JSON = require 'modules_json'

local alg_sign = {
	['HS256'] = function(data, key) return sha256.hmac(key, data) end
}

local alg_verify = {
	['HS256'] = function(data, signature, key) return signature == alg_sign['HS256'](data, key) end
}

local function b64_encode(input)
	local result = base64.encode(input)

	result = result:gsub('+','-'):gsub('/','_'):gsub('=','')

	return result
end

local function b64_decode(input)
  local reminder = #input % 4

	if reminder > 0 then
		local padlen = 4 - reminder
		input = input .. string.rep('=', padlen)
	end

	input = input:gsub('-','+'):gsub('_','/')

	return base64.decode(input)
end

local function tokenize(str, div, len)
	local result, pos = {}, 0

	for st, sp in function() return str:find(div, pos, true) end do

		result[#result + 1] = str:sub(pos, st-1)
		pos = sp + 1

		len = len - 1

		if len <= 1 then
			break
		end
	end

	result[#result + 1] = str:sub(pos)

	return result
end

local M = {}

function M.encode(data, key, alg)
	if type(data) ~= 'table' then return nil, 'Argument #1 must be table' end
	if type(key) ~= 'string' then return nil, 'Argument #2 must be string' end

	alg = alg or 'HS256'

	if not alg_sign[alg] then
		return nil, 'Algorithm not supported'
	end

	local header = {
    typ = 'JWT',
    alg = alg
  }

	local segments = {
		b64_encode(JSON.stringify(header)),
		b64_encode(JSON.stringify(data))
	}

	local signing_input = table.concat(segments, '.')

	local signature = alg_sign[alg](signing_input, key)

	segments[#segments+1] = b64_encode(signature)

	return table.concat(segments, '.')
end

function M.decode(data, key, verify, alg)
	if key and verify == nil then verify = true end
	if type(data) ~= 'string' then return nil, 'Argument #1 must be string' end
	if verify and type(key) ~= 'string' then return nil, 'Argument #2 must be string' end

	local token = tokenize(data, '.', 3)

	if #token ~= 3 then
		return nil, 'Invalid token'
	end

	local headerb64, bodyb64, sigb64 = token[1], token[2], token[3]

	local ok, header, body, sig = pcall(function ()
		return JSON.parse(b64_decode(headerb64)),
			JSON.parse(b64_decode(bodyb64)),
			b64_decode(sigb64)
	end)

	if not ok then
		return nil, 'Invalid json'
	end

	if verify then
		if not header.typ or header.typ ~= 'JWT' then
			return nil, 'Invalid typ'
		end

		if not header.alg or type(header.alg) ~= 'string' then
			return nil, 'Invalid alg'
		end

		if body.exp and type(body.exp) ~= 'number' then
			return nil, 'exp must be number'
		end

		if body.nbf and type(body.nbf) ~= 'number' then
			return nil, 'nbf must be number'
		end

		if not alg_verify[alg or header.alg] then
			return nil, 'Algorithm not supported'
		end

		if not alg_verify[header.alg](headerb64 .. '.' .. bodyb64, sig, key) then
			return nil, 'Invalid signature'
		end

		if body.exp and os.time() >= body.exp then
			return nil, 'Not acceptable by exp'
		end

		if body.nbf and os.time() < body.nbf then
			return nil, 'Not acceptable by nbf'
		end
	end

	return body
end

return M

end

package.preload['controllers.user'] = function()
local UserO = require 'user_object'
local HttpError = require 'http-error'
local D = require 'modules_device'
local HamvChannel = require 'hamv_channel'
local R = require 'modules_moses'
local HamvModel = require 'hamv_model'
local UserPermissionModel = require 'user_permission_model'

local UserController = {}

function UserController.getProvisionToken(req, res, nxt)
  local user = UserO.findById(tonumber(req.parameters.id))
  local ttl = tonumber(req.parameters.ttl) or 30

  res:json(user:createProvisionToken(ttl*60))
	nxt()
end

function UserController.requestUserData(req, res, nxt)
  local user = req.user
  local solution = Config.solution()
  local emailSubject = string.format('GDPR Data Request - %d ',user.id)
  local emailBody = string.format([[
  solutionId: %s
  domain name: %s
  userId: %s
  userEmail: %s
  ]], solution.id,solution.domain,user.id,user.email)
  res:json({
	  emailSubject = emailSubject,
	  emailBody = emailBody,
  })
  nxt()
end

function UserController.deleteUser(req, res, nxt)
  local userId = req.parameters.id
  if not req.admin and req.parameters.id ~= "me" then
    return nxt(HttpError:new(403))
  end

  if not req.admin or req.parameters.id == "me" then
    userId = req.user.id
  end

  if _G.getUser(userId) == nil then
    return nxt(HttpError:new(400))
  end
  userId = tonumber(userId)
  HamvModel.notifyUser(userId, 'user_removed', nil)

  local kernel = require "kernel"
  -- work around sleep 2sec avoid notifyUser can't send.
  kernel.sleep(2)

  R.each(
    UserPermissionModel.getOwnDevices(userId),
    function (_, sn)
      D:new(sn):delete()
    end
  )

  R(HamvChannel.list(userId))
    :each(function(_, socketId)
      Websocket.close({
        socket_id = socketId,
      })
    end)

  HamvChannel.drop(userId)
  res:send(UserO.removeUser(userId))
  nxt()
end

function UserController.validateUser(req, _, nxt)
  local user = _G.currentUser(req)
  if user == nil then
    return nxt(HttpError:new(401,"No token received"))
  end
  if user ~= nil and user.error ~= nil then
    local errors = from_json(user.error)
    if errors.status_code == 400 or errors.status_code == 401 or errors.status_code == 403 then
      return nxt(HttpError:new(403,"User token invalid"))
    else
      return nxt(HttpError:new(404,"User not found"))
    end
  end
  req.user = user
  if _G.isAdmin(user) then
    req.admin = true
  end
  nxt()
end

function UserController.rejectNotAdminUser(req, _, nxt)
  if not req.admin then
    nxt(HttpError:new(403))
  else
    nxt()
  end
end

return UserController

end

package.preload['controllers.service'] = function()
local ServiceController = {}

function ServiceController.initResponseMessage(_, res, nxt)
  res.message = {}
  nxt()
end

function ServiceController.checkBulknotifyService(_, res, nxt)
  local result = Bulknotify.listResults()
  if result.error then
    res.code = result.status
  end
  res.message['Bulknotify.listResults'] = result
  nxt()
end

function ServiceController.checkHttpService(_, res, nxt)
  local result = Http.get({url = 'https://www.google.com'})
  if result.error then
    res.code = result.status
  end
  res.message['Http.get'] = result
  nxt()
end

return ServiceController

end

package.preload['error'] = function()
--[[--
error
@module error
]]
local Object = require 'modules_object'

local Error = Object:extend()

function Error.meta.__tostring(err)
	return err.message
end

function Error:initialize(msg)
	self.message = msg
end

return Error

end

package.preload['ifttt_triggers_model'] = function()
local KV = require 'modules_kv'
local R = require 'modules_moses'

local IftttTriggersModel = {}

function IftttTriggersModel.genStoreKey()
  return 'ifttt_triggers'
end

function IftttTriggersModel.setnx(triggerId, sn)
  return KV.hsetnx(
    IftttTriggersModel.genStoreKey(),
    triggerId,
    sn
  ) == 1
end

function IftttTriggersModel.get(triggerId)
  return KV.hget(
    IftttTriggersModel.genStoreKey(),
    triggerId
  )
end

function IftttTriggersModel.del(triggerId)
  return R.isNumber(
    KV.hdel(
      IftttTriggersModel.genStoreKey(),
      triggerId
    )
  )
end

return IftttTriggersModel

end

--[[
This file should be the script to run at the begining of app to bootstrap application
--]]

local Monitor = require 'monitor'
Monitor.listen({errorDetail = true, trace = true})
local args = true

require 'phone_hooks'
require 'hamv_hooks'
require 'admin_hooks'
require 'device_ifttt_hooks'
local JSON = require 'modules_json'
local R = require 'modules_moses'

local Bus = require 'event_bus'

local function logDumpReport()
  local dumps = Monitor.dump()
  local dumpReport = R(dumps)
    :map(function(_, record)
      if args then
        return ('%s(%s) %s'):format(record.fn, JSON.stringify(record.args[1]), record.elapsed)
      else
        return ('%s() %s'):format(record.fn, record.elapsed)
      end
    end)
    :join('\n')
    :value()
  if #dumpReport > 0 then
    print(dumpReport)
  end
end

local DevicePermissionModel = require 'device_permission_model'
local DevicePermissionBus = Bus('DevicePermission')
R({'add', 'remove'})
  :each(function(_, method)
    DevicePermissionModel[method] = R.wrap(DevicePermissionModel[method], function(f, ...)
       local success = f(...)
       if success then DevicePermissionBus:emit('change', ...) end
       return success
    end)
  end)

Bus():on('HAMV:data_in', logDumpReport)
Bus():on('Phone:data', logDumpReport)

START_TIME = '2018-01-01T00:00:00+00:00'

-- luacheck: globals Keystore User

function _G.getUserByToken(token)
  local user = User.getCurrentUser({token = token})
  if user ~= nil and user.id ~= nil then
    user.token = token
    return user
  end
  return user
end

-- get current logged in user from webservice request
-- returns user table or nil if no user is contained
-- in headers
function _G.currentUser(request)
  return _G.currentUserFromHeaders(request.headers)
end

-- determine the current user from the session information
-- stored in webservice or websocket request headers.
-- returns user table or nil if no user is contained
-- in headers
function _G.currentUserFromHeaders(headers)
  if type(headers.authorization) == 'string' then
    local _, _, sid = string.find(headers.authorization, 'Bearer (.+)')
    if type(sid) == 'string' then
      return _G.getUserByToken(sid)
    end
  end
  if type(headers.cookie) == 'string' then
    local _, _, sid = string.find(headers.cookie, 'sid=([^;]+)')
    if type(sid) == 'string' then
      return _G.getUserByToken(sid)
    end
  end
end

function _G.createpassword(x)
  math.randomseed(os.time())
	local pwd = {}
	for _ = 1, x do
		pwd[#pwd+1] = string.char(math.random(33,126))
	end
	return table.concat(pwd)
end

function _G.getTokenExp(token)
  local JWT = require 'jwt'
  local token_info = JWT.decode(token)
  if token_info ~= nil then
    return token_info.exp
  else
    return (os.time()-10)
  end
end

function _G.getResetPasswordCodeInf(code)
  local result = Keystore.command({
    key = 'resetPassword',
    command = 'hget',
    args = {code}
  })
  if result.value == nil then
    return nil
  end
  local resultUser = from_json(result.value)
  local overTime = os.time() - 86400
  local ret = User.getUser({id = resultUser['id']})
  if ret.error ~= nil or (resultUser['resetTime'] ~= nil and resultUser['resetTime'] < overTime) then
    Keystore.command({
      key = 'resetPassword',
      command = 'hdel',
      args = {code}
    })
    return nil
  else
    return resultUser
  end
end

function _G.getResetPasswordToken(token)
  local resp = Keystore.get({key = 'reset_token::' .. token})
  if type(resp) == 'table' and type(resp.value) == 'string' then
    return from_json(resp.value)
  end
  return nil
end

function _G.removeResetPasswordTokenAndCode(code, token)
  Keystore.command({
    key = 'resetPassword',
    command = 'hdel',
    args = {code}
  })
  Keystore.delete({key = 'reset_token::' .. token})
  return
end

-- USM doesn't consume '_', '-' ...
function _G.pruneInvalidCharForUSM(str)
  return str:gsub('%p', '')
end

function _G.__solutionDebugOn()
  local Solution = require 'modules_solution'
  return Solution.setSolutionConfig("debug", true)
end

function _G.__solutionDebugOff()
  local Solution = require 'modules_solution'
  return Solution.setSolutionConfig("debug", false)
end

function _G.__setSolution(data)
  local Solution = require 'modules_solution'
  return Solution.setSolutionConfig(data.key, data.value)
end

function _G.__getSolution(data)
  local Solution = require 'modules_solution'
  return Solution.getSolutionConfig(data.key)
end

function _G.getSolutionConfig(key)
  local Solution = require 'modules_solution'
  return Solution.getSolutionConfig(key)
end

-- add string new gsubnil allow give a nil without an error
function _G.string.gsubnil(self, s1, s2)
  return self:gsub(s1, s2 or "")
end

http_error_codes = {
  [400] = {
    code = 400,
    message = "Bad Request",
    headers = {}
  },
  [403] = {
    code = 403,
    message = "Permission Denied",
    headers = {}
  },
  [404] = {
    code = 404,
    message = "Not Found",
    headers = {}
  }
}

function http_error(code, response)
  if http_error_codes[code] ~= nil then
    for key, value in pairs(http_error_codes[code]) do
      response[key] = value
    end
  else
    response.code = code
    response.message = "No prepared message for this code"
  end
end

function trigger(alert, timerid)
  Timer.sendAfter({
    message = alert.message,
    duration = alert.timer * 60 * 1000,
    timer_id = timerid
  })
  alert.timer_running = true
  alert.timer_id = timerid
end

function cancel_trigger(alert)
  Timer.cancel({timer_id = alert.timer_id})
  alert.timer_running = false
end

-- set the code data
function setCodeData(code,data)
  local result = Keystore.command({
    key = "codeData",
    command = "hset",
    args = {code,to_json(data)}
  })
  return result
end
-- get the code data
function getCodeData(code)
  local result = Keystore.command({
    key = "codeData",
    command = "hget",
    args = {code}
  })
  if result.value == nil then
    return nil
  end
  return from_json(result.value)
end
-- delete the code data
function deleteCodeData(code)
  local result = Keystore.command({
    key = "codeData",
    command = "hdel",
    args = {code}
  })
  return result
end

function checkIsMobile(userAgent)
  if userAgent:find("Android") ~= nil then
    return true
  elseif userAgent:find("iPhone") then
    return true
  elseif userAgent:find("iPad") then
    return true
  else
    return false
  end
end

-- luacheck: globals User Keystore Websocket
-- luacheck: globals sendMsgToDebugConsole __debugMsg debug_cmd
-- luacheck: globals addToDebugConsole removeFromDebugConsole

function debug_cmd(cmd)
  if cmd == "clean" then
    for _, user in pairs(User.listUsers()) do
        User.deleteUser({id = user.id})
    end
    return User.listUsers()
  end
  if cmd == "activate" then
    for _, user in pairs(User.listUsers()) do
        if user.status == 0 then
          User.updateUser({id = user.id, status = 1})
        end
    end
    return User.listUsers()
  end

  local _, _, module, fun, args = string.find(cmd, "([%a]+)%.([%a]+)%((.*)%)")

  if module == nil then
    _, _, fun, args = string.find(cmd, "([%a_]+)%((.*)%)")
  end

  if fun ~= nil then
    if args == nil or args == "" then
      args = {}
    else
      args = from_json(args)
    end

    if module == nil then
      return _G[fun](args)
    else
      return _G[module][fun](args)
    end
  end
  return [[Unknown command. Try:
  User.listUsers()
  ]]
end

function addToDebugConsole(wsInfo)
  local result = Keystore.command({
    key = "debugConsole",
    command = "hset",
    args = {wsInfo.socket_id, wsInfo.socket_id}
  })
  return result
end

function removeFromDebugConsole(socket_id)
  local result = Keystore.command({
    key = "debugConsole",
    command = "hdel",
    args = {socket_id}
  })
  return result
end

function sendMsgToDebugConsole(msg)
  local result = Keystore.command({
    key = "debugConsole",
    command = "hkeys"
  })
  if result.value == nil then
    return false
  end
  local list = result.value
  if list ~= nil then
    for _, socket_id in pairs(list) do
      local ret = Websocket.send({socket_id = socket_id, message = msg})
      if ret.error ~= nil then
        removeFromDebugConsole(socket_id)
      end
    end
  end
end

function __debugMsg(message)
  if not _G.debug then
    return
  end

  local ws = _G.ws

  if not ws then
    return sendMsgToDebugConsole(message)
  end

  local PhoneSession = require 'phone_session'
  local sessionData = PhoneSession.getSessionData(ws)
  if not sessionData then
    sendMsgToDebugConsole(ws.socket_id .. "::" .. message)
  end

  -- app
  local executionTime = os.clock() - _G.time_start
  if sessionData.user then
    return sendMsgToDebugConsole(
      ('%s::%s::%s::%s'):format(
        tostring(sessionData.user.email),
        string.sub(ws.socket_id,-12),
        string.format("%.6f",executionTime),
        tostring(message)
      )
    )
  end

  if sessionData.device then
    if sessionData.device.id then
      return sendMsgToDebugConsole(
        ('%s::%s::%s::%s'):format(
          tostring(sessionData.device.id),
          string.sub(ws.socket_id,-12),
          string.format("%.6f",executionTime),
          tostring(message)
        )
      )
    end

    return sendMsgToDebugConsole(
      ('%s::%s::%s::%s'):format(
        tostring(sessionData.device),
        string.sub(ws.socket_id,-12),
        string.format("%.6f",executionTime),
        tostring(message)
      )
    )
  end

  sendMsgToDebugConsole(ws.socket_id .. "::" .. message)
end

-- Remove key k (and its value) from table t. Return a new (modified) table.
function table.removeKey(t, k)
  local i = 0
  local keys, values = {},{}
  for k,v in pairs(t) do
    i = i + 1
    keys[i] = k
    values[i] = v
  end

  while i>0 do
    if keys[i] == k then
      table.remove(keys, i)
      table.remove(values, i)
      break
    end
    i = i - 1
  end

  local a = {}
  for i = 1,#keys do
    a[keys[i]] = values[i]
  end

  return a
end

function tablefind(tab,el)
    for index, value in pairs(tab) do
        if value == el then
            return index
        end
    end
end

function table.contains(table, element)
  for _, value in pairs(table) do
    if value == element then
      return true
    end
  end
  return false
end

function table.map_length(t)
    local c = 0
    for k,v in pairs(t) do
         c = c+1
    end
    return c
end

-- default a particular key in a table to value
-- if that index already exists, otherwise does nothing.
function default(t, key, defaultValue)
  if not table.contains(t, key) then
    t[key] = defaultValue
  end
end

--
-- Task Scheduler
--
function addTask(name,args)
  local task = {
    name = name,
    args = args
  }
  local parameters = {
    schedule = {
      daily = "false",
      hourly = "false",
      weekly = "false",
      monthly = "false",
      yearly = "false"
    },
    duration = 100,
    message = to_json(task)
  }
  return Timer.sendAfter(parameters)
end

function urlencode(str)
   if (str) then
      str = string.gsub (str, "\n", "\r\n")
      str = string.gsub (str, "([^%w ])",
         function (c) return string.format ("%%%02X", string.byte(c)) end)
      str = string.gsub (str, " ", "+")
   end
   return str
end

function fw_path(follow)
  return '/fw/content/' .. follow
end

function _read_until(data, offset, stopchar)
  --[[
  Read from data[offset] until you encounter some char 'stopchar'.
  ]]
  local buf = {}
  local char = string.sub(data, offset + 1, offset + 1)
  local i = 2
  while not (char == stopchar) do
    -- Consumed all the characters and havent found ';'
    if i + offset > string.len(data) then
      error('Invalid')
    end
    table.insert(buf, char)
    char = string.sub(data, offset + i, offset + i)
    i = i + 1
  end
  -- (chars_read, data)
  return i - 2, table.concat(buf)
end

function _read_chars(data, offset, length)
  --[[
  Read 'length' number of chars from data[offset].
  ]]
  local buf = {}
  -- Account for the starting quote char
  -- offset += 1
  for i = 0, length - 1 do
    char = string.sub(data, offset + i, offset + i)
    table.insert(buf, char)
  end
  -- (chars_read, data)
  return length, table.concat(buf)
end

function unserialize(data, offset)
  offset = offset or 0
  --[[
  Find the next token and unserialize it.
  Recurse on array.
  offset = raw offset from start of data
  --]]
  local buf, dtype, dataoffset, typeconvert, datalength, chars, readdata, i,
         key, value, keys, properties, otchars, otype, property
  buf = {}
  dtype = string.lower(string.sub(data, offset + 1, offset + 1))
  -- 't:' = 2 chars
  dataoffset = offset + 2
  typeconvert = function(x) return x end
  datalength = 0
  chars = datalength
  -- int or double => Number
  if dtype == 'i' or dtype == 'd' then
    typeconvert = function(x) return tonumber(x) end
    chars, readdata = _read_until(data, dataoffset, ';')
    -- +1 for end semicolon
    dataoffset = dataoffset + chars + 1
  -- bool => Boolean
  elseif dtype == 'b' then
    typeconvert = function(x) return tonumber(x) == 1 end
    chars, readdata = _read_until(data, dataoffset, ';')
    -- +1 for end semicolon
    dataoffset = dataoffset + chars + 1
  -- n => None
  elseif dtype == 'n' then
    readdata = nil
  -- s => String
  elseif dtype == 's' then
    chars, stringlength = _read_until(data, dataoffset, ':')
    -- +2 for colons around length field
    dataoffset = dataoffset + chars + 2
    -- +1 for start quote
    chars, readdata = _read_chars(data, dataoffset + 1, tonumber(stringlength))
    -- +2 for endquote semicolon
    dataoffset = dataoffset + chars + 2
    --[[
    TODO
    review original: if chars != int(stringlength) != int(readdata):
    ]]
    if not (chars == tonumber(stringlength)) then
      error('String length mismatch')
    end
  -- array => Table
  -- If you originally serialized a Tuple or List, it will
  -- be unserialized as a Dict.  PHP doesn't have tuples or lists,
  -- only arrays - so everything has to get converted into an array
  -- when serializing and the original type of the array is lost
  elseif dtype == 'a' then
    readdata = {}
    -- How many keys does this list have?
    chars, keys = _read_until(data, dataoffset, ':')
    -- +2 for colons around length field
    dataoffset = dataoffset + chars + 2
    -- Loop through and fetch this number of key/value pairs
    for i = 0, tonumber(keys) - 1 do
      -- Read the key
      key, ktype, kchars = unserialize(data, dataoffset)
      dataoffset = dataoffset + kchars
      -- Read value of the key
      value, vtype, vchars = unserialize(data, dataoffset)
      -- Cound ending bracket of nested array
      if vtype == 'a' then
        vchars = vchars + 1
      end
      dataoffset = dataoffset + vchars
      -- Set the list element
      readdata[key] = value
    end
  -- object => Table
  elseif dtype == 'o' then
    readdata = {}
    -- How log is the type of this object?
    chars, otchars = _read_until(data, dataoffset, ':')
    dataoffset = dataoffset + chars + 2
    -- Which type is this object?
    otype = string.sub(data, dataoffset + 1, dataoffset + otchars)
    dataoffset = dataoffset + otchars + 2
    -- if otype == 'stdClass' then
      -- How many properties does this list have?
      chars, properties = _read_until(data, dataoffset, ':')
      -- +2 for colons around length field
      dataoffset = dataoffset + chars + 2
      -- Loop through and fetch this number of key/value pairs
      for i = 0, tonumber(properties) - 1 do
        -- Read the key
        property, ktype, kchars = unserialize(data, dataoffset)
        dataoffset = dataoffset + kchars
        -- Read value of the key
        value, vtype, vchars = unserialize(data, dataoffset)
        -- Cound ending bracket of nested array
        if vtype == 'a' then
          vchars = vchars + 1
        end
        dataoffset = dataoffset + vchars
        -- Set the list element
        readdata[property] = value
      end
    -- else
    --   _unknown_type(dtype)
    -- end
  else
    _unknown_type(dtype)
  end
  --~ return (dtype, dataoffset-offset, typeconvert(readdata))
  return typeconvert(readdata), dtype, dataoffset - offset
end
-- I don't know how to unserialize this

function _unknown_type(type_)
  error('Unknown / Unhandled data type (' .. type_ .. ')!', 2)
end

function getTemplateFooter(JavaScript,domain)
    local Footer = [[
        </td>
                                  </tr>
                          </table>
                      </td>
                  </tr>
                  <!-- 1 Column Text + Button : BEGIN -->

              </table>
              <!-- Email Body : END -->

              <!-- Email Footer : BEGIN -->
              <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" width="100%%" style="max-width: 680px; background-color: #fff">
                  <tr>
                      <td style="padding: 20px 20px; width: 100%%;font-size: 12px; font-family: sans-serif; line-height:18px; text-align: center; color: #353434;" class="x-gmail-data-detectors">
                          <a href="{{company_url}}" style="color:#353434;  font-weight: 700;">{{company_name}}</a>
                          <br>{{company_address}}
                          <br>{{company_contact}}
                          <br> <a href="https://{{domain}}/#/legal" style="color:{{primary_color}};">Terms of Service</a>
                      </td>
                  </tr>
              </table>
              <!-- Email Footer : END -->

              <!--[if mso]>
              </td>
              </tr>
              </table>
              <![endif]-->
          </div>
      </center>
      {{JavaScript}}
  </body>
  </html>
    ]]
    Footer = Footer:gsubnil("{{company_name}}",getSolutionConfig("company_name"))
    Footer = Footer:gsubnil("{{company_url}}",getSolutionConfig("company_url"))
    Footer = Footer:gsubnil("{{company_address}}",getSolutionConfig("company_address"))
    Footer = Footer:gsubnil("{{company_contact}}",getSolutionConfig("company_contact"))
    Footer = Footer:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))

    if JavaScript ~= nil or JavaScript ~= "" then
        Footer = Footer:gsubnil("{{JavaScript}}",JavaScript)
    else
        Footer = Footer:gsubnil("{{JavaScript}}","")
    end
    Footer = Footer:gsubnil("{{domain}}",domain)
    return Footer
end

function getTemplateHead(title,domain)
local Head = [[<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="utf-8"> <!-- utf-8 works for most cases -->
      <meta name="viewport" content="width=device-width"> <!-- Forcing initial-scale shouldn't be necessary -->
      <meta http-equiv="X-UA-Compatible" content="IE=edge"> <!-- Use the latest (edge) version of IE rendering engine -->
      <meta name="x-apple-disable-message-reformatting">  <!-- Disable auto-scale in iOS 10 Mail entirely -->
      <title>{{title}}</title>
      <![if mso]>
          <style>
              * {
                  font-family: 'Nunito Sans', sans-serif !important;
              }
          </style>
      <![endif]>
      <![if !mso]>
      <link href='https://fonts.googleapis.com/css?family=Nunito+Sans:400,700' rel='stylesheet' type='text/css'>
      <link rel="shortcut icon" type="image/png" onerror="this.href='src/assets/img/theme/favicon.png'" href="/theme/logo.png"/>
      <![endif]>

      <style>
          html,
          body {
              margin: 0 auto !important;
              padding: 0 !important;
              height: 100%% !important;
              width: 100%% !important;
              font-family: 'Nunito Sans';
              font-size: 16pt;
              font-weight: 400;
              color: #353434;
          }

          h1{
              color: {{primary_color}};
              font-size: 22.5pt;
              font-weight: 700;
          }
          * {
              -ms-text-size-adjust: 100%%;
              -webkit-text-size-adjust: 100%%;
          }

          div[style*="margin: 16px 0"] {
              margin:0 !important;
          }

          table,
          td {
              mso-table-lspace: 0pt !important;
              mso-table-rspace: 0pt !important;
          }

          table {
              border-spacing: 0 !important;
              border-collapse: collapse !important;
              table-layout: fixed !important;
              margin: 0 auto !important;
          }
          table table table {
              table-layout: auto;
          }

          img {
              -ms-interpolation-mode:bicubic;
          }

          *[x-apple-data-detectors] {
              color: inherit !important;
              text-decoration: none !important;
          }

          .x-gmail-data-detectors,
          .x-gmail-data-detectors *,
          .aBn {
              border-bottom: 0 !important;
              cursor: default !important;
          }

          .a6S {
            display: none !important;
            opacity: 0.01 !important;
          }

          img.g-img + div {
            display:none !important;
          }
          .reset_error, .fb_error {
              display:none;
          }
          .show-error {
            background: #f3f3f3f3;
            border-radius: 3px;
            display: block !important;
            padding: 10px;
            text-align: left;
          }
          .button-link {
              text-decoration: none !important;
          }
          @media only screen and (min-device-width: 375px) and (max-device-width: 413px) { /* iPhone 6 and 6+ */
              .email-container {
                  min-width: 375px !important;
              }
          }

      </style>
      <style>
          .button-td,
          .button-a {
              transition: all 100ms ease-in;
          }
          .button-td:hover,
          .button-a:hover {
              background: #555555 !important;
              border-color: #555555 !important;
          }

      </style>

  </head>
  <body width="100%%" bgcolor="#fff" style="margin: 0; mso-line-height-rule: exactly;">
      <center style="width: 100%%; background: #fff; text-align: left;">
          <div style="max-width: 600px; margin: auto;" class="email-container">
              <!--[if mso]>
              <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" width="600" align="center">
              <tr>
              <td>
              <![endif]-->
              <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" width="100%%" style="max-width: 600px;">
                  <tr>
                      <td style="padding: 20px 0 0; text-align: center; background: #fff;">
                           <!-- Make browsers reserve space for the image so the layout won't shift on page load -->
                           <div style="width: 100px; height: 100px; margin: auto">
                               <img onerror="this.src='https://{{domain}}src/assets/img/logo.png'" src="https://{{domain}}theme/logo.png" aria-hidden="true" width="100" height="100" alt="alt_text" border="0" style="height: auto; font-family: sans-serif; font-size: 15px; line-height: 20px; color: #555555;">
                           </div>
                      </td>
                  </tr>
              </table>
              <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" width="100%%" style="max-width: 600px;">
                  <tr>
                      <td bgcolor="#ffffff">
                      </td>
                  </tr>
                  <tr>
                      <td bgcolor="#ffffff">
                          <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" width="100%%">
                              <tr>
                                  <td style="padding: 0 20px 20px; font-family: sans-serif; font-size: 15px; color: #555555; text-align: center;">
]]
    if title ~= nil or title ~= "" then
        Head = Head:gsubnil("{{title}}",title)
    else
        Head = Head:gsubnil("{{title}}","")
    end
    Head = Head:gsubnil("{{domain}}",domain)
    Head = Head:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
    return Head
end
function getResetPwsTemplate(resetToken,domain)
  local html = [[{{head}}
                                      <h1>Set New Password</h1>
                                      To reset your password, enter a new password below.
                                      <br><br>
                                      <form id="reset_form">
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="text-align: left;font-weight: bold;padding: 1.2em 0.8em;" class="">
                                                  NEW PASSWORD<br>
                                                  <input id="pw_new1" class="input password-input" placeholder="Enter your new password" type="password" style="margin: auto; width:90%;border-style: none none solid none;border-bottom-color:rgb(210, 210, 210);">
                                              </td>
                                          </tr>
                                          <tr>
                                              <td style="text-align: left;font-weight: bold;padding: 1.2em 0.8em;" class="">
                                                  RETYPE NEW PASSWORD<br>
                                                  <input id="pw_new2" class="input password-input" placeholder="Retype your new password" type="password" style="margin: auto; width:90%;border-style: none none solid none;border-bottom-color:rgb(210, 210, 210);">
                                              </td>
                                          </tr>
                                          <tr>
                                              <td id="reset_error1" class="reset_error">
                                                  <h3 style="margin: 0;">Password too short or too long.</h3>
                                                  Passwords must be between 8-20 characters.
                                              </td>
                                          </tr>
                                          <tr>
                                              <td id="reset_error2" class="reset_error">
                                                  <h3 style="margin: 0;">Passwords not matching.</h3>
                                                  Make sure your new passwords match.
                                              </td>
                                          </tr>
                                          <tr>
                                              <td id="reset_error3" class="reset_error">
                                                  <h3 style="margin: 0;">Server error.</h3>
                                                  Please try again later.
                                              </td>
                                          </tr>
                                      </table>
                                      <br>
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a id="reset_button" href="#" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Reset Password&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                      </table>
                                      </form>
                                  {{footer}}
  ]]
  local head = getTemplateHead("Change Your Password",domain)
  html = html:gsubnil("{{head}}",head)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  local javascript = [[
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
      <script language="JavaScript">
      var resetToken = "{{resetToken}}";
      console.log(resetToken);
      </script>
      <script src="/src/assets/js/reset_pw.js" type="text/javascript"></script>
  ]]
  javascript = javascript:gsubnil("{{resetToken}}",resetToken)
  local footer = getTemplateFooter(javascript,domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{domain}}",domain)
  return html
end

function getResetPwsConfirmation(url,domain)
  local button = ""
  if url ~= nil then
    button = [[
                                      <!-- Button : Begin -->
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Open App&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                      </table>
                                      <!-- Button : END -->
    ]]
    button = button:gsubnil("{{url}}",url)
  end
  local html = [[{{head}}
                                      <h1>Password Changed</h1>
                                      Please reopen the {{app_name}} app and try logging into your account.
                                      <br><br>
                                      {{button}}
                                  {{footer}}
  ]]
  html = html:gsubnil("{{button}}",button)
  html = html:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  local head = getTemplateHead("",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html

end

function getResetPwsExpired(url,domain)
  local button = ""
  if url ~= nil then
    button = [[
                                      <!-- Button : Begin -->
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Open App&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                      </table>
                                      <!-- Button : END -->
    ]]
    button = button:gsubnil("{{url}}",url)
  end
  local html = [[{{head}}
                                      <h1>This password reset link is no longer available</h1>
                                      Your link expires after 24 hours or once a new password is set. If you still wish to reset your password, please use the mobile app to request a new password reset link.
                                      <br><br>
                                      {{button}}
                                  {{footer}}
  ]]
  local head = getTemplateHead("",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{button}}",button)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html
end

function getResetPwsEmailTemplate(url,email,domain)
  local button = ""
  if url ~= nil then
    button = [[
                                      <!-- Button : Begin -->
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Reset Password&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                      </table>
                                      <!-- Button : END -->
    ]]
    button = button:gsubnil("{{url}}",url)
  end
  local html = [[{{head}}
                                      <h1>Change Your Password</h1>
                                      We received a reset password request for your account {{email}}. <br>Please click the button below to change your password.
                                      <br><br>
                                      {{button}}
                                      <br>
                                      If you did not ask to change your password, you can ignore this email and your password will remain unchanged. This link will remain active for 24 hours.
                                  {{footer}}
  ]]
  local head = getTemplateHead("Change Your Password",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{button}}",button)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{email}}",email)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html
end

function getWelcomeTemplate(url,domain)
  local button = ""
  if url ~= nil then
    button = [[<br /><!-- Button : Begin -->
                                        <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                            <tr>
                                                <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                    <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: 'Nunito Sans', sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                        <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Open App&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                        <!-- Button : END -->]]
    button = button:gsubnil("{{url}}",url)
  end
  local html = [[{{head}}
                                      <h1>{{welcome_web_headline}}</h1>
                                      {{welcome_web_body}}
                                      <br><br>
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                      <tr>
                                          <td style="text-align: center;">
                                              <a href="{{apple_store}}"><img src="/src/assets/img/appStoreBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                          </td>
                                          <td style="text-align: center;">
                                              <a href="{{google_play}}"><img src="/src/assets/img/googlePlayBadge@2x.png" aria-hidden="true" alt="alt_text" border="0" style="width:95%; height: auto; font-family: sans-serif;"></a>
                                          </td>
                                      </tr>
                                      </table>
                                      {{button}}
                                  {{footer}}
  ]]
  html = html:gsubnil("{{welcome_web_headline}}",getSolutionConfig("welcome_web_headline"))
  html = html:gsubnil("{{welcome_web_body}}",getSolutionConfig("welcome_web_body"))
  html = html:gsubnil("{{product_name}}",getSolutionConfig("product_name"))
  html = html:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  html = html:gsubnil("{{apple_store}}",getSolutionConfig("apple_store"))
  html = html:gsubnil("{{google_play}}",getSolutionConfig("google_play"))

  local head = getTemplateHead("",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{button}}",button)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html
end

function getWelcomeEmailTemplate(url,email,domain)
  local button = ""
  if url ~= nil then
    button = [[
                                      <!-- Button : Begin -->
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a href="{{url}}" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Get Started&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                      </table>
                                      <!-- Button : END -->
    ]]
    button = button:gsubnil("{{url}}",url)
  end
  local html = [[{{head}}
                                      <h1>{{welcome_email_headline}}</h1>
                                      {{welcome_email_body}}
                                      <br><br>
                                      {{button}}
                                  {{footer}}
  ]]

  local head = getTemplateHead("",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{button}}",button)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{welcome_email_headline}}",getSolutionConfig("welcome_email_headline"))
  html = html:gsubnil("{{welcome_email_body}}",getSolutionConfig("welcome_email_body"))
  html = html:gsubnil("{{product_name}}",getSolutionConfig("product_name"))
  html = html:gsubnil("{{app_name}}",getSolutionConfig("app_name"))
  html = html:gsubnil("{{email}}",email)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html
end

function getLoginTemplate(domain)
  local facebookbutton = User.getSocialLoginUrl({consumer="Facebook"}).error ~= nil and "display: none; " or ""
  local html = [[{{head}}
                                      <h1>Sign In</h1>
                                      <br>
                                      <form id="loginform">
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="text-align: left;font-weight: bold;padding: 1.2em 0.8em;" class="">
                                                  EMAIL<br>
                                                  <input id="email" class="input" required name="email" type="email" placeholder="Email Address" style="margin: auto; width:90%;border-style: none none solid none;border-bottom-color:rgb(210, 210, 210);">
                                              </td>
                                          </tr>
                                          <tr>
                                              <td style="text-align: left;font-weight: bold;padding: 1.2em 0.8em;" class="">
                                                  PASSWORD<br>
                                                  <input id="password" class="input password-input" required name="password" placeholder="Password" type="password" style="margin: auto; width:90%;border-style: none none solid none;border-bottom-color:rgb(210, 210, 210);">
                                              </td>
                                          </tr>
                                          <tr>
                                              <td id="loginerror" class="reset_error">
                                                  <h3 style="margin: 0;">There was an issue signing in</h3>
                                                  The username or password you entered may be incorrect. Please check your settings and try again. Or if you have forgotten your password, you can reset it.
                                              </td>
                                              <td id="facebookerror" class="fb_error">
                                                  <h3 style="margin: 0;">There was an issue signing in with Facebook</h3>
                                                  <span id="fberror"></span>
                                              </td>
                                          </tr>
                                      </table>
                                      <br>
                                      <table role="presentation" aria-hidden="true" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto; width:90%;">
                                          <tr>
                                              <td style="border-radius: 30px; background: {{primary_color}}; text-align: center;" class="button-td">
                                                  <a id="signin_button" href="#" style="background: {{primary_color}}; border: 15px solid {{primary_color}}; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                      <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Sign In&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                                  </a>
                                              </td>
                                          </tr>
                                          <tr>
                                            <td style="height: 2em;">
                                            </td>
                                          </tr>
                                          <tr>
                                            <td style="{{facebookbutton}}border-radius: 30px; background: #4266b2; text-align: center;" class="button-td">
                                              <a id="signin_button" href="#" onclick="loginFB();return false;" style="background: #4266b2; border: 15px solid #4266b2; font-family: sans-serif; font-size: 17px; font-weight: 700; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 30px;" class="button-a">
                                                  <span style="color:#ffffff;" class="button-link">&nbsp;&nbsp;&nbsp;&nbsp;Sign In with Facebook&nbsp;&nbsp;&nbsp;&nbsp;</span>
                                              </a>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td style="display: none; height: 5em; padding-top:10px; color:#00BAFF; font-size: 12px;">
                                              <a id="facebook_button" style="color:#00BAFF;">Forgot Password
                                            </td>
                                          </tr>
                                          <tr>
                                            <td style="display: none; height: 1em; font-size: 12px;">
                                              Don't have an account? <a id="sign-up" style="color:#00BAFF; ">Sign up</a>
                                            </td>
                                          </tr>
                                      </table>
                                      </form>
                                  {{footer}}
  ]]
  local head = getTemplateHead("Sign In",domain)
  html = html:gsubnil("{{head}}",head)
  html = html:gsubnil("{{facebookbutton}}",facebookbutton)
  local javascript = [[
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/js-cookie@2.1.3/src/js.cookie.min.js" type="text/javascript"></script>
      <script>
        function loginFB() {
          var fburl = window.location.href;
          Cookies.set('fbBackurl', btoa(fburl));
          window.location.href = '/api:1/social/handle/Facebook/loginurl';
        }

        function login(e) {
            if (e) e.preventDefault();
            var values = {};
            $('#loginform :input').each(function() {
                values[this.name] = $(this).val();
            });
            $.ajax({
                type: 'POST',
                url: '/api:1/integration_session',
                contentType: 'application/json',
                data: JSON.stringify(values),
                cache: false,
                processData: false
            }).done(function(data) {
              window.location.href = window.location.href.replace('/oauth2/authorize','/oauth2/approved');
            }).fail(function() {
                $('#loginerror').removeClass('reset_error').addClass('show-error');
            })
        }

        function progressHandlingFunction(e){
            if(e.lengthComputable){
                $('progress').attr({value:e.loaded,max:e.total});
            }
        }

        function capitalizeFirstLetter(string) {
          return string[0].toUpperCase() + string.slice(1);
        }

        $(document).ready(function(){
            Cookies.remove('fbBackurl');
            $("#signin_button").click(login);
            $("#loginform").submit(login);
            logined = Cookies.get('logined');
            if (logined != "true") {
              Cookies.remove('sid', { path: '/' });
              Cookies.set('logined', 'true', { path: '/' });
            }
            FaceBookerror = Cookies.get('FaceBookerror');
            if (FaceBookerror !== undefined) {
              FaceBookerror = JSON.parse(FaceBookerror);
              var error_msg = capitalizeFirstLetter(FaceBookerror.error.replace('_',' ')) + ': ' + FaceBookerror.error_reason.replace('_',' ') + '.';
              $('#facebookerror').removeClass('fb_error').addClass('show-error');
              $('#fberror').html(error_msg);
              Cookies.remove('FaceBookerror', { path: '/' });
            }
        });
      </script>
  ]]
  local footer = getTemplateFooter(javascript,domain)
  html = html:gsubnil("{{footer}}",footer)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{primary_color}}",getSolutionConfig('primary_color'))
  return html
end

function getTermsCTemplate(domain)
  local terms_conditions = [[
  <div class="entry-content">
    <!-- AddThis Sharing Buttons above via filter on the_content -->
<div class="at-above-post-page" data-url="https://exosite.com/murano-terms-conditions/" data-title="MURANO TERMS &amp;amp; CONDITIONS"></div><script>if (typeof window.atnt !== 'undefined') { window.atnt(); }</script><p>IN THE ABSENCE OF A CUSTOM SERVICES AGREEMENT, THIS <em>EXOSITE SERVICES AGREEMENT</em> (“AGREEMENT”) GOVERNS USE OF EXOSITE SERVICES (“SERVICES”) IN ACCORDANCE WITH TERMS SET FORTH BELOW.&nbsp;BY ACCEPTING THIS AGREEMENT, BY CLICKING THE BOX INDICATING YOUR ACCEPTANCE, YOU AGREE TO THIS AGREEMENT. IF YOU ARE ENTERING INTO THIS AGREEMENT ON BEHALF OF A COMPANY OR OTHER LEGAL ENTITY, YOU REPRESENT THAT YOU HAVE THE AUTHORITY TO BIND SUCH ENTITY AND ITS AFFILIATES TO THIS AGREEMENT, IN WHICH CASE THE TERMS “YOU” OR “YOUR” SHALL REFER TO SUCH ENTITY AND ITS AFFILIATES. IF YOU DO NOT HAVE SUCH AUTHORITY, OR IF YOU DO NOT AGREE WITH THIS AGREEMENT, YOU MUST NOT ACCEPT THIS AGREEMENT AND MAY NOT USE THE SERVICES.</p>
<p>You may not use the Services if You are Our direct competitor, except with Our prior written consent. In addition, You may not access the Online Services for the purposes of monitoring its availability, performance, or functionality, or for any other benchmarking or competitive purposes.&nbsp;This Agreement was last updated on February 22, 2016. It is effective between You and Us as of the&nbsp;date&nbsp;of&nbsp;Your acceptance of this Agreement.</p>
<p><strong>CONFIDENTIALITY</strong></p>
<p><strong>Definition of Confidential Information<br>
</strong>As used herein, “Confidential Information” means all confidential information disclosed by a party (“Disclosing Party”) to the other party (“Receiving Party”), whether orally or in writing, that is designated as confidential or that reasonably should be understood to be confidential given the nature of the information and the circumstances of disclosure. Your Confidential Information shall include Your Data; Our Confidential Information shall include Our Online Services; and Confidential Information of each party shall include the terms and conditions of this Agreement, as well as business and marketing plans, technology and technical information, product plans and designs, and business processes disclosed by such party. However, Confidential Information shall not include any information that: (i) is or becomes generally known to the public without breach of any obligation owed to the Disclosing Party; (ii) was known to the Receiving Party prior to its disclosure by the Disclosing Party without breach of any obligation owed to the Disclosing Party; (iii) is received from a third party without breach of any obligation owed to the Disclosing Party; or (iv) was independently developed by the Receiving Party.</p>
<p><strong>Protection of Confidential Information<br>
</strong>Except as otherwise permitted in writing by the Disclosing Party: (i) the Receiving Party shall use the same degree of care that it uses to protect the confidentiality of its own confidential information of like kind (but in no event less than reasonable care) not to disclose or use any Confidential Information of the Disclosing Party for any purpose outside the scope of this Agreement; and (ii) the Receiving Party shall limit access to Confidential Information of the Disclosing Party to those of its employees, contractors, licensees, and agents who need such access for purposes consistent with this Agreement.</p>
<p><strong>Compelled Disclosure<br>
</strong>The Receiving Party may disclose Confidential Information of the Disclosing Party if it is compelled by law to do so, provided the Receiving Party gives the Disclosing Party prior notice of such compelled disclosure (to the extent legally permitted) and reasonable assistance, at the Disclosing Party’s cost, if the Disclosing Party wishes to contest the disclosure. If the Receiving Party is compelled by law to disclose the Disclosing Party’s Confidential Information as part of a civil proceeding to which the Disclosing Party is a party, and the Disclosing Party is not contesting the disclosure, the Disclosing Party will reimburse the Receiving Party for its reasonable cost of compiling and providing secure access to such Confidential Information.</p>
<p><strong>YOUR RESPONSIBILITIES</strong></p>
<p>You shall not: (i) permit any third party to access the Online Services except as permitted herein; (ii)&nbsp;create derivate works based on the Online Services; (iii) copy, frame, or mirror any part or content of the Online Services, other than copying or framing on Your own intranets or otherwise for Your own internal business purposes; (iv) reverse engineer the Online Services; (v) access the Online Services in order to build a competitive product or service or to copy any features, functions, or graphics of the Online Services; (vi) use the Online Services to store or transmit infringing, libelous, or otherwise unlawful or tortuous material, or to store or transmit material in violation of third-party privacy rights; (vii) use the Online Services to store or transmit malicious code or malware, or to engage in phishing or other fraudulent activity; (viii) interfere with or disrupt the integrity or performance of the Online Services or third-party data contained therein; or (ix) attempt to gain unauthorized access to the Online Services, Our systems, Our data, or networks.</p>
<p>You shall: (i) be responsible for Your compliance with this Agreement; (ii) be solely responsible for the accuracy, quality, integrity, and legality of and for the means by which You acquired Your Data and Your Application Resources; (iii) enter into Exosite-approved agreements with Your Partners and Customers excluding warranties and limiting the liability of Exosite due to their use of the Online Services; (iv) use commercially reasonable efforts to prevent unauthorized access to or use of the Online Services and notify Us promptly of any such unauthorized access or use; (v) use the Online Services only in accordance with applicable laws and government regulations; and (vi) provide Us with complete and accurate contact information.</p>
<p><strong>OWNERSHIP AND LICENSES</strong></p>
<p>Subject to the limited rights expressly granted hereunder, We reserve all rights, title, and interest in and to Our Online Services and other Proprietary Software, including all related intellectual property rights subsisting therein. We grant no rights to You hereunder other than as expressly set forth herein.</p>
<p><strong>What We License to You</strong><br>
We grant you a worldwide license during the term of this Agreement to use the Services to collect and view Your Data.</p>
<p><strong>What you License to Us<br>
</strong>You grant us a worldwide license to use, reproduce, transmit, display, and adapt Your Data and Your Application Resources solely as necessary for Us to provide the Online Services in accordance with this Agreement.</p>
<p>You grant us a royalty-free, worldwide, transferable, sub-licensable, irrevocable, perpetual license to use or incorporate into our Online Services any suggestions, enhancement requests, recommendations, or other feedback provided by You relating to the Online Services.</p>
<p><strong>Property Rights Retained by Us<br>
</strong>You acknowledge that We may incorporate certain computer code, methods, inventions, concepts, and know-how into any source code, compiled code, custom software, or other programming or design work delivered by Us to You (“Deliverables”) that were not or will not be created solely for use in or with such Deliverables. You acknowledge that such code, methods, inventions, concepts, and know-how will not become Your property, and that the rights therein are part of Our stock in trade and general know‑how that will remain Our sole and unencumbered property, without any claim of Yours thereto, other than a perpetual paid-up license to use the same as incorporated in, and only as incorporated in, the Deliverables or any derivatives thereof.<strong><br>
</strong></p>
<p><strong>Our Proprietary Software</strong><br>
You expressly acknowledge that existing proprietary software of Ours and software of third parties, which is provided by Us for use in conjunction with any Deliverables (including subsequent versions of proprietary software of Ours, or third-party software, and enhancements thereof provided by Us), is and will remain the sole and exclusive property of Ours or such third parties, subject only to Your rights pursuant to license agreement(s) for such software.</p>
<p><strong>RELATIONSHIP TO THE PARTIES</strong></p>
<p>You and We are independent contractors, and nothing in this Agreement will create any partnership, joint venture, agency, franchise, sales representative, or employment relationship between the parties. You are in no way authorized to make any license, contract, agreement, warranty, or representation on behalf of Us, or to create any obligations, expressed or implied, on behalf of Us except to the extent and for the purposes expressly provided for and set forth herein.</p>
<p><strong>WARRANTIES</strong></p>
<p>OTHER THAN ANY EXPRESS WARRANTIES MADE IN SUBSEQUENT PARAGRAPHS IN THIS SECTION, WE MAKE NO WARRANTIES OF ANY KIND, WHETHER IMPLIED, STATUTORY, OR OTHERWISE, AND WE SPECIFICALLY DISCLAIM ALL IMPLIED WARRANTIES, INCLUDING ANY WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW. IN ADDITION, WE MAKE NO WARRANTIES REGARDING ANY THIRD-PARTY SOFTWARE OR PRODUCTS PROVIDED TO OR USED BY YOU. WITHOUT LIMITING THE GENERALITY OF THE FOREGOING, WE DO NOT REPRESENT OR WARRANT THAT YOUR USE OF THE ONLINE SERVICES WILL MEET YOUR REQUIREMENTS OR THAT YOUR USE OF THE ONLINE SERVICES WILL BE UNINTERRUPTED, TIMELY, SECURE, OR FREE FROM ERROR.</p>
<p><strong>LIMITATION OF LIABILITY</strong></p>
<p>EXCEPT FOR BREACHES OF CONFIDENTIALITY AND INDEMNIFICATION OBLIGATIONS IN SECTION: INDEMNITY&nbsp;BELOW, EACH PARTY HERETO: (I) EXPRESSLY WAIVES ANY AND ALL CLAIMS AGAINST THE OTHER FOR CONSEQUENTIAL, INCIDENTAL, OR SPECIAL DAMAGES (INCLUDING, WITHOUT LIMITATION, CLAIMS FOR LOST PROFITS, REVENUES, DATA, OR INTERRUPTIONS IN SERVICE) ARISING OUT OF OR RELATED TO THE PROVISION OF ANY SERVICES OR WORK PRODUCT PURSUANT TO THIS AGREEMENT; AND (II) EXPRESSLY AGREES THE MAXIMUM LIABILITY FOR US WITH RESPECT TO ANY CLAIM RELATED TO THIS AGREEMENT OR THE SERVICES HEREUNDER WILL BE LIMITED TO THE AMOUNT OF FEES RECEIVED BY US FOR SERVICES IN THE PRECEDING 12 MONTHS.</p>
<p><strong>INDEMNITY</strong></p>
<p>EACH PARTY WILL INDEMNIFY, DEFEND, AND HOLD THE OTHER HARMLESS FROM AND AGAINST ANY AND ALL CLAIMS, DAMAGES, AND EXPENSES (INCLUDING REASONABLE ATTORNEYS’ FEES AND COSTS OF LITIGATION) BY ANY THIRD PARTY RESULTING FROM ANY ACTS OR OMISSIONS OF THE INDEMNIFYING PARTY RELATING TO ITS ACTIVITIES IN CONNECTION WITH THIS AGREEMENT, THEIR BREACH OF THIS AGREEMENT, OR THEIR MISREPRESENTATIONS RELATING TO THE OTHER PARTY, THE SERVICES, OR THIS AGREEMENT, REGARDLESS OF THE FORM OF ACTION.</p>
<p><strong>TERM AND TERMINATION</strong></p>
<p>This Agreement commences on the date You accept it and continues until terminated by either party in accordance with this Agreement. Upon any termination of Your subscription to the Online Services, this Agreement shall also terminate, subject to the Surviving Provisions.</p>
<p>UPON ANY TERMINATION OF YOUR SUBSCRIPTION TO THE ONLINE SERVICES, YOUR INFORMATION AND OTHER MATERIALS DEVELOPED BY YOU USING THE ONLINE SERVICES MAY BE PERMANENTLY LOST.</p>
<p><strong>Online Services Termination<br>
</strong>You may terminate Your subscription to the Online Services without cause at any time upon written request to Us. Such requests shall be deemed accepted by a written response verifying We received Your request.</p>
<p>We may terminate Your subscription to the Online Services at any time without cause upon 30 days’ written notice to You, or automatically if you fail to comply with any term or condition of this Agreement.</p>
<p><strong>Surviving Provisions<br>
</strong>The following sections shall survive any termination or expiration of this agreement: Property Rights Retained by Us, Our Proprietary Software, Warranties, Limitation of Liability, Indemnity, and General Provisions.<strong><br>
</strong></p>
<p><strong>CHANGES TO ONLINE SERVICES</strong></p>
<p>As part of the normal process of operating and updating the Online Services, We reserve the right at any time and from time to time to enhance, amend, or modify the features of the Online Services (or any part thereof) with or without notice. Notwithstanding the forgoing, We will use commercially reasonable efforts to notify You in writing of any major change to the Service that is known to have a substantially negative material impact to You.</p>
<p><strong>FEES</strong></p>
<p>The Services being subscribed to, and their associated fees and engagement levels, are described at <a href="https://exosite.com/business">https://exosite.com/business</a>.</p>
<p><strong>Online Services</strong><br>
The Online Services are billed for on a monthly basis and are non-refundable. There are no refunds or credits for partial months of service, plan downgrades, or refunds for months unused. You are responsible for paying all charges in accordance with the use of the Online Services associated with Your Data and Your Application Resources, even if you did not use or authorize the use of the Online Services. If You cancel Your subscription to the Online Services before the end of the current month, Your cancellation will take effect immediately and You will not be charged again, but You shall be responsible for all charges already incurred.</p>
<p><strong>Payment for Online Services</strong><br>
We may choose to bill for Online Service Fees through an invoice, in which case, full payment for invoices issued in any given month must be received by Us 30 days after the date of the invoice, or the Online Services may be terminated or suspended as soon as one day after the date due as indicated on the invoice. Unpaid invoices are subject to a finance charge of 1.5% per month on any outstanding balance, or the maximum permitted by law, whichever is lower, plus all expenses of collection. You have 30 days after receiving the invoice to dispute any charges. Agreed-upon changes to a past invoice will be reflected in the next applicable invoice to You.</p>
<p>If payment has been authorized by credit card, no additional notice or consent will be required for billings to that credit card for all amounts (including late charges and termination fees).</p>
<p><strong>Fee Change</strong><br>
We reserve the right to annually change our Fees (“Fee Changes”) for all Services, including but not limited to monthly subscription plan fees to the Online Services, upon 30 days’ notice via email from Us.</p>
<p><strong>Taxes</strong><br>
You will pay any and all applicable taxes, however designated, incurred as a result of or otherwise in connection with this Agreement or the Services, excluding taxes based on Our net income.</p>
<p><strong>GENERAL PROVISIONS</strong></p>
<p><strong>Notices</strong><br>
Any notice to be given under this Agreement will be sufficient if in writing and sent by certified or registered mail or delivered by courier to the addresses set forth at the beginning of this Agreement. A party’s address or designee for purposes of any notices may be changed by written notice to the other party.</p>
<p><strong>Entire Agreement&nbsp;</strong><br>
This Agreement constitutes the entire agreement between the parties and supersedes all prior and contemporaneous agreements, proposals, or representations, either written or oral, concerning its subject matter.</p>
<p><strong>Governing Law</strong><br>
This Agreement, and any disputes arising out of or related hereto, shall be governed exclusively by the internal laws of the State of Minnesota, without regard to their conflicts of laws rules.</p>
<p><strong>Venue; Waiver of Jury Trial<br>
</strong>The state and federal courts located in Hennepin County, Minnesota, shall have exclusive jurisdiction to adjudicate any dispute arising out of or relating to this Agreement. Each party hereby consents to the exclusive jurisdiction of such courts. Each party hereby waives any right to jury trial in connection with any action or litigation in any way arising out of or related to this Agreement.</p>
<p><strong>Export Compliance</strong><br>
Each party shall comply with the export laws and regulations of the United States and other applicable jurisdictions in providing and using the Services.</p>
<p><strong>Assignment</strong><br>
Neither party may assign any interest in this Agreement or any of its duties or rights under this Agreement without the prior written consent of the other except that: (i) each party may assign its rights and obligations to an Affiliate of such party upon advance written notice to the other; and (ii) either party may assign its rights and obligations upon advance notice to the other in connection with any merger, acquisition, or sale of all or substantially all of its assets.</p>
<p><strong>DEFINITIONS</strong></p>
<p>“<strong>Affiliate</strong>” means any entity that directly or indirectly controls, is controlled by, or is under common control with the subject entity. “Control,” for purposes of this definition, means direct or indirect ownership or control of more than 50% of the voting interests of the subject entity.</p>
<p>“<strong>Online Services</strong>” means the online services provided by Us as described in this Agreement that You manage at: <a href="https://exosite.com/business">https://exosite.com/business</a>.</p>
<p>“<strong>Proprietary Software</strong>” means the software that is developed, licensed, or purchased by Us, and includes our Online Services and other software that can be deployed onto embedded systems, computers, handheld systems, and servers.</p>
<p>“<strong>Services</strong>” means Online Services.</p>
<p>“<strong>We</strong>,” ” <strong>Us</strong>,” or ” <strong>Our</strong>” means Exosite LLC, a Delaware Limited Liability Corporation with a principal place of business at 275 Market Street, Suite 535, Minneapolis, Minnesota, 55405, United States of America.</p>
<p>“<strong>You</strong>” or “<strong>Your</strong>” means: (i) the company or other legal entity for which you are accepting this Agreement and Affiliates of that company or entity; or (ii) an individual, in the case of a non-legal entity as defined in the registration information provided to Us.</p>
<p>“<strong>Your Application Resources</strong>” means a web, server, personal computer, or handheld application and related configuration parameters, that We, You, or a third party acting on Your behalf create and that interoperates with the Services.</p>
<p>“<strong>Your Data</strong>” means all electronic data or information submitted by You, or by devices owned by You or Your Customers or Your Partners, to the Online Services.</p>
<p>“<strong>Your Partners</strong>” and “<strong>Your Customers</strong>” means any individuals or entities that are neither You nor your Affiliates, but who use the Online Services.</p>
<!-- AddThis Sharing Buttons below via filter on the_content -->
<div class="at-below-post-page" data-url="https://exosite.com/murano-terms-conditions/" data-title="MURANO TERMS &amp;amp; CONDITIONS"></div><script>if (typeof window.atnt !== 'undefined') { window.atnt(); }</script><!-- AddThis Sharing Buttons generic via filter on the_content -->
<!-- AddThis Recommended Content generic via filter on the_content -->
      </div>
  ]]
  local html = [[{{head}}
                                      <h1>{{app_name}} TERMS & CONDITIONS </h1>
                                      {{terms_conditions}}
                                  {{footer}}
  ]]
  local head = getTemplateHead("TERMS & CONDITIONS",domain)
  html = html:gsubnil("{{head}}",head)
  local footer = getTemplateFooter("",domain)
  html = html:gsubnil("{{footer}}",footer)
  local app_name = getSolutionConfig("app_name")
  html = html:gsubnil("{{app_name}}",app_name)
  html = html:gsubnil("{{domain}}",domain)
  html = html:gsubnil("{{terms_conditions}}",terms_conditions)
  return html
end

function testCmd(cmd)
  if cmd == "clean" then
    for _, user in pairs(User.listUsers()) do
        User.deleteUser({id = user.id})
    end
    return User.listUsers()
  end
  if cmd == "activate" then
    for _, user in pairs(User.listUsers()) do
        if user.status == 0 then
          User.updateUser({id = user.id, status = 1})
        end
    end
    return User.listUsers()
  end

  local _, _, module, fun, args = string.find(cmd, "([%a]+)%.([%a]+)%((.*)%)")

  if module == nil then
    _, _, fun, args = string.find(cmd, "([%a_]+)%((.*)%)")
  end

  if fun ~= nil then
    if args == nil or args == "" then
      args = {}
    else
      args = from_json(args)
    end

    if module == nil then
      return _G[fun](args)
    end
  end
  return [[Unknown command. Try:
  User.listUsers()
  kv_read(1)
  ]]
end
function handleTestRequest(request,data)
  local switch = {
    ["provision"] = function()
        __debugMsg("TestRequest::provision" .. " :: " .. to_json(data))
        if deviceProvision(data.sn,data.secret) == true then
          local res = {["id"] = requestId,["response"] = obj.request, ["status"] = "ok"}
          ws.send(res)
          return true
        end
    end,
    ["test"] = function()
        __debugMsg("TestRequest::test" .. " :: " .. to_json(data))
        local res = {["id"] = requestId,["response"] = obj.request, ["status"] = "ok"}
        ws.send(res)
        return true
    end
  }
  local requestCall = switch[request]
  if(requestCall) then
      return requestCall()
  else
      -- no request able to handel
      return false
  end
end
function provision_(data)
  return deviceProvision(data.id,data.key)
end
function addToTestConsole(wsInfo)
  local result = Keystore.command({
    key = "TestConsole",
    command = "hset",
    args = {wsInfo.socket_id,to_json(wsInfo)}
  })
  return result
end

function removeFromTestConsole(wsInfo)
  local result = Keystore.command({
    key = "TestConsole",
    command = "hdel",
    args = {wsInfo.socket_id}
  })
  return result
end

function sendMsgToTestConsole(msg)
  local result = Keystore.command({
    key = "TestConsole",
    command = "hkeys"
  })
  if result.value == nil then
    return false
  end
  local list = result.value
  if list ~= nil then
    for key,value in pairs(list) do
      Websocket.send({socket_id = value,message = msg})
    end
  end
end

-- luacheck: globals Keystore User

local R = require 'modules_moses'

-- TODO: change to SET and encrypt the password
function _G.setUserPassword(userID, password)
  local user = _G.user_read(userID)
  if user == nil then
    user = {}
  end
  user.password = password
  _G.user_write(userID, user)
end

-- TODO: change to SET and encrypt the password
function _G.getUserPassword(userID)
  local user = _G.user_read(userID)
  if user == nil then
    return nil
  end
  if user.password ~= nil then
    return user.password
  end
  return nil
end

function _G.user_read(id)
  local resp = Keystore.get({key = 'User_' .. id})
  local user = nil
  if type(resp) == 'table' and type(resp.value) == 'string' then
    user = from_json(resp.value)
  end
  return user
end

function _G.user_write(id, values)
  Keystore.set({key = 'User_' .. id, value = to_json(values)})
end

function _G.resetPasswordCode(userInfo)
  local osTime = os.time()
  math.randomseed(osTime)
  local key = ''
  for _ = 1, 32 do
    if (math.random(0, 1) == 1) then
      key = key .. string.char(math.random(48, 57))
    else
      key = key .. string.char(math.random(97, 122))
    end
  end
  userInfo['resetTime'] = osTime
  Keystore.command({
    key = 'resetPassword',
    command = 'hset',
    args = {key,to_json(userInfo)}
  })
  return key
end

function _G.resetPasswordToken(userInfo)
  math.randomseed(os.time())
  local key = ''
  for _ = 1, 32 do
    if (math.random(0,1) == 1) then
      key = key .. string.char(math.random(48, 57))
    else
      key = key .. string.char(math.random(97, 122))
    end
  end
  Keystore.command({
    key = 'reset_token::' .. key,
    command = 'setex',
    args = {1800,to_json(userInfo)}
    -- 30 mine
  })
  return key
end

function _G.getUserDevicelist(userID)
  local L = require 'lodash'
  local HamvModel = require 'hamv_model'
  local DevicePropertyModel = require 'device_property_model'
  local UserPermissionModel = require 'user_permission_model'
  local DevicePermissionModel = require 'device_permission_model'
  local userProfile = _G.getUser(userID)

  local list = {}
  list = R.append(list,
    R(UserPermissionModel.getOwnDevices(userID) or {})
      :filter(function(_, sn) -- remove this by cleaning the list at some other timing
        return HamvModel.isProvisioned(sn)
      end)
      :map(function(_, sn)
        return {
          device = sn,
          role = 'owner',
          owner = userProfile.email,
          properties = DevicePropertyModel.get(userID, sn)
        }
      end)
      :value()
  )

  list = R.append(list,
    R(UserPermissionModel.getShareDevices(userID) or {})
      :filter(function(_, sn) -- remove this by cleaning the list at some other timing
        return HamvModel.isProvisioned(sn)
      end)
      :map(function(_, sn)
        return {
          device = sn,
          role = 'guest',
          owner = _G.getUser(DevicePermissionModel.getDeviceOwners(sn)[1]).email,
          properties = DevicePropertyModel.get(userID, sn)
        }
      end)
      :value()
  )

  return L.castArray(list)
end

function _G.deleteAdminUser(userID)
  local resp = User.deassignUserParam({
    id = userID,
    role_id = 'admin',
    parameter_name = 'customRoleName',
    parameter_value = 'admin'
  })
  return resp.error == nil
end

function _G.addAdminUser(userID)
  --It needs parameters for calling assign
  local resp = User.assignUser({
    id = userID,
    roles = {{
      role_id = 'admin',
      parameters = {{
        name = 'customRoleName',
        value = 'admin'
      }}
    }}
  })
  return resp.error == nil
end

_G.getUser = R.memoize(function(userID)
  local ret = User.getUser({id = userID})
  if ret.error ~= nil then
    return nil
  end
  return ret
end)

function _G.getUserByEmail(email)
  local guest = User.listUsers({filter = 'email::like::' .. email})
  if #guest == 1 and guest[1].id ~= nil then
    return guest[1]
  else
    return nil
  end
end

function _G.isAdmin(user)
  if user == nil or user.id == nil then
    return false
  end
  if user.email:find('@exosite.com$') then
    return true
  end
  local roles = User.listUserRoles({id = user.id})
  for _, role in ipairs(roles) do
    if role.role_id == 'admin' then
      return true
    end
  end
  return false
end

function _G.getUserData(userID)
  local userData = User.listUserData({id = userID})

  if userData.error ~= nil then
    userData = {}
  end

  local dataMap = {}
  for key, value in pairs(userData) do
    dataMap[key] = from_json(value) or value
  end

  return dataMap
end
--TODO use global
function _G.addToAlexaSession(state,data)
  local result = Keystore.command({
    key = "AlexaStat",
    command = "hset",
    args = {state,to_json(data)}
  })
  return result
end
function _G.getAlexaSession(state)
  local result = Keystore.command({
    key = "AlexaStat",
    command = "hget",
    args = {state}
  })
  if result.value == nil then
    return nil
  end
  return from_json(result.value)
end

function _G.addToAlexaCode(code,data)
  local result = Keystore.command({
    key = "AlexaCode",
    command = "hset",
    args = {code,to_json(data)}
  })
  return result
end

function _G.getAlexaCode(code)
  local result = Keystore.command({
    key = "AlexaCode",
    command = "hget",
    args = {code}
  })
  if result.value == nil then
    return nil
  end
  return from_json(result.value)
end
