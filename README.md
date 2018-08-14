![](https://i.imgur.com/fwsM0gZ.jpg)

# AKA8 Solution Template

**As know as shipData** - An application template in order to cache the aggregated or calculated device data faster and easier. Currently, it will cache the average, maximum, minimum, total count, and summary value for all data in.

# Contents

- [Features](#features)
  - [getCacheIdKeys](#getcacheidkeys)
  - [getCacheId](#getcacheid)
  - [getTsdbQuery](#gettsdbquery)
  - [postCacheIdKey](#postcacheidkey)
- [Tech](#tech)
- [Authors](#authors)
- [Testing](#testing)

## Features

### getCacheIdKeys

Returns specific data for a specific device.

#### Arguments

| Name | Type   | Description                         | Required |
| ---- | ------ | ----------------------------------- | :------: |
| id   | String | Identifier of the keys.             |   Yes    |
| keys | String | Sensor of string use ',' split that |   Yes    |

#### Example

```lua=
local ret = aka8.getCacheIdKeys({
  {
    id="Test001",
    keys="H01,AAA,Temp"
  }
})

return ret
```

#### Response

| Name   | Type    | Description           |
| ------ | ------- | --------------------- |
| status | Integer | [200] success;        |
| value  | Number  | The calculated result |
| error  | String  | Error message         |

```json=
{
  "H01": {
    "avg": 15789.257858068697,
    "count": 24688,
    "last": 1,
    "max": 28750,
    "min": -10,
    "sum": 389805198
  },
  "AAA": {
    "avg": 15789.257858068697,
    "count": 24688,
    "last": 1,
    "max": 28750,
    "min": -10,
    "sum": 389805198
  },
  "Temp": {
    "avg": 15789.257858068697,
    "count": 24688,
    "last": 1,
    "max": 28750,
    "min": -10,
    "sum": 389805198
  }
}
```

### getCacheId

Return the data of the specific id.

#### Arguments

| Name | Type   | Description             | Required |
| ---- | ------ | ----------------------- | :------: |
| id   | String | Identifier of the keys. |   Yes    |

#### Example

```lua=
local ret = aka8.getCacheId({
  id="Test001"
})

return ret
```

#### Response

| Name   | Type    | Description           |
| ------ | ------- | --------------------- |
| status | Integer | [200] success;        |
| value  | Number  | The calculated result |
| error  | String  | Error message         |

```json=
{
  "H01": {
    "avg": 15789.257858068697,
    "count": 24688,
    "last": 1,
    "max": 28750,
    "min": -10,
    "sum": 389805198
  },
  "H03": {
    "avg": 15799.924893487523,
    "count": 24645,
    "last": 28750,
    "max": 28750,
    "min": 1,
    "sum": 389389149
  },
  "H04": {
    "avg": 15816.28009986309,
    "count": 24834,
    "last": 28751,
    "max": 28751,
    "min": 1,
    "sum": 392781500
  },
  "temp": {
    "avg": 0.9539817821886839,
    "count": 21,
    "last": 0.2057041382542372,
    "max": 10,
    "min": 0.034124198646731774,
    "sum": 20.033617425962362
  }
}
```

### getTsdbQuery

Support the function of [TSDB](http://docs.exosite.com/reference/services/tsdb/) service .

#### Arguments

| Name  | Type   | Description                                                         | Required |
| ----- | ------ | --------------------------------------------------------------------| :------: |
| query | String | See [query](http://docs.exosite.com/reference/services/tsdb/#query) |   Yes    |

#### Example

```lua=
local ret = aka8.getTsdbQuery({
  query=to_json({
    metrics={
      "H01"
    }
  })
})

return ret
```

#### Response

| Name   | Type    | Description           |
| ------ | ------- | --------------------- |
| status | Integer | [200] success;        |
| value  | Number  | The calculated result |
| error  | String  | Error message         |

```json=
{
  "columns": ["time", "H01"],
  "metrics": ["H01"],
  "tags": {},
  "values": [
    ["2018-08-14T02:31:00.184945+00:00", 1],
    ["2018-08-14T02:30:59.733304+00:00", 28750],
    ["2018-08-14T02:30:59.138229+00:00", 28749],
    ["2018-08-14T02:30:58.324533+00:00", 28748]
  ]
}
```

### postCacheIdKey

Enter specific data to a specific device.

#### Arguments

| Name       | Type   | Description             | Required |
| ---------- | ------ | ----------------------- | :------: |
| id         | String | Identifier of the keys. |   Yes    |
| key        | String | The name of the key.    |   Yes    |
| body       | Object |                         |   Yes    |
| body.value | Number | The value of the key.   |   Yes    |

#### Example

```lua=
local ret = aka8.postCacheIdKey({
  id="Test001",
  key="H01",
  body={
    value=100
  }
})

return ret
```

#### Response

| Name   | Type    | Description           |
| ------ | ------- | --------------------- |
| status | Integer | [200] success;        |
| value  | Number  | The calculated result |
| error  | String  | Error message         |

```json=
{
  "kv": {
    "value": 0
  },
  "tsdb": {
    "status": 204,
    "status_code": 204
  }
}
```

## Tech

- [keyStore](http://docs.exosite.com/reference/services/keystore/)
- [TSDB](http://docs.exosite.com/reference/services/tsdb/)
- [k6](https://k6.io/)

## Authors

See also the list of [contributors](https://github.com/exosite/hackathon2018-aka8/contributors) who participated in this project.

## Testing

```shell
test/
├── unit/
├── e2e/
|    └── AKA8Test.py
└── k6/
     ├── device.csv
     └── script.js
```

### Unit Test

### End-To-End Test

#### How To Use

- Output Report

report file will export in `<folder>/test-reports/`

```shell
python <filename>.py
```

- Output only on console

```shell
python -m unittest <filename>.<ClassName>
```

#### Test Case

- GetCacheId

```
Get /cache/{id}
```

- GetCacheIdKeys_humidity

```
Get /cache/{id}/humidity
```

- GetCacheIdKeys_temp

```
 Get /cache/{id}/temp
```

- GetTsdbQuery

```
Get /tsdb/{query}
```

- PostCacheIdKey_humidity

```
Post /cache/{id}/humidity
```

- PostCacheIdKey_temp

```
Post /cache/{id}/temp
```

### Performance Test

- device.csv
  the list of device for testing

| Name   | Type   | Description |
| ------ | ------ | ----------- |
| device | string | device name |

- script.js
  the script file for performance test
