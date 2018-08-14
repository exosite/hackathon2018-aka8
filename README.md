# AKA8 Solution Template

**As know as shipData** - An application template in order to cache the aggredated or calculated device data faster and easier. Currently, it will cache the average, maximum, minimum, total count, and summary value for all data in.


```
getting-started-solution-template/
├── assets/index.html
├── endpoints/example.lua
├── modules/example.lua
├── services/<service_event>.lua | <service>.yaml
├── init.lua
└── murano.yaml
```

## Template format [murano.yaml](./murano.yaml)

**murano.yaml** is the only required component of a template and defines the solution resources.

### Required sections for the template

Section name  | Format | Example                                  | Description
--------------|--------|------------------------------------------|----------------------------------
formatversion | string | `formatversion: 1.0.0`                   | The format version of this file. Must be "1.0.0".
info          | object | [See in the info section](#info-section) | Metadata about this project.

### Optional sections for the template

Following sections are optional and their order is not enforced. If not specified related source files will be ignored. The different section sub-items are themself optional and default values are provided.
=======
Contents
=================

<!--ts-->
   * [AKA8 Solution Template](#aka8-solution-template)
   * [Table of Contents](#table-of-contents)
   * [Features](#features)
   * [Tech](#tech)
   * [Authors](#authors)
   * [Testing](#testing)
<!--te-->

## Features
### tsdb
Support the function of [TSDB](http://docs.exosite.com/reference/services/tsdb/) service .

```python
<solution-prefix>aka8.tsdb(query?)
```
### cacheIdKeys
Returns specific data for a specific device.
```python
<solution-prefix>aka8.cacheIdKeys({id=id, keys})
```
- `id`: string, identifier of the keys.
- `keys`: object, containing the following parameters:
   - `Count`: number, the number of reports.
   - `Last`: number, the value of the latest data.
   - `Min`: number, the minimum number of reported values.
   - `Max`: number, the maximum number of reported values.
   - `Sum`: number, the total number of reported values.
   - `Avg`: number, the average number of reported values.

### cacheIdKey
Enter specific data to a specific device.
```python
<solution-prefix>aka8.cacheIdKey({id=id, key, body={value}})
```
- `id`: string, identifier of the keys.
- `key`: string, the name of the key.
- `body`: object, containing the following parameters:
   - `value`: number, the value of the key.

### cacheId
Return the data of the specific id.
```python
<solution-prefix>aka8.cacheId({id=id})
```
- `id`: string, identifier of the keys.


## Tech
* [keystore](http://docs.exosite.com/reference/services/keystore/)
* [TSDB](http://docs.exosite.com/reference/services/tsdb/)
* [k6](https://k6.io/)


## Authors
See also the list of [contributors](https://github.com/exosite/hackathon2018-aka8/contributors) who participated in this project.

## Testing
* GetCacheId
To verify Get /method/id/key Success

* GetCacheIdKeys_humidity

* GetCacheIdKeys_temp

* GetTsdb

* PostCacheIdKey_humidity

* PostCacheIdKey_temp
