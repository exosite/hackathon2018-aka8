import unittest, time, json
import requests
from random import randint

class AKA8Test(unittest.TestCase):
    def setUp(self):
        self.CacheIdKeys = 'https://aka8.apps.exosite.io/cache/{id}/{keys}'
        self.CacheIdKey = 'https://aka8.apps.exosite.io/cache/{id}/{key}'
        self.CacheId = 'https://aka8.apps.exosite.io/cache/{id}'
        self.Tsdb = 'https://aka8.apps.exosite.io/tsdb'
        self.headers = {
            'content-type': 'application/json',
        }
        self.number = str(randint(0, 100))

    def test_GetCacheId(self):
        print('\n**** GetCacheId ****')
        response = requests.get(self.CacheId.format(id='qimat'), headers=self.headers)
        print(response.json())
        self.assertEqual(response.status_code, 200)

    def test_GetCacheIdKeys_humidity(self):
        print('\n**** GetCacheIdKeys(humidity) ****')
        response = requests.get(self.CacheIdKeys.format(id='qimat', keys='humidity'),headers=self.headers)
        print(response.json())
        self.assertEqual(response.status_code, 200)

    def test_GetCacheIdKeys_temp(self):
        print('\n**** GetCacheIdKeys(temp) ****')
        data = '{"value":'+self.number+'}'
        response = requests.get(
            self.CacheIdKeys.format(id='qimat', keys='temp'),
            headers=self.headers, data=data)
        print(response.json())
        self.assertEqual(response.status_code, 200)

    def test_GetTsdb(self):
        print('\n**** GetTsdb ****')
        params = (
            ('query', '{"metrics":["H01"], "limit":10}'),
        )
        response = requests.get(
            'https://aka8.apps.exosite.io/tsdb', params=params, headers=self.headers)
        print(response.content)
        self.assertEqual(response.status_code, 200)

    def test_PostCacheIdKey_humidity(self):
        print('\n**** PostCacheIdKey(humidity) ****')
        data = '{"value":'+self.number+'}'
        response = requests.post(
            self.CacheIdKey.format(id='qimat', key='humidity'),
            headers=self.headers, data=data)
        print(response.json())
        self.assertEqual(response.status_code, 200)

    def test_PostCacheIdKey_temp(self):
        print('\n**** PostCacheIdKey(temp) ****')
        data = '{"value":'+self.number+'}'
        response = requests.post(
            self.CacheIdKey.format(id='qimat', key='temp'),
            headers=self.headers, data=data)
        print(response.json())
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()