import ast
import json
import requests
import time
import unittest
import xmlrunner
from random import randint
from mock import patch


class AKA8Test(unittest.TestCase):
    def setUp(self):
        self.CacheIdKeys = 'https://aka8.apps.exosite.io/cache/{id}/{keys}'
        self.CacheIdKey = 'https://aka8.apps.exosite.io/cache/{id}/{key}'
        self.CacheId = 'https://aka8.apps.exosite.io/cache/{id}'
        self.Tsdb = 'https://aka8.apps.exosite.io/tsdb/{query}'
        self.headers = {
            'content-type': 'application/json',
        }
        self.number = str(randint(0, 100))

    def test_GetCacheId(self):
        response = requests.get(self.CacheId.format(
            id='qimat'), headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_GetCacheIdKeys_humidity(self):
        response = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='humidity'), headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_GetCacheIdKeys_temp(self):
        data = '{"value":' + self.number + '}'
        response = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='temp'), headers=self.headers, data=data)
        self.assertEqual(response.status_code, 200)

    def test_GetTsdb(self):
        response = requests.get(
            self.Tsdb.format(query='{"metrics":["H01"], "limit":10}'), headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_PostCacheIdKey_humidity(self):
        resp = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='humidity'), headers=self.headers)
        dict = ast.literal_eval(resp.content).get('humidity')
        old_count = dict.get('count')
        old_sum = float(dict.get('sum'))
        data = '{"value":' + self.number + '}'
        response = requests.post(self.CacheIdKey.format(
            id='qimat', key='humidity'), headers=self.headers, data=data)
        resp = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='humidity'), headers=self.headers)
        dict = ast.literal_eval(resp.content).get('humidity')
        check_count = dict.get('count')
        new_sum = float(dict.get('sum'))
        check_sum = float(old_sum) + float(self.number)
        self.assertEqual(old_count+1, check_count)
        self.assertEqual(check_sum, new_sum)
        self.assertEqual(response.status_code, 200)

    def test_PostCacheIdKey_temp(self):
        resp = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='temp'), headers=self.headers)
        dict = ast.literal_eval(resp.content).get('temp')
        old_count = float(dict.get('count'))
        old_sum = float(dict.get('sum'))
        data = '{"value":' + self.number + '}'
        response = requests.post(self.CacheIdKey.format(
            id='qimat', key='temp'), headers=self.headers, data=data)
        resp = requests.get(self.CacheIdKeys.format(
            id='qimat', keys='temp'), headers=self.headers)
        dict = ast.literal_eval(resp.content).get('temp')
        check_count = dict.get('count')
        new_sum = float(dict.get('sum'))
        check_sum = float(old_sum) + float(self.number)
        self.assertEqual(old_count+1, check_count)
        self.assertEqual(check_sum, new_sum)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main(testRunner=xmlrunner.XMLTestRunner(
        output='test-reports'))
