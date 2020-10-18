import json
import unittest

from application import create_app


class PingTest(unittest.TestCase):
    """
    Users Test Case
    """

    def setUp(self):
        """
        Test Setup
        """
        self.app = create_app()
        self.client = self.app.test_client

    def tearDown(self):
        pass

    def test_ping_4_valid(self):
        res = self.client().get('/api/ping/4/9.9.9.9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), dict)
        self.assertEqual(json_data.get('data').get('destination'), "9.9.9.9")
        self.assertEqual(json_data.get('data').get('icmp_type'), 0)

        res = self.client().get('/api/ping/4/acorso.fr')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), dict)
        self.assertEqual(json_data.get('data').get('destination'), "45.12.184.4")
        self.assertEqual(json_data.get('data').get('icmp_type'), 0)

    def test_ping_4_invalid(self):
        res = self.client().get('/api/ping/4/2001::1')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

        res = self.client().get('/api/ping/4/dontexist')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

    def test_ping_4_error(self):
        res = self.client().get('/api/ping/4/9.9.9.9/')
        self.assertEqual(res.status_code, 404)

        res = self.client().get('/api/ping/4/acorso.fr/')
        self.assertEqual(res.status_code, 404)

    def test_ping_6_valid(self):
        res = self.client().get('/api/ping/6/2620:fe::fe:9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), dict)
        self.assertEqual(json_data.get('data').get('destination'), "2620:fe::fe:9")
        self.assertEqual(json_data.get('data').get('icmp_type'), 129)

        res = self.client().get('/api/ping/6/acorso.fr')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), dict)
        self.assertEqual(json_data.get('data').get('destination'), "2a0e:b700::4")
        self.assertEqual(json_data.get('data').get('icmp_type'), 129)

    def test_ping_6_invalid(self):
        res = self.client().get('/api/ping/6/9.9.9.9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

        res = self.client().get('/api/ping/6/2001::1')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

        res = self.client().get('/api/ping/6/dontexist')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

    def test_ping_6_error(self):
        res = self.client().get('/api/ping/6/9.9.9.9/')
        self.assertEqual(res.status_code, 404)

        res = self.client().get('/api/ping/6/acorso.fr/')
        self.assertEqual(res.status_code, 404)
