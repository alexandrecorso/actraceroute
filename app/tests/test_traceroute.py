import json
import unittest

from application import create_app


class TracerouteTest(unittest.TestCase):
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

    def test_traceroute_4_valid(self):
        res = self.client().get('/api/traceroute/4/9.9.9.9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), list)
        data = json_data.get('data')
        self.assertEqual(data[len(data) - 1].get("destination"), "9.9.9.9")
        self.assertEqual(data[len(data) - 1].get("icmp_type"), 0)

        res = self.client().get('/api/traceroute/4/acorso.fr')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), list)
        data = json_data.get('data')
        self.assertEqual(data[len(data) - 1].get("destination"), "45.12.184.4")
        self.assertEqual(data[len(data) - 1].get("icmp_type"), 0)

    def test_traceroute_4_invalid(self):
        res = self.client().get('/api/traceroute/4/2001::1')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

        res = self.client().get('/api/traceroute/4/dontexist')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

    def test_traceroute_4_error(self):
        res = self.client().get('/api/traceroute/4/9.9.9.9/')
        self.assertEqual(res.status_code, 404)
        res = self.client().get('/api/traceroute/4/acorso.fr/')
        self.assertEqual(res.status_code, 404)

    def test_traceroute_6_valid(self):
        res = self.client().get('/api/traceroute/6/2620:fe::fe:9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), list)
        data = json_data.get('data')
        self.assertEqual(data[len(data) - 1].get("destination"), "2620:fe::fe:9")
        self.assertEqual(data[len(data) - 1].get("icmp_type"), 129)

        res = self.client().get('/api/traceroute/6/acorso.fr')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertTrue(json_data.get('is_valid'))
        self.assertIsInstance(json_data.get('data'), list)
        data = json_data.get('data')
        self.assertEqual(data[len(data) - 1].get("destination"), "2a0e:b700::4")
        self.assertEqual(data[len(data) - 1].get("icmp_type"), 129)

    def test_traceroute_6_invalid(self):
        res = self.client().get('/api/traceroute/6/9.9.9.9')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

        res = self.client().get('/api/traceroute/6/dontexist')
        self.assertEqual(res.status_code, 200)
        json_data = json.loads(res.data)
        self.assertFalse(json_data.get('is_valid'))

    def test_traceroute_6_error(self):
        res = self.client().get('/api/traceroute/6/9.9.9.9/')
        self.assertEqual(res.status_code, 404)
        res = self.client().get('/api/traceroute/6/acorso.fr/')
        self.assertEqual(res.status_code, 404)