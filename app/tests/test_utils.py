import unittest

from app.tools import utils


class TestResolveDomainIpv4(unittest.TestCase):

    def test_valid_resolver(self):
        self.assertEqual(utils.resolve_domain_to_ipv4("acorso.fr"), "45.12.184.4")
        self.assertEqual(utils.resolve_domain_to_ipv4("www.python.org"), "151.101.120.223")

    def test_invalid_resolver(self):
        self.assertNotEqual(utils.resolve_domain_to_ipv4("acorso.fr"), "45.12.184.0")
        self.assertNotEqual(utils.resolve_domain_to_ipv4("one.one.one.one"), "2.2.2.2")

    def test_not_found_resolver(self):
        self.assertIsNone(utils.resolve_domain_to_ipv4("acorso1.fr"))
        self.assertIsNone(utils.resolve_domain_to_ipv4("nothing"))
        self.assertIsNone(utils.resolve_domain_to_ipv4("1.1.1.1"))
        self.assertIsNone(utils.resolve_domain_to_ipv4("2001:db8::1"))

    def test_empty_resolver(self):
        self.assertIsNone(utils.resolve_domain_to_ipv4(None))


class TestResolveDomainIpv6(unittest.TestCase):

    def test_valid_resolver(self):
        self.assertEqual(utils.resolve_domain_to_ipv6("www.python.org"), "2a04:4e42:1d::223")
        self.assertEqual(utils.resolve_domain_to_ipv6("smokeping.acorso.fr"), "2a0e:b700::4")

    def test_invalid_resolver(self):
        self.assertNotEqual(utils.resolve_domain_to_ipv6("one.one.one.one"), "2001:db8::1")
        self.assertNotEqual(utils.resolve_domain_to_ipv6("dns9.quad9.net"), "2001:db8::1")

    def test_not_found_resolver(self):
        self.assertIsNone(utils.resolve_domain_to_ipv6("acorso1.fr"))
        self.assertIsNone(utils.resolve_domain_to_ipv6("nothing"))
        self.assertIsNone(utils.resolve_domain_to_ipv6("1.1.1.1"))
        self.assertIsNone(utils.resolve_domain_to_ipv6("2620:fe::fe:9"))

    def test_empty_resolver(self):
        self.assertIsNone(utils.resolve_domain_to_ipv6(None))


class TestPingIpv4(unittest.TestCase):

    def test_valid_ping(self):
        data = utils.ping4("45.12.184.128")
        self.assertEqual(data.get("destination"), "45.12.184.128")
        self.assertEqual(data.get("icmp_type"), 0)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping4("45.12.184.128", resolve=True)
        self.assertEqual(data.get("destination"), "45.12.184.128")
        self.assertEqual(data.get("ptr"), "as35085.ac.acorso.fr.")
        self.assertEqual(data.get("icmp_type"), 0)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping4("9.9.9.9")
        self.assertEqual(data.get("destination"), "9.9.9.9")
        self.assertEqual(data.get("icmp_type"), 0)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping4("9.9.9.9", resolve=True)
        self.assertEqual(data.get("destination"), "9.9.9.9")
        self.assertEqual(data.get("ptr"), "dns9.quad9.net.")
        self.assertEqual(data.get("icmp_type"), 0)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

    def test_timeout(self):
        self.assertIsNone(utils.ping4("45.12.184.133"))

    def test_invalid_ping(self):
        self.assertIsNone(utils.ping4("doekodkoek"))
        self.assertIsNone(utils.ping4(None))


class TestPingIpv6(unittest.TestCase):

    def test_valid_ping(self):
        data = utils.ping6("2a0e:b700::1")
        self.assertEqual(data.get("destination"), "2a0e:b700::1")
        self.assertEqual(data.get("icmp_type"), 129)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping6("2001:4860:4860::8844", resolve=True)
        self.assertEqual(data.get("destination"), "2001:4860:4860::8844")
        self.assertEqual(data.get("ptr"), "dns.google.")
        self.assertEqual(data.get("icmp_type"), 129)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping6("2a00:a4c0:1:1::69")
        self.assertEqual(data.get("destination"), "2a00:a4c0:1:1::69")
        self.assertEqual(data.get("icmp_type"), 129)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

        data = utils.ping6("2620:fe::9", resolve=True)
        self.assertEqual(data.get("destination"), "2620:fe::9")
        self.assertEqual(data.get("ptr"), "dns9.quad9.net.")
        self.assertEqual(data.get("icmp_type"), 129)
        self.assertTrue(data.get("ttl"))
        self.assertTrue(data.get("time"))

    def test_timeout(self):
        self.assertIsNone(utils.ping6("2620:fe::1"))

    def test_invalid_ping(self):
        self.assertIsNone(utils.ping6("doekodkoek"))
        self.assertIsNone(utils.ping6(None))
