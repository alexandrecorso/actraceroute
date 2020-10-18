
import ipaddress
import logging
import socket

import dns.resolver
from ipwhois import IPWhois
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1
from scapy.volatile import RandInt, RandShort

from .errors import UnknownError

logger = logging.getLogger(__name__)

TIMEOUT = 1.


def resolve_domain_to_ipv4(domain):
    """
    Resolve the domain to the first IPv4 found
    :param domain: String
    :return: String (IPv4) or None
    """
    return _resolve_type_with_first_item(domain, dns_type='A')


def resolve_domain_to_ipv6(domain):
    """
    Resolve the domain to the first IPv6 found
    :param domain: String
    :return: String (IPv6) or None
    """
    return _resolve_type_with_first_item(domain, dns_type='AAAA')


def resolve_ip_to_ptr(ip):
    """
    :param ip:
    :return:
    """
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return
    return _resolve_type_with_first_item(ip_address.reverse_pointer, dns_type='PTR')


def _resolve_type_with_first_item(query, dns_type='A'):
    """
    Find the A or AAAA value of the domain
    :param query: String
    :param dns_type: String (A or AAAA)
    :return: String or None
    """
    if not query:
        return
    try:
        data = dns.resolver.resolve(query, dns_type, lifetime=TIMEOUT)
    except dns.resolver.NXDOMAIN:
        return
    except dns.resolver.NoAnswer:
        return
    except dns.exception.Timeout:
        return
    except dns.resolver.NoNameservers:
        return
    if not data:
        return
    # If there is no anwser - Exception above
    if dns_type == "A" or dns_type == "AAAA":
        return data.rrset[0].address
    elif dns_type == "PTR":
        return data.rrset[0].to_text()
    else:
        return


def get_asn(ip_address):
    """
    Get the ASN from the IP address if this one is global
    :param ip_address:
    :return:
    """
    try:
        ip_address = ipaddress.ip_address(ip_address)
        if not ip_address.is_global:
            return
        asn_lookup = IPWhois(ip_address.compressed).ipasn.lookup()
        if not asn_lookup:
            return
        return asn_lookup.get("asn")
    except ValueError:
        return


def ping4(destination, resolve=False):
    """
    Ping (ICMP) to a destination.
    :param destination: String (IPv4)
    :param resolve
    :return: Dict or None
    """
    if not destination:
        return
    try:
        icmp = IP(dst=destination) / ICMP()
    except socket.gaierror:
        logger.error(f"Cannot create the packet due to resolve: {destination}")
        return
    logger.debug(f"ICMP packet: {icmp.summary()}")
    try:
        logger.debug("Sending ICMP packet")
        response = sr1(icmp, timeout=TIMEOUT, verbose=False)
        logger.debug("ICMP packet sent")
    except Exception as e:
        logger.error(e)
        return

    if response:
        logger.debug("ICMP response received")
        # Scapy get only ICMP result (can be OK or TTL or others)
        # scapy.layers.inet.icmptypes -> 0: 'echo-reply'
        if response.type == 0:
            logger.debug("ICMP 'echo-reply' received")

            value = {
                # 'destination': destination
                'destination': response.src,
                'ttl': response.ttl,
                'icmp_type': response.type,
                # Time in second -> *1000 -> ms
                'time': (response.time - icmp.sent_time) * 1000
            }
            if resolve:
                value['ptr'] = resolve_ip_to_ptr(response.src)
            return value

        # scapy.layers.inet.icmptypes -> 11: 'time-exceeded'
        elif response.type == 11:
            logger.debug("ICMP 'time-exceeded' received")
            # raise TimeExceeded(destination)
            return
        else:
            logger.debug(f"Something received: {response.summary()}")
            raise UnknownError()
    else:
        logger.debug(f"Nothing received (within {TIMEOUT} secondes)")
        return


def ping6(destination, resolve=False):
    """
    Ping (ICMPv6) to a destination.
    :param destination: String (IPv6)
    :param resolve
    :return: Dict or None
    """
    if not destination:
        return

    try:
        icmpv6 = IPv6(dst=destination) / ICMPv6EchoRequest()
    except socket.gaierror:
        logger.error(f"Cannot create the packet due to resolve: {destination}")
        return
    logger.debug(f"ICMPv6 packet: {icmpv6.summary()}")
    try:
        logger.debug("Sending ICMPv6 packet")
        response = sr1(icmpv6, timeout=TIMEOUT, verbose=False)
        logger.debug("ICMPv6 packet sent")
    except Exception as e:
        logger.error(e)
        return

    if response:
        logger.debug("ICMPv6 response received")
        # Scapy get only ICMP result (can be OK or TTL or others)
        # scapy.layers.inet6.icmp6types -> 129: 'Echo Reply'
        if response.type == 129:
            logger.debug(f"ICMPv6 'Echo Reply' received: {response.summary()}")

            value = {
                # 'destination': destination
                'destination': response.src,
                'ttl': response.hlim,
                'icmp_type': response.type,
                # Time in second -> *1000 -> ms
                'time': (response.time - icmpv6.sent_time) * 1000
            }
            if resolve:
                value['ptr'] = resolve_ip_to_ptr(response.src)
            return value
        # scapy.layers.inet6.icmp6types-> 3: 'Time exceeded',
        elif response.type == 3:
            logger.debug("ICMPv6 'Time exceeded' received")
            # raise TimeExceeded(destination)
            return
        else:
            logger.debug(f"Something received: {response.summary()}")
            raise UnknownError()
    else:
        logger.debug("Nothing received")
        return


def traceroute_ipv4(destination, hops=20, resolve=False, asn_lookup=False):
    """
    Traceroute (ICMP) to a destination.
    :param destination: String (IPv4)
    :param resolve: Boolean (Reverse DNS the IP)
    :param hops: Number of maximum HOP
    :param asn_lookup: Boolean (find ASN)
    :return: Dict or None
    """
    try:
        ip_address = ipaddress.IPv4Address(destination)
        return traceroute_icmp_ipv4(ip_address.compressed, hops=hops, resolve=resolve, asn_lookup=asn_lookup)
    except ValueError:
        ip_address = resolve_domain_to_ipv4(destination)
        return traceroute_icmp_ipv4(ip_address, hops=hops, resolve=resolve, asn_lookup=asn_lookup)


def traceroute_ipv6(destination, hops=20, resolve=False, asn_lookup=False):
    """
    Traceroute (ICMP) to a destination.
    :param destination: String (IPv6)
    :param resolve: Boolean (Reverse DNS the IP)
    :param hops: Number of maximum HOP
    :param asn_lookup: Boolean (find ASN)
    :return: Dict or None
    """
    try:
        ip_address = ipaddress.IPv6Address(destination)
        return traceroute_icmp_ipv6(ip_address.compressed, hops=hops, resolve=resolve, asn_lookup=asn_lookup)
    except ValueError:
        ip_address = resolve_domain_to_ipv6(destination)
        return traceroute_icmp_ipv6(ip_address, hops=hops, resolve=resolve, asn_lookup=asn_lookup)


def traceroute_icmp_ipv4(destination, hops=20, resolve=False, asn_lookup=False):
    """
    Traceroute (ICMP) to a destination.
    :param destination: String (IPv4)
    :param resolve: Boolean (Reverse DNS the IP)
    :param hops: Number of maximum HOP
    :param asn_lookup: Boolean (find ASN)
    :return: Dict or None
    """
    if not destination:
        return
    values = []
    for i in range(1, hops + 1):
        try:
            icmp = IP(dst=destination, ttl=i) / ICMP(type='echo-request')
            logger.debug(f"ICMP packet: {icmp.summary()}")
        except socket.gaierror:
            logger.error(f"Cannot create the packet due to resolve: {destination}")
            return
        logger.debug("Sending ICMP packet")
        try:
            response = sr1(icmp, timeout=TIMEOUT, verbose=False)
        except Exception as e:
            logger.error(e)
            return
        logger.debug("ICMP packet sent")

        if response:
            logger.debug("ICMP response received")

            # Scapy get only ICMP result (can be OK or TTL or others)
            # scapy.layers.inet.icmptypes -> 0: 'echo-reply'
            # scapy.layers.inet.icmptypes -> 11: 'time-exceeded'
            if response.type == 0 or response.type == 11:
                logger.debug("ICMP 'echo-reply' received")
                value = {
                    # 'destination': destination
                    'destination': response.src,
                    'ttl': i,
                    'icmp_type': response.type,
                    # Time in second -> *1000 -> ms
                    'time': (response.time - icmp.sent_time) * 1000
                }
                if resolve:
                    value['ptr'] = resolve_ip_to_ptr(response.src)

                if asn_lookup:
                    value['asn'] = get_asn(response.src)

                values.append(value)
            else:
                logger.debug(f"Something received: {response.summary()}")
                # raise UnknownError()

            # End of the traceroute
            if response.src == destination:
                break
        else:
            logger.debug(f"Nothing received (within {TIMEOUT} secondes)")
            values.append({'ttl': i})
    return values


def traceroute_icmp_ipv6(destination, hops=20, resolve=False, asn_lookup=False):
    """
    Traceroute (ICMP) to a destination.
    :param destination: String (IPv4)
    :param resolve: Boolean (Reverse DNS the IP)
    :param hops: Number of maximum HOP
    :param asn_lookup: Boolean (find ASN)
    :return: Dict or None
    """
    if not destination:
        return
    values = []

    for i in range(1, hops + 1):
        try:
            icmpv6 = IPv6(dst=destination, hlim=i) / ICMPv6EchoRequest()
            logger.debug(f"ICMPv6 packet: {icmpv6.summary()}")
        except socket.gaierror:
            logger.error(f"Cannot create the packet due to resolve: {destination}")
            return
        logger.debug("Sending ICMPv6 packet")
        try:
            response = sr1(icmpv6, timeout=TIMEOUT, verbose=False)
        except Exception as e:
            logger.error(e)
            return
        logger.debug("ICMPv6 packet sent")

        if response:
            logger.debug(f"ICMPv6 response received {response.summary()}")

            # Scapy get only ICMP result (can be OK or TTL or others)
            # scapy.layers.inet6.icmp6types -> 129: 'Echo Reply'
            # scapy.layers.inet6.icmp6types -> 3: 'ICMPv6TimeExceeded'
            if response.type == 129 or response.type == 3:
                logger.debug("ICMP 'echo-reply' received")
                value = {
                    # 'destination': destination
                    'destination': response.src,
                    'ttl': i,
                    'icmp_type': response.type,
                    # Time in second -> *1000 -> ms
                    'time': (response.time - icmpv6.sent_time) * 1000
                }

                if resolve:
                    value['ptr'] = resolve_ip_to_ptr(response.src)

                if asn_lookup:
                    value['asn'] = get_asn(response.src)

                values.append(value)
            else:
                logger.debug(f"Something received: {response.summary()}")
                # raise UnknownError()

            # End of the traceroute
            # Destination or resolver
            if response.src == destination:
                break
        else:
            logger.debug(f"Nothing received (within {TIMEOUT} secondes)")
            values.append({'ttl': i})
    return values


def traceroute_tcp_ipv6(destination, hops=20, resolve=False, sport=RandShort(), dport=80):
    """
    Traceroute (ICMP) to a destination.
    :param destination: String (IPv4)
    :param resolve: Boolean (Reverse DNS the IP)
    :param hops: Number of maximum HOP
    :param sport:
    :param dport:
    :return: Dict or None
    """
    if not destination:
        return
    values = []

    for i in range(1, hops + 1):
        try:
            packet_tcp = IPv6(dst=destination, hlim=i) / TCP(seq=RandInt(), sport=sport, dport=dport)
            logger.debug(f"TCP packet: {packet_tcp.summary()}")
        except socket.gaierror:
            logger.error(f"Cannot create the packet due to resolve: {destination}")
            return
        logger.debug("Sending TCP packet")
        try:
            response = sr1(packet_tcp, timeout=TIMEOUT, verbose=False, filter="icmp6 or tcp")
        except Exception as e:
            logger.error(e)
            return
        logger.debug("TCP packet sent")

        if response:
            logger.debug(f"TCP response received {response.summary()}")

            if resolve:
                ptr = resolve_ip_to_ptr(response.src)
            else:
                ptr = None

            # Scapy get only ICMP result (can be OK or TTL or others)
            # scapy.layers.inet6.icmp6types -> 129: 'Echo Reply'
            # scapy.layers.inet6.icmp6types -> 3: 'ICMPv6TimeExceeded'
            if response.type == 129 or response.type == 3:
                logger.debug("ICMP 'echo-reply' received")
                value = {
                    # 'destination': destination
                    'destination': response.src,
                    'ptr': ptr,
                    'ttl': i,
                    'icmp_type': response.type,
                    # Time in second -> *1000 -> ms
                    'time': (response.time - packet_tcp.sent_time) * 1000
                }
                values.append(value)
            else:
                logger.debug(f"Something received: {response.summary()}")
                # raise UnknownError()

            # End of the traceroute
            # Destination or resolver
            if response.src == destination:
                break
        else:
            logger.debug(f"Nothing received (within {TIMEOUT} secondes)")
            values.append({'ttl': i})
    return values
