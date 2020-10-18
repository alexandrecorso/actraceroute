
from flask_restplus import Resource, Namespace
from marshmallow import fields, Schema

from tools import schemas
from tools import utils

traceroute_ns = Namespace('traceroute', description="Traceroute endpoints")


class TracerouteDataSchema(Schema):
    is_valid = fields.Boolean(required=True)
    data = fields.List(fields.Nested(schemas.TraceICMPSchema), default=[])
    message = fields.String()


@traceroute_ns.route('/<string:destination>')
@traceroute_ns.route('/4/<string:destination>')
class Traceroute4(Resource):
    def get(self, destination):

        hop_list = utils.traceroute_ipv4(destination)
        if not hop_list:
            return TracerouteDataSchema().load({'is_valid': False})
        return TracerouteDataSchema().load({'is_valid': True, 'data': hop_list})


@traceroute_ns.route('/6/<string:destination>')
class Traceroute6(Resource):
    def get(self, destination):
        hop_list = utils.traceroute_ipv6(destination)
        if not hop_list:
            return TracerouteDataSchema().load({'is_valid': False})
        return TracerouteDataSchema().load({'is_valid': True, 'data': hop_list})


@traceroute_ns.route('/asn/<string:destination>')
@traceroute_ns.route('/4/asn/<string:destination>')
class Traceroute4ASN(Resource):
    def get(self, destination):
        hop_list = utils.traceroute_ipv4(destination, asn_lookup=True)
        if not hop_list:
            return TracerouteDataSchema().load({'is_valid': False})
        return TracerouteDataSchema().load({'is_valid': True, 'data': hop_list})


@traceroute_ns.route('/6/asn/<string:destination>')
class Traceroute6ASN(Resource):
    def get(self, destination):
        hop_list = utils.traceroute_ipv6(destination, asn_lookup=True)
        if not hop_list:
            return TracerouteDataSchema().load({'is_valid': False})
        return TracerouteDataSchema().load({'is_valid': True, 'data': hop_list})
