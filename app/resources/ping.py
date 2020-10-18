
from flask_restplus import Resource, Namespace
from marshmallow import fields, Schema

from tools import schemas
from tools import utils

ping_ns = Namespace('ping', description="Ping endpoints")


class PingDataSchema(Schema):
    is_valid = fields.Boolean(required=True)
    data = fields.Nested(schemas.PingSchema)
    message = fields.String()


@ping_ns.route('/<string:destination>', doc={"description": "Alias for /api/ping/4/<destination>"})
@ping_ns.route('/4/<string:destination>')
class Ping4(Resource):

    def get(self, destination):

        data = utils.ping4(destination)
        if not data:
            return PingDataSchema().load({'is_valid': False})
        return PingDataSchema().load({'is_valid': True, 'data': data})


@ping_ns.route('/6/<string:destination>')
class Ping6(Resource):

    def get(self, destination):
        data = utils.ping6(destination)
        if not data:
            return PingDataSchema().load({'is_valid': False})
        return PingDataSchema().load({'is_valid': True, 'data': data})


@ping_ns.route('/4/<string:destination>')
class Ping4PTR(Resource):

    def get(self, destination):

        data = utils.ping4(destination, resolve=True)
        if not data:
            return PingDataSchema().load({'is_valid': False})
        return PingDataSchema().load({'is_valid': True, 'data': data})


@ping_ns.route('/6/<string:destination>')
class Ping6PTR(Resource):

    def get(self, destination):
        data = utils.ping6(destination, resolve=True)
        if not data:
            return PingDataSchema().load({'is_valid': False})
        return PingDataSchema().load({'is_valid': True, 'data': data})
