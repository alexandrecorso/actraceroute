
from marshmallow import fields, Schema


class PingSchema(Schema):
    destination = fields.String()
    ttl = fields.Integer()
    icmp_type = fields.Integer()
    time = fields.Float()


class TraceICMPSchema(Schema):
    destination = fields.String()
    ptr = fields.String(allow_none=True)
    asn = fields.String(allow_none=True)
    ttl = fields.Integer()
    icmp_type = fields.Integer()
    time = fields.Float()
