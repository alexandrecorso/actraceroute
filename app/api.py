
from flask import Blueprint
from flask_restplus import Api

VERSION = "0.1"

api_blueprint = Blueprint('api', __name__, url_prefix='/api')

api = Api(
    api_blueprint,
    version=VERSION,
    title="ACTraceroute API",
    description="Network tools - ping/traceroute/etc",
)


def init_app(app):
    app.register_blueprint(api_blueprint)


def inject_global_vars():
    return dict(version=VERSION)


def add_context(app):
    app.context_processor(inject_global_vars)
