import logging
import os

from flask import Flask
from flask.logging import default_handler
# from werkzeug.middleware.proxy_fix import ProxyFix

CONFIG_MAPPER = {
    'development': 'config.DevelopmentConfig',
    'testing': 'config.TestingConfig',
    'production': 'config.ProductionConfig',
}


def configure_loggers(app):
    loggers = app.config.get("LOGGERS")
    for logger_name, logger_value in loggers.items():
        root_logger = logging.getLogger(logger_name)
        root_logger.addHandler(default_handler)
        root_logger.setLevel(logger_value)


def create_app():
    flask_env = os.getenv('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(CONFIG_MAPPER.get(flask_env, 'development'))

    configure_loggers(app)

    import api
    api.init_app(app)
    api.add_context(app)

    import resources
    resources.init_app(app)

    # app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    return app
