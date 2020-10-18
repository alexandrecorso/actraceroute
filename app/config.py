
import logging


class Config(object):
    DEBUG = False
    PORT = 5001
    HOST = '0.0.0.0'
    LOGGERS = {
        'tools.utils': logging.INFO
    }


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = 'development'
    LOGGERS = {
        'tools.utils': logging.DEBUG
    }


class ProductionConfig(Config):
    pass


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = 'testing'
