from api import api


def init_app(app):

    from resources import home
    app.register_blueprint(home.home_blueprint)

    from resources import ping
    api.add_namespace(ping.ping_ns)

    from resources import traceroute
    api.add_namespace(traceroute.traceroute_ns)
