
from flask import Blueprint

home_blueprint = Blueprint('home', __name__, template_folder='templates')


@home_blueprint.route('/')
def home():
    return "Welcome to ACTraceroute -> /api"
