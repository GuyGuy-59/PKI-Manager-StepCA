from asgiref.wsgi import WsgiToAsgi

from app import app as flask_app

app = WsgiToAsgi(flask_app)
