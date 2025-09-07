from app import app
from flask import request

def handler(request):
    with app.app_context():
        response = app.full_dispatch_request()
        return response