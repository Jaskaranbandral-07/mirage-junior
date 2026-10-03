from flask import Flask
from dashboard.routes import dashboard_bp
import threading

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'mirage-junior-secret'
    app.register_blueprint(dashboard_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
