from flask import Flask, request, make_response
from dashboard.routes import dashboard_bp

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'mirage-junior-secret'
    app.register_blueprint(dashboard_bp)

    @app.before_request
    def handle_api_preflight():
        if request.method == 'OPTIONS' and request.path.startswith('/api/'):
            resp = make_response('', 204)
            resp.headers['Access-Control-Allow-Origin'] = '*'
            resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            return resp

    @app.after_request
    def add_cors_headers(response):
        if request.path.startswith('/api/'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
