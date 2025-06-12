from routes.account import account_bp
from routes.emails import email_bp
from routes.vue_routes import vue_bp
from routes.graph import graph_bp

def register_routes(app):
    app.register_blueprint(account_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(vue_bp)
    app.register_blueprint(graph_bp)
