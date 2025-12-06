
import os
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(
        __name__,   
        template_folder='context/templates',
        static_folder='context/static'
    )

    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-key-change-this-in-production")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # These two lines are still needed
    app.template_folder = 'context/templates'
    app.static_folder = 'context/static'

    # Initialize extensions with app
    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = 'routes.login'
    login_manager.login_message_category = "info"

    # Import User only after db is initialized
    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # === THIS BLOCK MUST BE INSIDE create_app() and properly indented ===
    with app.app_context():
        db.create_all()  # Create tables

        # Create admin user if doesn't exist
        if not User.query.filter_by(username='admin').first():
            from werkzeug.security import generate_password_hash
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created → username: admin | password: admin123")

        # Register the blueprint (routes)
        from routes import routes
        app.register_blueprint(routes)

    return app

