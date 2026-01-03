
import os
import sys
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()


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
    
    # ← THIS LINE IS MISSING! Add it here:
    migrate.init_app(app, db)   # ← Critical fix!

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
        # Register blueprint first — always needed
        from routes import routes
        app.register_blueprint(routes)

        # === ONLY create admin user when NOT running migration commands ===
        # sys.argv contains the command line args, e.g. ['flask', 'db', 'migrate']
        if 'db' not in sys.argv and 'flask' in sys.argv[0]:
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
            else:
                print("Admin user already exists.")

    return app

