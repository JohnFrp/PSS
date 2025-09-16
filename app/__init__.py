from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from urllib.parse import quote_plus
import os

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Configuration - Load from config.py
    try:
        app.config.from_pyfile('config.py')
        
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        # Fallback to direct configuration
        password = "Johnh4k3r@123"
        encoded_password = quote_plus(password)
        # Database URI
        DATABASE_URI = DATABASE_URI = f"postgresql://postgres.okwpnjobjxrcxhtzvysw:{encoded_password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres"
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pharmacy-pos-secret-key')
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
       
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    
    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        try:
            return User.query.get(int(user_id))
        except:
            return None
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.inventory import inventory_bp
    from app.routes.sales import sales_bp
    from app.routes.customers import customers_bp
    from app.routes.reports import reports_bp
    from app.routes.main import main_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(inventory_bp)
    app.register_blueprint(sales_bp)
    app.register_blueprint(customers_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(main_bp)
    
    # Create tables and admin user
    with app.app_context():
        db.create_all()
        from app.utils.helpers import create_admin_user
        create_admin_user()
    
    return app