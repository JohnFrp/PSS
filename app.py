from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
import pandas as pd
import os
import re
from io import BytesIO
import json
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import quote_plus
from sqlalchemy import func, and_, or_, inspect, text
from sqlalchemy.orm import joinedload
from functools import wraps  # Added missing import


# Initialize SQLAlchemy
db = SQLAlchemy()

# Password with special characters must be URL-encoded
password = "Johnh4k3r@123"
encoded_password = quote_plus(password)

# Database URI
#DATABASE_URI = f"postgresql://postgres:{encoded_password}@db.okwpnjobjxrcxhtzvysw.supabase.co:5432/postgres"
DATABASE_URI = "postgresql://db_fl3y_user:CtXcM94mT7Y78odOTyjklU49GoeTsb4O@dpg-d2vr12n5r7bs73anq23g-a.oregon-postgres.render.com/db_fl3y"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pharmacy-pos-secret-key')
    
    # Configure the database URI
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize the app with the extension
    db.init_app(app)
    migrate = Migrate(app, db)

     # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        # Create tables if they don't exist
        try:
            db.create_all()
            print("✅ Tables created successfully!")
        except Exception as e:
            print(f"❌ Error creating tables: {str(e)}")
        
        # Create admin user if no users exist
        if User.query.count() == 0:
            try:
                admin_user = User(
                    username='admin',
                    email='admin@pharmacy.com',
                    role='admin'
                )
                # Use a simpler password hashing method to ensure it fits
                admin_user.set_password('admin123', method='pbkdf2:sha256')  # Change this in production!
                
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created: username='admin', password='admin123'")
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error creating admin user: {str(e)}")
    
    return app


# Add User model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Increased length for password hash
    role = db.Column(db.String(20), default='user', nullable=False)  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, server_default=func.now())
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    def set_password(self, password, method='pbkdf2:sha256'):
        # Use a method that generates shorter hashes by default
        self.password_hash = generate_password_hash(password, method=method)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def __repr__(self):
        return f'<User {self.username}>'

# Define models
class Medication(db.Model):
    __tablename__ = 'medications'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    generic_name = db.Column(db.String(255), nullable=True)
    manufacturer = db.Column(db.String(255), nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    barcode = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationship to sales
    sales = db.relationship('Sale', backref='medication', lazy=True)

    def __repr__(self):
        return f"<Medication {self.name}>"


# Add these after the models
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Administrator access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def login_required_with_redirect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


class Sale(db.Model):
    __tablename__ = 'sales'

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)
    medication_id = db.Column(db.Integer, db.ForeignKey('medications.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    sale_date = db.Column(db.DateTime, server_default=func.now())

    def __repr__(self):
        return f"<Sale {self.transaction_id}>"


# Create app
app = create_app()

# Helper Functions
def get_sales_summary():
    # Total medications
    total_medications = Medication.query.count()
    
    # Low stock count
    low_stock_count = Medication.query.filter(Medication.stock_quantity <= 10).count()
    
    # Expired medications count
    expired_count = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < datetime.now().date()
        )
    ).count()
    
    # Today's sales
    today = datetime.now().date()
    today_sales = db.session.query(
        func.coalesce(func.sum(Sale.total_price), 0)
    ).filter(
        func.date(Sale.sale_date) == today
    ).scalar()
    
    # Month sales
    current_month = datetime.now().strftime('%Y-%m')
    month_sales = db.session.query(
        func.coalesce(func.sum(Sale.total_price), 0)
    ).filter(
        func.to_char(Sale.sale_date, 'YYYY-MM') == current_month
    ).scalar()
    
    return {
        'total_medications': total_medications,
        'low_stock_count': low_stock_count,
        'expired_count': expired_count,
        'today_sales': float(today_sales),
        'month_sales': float(month_sales)
    }

def search_medications(search_term):
    search_pattern = f'%{search_term}%'
    results = Medication.query.filter(
        and_(
            Medication.deleted == False,
            or_(
                Medication.name.ilike(search_pattern),
                Medication.generic_name.ilike(search_pattern),
                Medication.category.ilike(search_pattern),
                Medication.barcode == search_term
            )
        )
    ).order_by(Medication.name).all()
    
    return results

def get_low_stock_medications(threshold=10):
    results = Medication.query.filter(Medication.stock_quantity <= threshold).all()
    return results

def get_expired_medications():
    today = datetime.now().date()
    results = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < today
        )
    ).all()
    return results

def get_expiring_soon_medications(days=30):
    today = datetime.now().date()
    soon_date = today + timedelta(days=days)
    results = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date >= today,
            Medication.expiry_date <= soon_date
        )
    ).all()
    return results



def get_medication_by_id(medication_id):
    medication = Medication.query.get(medication_id)
    return medication

def get_all_medications():
    medications = Medication.query.filter_by(deleted=False).order_by(Medication.name).all()
    return medications

def get_medications_with_stock():
    medications = Medication.query.filter(Medication.stock_quantity > 0).order_by(Medication.name).all()
    return medications

def get_all_sales():
    sales = Sale.query.options(joinedload(Sale.medication)).order_by(Sale.sale_date.desc()).all()
    return sales

def get_filtered_sales(filter_type):
    if filter_type == 'today':
        today = datetime.now().date()
        sales = Sale.query.options(joinedload(Sale.medication)).filter(
            func.date(Sale.sale_date) == today
        ).order_by(Sale.sale_date.desc()).all()
    elif filter_type == 'week':
        week_ago = datetime.now() - timedelta(days=7)
        sales = Sale.query.options(joinedload(Sale.medication)).filter(
            Sale.sale_date >= week_ago
        ).order_by(Sale.sale_date.desc()).all()
    elif filter_type == 'month':
        current_month = datetime.now().strftime('%Y-%m')
        sales = Sale.query.options(joinedload(Sale.medication)).filter(
            func.to_char(Sale.sale_date, 'YYYY-MM') == current_month
        ).order_by(Sale.sale_date.desc()).all()
    else:
        sales = Sale.query.options(joinedload(Sale.medication)).order_by(Sale.sale_date.desc()).all()
    
    return sales


# Add these routes after the existing routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        # Create user (first user becomes admin)
        user_count = User.query.count()
        role = 'admin' if user_count == 0 else 'user'
        
        user = User(username=username, email=email, role=role)
        user.set_password(password, method='pbkdf2:sha256')  # Use shorter hash method
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'danger')
    
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# Admin panel routes
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    # Get statistics for admin dashboard
    user_count = User.query.count()
    admin_count = User.query.filter_by(role='admin').count()
    sales_count = Sale.query.count()
    
    stats = {
        'user_count': user_count,
        'admin_count': admin_count,
        'sales_count': sales_count,
        **get_sales_summary()  # Include the existing sales stats
    }
    
    return render_template('admin_panel.html', stats=stats)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/promote_user/<int:user_id>')
@login_required
@admin_required
def admin_promote_user(user_id):
    user = User.query.get_or_404(user_id)
    
    try:
        user.role = 'admin'
        db.session.commit()
        flash(f'User {user.username} has been promoted to administrator.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error promoting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/demote_user/<int:user_id>')
@login_required
@admin_required
def admin_demote_user(user_id):
    if user_id == current_user.id:
        flash('You cannot demote yourself.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        user.role = 'user'
        db.session.commit()
        flash(f'User {user.username} has been demoted to regular user.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error demoting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

# Database management routes
@app.route('/admin/database')
@login_required
@admin_required
def admin_database():
    # Get database statistics
    table_stats = {}
    inspector = inspect(db.engine)
    
    for table_name in inspector.get_table_names():
        count = db.session.execute(text(f'SELECT COUNT(*) FROM {table_name}')).scalar()
        table_stats[table_name] = count
    
    return render_template('admin_database.html', table_stats=table_stats)

@app.route('/admin/delete_database', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_delete_database():
    """
    DANGER: This will delete ALL data from the entire database.
    Use with extreme caution - this operation cannot be undone!
    """
    
    if request.method == 'GET':
        # Show confirmation page
        return render_template('admin_delete_database.html')
    
    elif request.method == 'POST':
        # Check for confirmation
        confirmation = request.form.get('confirmation', '').lower().strip()
        if confirmation != 'delete everything':
            flash('Confirmation phrase incorrect. Operation cancelled.', 'warning')
            return redirect(url_for('admin_database'))
        
        try:
            # Delete data from tables in correct order to handle foreign keys
            # Start with tables that have foreign key constraints
            tables_to_delete = ['sales', 'medications', 'users']
            
            for table_name in tables_to_delete:
                try:
                    db.session.execute(text(f'DELETE FROM {table_name}'))
                    print(f"Deleted all data from {table_name}")
                except Exception as e:
                    print(f"Error deleting from {table_name}: {str(e)}")
                    # Continue with other tables even if one fails
                    continue
            
            db.session.commit()
            flash('Entire database has been deleted successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting database: {str(e)}', 'danger')
            print(f"Database deletion error: {str(e)}")
        
        return redirect(url_for('admin_database'))

@app.route('/admin/backup_database')
@login_required
@admin_required
def admin_backup_database():
    try:
        # Create a backup of all data
        backup_data = {}
        
        # Backup users
        users = User.query.all()
        backup_data['users'] = [{
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash,
            'role': user.role,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'is_active': user.is_active
        } for user in users]
        
        # Backup medications
        medications = Medication.query.all()
        backup_data['medications'] = [{
            'name': med.name,
            'generic_name': med.generic_name,
            'manufacturer': med.manufacturer,
            'price': float(med.price),
            'stock_quantity': med.stock_quantity,
            'expiry_date': med.expiry_date.isoformat() if med.expiry_date else None,
            'category': med.category,
            'barcode': med.barcode,
            'created_at': med.created_at.isoformat() if med.created_at else None,
            'deleted': med.deleted
        } for med in medications]
        
        # Backup sales
        sales = Sale.query.all()
        backup_data['sales'] = [{
            'transaction_id': sale.transaction_id,
            'medication_id': sale.medication_id,
            'quantity': sale.quantity,
            'total_price': float(sale.total_price),
            'sale_date': sale.sale_date.isoformat() if sale.sale_date else None
        } for sale in sales]
        
        # Create JSON response
        response = jsonify(backup_data)
        response.headers.add('Content-Disposition', 'attachment', filename=f'database_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        return response
        
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'danger')
        return redirect(url_for('admin_database'))

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    """Add a new user from the admin panel"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('admin_add_user.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('admin_add_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('admin_add_user.html')
        
        # Create user
        user = User(username=username, email=email, role=role)
        user.set_password(password, method='pbkdf2:sha256')
        
        try:
            db.session.add(user)
            db.session.commit()
            flash(f'User {username} has been created successfully!', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
    
    return render_template('admin_add_user.html')

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@admin_required
def admin_toggle_user(user_id):
    """Activate/Deactivate a user"""
    if user_id == current_user.id:
        flash('You cannot modify your own account status.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        status = "activated" if user.is_active else "deactivated"
        flash(f'User {user.username} has been {status}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/restore_database', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_restore_database():
    """Restore database from a backup file"""
    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('admin_database'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin_database'))
        
        if file and file.filename.endswith('.json'):
            try:
                # Read and parse the backup file
                backup_data = json.load(file)
                
                # Validate backup file structure
                required_tables = ['users', 'medications', 'sales']
                for table in required_tables:
                    if table not in backup_data:
                        flash(f'Invalid backup file: missing {table} data', 'danger')
                        return redirect(url_for('admin_database'))
                
                # Start restoration process
                flash('Starting database restoration...', 'info')
                
                # Clear existing data first
                try:
                    db.session.execute(text('DELETE FROM sales'))
                    db.session.execute(text('DELETE FROM medications'))
                    db.session.execute(text('DELETE FROM users'))
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error clearing existing data: {str(e)}', 'danger')
                    return redirect(url_for('admin_database'))
                
                # Restore users
                users_restored = 0
                for user_data in backup_data['users']:
                    try:
                        user = User(
                            username=user_data['username'],
                            email=user_data['email'],
                            password_hash=user_data['password_hash'],
                            role=user_data['role'],
                            is_active=user_data['is_active']
                        )
                        if 'created_at' in user_data and user_data['created_at']:
                            user.created_at = datetime.fromisoformat(user_data['created_at'])
                        db.session.add(user)
                        users_restored += 1
                    except Exception as e:
                        print(f"Error restoring user {user_data.get('username', 'unknown')}: {str(e)}")
                
                # Restore medications
                meds_restored = 0
                for med_data in backup_data['medications']:
                    try:
                        medication = Medication(
                            name=med_data['name'],
                            generic_name=med_data['generic_name'],
                            manufacturer=med_data['manufacturer'],
                            price=med_data['price'],
                            stock_quantity=med_data['stock_quantity'],
                            category=med_data['category'],
                            barcode=med_data['barcode'],
                            deleted=med_data['deleted']
                        )
                        if med_data['expiry_date']:
                            medication.expiry_date = datetime.fromisoformat(med_data['expiry_date']).date()
                        if 'created_at' in med_data and med_data['created_at']:
                            medication.created_at = datetime.fromisoformat(med_data['created_at'])
                        db.session.add(medication)
                        meds_restored += 1
                    except Exception as e:
                        print(f"Error restoring medication {med_data.get('name', 'unknown')}: {str(e)}")
                
                # Restore sales
                sales_restored = 0
                for sale_data in backup_data['sales']:
                    try:
                        sale = Sale(
                            transaction_id=sale_data['transaction_id'],
                            medication_id=sale_data['medication_id'],
                            quantity=sale_data['quantity'],
                            total_price=sale_data['total_price']
                        )
                        if 'sale_date' in sale_data and sale_data['sale_date']:
                            sale.sale_date = datetime.fromisoformat(sale_data['sale_date'])
                        db.session.add(sale)
                        sales_restored += 1
                    except Exception as e:
                        print(f"Error restoring sale {sale_data.get('transaction_id', 'unknown')}: {str(e)}")
                
                # Commit all changes
                db.session.commit()
                
                flash(
                    f'Database restored successfully! '
                    f'Users: {users_restored}, Medications: {meds_restored}, Sales: {sales_restored}',
                    'success'
                )
                
            except json.JSONDecodeError:
                flash('Invalid JSON file format', 'danger')
            except Exception as e:
                db.session.rollback()
                flash(f'Error restoring database: {str(e)}', 'danger')
                print(f"Restore error: {str(e)}")
        else:
            flash('Invalid file format. Please upload a JSON backup file.', 'danger')
    
    return redirect(url_for('admin_database'))
    

# Add decorators to your existing routes
@app.route('/')
def index():
    stats = get_sales_summary()
    return render_template('index.html', stats=stats, now=datetime.now())

@app.route('/search')
@login_required
def search():
    search_term = request.args.get('q', '')
    results = []
    if search_term:
        results = search_medications(search_term)
    return render_template('search.html', results=results, search_term=search_term)


@app.route('/sales', methods=['GET', 'POST'])
@login_required
def sales():
    if request.method == 'POST':
        # Process sale
        medication_id = request.form.get('medication_id')
        quantity = int(request.form.get('quantity', 1))
        
        medication = get_medication_by_id(medication_id)
        if not medication:
            flash('Medication not found', 'danger')
            return redirect(url_for('sales'))
        
        if quantity > medication.stock_quantity:
            flash(f'Not enough stock. Only {medication.stock_quantity} available.', 'warning')
            return redirect(url_for('sales'))
        
        # Generate transaction ID
        transaction_id = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}"
        total_price = float(medication.price) * quantity
        
        try:
            # Update stock
            medication.stock_quantity -= quantity
            
            # Record sale
            sale = Sale(
                transaction_id=transaction_id,
                medication_id=medication_id,
                quantity=quantity,
                total_price=total_price
            )
            
            db.session.add(sale)
            db.session.commit()
            
            flash(f'Sale completed successfully! Transaction ID: {transaction_id}', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing sale: {str(e)}', 'danger')
        
        return redirect(url_for('sales'))
    
    medications = get_medications_with_stock()
    return render_template('sales.html', medications=medications)

@app.route('/inventory')
@login_required
def inventory():
    filter_type = request.args.get('filter', 'all')
    today = datetime.now().date()  # Get today's date as a date object
    
    if filter_type == 'low_stock':
        medications = get_low_stock_medications()
    elif filter_type == 'expired':
        medications = get_expired_medications()
    elif filter_type == 'expiring_soon':
        medications = get_expiring_soon_medications()
    else:
        medications = get_all_medications()
    
    return render_template('inventory.html', medications=medications, filter_type=filter_type, now=today)

@app.route('/add_medication', methods=['GET', 'POST'])
@login_required
def add_medication():
    if request.method == 'POST':
        try:
            name = request.form['name']
            generic_name = request.form.get('generic_name', '')
            manufacturer = request.form.get('manufacturer', '')
            price = float(request.form['price'])
            stock_quantity = int(request.form['stock_quantity'])
            expiry_date_str = request.form.get('expiry_date', '')
            category = request.form.get('category', '')
            barcode = request.form.get('barcode', '')
            
            # Convert expiry_date string to date object if provided
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
            
            medication = Medication(
                name=name,
                generic_name=generic_name,
                manufacturer=manufacturer,
                price=price,
                stock_quantity=stock_quantity,
                expiry_date=expiry_date,
                category=category,
                barcode=barcode
            )
            
            db.session.add(medication)
            db.session.commit()
            
            flash('Medication added successfully!', 'success')
            return redirect(url_for('inventory'))
            
        except Exception as e:
            db.session.rollback()
            if 'unique constraint' in str(e).lower() or 'duplicate key' in str(e).lower():
                flash('A medication with this name or barcode already exists.', 'danger')
            else:
                flash(f'Error adding medication: {str(e)}', 'danger')
    
    return render_template('add_medication.html')

@app.route('/edit_medication/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_medication(id):
    medication = get_medication_by_id(id)
    if not medication:
        flash('Medication not found', 'danger')
        return redirect(url_for('inventory'))
    
    if request.method == 'POST':
        try:
            medication.name = request.form['name']
            medication.generic_name = request.form.get('generic_name', '')
            medication.manufacturer = request.form.get('manufacturer', '')
            medication.price = float(request.form['price'])
            medication.stock_quantity = int(request.form['stock_quantity'])
            
            expiry_date_str = request.form.get('expiry_date', '')
            medication.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
            
            medication.category = request.form.get('category', '')
            medication.barcode = request.form.get('barcode', '')
            
            db.session.commit()
            
            flash('Medication updated successfully!', 'success')
            return redirect(url_for('inventory'))
            
        except Exception as e:
            db.session.rollback()
            if 'unique constraint' in str(e).lower() or 'duplicate key' in str(e).lower():
                flash('A medication with this barcode already exists.', 'danger')
            else:
                flash(f'Error updating medication: {str(e)}', 'danger')
    
    # Convert date to string for form display
    expiry_date_str = medication.expiry_date.strftime('%Y-%m-%d') if medication.expiry_date else ''
    return render_template('edit_medication.html', medication=medication, expiry_date_str=expiry_date_str)

@app.route('/delete_medication/<int:id>')
@login_required
def delete_medication(id):
    medication = get_medication_by_id(id)
    if not medication:
        flash('Medication not found', 'danger')
        return redirect(url_for('inventory'))
    
    try:
        # Soft delete - mark as deleted instead of removing
        medication.deleted = True
        db.session.commit()
        flash('Medication marked as deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting medication: {str(e)}', 'danger')
    
    return redirect(url_for('inventory'))

@app.route('/transactions')
@login_required
def transactions():
    filter_type = request.args.get('filter', 'all')
    sales = get_filtered_sales(filter_type)
    return render_template('transactions.html', sales=sales, filter_type=filter_type)

@app.route('/import_medications', methods=['GET', 'POST'])
@login_required
def import_medications():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('import_medications'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('import_medications'))
        
        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            try:
                df = pd.read_excel(file)
                success_count = 0
                error_messages = []
                
                for index, row in df.iterrows():
                    try:
                        # Extract data from the row, handling missing values
                        name = row.get('name', '')
                        if not name:
                            error_messages.append(f"Row {index+1}: Missing name")
                            continue
                        
                        generic_name = row.get('generic_name', '')
                        manufacturer = row.get('manufacturer', '')
                        
                        # Handle price conversion
                        price_str = str(row.get('price', 0)).strip()
                        price = float(price_str) if price_str else 0.0
                        
                        if price <= 0:
                            error_messages.append(f"Row {index+1}: Invalid price")
                            continue
                        
                        # Handle stock quantity conversion
                        stock_str = str(row.get('stock_quantity', 0)).strip()
                        stock_quantity = int(stock_str) if stock_str else 0
                        
                        # Handle expiry date
                        expiry_date = row.get('expiry_date', '')
                        if pd.notna(expiry_date) and isinstance(expiry_date, datetime):
                            expiry_date = expiry_date.date()
                        elif pd.isna(expiry_date):
                            expiry_date = None
                        elif isinstance(expiry_date, str):
                            # Try to parse string date
                            try:
                                expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
                            except ValueError:
                                # If parsing fails, keep as None
                                expiry_date = None
                        
                        category = row.get('category', '')
                        
                        # Handle barcode - ensure it's always treated as a string
                        barcode = row.get('barcode', '')
                        if pd.notna(barcode):
                            barcode = str(barcode).strip()
                        else:
                            barcode = None
                        
                        # Check if medication already exists
                        existing = Medication.query.filter(
                            (Medication.name == name) | 
                            (Medication.barcode.isnot(None) & (Medication.barcode == barcode))
                        ).first()
                        
                        if existing:
                            error_messages.append(f"Row {index+1}: Medication already exists")
                            continue
                        
                        # Add medication to database
                        medication = Medication(
                            name=name,
                            generic_name=generic_name,
                            manufacturer=manufacturer,
                            price=price,
                            stock_quantity=stock_quantity,
                            expiry_date=expiry_date,
                            category=category,
                            barcode=barcode
                        )
                        
                        db.session.add(medication)
                        success_count += 1
                        
                    except Exception as e:
                        error_messages.append(f"Row {index+1}: {str(e)}")
                        continue
                
                db.session.commit()
                
                if error_messages:
                    flash_message = f"Imported {success_count} medications with {len(error_messages)} errors. First error: {error_messages[0]}"
                    if len(error_messages) > 1:
                        flash_message += f" (and {len(error_messages)-1} more)"
                    flash(flash_message, 'warning')
                else:
                    flash(f"Successfully imported {success_count} medications", 'success')
                
                return redirect(url_for('inventory'))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Failed to read file: {str(e)}", 'danger')
        
        else:
            flash('Invalid file format. Please upload an Excel file.', 'danger')
    
    return render_template('import_medications.html')

@app.route('/generate_sample_excel')
@login_required
def generate_sample_excel():
    # Create sample data
    sample_data = {
        'name': ['Aspirin', 'Paracetamol', 'Ibuprofen'],
        'generic_name': ['Acetylsalicylic acid', 'Acetaminophen', 'Ibuprofen'],
        'manufacturer': ['Bayer', 'GSK', 'Advil'],
        'price': [5.99, 4.50, 6.25],
        'stock_quantity': [100, 50, 75],
        'expiry_date': ['2024-12-31', '2025-06-30', '2024-10-15'],
        'category': ['Pain Relief', 'Pain Relief', 'Pain Relief'],
        'barcode': ['1234567890123', '2345678901234', '3456789012345']
    }
    
    # Create DataFrame
    df = pd.DataFrame(sample_data)
    
    # Save to BytesIO buffer
    buffer = BytesIO()
    df.to_excel(buffer, index=False)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name='sample_medications.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

# API endpoints for AJAX requests
@app.route('/api/medications')
def api_medications():
    search_term = request.args.get('q', '')
    if search_term:
        medications = search_medications(search_term)
    else:
        medications = get_all_medications()
    
    # Convert to list of dictionaries
    medications_list = []
    for med in medications:
        med_dict = {
            'id': med.id,
            'name': med.name,
            'generic_name': med.generic_name,
            'manufacturer': med.manufacturer,
            'price': float(med.price),
            'stock_quantity': med.stock_quantity,
            'expiry_date': med.expiry_date.isoformat() if med.expiry_date else None,
            'category': med.category,
            'barcode': med.barcode,
            'created_at': med.created_at.isoformat() if med.created_at else None
        }
        medications_list.append(med_dict)
    
    return jsonify(medications_list)

@app.route('/delete_entire_database', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_entire_database():
    """
    DANGER: This will delete ALL data from the entire database.
    Use with extreme caution - this operation cannot be undone!
    """
    
    if request.method == 'GET':
        # Show confirmation page
        return render_template('confirm_delete_db.html')
    
    elif request.method == 'POST':
        # Check for confirmation
        confirmation = request.form.get('confirmation', '').lower().strip()
        if confirmation != 'delete everything':
            flash('Confirmation phrase incorrect. Operation cancelled.', 'warning')
            return redirect(url_for('index'))
        
        try:
            # Delete data from tables in correct order to handle foreign keys
            tables_to_delete = ['sales', 'medications', 'users']
            
            for table_name in tables_to_delete:
                try:
                    db.session.execute(text(f'DELETE FROM {table_name}'))
                    print(f"Deleted all data from {table_name}")
                except Exception as e:
                    print(f"Error deleting from {table_name}: {str(e)}")
                    # Continue with other tables even if one fails
                    continue
            
            db.session.commit()
            flash('Entire database has been deleted successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting database: {str(e)}', 'danger')
            print(f"Database deletion error: {str(e)}")
        
        return redirect(url_for('index'))

@app.route('/api/sales_summary')
def api_sales_summary():
    return jsonify(get_sales_summary())
    
# This is needed for Vercel
if __name__ == '__main__':
    app.run(debug=True)
else:
    # This is for Vercel deployment
    from flask import Flask
    application = app