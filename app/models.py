from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, or_

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    
    def set_password(self, password, method='pbkdf2:sha256'):
        self.password_hash = generate_password_hash(password, method=method)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def can_login(self):
        return self.is_active and self.is_approved
    
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
    cost_price = db.Column(db.Numeric(10, 2), nullable=True)  # Added for profit calculation
    stock_quantity = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    barcode = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationship to sale items
    sale_items = db.relationship('SaleItem', backref='medication', lazy=True)

    def __repr__(self):
        return f"<Medication {self.name}>"

class Customer(db.Model):
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    address = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    
    # Relationship to sales
    sales = db.relationship('SaleTransaction', backref='customer', lazy=True)
    
    def __repr__(self):
        return f"<Customer {self.name}>"

class SaleTransaction(db.Model):
    __tablename__ = 'sale_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    tax_amount = db.Column(db.Numeric(10, 2), default=0)
    discount_amount = db.Column(db.Numeric(10, 2), default=0)
    payment_method = db.Column(db.String(20), nullable=False)  # cash, card, digital, etc.
    payment_status = db.Column(db.String(20), default='completed')  # completed, pending, refunded
    sale_date = db.Column(db.DateTime, server_default=func.now())
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='sales')
    items = db.relationship('SaleItem', backref='sale_transaction', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<SaleTransaction {self.transaction_id}>"

class SaleItem(db.Model):
    __tablename__ = 'sale_items'
    
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sale_transactions.id'), nullable=False)
    medication_id = db.Column(db.Integer, db.ForeignKey('medications.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    
    def __repr__(self):
        return f"<SaleItem {self.id}>"