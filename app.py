from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from datetime import datetime, timedelta
import pandas as pd
import os
import re
from io import BytesIO
import json
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import quote_plus
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import joinedload

# Initialize SQLAlchemy
db = SQLAlchemy()

# Password with special characters must be URL-encoded
password = "Johnh4k3r@123"
encoded_password = quote_plus(password)

# Database URI
DATABASE_URI = f"postgresql://postgres:{encoded_password}@db.okwpnjobjxrcxhtzvysw.supabase.co:5432/postgres"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pharmacy-pos-secret-key')
    
    # Configure the database URI
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize the app with the extension
    db.init_app(app)
    
    return app

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
    
    # Relationship to sales
    sales = db.relationship('Sale', backref='medication', lazy=True)

    def __repr__(self):
        return f"<Medication {self.name}>"


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

# Initialize the database when the app starts
with app.app_context():
    db.create_all()
    print("✅ Tables created successfully in Supabase!")

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
        or_(
            Medication.name.ilike(search_pattern),
            Medication.generic_name.ilike(search_pattern),
            Medication.category.ilike(search_pattern),
            Medication.barcode == search_term
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
    medications = Medication.query.order_by(Medication.name).all()
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

# Routes
@app.route('/')
def index():
    stats = get_sales_summary()
    return render_template('index.html', stats=stats, now=datetime.now())

@app.route('/search')
def search():
    search_term = request.args.get('q', '')
    results = []
    if search_term:
        results = search_medications(search_term)
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/sales', methods=['GET', 'POST'])
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
def delete_medication(id):
    medication = get_medication_by_id(id)
    if not medication:
        flash('Medication not found', 'danger')
        return redirect(url_for('inventory'))
    
    # Check if medication has sales
    sales_count = Sale.query.filter_by(medication_id=id).count()
    if sales_count > 0:
        flash('Cannot delete medication with sales history', 'danger')
        return redirect(url_for('inventory'))
    
    try:
        db.session.delete(medication)
        db.session.commit()
        flash('Medication deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting medication: {str(e)}', 'danger')
    
    return redirect(url_for('inventory'))

@app.route('/transactions')
def transactions():
    filter_type = request.args.get('filter', 'all')
    sales = get_filtered_sales(filter_type)
    return render_template('transactions.html', sales=sales, filter_type=filter_type)

@app.route('/import_medications', methods=['GET', 'POST'])
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
