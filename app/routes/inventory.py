from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from app import db
from app.models import Medication
from app.utils.decorators import admin_required
from app.utils.helpers import get_low_stock_medications, get_expired_medications, get_expiring_soon_medications
from datetime import datetime
import pandas as pd
from io import BytesIO

inventory_bp = Blueprint('inventory', __name__)

@inventory_bp.route('/inventory')
@login_required
def inventory():
    filter_type = request.args.get('filter', 'all')
    today = datetime.now().date()
    
    if filter_type == 'low_stock':
        medications = get_low_stock_medications()
    elif filter_type == 'expired':
        medications = get_expired_medications()
    elif filter_type == 'expiring_soon':
        medications = get_expiring_soon_medications()
    else:
        medications = Medication.query.filter_by(deleted=False).order_by(Medication.name).all()
    
    return render_template('inventory/inventory.html', medications=medications, filter_type=filter_type, now=today)

@inventory_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_medication():
    if request.method == 'POST':
        try:
            name = request.form['name']
            generic_name = request.form.get('generic_name', '')
            manufacturer = request.form.get('manufacturer', '')
            price = float(request.form['price'])
            cost_price = float(request.form.get('cost_price', 0)) or None
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
                cost_price=cost_price,
                stock_quantity=stock_quantity,
                expiry_date=expiry_date,
                category=category,
                barcode=barcode
            )
            
            db.session.add(medication)
            db.session.commit()
            
            flash('Medication added successfully!', 'success')
            return redirect(url_for('inventory.inventory'))
            
        except Exception as e:
            db.session.rollback()
            if 'unique constraint' in str(e).lower() or 'duplicate key' in str(e).lower():
                flash('A medication with this name or barcode already exists.', 'danger')
            else:
                flash(f'Error adding medication: {str(e)}', 'danger')
    
    return render_template('inventory/add_medication.html')

@inventory_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_medication(id):
    medication = Medication.query.get_or_404(id)
    if not medication:
        flash('Medication not found', 'danger')
        return redirect(url_for('inventory.inventory'))
    
    if request.method == 'POST':
        try:
            medication.name = request.form['name']
            medication.generic_name = request.form.get('generic_name', '')
            medication.manufacturer = request.form.get('manufacturer', '')
            medication.price = float(request.form['price'])
            medication.cost_price = float(request.form.get('cost_price', 0)) or None
            medication.stock_quantity = int(request.form['stock_quantity'])
            
            expiry_date_str = request.form.get('expiry_date', '')
            medication.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
            
            medication.category = request.form.get('category', '')
            medication.barcode = request.form.get('barcode', '')
            
            db.session.commit()
            
            flash('Medication updated successfully!', 'success')
            return redirect(url_for('inventory.inventory'))
            
        except Exception as e:
            db.session.rollback()
            if 'unique constraint' in str(e).lower() or 'duplicate key' in str(e).lower():
                flash('A medication with this barcode already exists.', 'danger')
            else:
                flash(f'Error updating medication: {str(e)}', 'danger')
    
    # Convert date to string for form display
    expiry_date_str = medication.expiry_date.strftime('%Y-%m-%d') if medication.expiry_date else ''
    return render_template('inventory/edit_medication.html', medication=medication, expiry_date_str=expiry_date_str)

@inventory_bp.route('/delete/<int:id>')
@login_required
def delete_medication(id):
    medication = Medication.query.get_or_404(id)
    if not medication:
        flash('Medication not found', 'danger')
        return redirect(url_for('inventory.inventory'))
    
    try:
        # Soft delete - mark as deleted instead of removing
        medication.deleted = True
        db.session.commit()
        flash('Medication deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting medication: {str(e)}', 'danger')
    
    return redirect(url_for('inventory.inventory'))

@inventory_bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_medications():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('inventory.import_medications'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('inventory.import_medications'))
        
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
                        
                        # Handle cost price conversion
                        cost_price_str = str(row.get('cost_price', '')).strip()
                        cost_price = float(cost_price_str) if cost_price_str else None
                        
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
                            cost_price=cost_price,
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
                
                return redirect(url_for('inventory.inventory'))
                
            except Exception as e:
                db.session.rollback()
                flash(f"Failed to read file: {str(e)}", 'danger')
        
        else:
            flash('Invalid file format. Please upload an Excel file.', 'danger')
    
    return render_template('inventory/import_medications.html')

@inventory_bp.route('/generate_sample_excel')
@login_required
def generate_sample_excel():
    # Create sample data
    sample_data = {
        'name': ['Aspirin', 'Paracetamol', 'Ibuprofen'],
        'generic_name': ['Acetylsalicylic acid', 'Acetaminophen', 'Ibuprofen'],
        'manufacturer': ['Bayer', 'GSK', 'Advil'],
        'price': [5.99, 4.50, 6.25],
        'cost_price': [3.50, 2.80, 4.00],
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

@inventory_bp.route('/api/medications')
@login_required
def api_medications():
    search_term = request.args.get('q', '')
    if search_term:
        from app.utils.helpers import search_medications
        medications = search_medications(search_term)
    else:
        medications = Medication.query.filter_by(deleted=False).order_by(Medication.name).all()
    
    # Convert to list of dictionaries
    medications_list = []
    for med in medications:
        med_dict = {
            'id': med.id,
            'name': med.name,
            'generic_name': med.generic_name,
            'manufacturer': med.manufacturer,
            'price': float(med.price),
            'cost_price': float(med.cost_price) if med.cost_price else None,
            'stock_quantity': med.stock_quantity,
            'expiry_date': med.expiry_date.isoformat() if med.expiry_date else None,
            'category': med.category,
            'barcode': med.barcode,
            'created_at': med.created_at.isoformat() if med.created_at else None
        }
        medications_list.append(med_dict)
    
    return jsonify(medications_list)

@inventory_bp.route('/api/medications/search')
@login_required
def api_medications_search():
    search_term = request.args.get('q', '')
    if search_term:
        from app.utils.helpers import search_medications
        medications = search_medications(search_term)
    else:
        medications = Medication.query.filter(Medication.stock_quantity > 0, Medication.deleted == False).order_by(Medication.name).all()
    
    results = []
    for med in medications:
        results.append({
            'id': med.id,
            'name': med.name,
            'generic_name': med.generic_name,
            'price': float(med.price),
            'stock_quantity': med.stock_quantity,
            'barcode': med.barcode
        })
    
    return jsonify(results)

@inventory_bp.route('/low_stock')
@login_required
def low_stock():
    medications = get_low_stock_medications()
    return render_template('inventory/low_stock.html', medications=medications)

@inventory_bp.route('/expired')
@login_required
def expired():
    medications = get_expired_medications()
    return render_template('inventory/expired.html', medications=medications)

@inventory_bp.route('/expiring_soon')
@login_required
def expiring_soon():
    medications = get_expiring_soon_medications()
    return render_template('inventory/expiring_soon.html', medications=medications)