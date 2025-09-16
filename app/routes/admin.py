from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from app import db
from app.models import User, Medication, SaleTransaction, SaleItem, Customer
from app.utils.decorators import admin_required
from app.utils.helpers import get_sales_summary
import json
from sqlalchemy import text, inspect
from datetime import datetime
from io import BytesIO
import pandas as pd

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
@login_required
@admin_required
def admin_panel():
    # Get statistics for admin dashboard
    user_count = User.query.count()
    admin_count = User.query.filter_by(role='admin').count()
    sales_count = SaleTransaction.query.count()
    
    # Get sales summary and ensure all values are serializable
    sales_summary = get_sales_summary()
    
    stats = {
        'user_count': user_count,
        'admin_count': admin_count,
        'sales_count': sales_count,
        **sales_summary  # Unpack the sales summary dictionary
    }
    
    return render_template('admin/admin_panel.html', stats=stats)

@admin_bp.route('/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    pending_count = User.query.filter_by(is_approved=False).count()
    return render_template('admin/users.html', users=users, pending_count=pending_count)

@admin_bp.route('/pending_approvals')
@login_required
@admin_required
def admin_pending_approvals():
    """Show users pending approval"""
    pending_users = User.query.filter_by(is_approved=False).order_by(User.created_at.desc()).all()
    return render_template('admin/pending_approvals.html', users=pending_users)

@admin_bp.route('/approve_user/<int:user_id>')
@login_required
@admin_required
def admin_approve_user(user_id):
    """Approve a user registration"""
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_approved = True
        user.is_active = True
        db.session.commit()
        
        flash(f'User {user.username} has been approved and can now log in.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.admin_pending_approvals'))

@admin_bp.route('/reject_user/<int:user_id>')
@login_required
@admin_required
def admin_reject_user(user_id):
    """Reject a user registration and delete the account"""
    user = User.query.get_or_404(user_id)
    username = user.username
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} has been rejected and their registration deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.admin_pending_approvals'))

@admin_bp.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/promote_user/<int:user_id>')
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
    
    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/demote_user/<int:user_id>')
@login_required
@admin_required
def admin_demote_user(user_id):
    if user_id == current_user.id:
        flash('You cannot demote yourself.', 'danger')
        return redirect(url_for('admin.admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        user.role = 'user'
        db.session.commit()
        flash(f'User {user.username} has been demoted to regular user.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error demoting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/database')
@login_required
@admin_required
def admin_database():
    # Get database statistics
    table_stats = {}
    inspector = inspect(db.engine)
    
    for table_name in inspector.get_table_names():
        count = db.session.execute(text(f'SELECT COUNT(*) FROM {table_name}')).scalar()
        table_stats[table_name] = count
    
    return render_template('admin/database.html', table_stats=table_stats)


@admin_bp.route('/backup_database')
@login_required
@admin_required
def admin_backup_database():
    try:
        # Create a backup of all data
        backup_data = {}
        
        # Backup users (exclude admin user)
        users = User.query.filter(User.username != 'admin').all()
        backup_data['users'] = [{
            'id': user.id,  # Include ID for restoration mapping
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash,
            'role': user.role,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'is_active': user.is_active,
            'is_approved': user.is_approved
        } for user in users]
        
        # Backup medications - include ID
        medications = Medication.query.all()
        backup_data['medications'] = [{
            'id': med.id,  # Include ID for restoration mapping
            'name': med.name,
            'generic_name': med.generic_name,
            'manufacturer': med.manufacturer,
            'price': float(med.price),
            'cost_price': float(med.cost_price) if med.cost_price else None,
            'stock_quantity': med.stock_quantity,
            'expiry_date': med.expiry_date.isoformat() if med.expiry_date else None,
            'category': med.category,
            'barcode': med.barcode,
            'created_at': med.created_at.isoformat() if med.created_at else None,
            'deleted': med.deleted
        } for med in medications]
        
        # Backup customers - include ID
        customers = Customer.query.all()
        backup_data['customers'] = [{
            'id': customer.id,  # Include ID for restoration mapping
            'name': customer.name,
            'phone': customer.phone,
            'email': customer.email,
            'address': customer.address,
            'created_at': customer.created_at.isoformat() if customer.created_at else None
        } for customer in customers]
        
        # Backup sales transactions - include ID
        sales = SaleTransaction.query.all()
        backup_data['sale_transactions'] = [{
            'id': sale.id,  # Include ID for restoration mapping
            'transaction_id': sale.transaction_id,
            'customer_id': sale.customer_id,
            'user_id': sale.user_id,
            'total_amount': float(sale.total_amount),
            'tax_amount': float(sale.tax_amount),
            'discount_amount': float(sale.discount_amount),
            'payment_method': sale.payment_method,
            'payment_status': sale.payment_status,
            'sale_date': sale.sale_date.isoformat() if sale.sale_date else None,
            'notes': sale.notes
        } for sale in sales]
        
        # Backup sale items - include ID
        sale_items = SaleItem.query.all()
        backup_data['sale_items'] = [{
            'id': item.id,  # Include ID for restoration mapping
            'sale_id': item.sale_id,
            'medication_id': item.medication_id,
            'quantity': item.quantity,
            'unit_price': float(item.unit_price),
            'total_price': float(item.total_price)
        } for item in sale_items]
        
        # Create JSON response
        response = jsonify(backup_data)
        response.headers.add('Content-Disposition', 'attachment', filename=f'database_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        return response
        
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_database'))
    try:
        # Create a backup of all data
        backup_data = {}
        
        # Backup users (exclude admin user)
        users = User.query.filter(User.username != 'admin').all()
        backup_data['users'] = [{
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash,
            'role': user.role,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'is_active': user.is_active,  # This is a boolean, should be fine
            'is_approved': user.is_approved  # This is a boolean, should be fine
        } for user in users]
        
        # Backup medications - ensure all values are serializable
        medications = Medication.query.all()
        backup_data['medications'] = [{
            'name': med.name,
            'generic_name': med.generic_name,
            'manufacturer': med.manufacturer,
            'price': float(med.price),  # Convert Decimal to float
            'cost_price': float(med.cost_price) if med.cost_price else None,  # Convert Decimal to float
            'stock_quantity': med.stock_quantity,  # This is an integer
            'expiry_date': med.expiry_date.isoformat() if med.expiry_date else None,  # Convert date to string
            'category': med.category,
            'barcode': med.barcode,
            'created_at': med.created_at.isoformat() if med.created_at else None,  # Convert datetime to string
            'deleted': med.deleted  # This is a boolean
        } for med in medications]
        
        # Backup customers
        customers = Customer.query.all()
        backup_data['customers'] = [{
            'name': customer.name,
            'phone': customer.phone,
            'email': customer.email,
            'address': customer.address,
            'created_at': customer.created_at.isoformat() if customer.created_at else None  # Convert datetime to string
        } for customer in customers]
        
        # Backup sales transactions - ensure all numeric values are converted to float
        sales = SaleTransaction.query.all()
        backup_data['sale_transactions'] = [{
            'transaction_id': sale.transaction_id,
            'customer_id': sale.customer_id,
            'user_id': sale.user_id,
            'total_amount': float(sale.total_amount),  # Convert Decimal to float
            'tax_amount': float(sale.tax_amount),  # Convert Decimal to float
            'discount_amount': float(sale.discount_amount),  # Convert Decimal to float
            'payment_method': sale.payment_method,
            'payment_status': sale.payment_status,
            'sale_date': sale.sale_date.isoformat() if sale.sale_date else None,  # Convert datetime to string
            'notes': sale.notes
        } for sale in sales]
        
        # Backup sale items - ensure all numeric values are converted to float
        sale_items = SaleItem.query.all()
        backup_data['sale_items'] = [{
            'sale_id': item.sale_id,
            'medication_id': item.medication_id,
            'quantity': item.quantity,  # This is an integer
            'unit_price': float(item.unit_price),  # Convert Decimal to float
            'total_price': float(item.total_price)  # Convert Decimal to float
        } for item in sale_items]
        
        # Create JSON response
        response = jsonify(backup_data)
        response.headers.add('Content-Disposition', 'attachment', filename=f'database_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        return response
        
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_database'))

@admin_bp.route('/delete_database', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_delete_database():
    """
    DANGER: This will delete ALL data from the entire database.
    Use with extreme caution - this operation cannot be undone!
    """
    
    if request.method == 'GET':
        # Show confirmation page
        return render_template('admin/delete_database.html')
    
    elif request.method == 'POST':
        # Check for confirmation
        confirmation = request.form.get('confirmation', '').lower().strip()
        if confirmation != 'delete everything':
            flash('Confirmation phrase incorrect. Operation cancelled.', 'warning')
            return redirect(url_for('admin.admin_database'))
        
        try:
            # Delete data from tables in correct order to handle foreign keys
            tables_to_delete = ['sale_items', 'sale_transactions', 'medications', 'customers', 'users']
            
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
        
        return redirect(url_for('admin.admin_database'))

@admin_bp.route('/add_user', methods=['GET', 'POST'])
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
            return render_template('admin/add_user.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('admin/add_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('admin/add_user.html')
        
        # Create user
        user = User(username=username, email=email, role=role)
        user.set_password(password, method='pbkdf2:sha256')
        
        try:
            db.session.add(user)
            db.session.commit()
            flash(f'User {username} has been created successfully!', 'success')
            return redirect(url_for('admin.admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
    
    return render_template('admin/add_user.html')

@admin_bp.route('/toggle_user/<int:user_id>')
@login_required
@admin_required
def admin_toggle_user(user_id):
    """Activate/Deactivate a user"""
    if user_id == current_user.id:
        flash('You cannot modify your own account status.', 'danger')
        return redirect(url_for('admin.admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        status = "activated" if user.is_active else "deactivated"
        flash(f'User {user.username} has been {status}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.admin_users'))


@admin_bp.route('/restore_database', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_restore_database():
    """Restore database from a backup file"""
    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('admin.admin_database'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin.admin_database'))
        
        if file and file.filename.endswith('.json'):
            try:
                # Read and parse the backup file
                backup_data = json.load(file)
                
                # Validate backup file structure
                required_tables = ['users', 'medications', 'customers', 'sale_transactions', 'sale_items']
                for table in required_tables:
                    if table not in backup_data:
                        flash(f'Invalid backup file: missing {table} data', 'danger')
                        return redirect(url_for('admin.admin_database'))
                
                # Start restoration process
                flash('Starting database restoration...', 'info')
                
                # Clear existing data first (in correct order to handle foreign keys)
                try:
                    # Delete in reverse order of dependencies
                    db.session.execute(text('DELETE FROM sale_items'))
                    db.session.execute(text('DELETE FROM sale_transactions'))
                    db.session.execute(text('DELETE FROM medications'))
                    db.session.execute(text('DELETE FROM customers'))
                    db.session.execute(text('DELETE FROM users'))
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error clearing existing data: {str(e)}', 'danger')
                    return redirect(url_for('admin.admin_database'))
                
                # Create mapping dictionaries to track old ID -> new ID relationships
                user_id_map = {}
                customer_id_map = {}
                medication_id_map = {}
                sale_id_map = {}
                
                # Restore users
                users_restored = 0
                for user_data in backup_data['users']:
                    try:
                        user = User(
                            username=user_data['username'],
                            email=user_data['email'],
                            password_hash=user_data['password_hash'],
                            role=user_data['role'],
                            is_active=user_data['is_active'],
                            is_approved=user_data['is_approved']
                        )
                        if 'created_at' in user_data and user_data['created_at']:
                            user.created_at = datetime.fromisoformat(user_data['created_at'])
                        db.session.add(user)
                        db.session.flush()  # Get the new ID without committing
                        
                        # Map old user ID to new user ID
                        user_id_map[user_data.get('id', users_restored)] = user.id
                        users_restored += 1
                    except Exception as e:
                        print(f"Error restoring user {user_data.get('username', 'unknown')}: {str(e)}")
                
                # Restore customers
                customers_restored = 0
                for customer_data in backup_data['customers']:
                    try:
                        customer = Customer(
                            name=customer_data['name'],
                            phone=customer_data['phone'],
                            email=customer_data['email'],
                            address=customer_data['address']
                        )
                        if 'created_at' in customer_data and customer_data['created_at']:
                            customer.created_at = datetime.fromisoformat(customer_data['created_at'])
                        db.session.add(customer)
                        db.session.flush()  # Get the new ID without committing
                        
                        # Map old customer ID to new customer ID
                        customer_id_map[customer_data.get('id', customers_restored)] = customer.id
                        customers_restored += 1
                    except Exception as e:
                        print(f"Error restoring customer {customer_data.get('name', 'unknown')}: {str(e)}")
                
                # Restore medications
                meds_restored = 0
                for med_data in backup_data['medications']:
                    try:
                        medication = Medication(
                            name=med_data['name'],
                            generic_name=med_data['generic_name'],
                            manufacturer=med_data['manufacturer'],
                            price=med_data['price'],
                            cost_price=med_data.get('cost_price'),
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
                        db.session.flush()  # Get the new ID without committing
                        
                        # Map old medication ID to new medication ID
                        medication_id_map[med_data.get('id', meds_restored)] = medication.id
                        meds_restored += 1
                    except Exception as e:
                        print(f"Error restoring medication {med_data.get('name', 'unknown')}: {str(e)}")
                
                # Restore sale transactions with updated foreign keys
                sales_restored = 0
                for sale_data in backup_data['sale_transactions']:
                    try:
                        # Update foreign key references
                        customer_id = sale_data['customer_id']
                        user_id = sale_data['user_id']
                        
                        # Map old IDs to new IDs
                        new_customer_id = customer_id_map.get(customer_id) if customer_id else None
                        new_user_id = user_id_map.get(user_id)
                        
                        if new_user_id is None:
                            print(f"Warning: User ID {user_id} not found in mapping. Using current user.")
                            new_user_id = current_user.id
                        
                        sale = SaleTransaction(
                            transaction_id=sale_data['transaction_id'],
                            customer_id=new_customer_id,  # Use mapped customer ID
                            user_id=new_user_id,  # Use mapped user ID
                            total_amount=sale_data['total_amount'],
                            tax_amount=sale_data['tax_amount'],
                            discount_amount=sale_data['discount_amount'],
                            payment_method=sale_data['payment_method'],
                            payment_status=sale_data['payment_status'],
                            notes=sale_data['notes']
                        )
                        if 'sale_date' in sale_data and sale_data['sale_date']:
                            sale.sale_date = datetime.fromisoformat(sale_data['sale_date'])
                        db.session.add(sale)
                        db.session.flush()  # Get the new ID without committing
                        
                        # Map old sale ID to new sale ID
                        sale_id_map[sale_data.get('id', sales_restored)] = sale.id
                        sales_restored += 1
                    except Exception as e:
                        print(f"Error restoring sale {sale_data.get('transaction_id', 'unknown')}: {str(e)}")
                
                # Restore sale items with updated foreign keys
                sale_items_restored = 0
                for item_data in backup_data['sale_items']:
                    try:
                        # Update foreign key references
                        sale_id = item_data['sale_id']
                        medication_id = item_data['medication_id']
                        
                        # Map old IDs to new IDs
                        new_sale_id = sale_id_map.get(sale_id)
                        new_medication_id = medication_id_map.get(medication_id)
                        
                        if new_sale_id is None or new_medication_id is None:
                            print(f"Warning: Sale ID {sale_id} or Medication ID {medication_id} not found in mapping. Skipping.")
                            continue
                        
                        sale_item = SaleItem(
                            sale_id=new_sale_id,  # Use mapped sale ID
                            medication_id=new_medication_id,  # Use mapped medication ID
                            quantity=item_data['quantity'],
                            unit_price=item_data['unit_price'],
                            total_price=item_data['total_price']
                        )
                        db.session.add(sale_item)
                        sale_items_restored += 1
                    except Exception as e:
                        print(f"Error restoring sale item: {str(e)}")
                
                # Commit all changes
                db.session.commit()
                
                flash(
                    f'Database restored successfully! '
                    f'Users: {users_restored}, Medications: {meds_restored}, Customers: {customers_restored}, '
                    f'Sales: {sales_restored}, Sale Items: {sale_items_restored}',
                    'success'
                )
                
            except json.JSONDecodeError:
                flash('Invalid JSON file format', 'danger')
            except Exception as e:
                db.session.rollback()
                flash(f'Error restoring database: {str(e)}', 'danger')
                print(f"Restore error: {str(e)}")
                import traceback
                traceback.print_exc()
        else:
            flash('Invalid file format. Please upload a JSON backup file.', 'danger')
    
    return redirect(url_for('admin.admin_database'))
    """Restore database from a backup file"""
    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('admin.admin_database'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin.admin_database'))
        
        if file and file.filename.endswith('.json'):
            try:
                # Read and parse the backup file
                backup_data = json.load(file)
                
                # Validate backup file structure
                required_tables = ['users', 'medications', 'customers', 'sale_transactions', 'sale_items']
                for table in required_tables:
                    if table not in backup_data:
                        flash(f'Invalid backup file: missing {table} data', 'danger')
                        return redirect(url_for('admin.admin_database'))
                
                # Start restoration process
                flash('Starting database restoration...', 'info')
                
                # Clear existing data first
                try:
                    db.session.execute(text('DELETE FROM sale_items'))
                    db.session.execute(text('DELETE FROM sale_transactions'))
                    db.session.execute(text('DELETE FROM medications'))
                    db.session.execute(text('DELETE FROM customers'))
                    db.session.execute(text('DELETE FROM users'))
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error clearing existing data: {str(e)}', 'danger')
                    return redirect(url_for('admin.admin_database'))
                
                # Restore users
                users_restored = 0
                for user_data in backup_data['users']:
                    try:
                        user = User(
                            username=user_data['username'],
                            email=user_data['email'],
                            password_hash=user_data['password_hash'],
                            role=user_data['role'],
                            is_active=user_data['is_active'],
                            is_approved=user_data['is_approved']
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
                            cost_price=med_data.get('cost_price'),
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
                
                # Restore customers
                customers_restored = 0
                for customer_data in backup_data['customers']:
                    try:
                        customer = Customer(
                            name=customer_data['name'],
                            phone=customer_data['phone'],
                            email=customer_data['email'],
                            address=customer_data['address']
                        )
                        if 'created_at' in customer_data and customer_data['created_at']:
                            customer.created_at = datetime.fromisoformat(customer_data['created_at'])
                        db.session.add(customer)
                        customers_restored += 1
                    except Exception as e:
                        print(f"Error restoring customer {customer_data.get('name', 'unknown')}: {str(e)}")
                
                # Restore sale transactions
                sales_restored = 0
                for sale_data in backup_data['sale_transactions']:
                    try:
                        sale = SaleTransaction(
                            transaction_id=sale_data['transaction_id'],
                            customer_id=sale_data['customer_id'],
                            user_id=sale_data['user_id'],
                            total_amount=sale_data['total_amount'],
                            tax_amount=sale_data['tax_amount'],
                            discount_amount=sale_data['discount_amount'],
                            payment_method=sale_data['payment_method'],
                            payment_status=sale_data['payment_status'],
                            notes=sale_data['notes']
                        )
                        if 'sale_date' in sale_data and sale_data['sale_date']:
                            sale.sale_date = datetime.fromisoformat(sale_data['sale_date'])
                        db.session.add(sale)
                        sales_restored += 1
                    except Exception as e:
                        print(f"Error restoring sale {sale_data.get('transaction_id', 'unknown')}: {str(e)}")
                
                # Restore sale items
                sale_items_restored = 0
                for item_data in backup_data['sale_items']:
                    try:
                        sale_item = SaleItem(
                            sale_id=item_data['sale_id'],
                            medication_id=item_data['medication_id'],
                            quantity=item_data['quantity'],
                            unit_price=item_data['unit_price'],
                            total_price=item_data['total_price']
                        )
                        db.session.add(sale_item)
                        sale_items_restored += 1
                    except Exception as e:
                        print(f"Error restoring sale item {item_data.get('id', 'unknown')}: {str(e)}")
                
                # Commit all changes
                db.session.commit()
                
                flash(
                    f'Database restored successfully! '
                    f'Users: {users_restored}, Medications: {meds_restored}, Customers: {customers_restored}, '
                    f'Sales: {sales_restored}, Sale Items: {sale_items_restored}',
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
    
    return redirect(url_for('admin.admin_database'))