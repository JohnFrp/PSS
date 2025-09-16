# FIX: Added jsonify and or_ to imports
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required
from sqlalchemy import func, or_, desc
from app import db
from app.models import Customer, SaleTransaction # Assuming SaleTransaction model is available

customers_bp = Blueprint('customers', __name__, url_prefix='/customers')

@customers_bp.route('/')
@login_required
def customers():
    # --- Main Query for the Customer List ---
    # Gets each customer with their total sales count and amount spent in one go.
    customers_query = db.session.query(
        Customer,
        func.count(SaleTransaction.id).label('sales_count'),
        func.coalesce(func.sum(SaleTransaction.total_amount), 0).label('total_spent')
    ).outerjoin(SaleTransaction).group_by(Customer.id)
    
    # --- Additional Queries for Statistics ---
    # These are now fast because they are simple, direct queries.
    total_revenue = db.session.query(func.sum(SaleTransaction.total_amount)).scalar() or 0
    
    active_customer_count = db.session.query(
        func.count(Customer.id.distinct())
    ).join(SaleTransaction).scalar()
    
    new_customer_count = db.session.query(func.count(Customer.id))\
        .filter(Customer.sales == None).scalar()

    # --- Queries for Customer Insights ---
    top_spender = customers_query.order_by(desc('total_spent')).first()
    most_frequent = customers_query.order_by(desc('sales_count')).first()
    newest_customer = Customer.query.order_by(Customer.created_at.desc()).first()
    
    # --- Pass all pre-calculated data to the template ---
    return render_template(
        'customers/customers.html', 
        customers=customers_query.order_by(Customer.name).all(),
        total_revenue=total_revenue,
        active_customer_count=active_customer_count,
        new_customer_count=new_customer_count,
        top_spender=top_spender[0] if top_spender else None,
        most_frequent_customer=most_frequent[0] if most_frequent else None,
        newest_customer=newest_customer
    )

@customers_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        # IMPROVEMENT: Use .get() and add validation
        name = request.form.get('name', '').strip()
        if not name:
            flash('Customer name is required.', 'danger')
            return render_template('customers/add_customer.html')

        try:
            phone = request.form.get('phone', '')
            email = request.form.get('email', '')
            address = request.form.get('address', '')
            
            customer = Customer(name=name, phone=phone, email=email, address=address)
            db.session.add(customer)
            db.session.commit()
            
            flash('Customer added successfully!', 'success')
            return redirect(url_for('customers.customers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding customer: {str(e)}', 'danger')
    
    return render_template('customers/add_customer.html')

@customers_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_customer(id):
    customer = Customer.query.get_or_404(id)
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Customer name is required.', 'danger')
            return render_template('customers/edit_customer.html', customer=customer)
            
        try:
            customer.name = name
            customer.phone = request.form.get('phone', '')
            customer.email = request.form.get('email', '')
            customer.address = request.form.get('address', '')
            
            db.session.commit()
            
            flash('Customer updated successfully!', 'success')
            return redirect(url_for('customers.customers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating customer: {str(e)}', 'danger')
    
    return render_template('customers/edit_customer.html', customer=customer)

@customers_bp.route('/delete/<int:id>', methods=['POST']) # FIX: Changed to POST
@login_required
def delete_customer(id):
    customer = Customer.query.get_or_404(id)
    
    try:
        if customer.sales:
            flash('Cannot delete customer with existing sales records.', 'danger')
            return redirect(url_for('customers.customers'))
        
        db.session.delete(customer)
        db.session.commit()
        flash('Customer deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting customer: {str(e)}', 'danger')
    
    return redirect(url_for('customers.customers'))

@customers_bp.route('/view/<int:id>')
@login_required
def view_customer(id):
    customer = Customer.query.get_or_404(id)
    return render_template('customers/view_customer.html', customer=customer)

# --- API ---
@customers_bp.route('/api/search')
@login_required
def api_customers_search():
    search_term = request.args.get('q', '')
    
    # IMPROVEMENT: Use a helper or inline query for clarity
    query = Customer.query
    if search_term:
        search_pattern = f'%{search_term}%'
        query = query.filter(
            or_(
                Customer.name.ilike(search_pattern),
                Customer.phone.ilike(search_pattern),
                Customer.email.ilike(search_pattern)
            )
        )
    customers = query.order_by(Customer.name).all()
    
    # IMPROVEMENT: Use a to_dict() method on the model for cleaner serialization
    results = [customer.to_dict() for customer in customers]
    
    return jsonify(results) # FIX: Return a proper JSON response