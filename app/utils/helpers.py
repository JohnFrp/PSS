from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import joinedload
from app import db
from app.models import User, Medication, SaleTransaction, SaleItem, Customer

def create_admin_user():
    """Create admin user if it doesn't exist"""
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        try:
            admin_user = User(
                username='admin',
                email='admin@pharmacy.com',
                role='admin',
                is_approved=True,
                is_active=True
            )
            admin_user.set_password('admin123')
            
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created: username='admin', password='admin123'")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error creating admin user: {str(e)}")

def get_sales_summary():
    # Total medications (exclude deleted)
    total_medications = Medication.query.filter_by(deleted=False).count()
    
    # Low stock count (exclude deleted)
    low_stock_count = Medication.query.filter(
        and_(
            Medication.stock_quantity <= 10,
            Medication.deleted == False
        )
    ).count()
    
    # Expired medications count (exclude deleted)
    expired_count = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < datetime.now().date(),
            Medication.deleted == False
        )
    ).count()
    
    # Today's sales
    today = datetime.now().date()
    today_sales = db.session.query(
        func.coalesce(func.sum(SaleTransaction.total_amount), 0)
    ).filter(
        func.date(SaleTransaction.sale_date) == today,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    # Month sales
    current_month = datetime.now().strftime('%Y-%m')
    month_sales = db.session.query(
        func.coalesce(func.sum(SaleTransaction.total_amount), 0)
    ).filter(
        func.to_char(SaleTransaction.sale_date, 'YYYY-MM') == current_month,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    # Today's profit
    today_profit = db.session.query(
        func.coalesce(func.sum(SaleItem.quantity * (SaleItem.unit_price - Medication.cost_price)), 0)
    ).join(Medication, SaleItem.medication_id == Medication.id
    ).join(SaleTransaction, SaleItem.sale_id == SaleTransaction.id
    ).filter(
        func.date(SaleTransaction.sale_date) == today,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    return {
        'total_medications': total_medications,
        'low_stock_count': low_stock_count,
        'expired_count': expired_count,
        'today_sales': float(today_sales),
        'month_sales': float(month_sales),
        'today_profit': float(today_profit) if today_profit else 0
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
    results = Medication.query.filter(
        and_(
            Medication.stock_quantity <= threshold,
            Medication.deleted == False
        )
    ).all()
    return results

def get_expired_medications():
    today = datetime.now().date()
    results = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < today,
            Medication.deleted == False
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
            Medication.expiry_date <= soon_date,
            Medication.deleted == False
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
    medications = Medication.query.filter(
        Medication.stock_quantity > 0, 
        Medication.deleted == False
    ).order_by(Medication.name).all()
    return medications

def get_all_sales():
    sales = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).order_by(SaleTransaction.sale_date.desc()).all()
    return sales

def get_filtered_sales(filter_type):
    query = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).filter(SaleTransaction.payment_status == 'completed')
    
    if filter_type == 'today':
        today = datetime.now().date()
        query = query.filter(func.date(SaleTransaction.sale_date) == today)
    elif filter_type == 'week':
        week_ago = datetime.now() - timedelta(days=7)
        query = query.filter(SaleTransaction.sale_date >= week_ago)
    elif filter_type == 'month':
        current_month = datetime.now().strftime('%Y-%m')
        query = query.filter(func.to_char(SaleTransaction.sale_date, 'YYYY-MM') == current_month)
    
    sales = query.order_by(SaleTransaction.sale_date.desc()).all()
    return sales

def get_customer_by_id(customer_id):
    return Customer.query.get(customer_id)

def search_customers(search_term):
    search_pattern = f'%{search_term}%'
    return Customer.query.filter(
        or_(
            Customer.name.ilike(search_pattern),
            Customer.phone.ilike(search_pattern),
            Customer.email.ilike(search_pattern)
        )
    ).all()

def create_customer(name, phone=None, email=None, address=None):
    customer = Customer(name=name, phone=phone, email=email, address=address)
    db.session.add(customer)
    db.session.commit()
    return customer

def process_sale_transaction(items, customer_id, user_id, payment_method, discount=0, tax_rate=0, notes=None):
    """
    Process a complete sale transaction with multiple items
    """
    try:
        # Validate items
        if not items or len(items) == 0:
            raise Exception("No items in cart")
        
        # Calculate totals
        subtotal = 0
        for item in items:
            # Ensure all required fields are present
            if 'medication_id' not in item:
                raise Exception("Missing medication_id in item")
            if 'unit_price' not in item:
                raise Exception("Missing unit_price in item")
            if 'quantity' not in item:
                raise Exception("Missing quantity in item")
            
            # Convert to proper types
            item['medication_id'] = int(item['medication_id'])
            item['unit_price'] = float(item['unit_price'])
            item['quantity'] = int(item['quantity'])
            
            subtotal += item['quantity'] * item['unit_price']
        
        tax_amount = subtotal * tax_rate
        total_amount = subtotal + tax_amount - discount
        
        # Generate transaction ID
        transaction_id = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Create sale transaction
        sale = SaleTransaction(
            transaction_id=transaction_id,
            customer_id=customer_id,
            user_id=user_id,
            total_amount=total_amount,
            tax_amount=tax_amount,
            discount_amount=discount,
            payment_method=payment_method,
            notes=notes
        )
        
        db.session.add(sale)
        db.session.flush()  # Get the sale ID without committing
        
        # Add sale items and update inventory
        for item in items:
            medication = Medication.query.get(item['medication_id'])
            if not medication:
                raise Exception(f"Medication with ID {item['medication_id']} not found")
            
            if medication.stock_quantity < item['quantity']:
                raise Exception(f"Not enough stock for {medication.name}. Available: {medication.stock_quantity}")
            
            # Create sale item
            sale_item = SaleItem(
                sale_id=sale.id,
                medication_id=item['medication_id'],
                quantity=item['quantity'],
                unit_price=item['unit_price'],
                total_price=item['quantity'] * item['unit_price']
            )
            db.session.add(sale_item)
            
            # Update medication stock
            medication.stock_quantity -= item['quantity']
        
        db.session.commit()
        return sale
        
    except Exception as e:
        db.session.rollback()
        raise e

def get_sale_details(sale_id):
    return SaleTransaction.query.options(
        joinedload(SaleTransaction.items).joinedload(SaleItem.medication),
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).get(sale_id)

def get_sales_report(start_date=None, end_date=None):
    query = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).filter(SaleTransaction.payment_status == 'completed')
    
    if start_date and end_date:
        query = query.filter(SaleTransaction.sale_date.between(start_date, end_date))
    elif start_date:
        query = query.filter(SaleTransaction.sale_date >= start_date)
    elif end_date:
        query = query.filter(SaleTransaction.sale_date <= end_date)
    
    return query.order_by(SaleTransaction.sale_date.desc()).all()

def get_daily_sales_chart_data(days=30):
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    
    # Get daily sales data
    daily_sales = db.session.query(
        func.date(SaleTransaction.sale_date).label('sale_date'),
        func.sum(SaleTransaction.total_amount).label('total_sales'),
        func.count(SaleTransaction.id).label('transaction_count')
    ).filter(
        SaleTransaction.sale_date.between(start_date, end_date),
        SaleTransaction.payment_status == 'completed'
    ).group_by(
        func.date(SaleTransaction.sale_date)
    ).order_by(
        func.date(SaleTransaction.sale_date)
    ).all()
    
    # Format data for chart
    dates = []
    sales = []
    transactions = []
    
    for day in daily_sales:
        dates.append(day.sale_date.strftime('%Y-%m-%d'))
        sales.append(float(day.total_sales) if day.total_sales else 0)
        transactions.append(day.transaction_count)
    
    return {
        'dates': dates,
        'sales': sales,
        'transactions': transactions
    }
    
    
    
def search_medications(search_term):
    from sqlalchemy import and_, or_
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
    from sqlalchemy import and_
    results = Medication.query.filter(
        and_(
            Medication.stock_quantity <= threshold,
            Medication.deleted == False
        )
    ).all()
    return results

def get_expired_medications():
    from sqlalchemy import and_
    today = datetime.now().date()
    results = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < today,
            Medication.deleted == False
        )
    ).all()
    return results

def get_expiring_soon_medications(days=30):
    from sqlalchemy import and_
    today = datetime.now().date()
    soon_date = today + timedelta(days=days)
    results = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date >= today,
            Medication.expiry_date <= soon_date,
            Medication.deleted == False
        )
    ).all()
    return results

def get_medication_by_id(medication_id):
    return Medication.query.get(medication_id)

def get_all_medications():
    medications = Medication.query.filter_by(deleted=False).order_by(Medication.name).all()
    return medications

def get_medications_with_stock():
    from sqlalchemy import and_
    medications = Medication.query.filter(
        and_(
            Medication.stock_quantity > 0, 
            Medication.deleted == False
        )
    ).order_by(Medication.name).all()
    return medications


def process_sale_transaction(items, customer_id, user_id, payment_method, discount=0, tax_rate=0, notes=None):
    """
    Process a complete sale transaction with multiple items
    """
    try:
        # Validate items
        if not items or len(items) == 0:
            raise Exception("No items in cart")
        
        # Calculate totals
        subtotal = 0
        for item in items:
            # Ensure all required fields are present
            if 'medication_id' not in item:
                raise Exception("Missing medication_id in item")
            if 'unit_price' not in item:
                raise Exception("Missing unit_price in item")
            if 'quantity' not in item:
                raise Exception("Missing quantity in item")
            
            # Convert to proper types
            item['medication_id'] = int(item['medication_id'])
            item['unit_price'] = float(item['unit_price'])
            item['quantity'] = int(item['quantity'])
            
            subtotal += item['quantity'] * item['unit_price']
        
        tax_amount = subtotal * tax_rate
        total_amount = subtotal + tax_amount - discount
        
        # Generate transaction ID
        transaction_id = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Create sale transaction
        from app.models import SaleTransaction, SaleItem, Medication
        sale = SaleTransaction(
            transaction_id=transaction_id,
            customer_id=customer_id,
            user_id=user_id,
            total_amount=total_amount,
            tax_amount=tax_amount,
            discount_amount=discount,
            payment_method=payment_method,
            notes=notes
        )
        
        db.session.add(sale)
        db.session.flush()  # Get the sale ID without committing
        
        # Add sale items and update inventory
        for item in items:
            medication = Medication.query.get(item['medication_id'])
            if not medication:
                raise Exception(f"Medication with ID {item['medication_id']} not found")
            
            if medication.stock_quantity < item['quantity']:
                raise Exception(f"Not enough stock for {medication.name}. Available: {medication.stock_quantity}")
            
            # Create sale item
            sale_item = SaleItem(
                sale_id=sale.id,
                medication_id=item['medication_id'],
                quantity=item['quantity'],
                unit_price=item['unit_price'],
                total_price=item['quantity'] * item['unit_price']
            )
            db.session.add(sale_item)
            
            # Update medication stock
            medication.stock_quantity -= item['quantity']
        
        db.session.commit()
        return sale
        
    except Exception as e:
        db.session.rollback()
        raise e

def get_sale_details(sale_id):
    from sqlalchemy.orm import joinedload
    return SaleTransaction.query.options(
        joinedload(SaleTransaction.items).joinedload(SaleItem.medication),
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).get(sale_id)

def get_filtered_sales(filter_type):
    from sqlalchemy.orm import joinedload
    from sqlalchemy import func
    
    query = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).filter(SaleTransaction.payment_status == 'completed')
    
    if filter_type == 'today':
        today = datetime.now().date()
        query = query.filter(func.date(SaleTransaction.sale_date) == today)
    elif filter_type == 'week':
        week_ago = datetime.now() - timedelta(days=7)
        query = query.filter(SaleTransaction.sale_date >= week_ago)
    elif filter_type == 'month':
        current_month = datetime.now().strftime('%Y-%m')
        query = query.filter(func.to_char(SaleTransaction.sale_date, 'YYYY-MM') == current_month)
    
    sales = query.order_by(SaleTransaction.sale_date.desc()).all()
    return sales

def get_sales_report(start_date=None, end_date=None):
    from sqlalchemy.orm import joinedload
    query = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).filter(SaleTransaction.payment_status == 'completed')
    
    if start_date and end_date:
        query = query.filter(SaleTransaction.sale_date.between(start_date, end_date))
    elif start_date:
        query = query.filter(SaleTransaction.sale_date >= start_date)
    elif end_date:
        query = query.filter(SaleTransaction.sale_date <= end_date)
    
    return query.order_by(SaleTransaction.sale_date.desc()).all()

def get_daily_sales_chart_data(days=30):
    from sqlalchemy import func
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    
    # Get daily sales data
    daily_sales = db.session.query(
        func.date(SaleTransaction.sale_date).label('sale_date'),
        func.sum(SaleTransaction.total_amount).label('total_sales'),
        func.count(SaleTransaction.id).label('transaction_count')
    ).filter(
        SaleTransaction.sale_date.between(start_date, end_date),
        SaleTransaction.payment_status == 'completed'
    ).group_by(
        func.date(SaleTransaction.sale_date)
    ).order_by(
        func.date(SaleTransaction.sale_date)
    ).all()
    
    # Format data for chart
    dates = []
    sales = []
    transactions = []
    
    for day in daily_sales:
        dates.append(day.sale_date.strftime('%Y-%m-%d'))
        sales.append(float(day.total_sales) if day.total_sales else 0)
        transactions.append(day.transaction_count)
    
    return {
        'dates': dates,
        'sales': sales,
        'transactions': transactions
    }
    


def search_customers(search_term):
    from sqlalchemy import or_
    search_pattern = f'%{search_term}%'
    return Customer.query.filter(
        or_(
            Customer.name.ilike(search_pattern),
            Customer.phone.ilike(search_pattern),
            Customer.email.ilike(search_pattern)
        )
    ).all()

def get_customer_by_id(customer_id):
    return Customer.query.get(customer_id)

def create_customer(name, phone=None, email=None, address=None):
    customer = Customer(name=name, phone=phone, email=email, address=address)
    db.session.add(customer)
    db.session.commit()
    return customer
    


def get_sales_report(start_date=None, end_date=None):
    from sqlalchemy.orm import joinedload
    query = SaleTransaction.query.options(
        joinedload(SaleTransaction.customer),
        joinedload(SaleTransaction.user)
    ).filter(SaleTransaction.payment_status == 'completed')
    
    if start_date and end_date:
        query = query.filter(SaleTransaction.sale_date.between(start_date, end_date))
    elif start_date:
        query = query.filter(SaleTransaction.sale_date >= start_date)
    elif end_date:
        query = query.filter(SaleTransaction.sale_date <= end_date)
    
    return query.order_by(SaleTransaction.sale_date.desc()).all()

def get_daily_sales_chart_data(days=30):
    from sqlalchemy import func
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    
    # Get daily sales data
    daily_sales = db.session.query(
        func.date(SaleTransaction.sale_date).label('sale_date'),
        func.sum(SaleTransaction.total_amount).label('total_sales'),
        func.count(SaleTransaction.id).label('transaction_count')
    ).filter(
        SaleTransaction.sale_date.between(start_date, end_date),
        SaleTransaction.payment_status == 'completed'
    ).group_by(
        func.date(SaleTransaction.sale_date)
    ).order_by(
        func.date(SaleTransaction.sale_date)
    ).all()
    
    # Format data for chart
    dates = []
    sales = []
    transactions = []
    
    for day in daily_sales:
        dates.append(day.sale_date.strftime('%Y-%m-%d'))
        sales.append(float(day.total_sales) if day.total_sales else 0)
        transactions.append(day.transaction_count)
    
    return {
        'dates': dates,
        'sales': sales,
        'transactions': transactions
    }

def get_sales_summary():
    from sqlalchemy import func, and_
    # Total medications (exclude deleted)
    total_medications = Medication.query.filter_by(deleted=False).count()
    
    # Low stock count (exclude deleted)
    low_stock_count = Medication.query.filter(
        and_(
            Medication.stock_quantity <= 10,
            Medication.deleted == False
        )
    ).count()
    
    # Expired medications count (exclude deleted)
    expired_count = Medication.query.filter(
        and_(
            Medication.expiry_date.isnot(None),
            Medication.expiry_date < datetime.now().date(),
            Medication.deleted == False
        )
    ).count()
    
    # Today's sales
    today = datetime.now().date()
    today_sales = db.session.query(
        func.coalesce(func.sum(SaleTransaction.total_amount), 0)
    ).filter(
        func.date(SaleTransaction.sale_date) == today,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    # Month sales
    current_month = datetime.now().strftime('%Y-%m')
    month_sales = db.session.query(
        func.coalesce(func.sum(SaleTransaction.total_amount), 0)
    ).filter(
        func.to_char(SaleTransaction.sale_date, 'YYYY-MM') == current_month,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    # Today's profit
    today_profit = db.session.query(
        func.coalesce(func.sum(SaleItem.quantity * (SaleItem.unit_price - Medication.cost_price)), 0)
    ).join(Medication, SaleItem.medication_id == Medication.id
    ).join(SaleTransaction, SaleItem.sale_id == SaleTransaction.id
    ).filter(
        func.date(SaleTransaction.sale_date) == today,
        SaleTransaction.payment_status == 'completed'
    ).scalar()
    
    return {
        'total_medications': total_medications,
        'low_stock_count': low_stock_count,
        'expired_count': expired_count,
        'today_sales': float(today_sales),
        'month_sales': float(month_sales),
        'today_profit': float(today_profit) if today_profit else 0
    }