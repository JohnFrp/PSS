# FIX: Moved all imports to the top of the file for clarity and best practice.
from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import current_user, login_required
from sqlalchemy import or_
from datetime import datetime, timedelta

from app.models import SaleTransaction, Medication, User
from app.utils.helpers import get_sales_summary, get_daily_sales_chart_data, get_expiring_soon_medications

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@main_bp.route('/index')
@login_required
def index():        
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # Dashboard route for authenticated users
    stats = get_sales_summary()
    
    
    # Get additional stats for dashboard
    expiring_soon_count = len(get_expiring_soon_medications())
    
    # Get recent activity counts
    one_day_ago = datetime.now() - timedelta(days=1)
    recent_sales_count = SaleTransaction.query.filter(
        SaleTransaction.sale_date >= one_day_ago
    ).count()
    
    seven_days_ago = datetime.now() - timedelta(days=7)
    recent_medications_count = Medication.query.filter(
        Medication.created_at >= seven_days_ago
    ).count()
    
    total_users_count = User.query.count()
    
    # Get chart data
    chart_data = get_daily_sales_chart_data(7)

    return render_template('dashboard.html', stats=stats,
                           expiring_soon_count=expiring_soon_count,
                           recent_sales_count=recent_sales_count,
                           recent_medications_count=recent_medications_count,
                           total_users_count=total_users_count,
                           chart_data=chart_data)

@main_bp.route('/search')
@login_required  # FIX: Added decorator to make this a secure, members-only page.
def search():
    search_term = request.args.get('q', '').strip()
    results = []
    
    if search_term:
        search_pattern = f"%{search_term}%"
        # Using the query logic from the previous step directly here
        results = Medication.query.filter_by(deleted=False).filter(
            or_(
                Medication.name.ilike(search_pattern),
                Medication.generic_name.ilike(search_pattern),
                Medication.category.ilike(search_pattern),
                Medication.barcode.ilike(search_pattern)
            )
        ).order_by(Medication.name).all()
        
    return render_template('search.html', results=results, search_term=search_term)