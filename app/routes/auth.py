from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_approved:
                flash('Your account is pending admin approval. Please wait for activation.', 'warning')
                return render_template('auth/login.html')
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact an administrator.', 'danger')
                return render_template('auth/login.html')
            
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page or url_for('main.index'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('auth/register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')
        
        # Create user (first user becomes admin and auto-approved)
        user_count = User.query.count()
        role = 'admin' if user_count == 0 else 'user'
        is_approved = True if user_count == 0 else False
        
        user = User(username=username, email=email, role=role, is_approved=is_approved)
        user.set_password(password, method='pbkdf2:sha256')
        
        try:
            db.session.add(user)
            db.session.commit()
            
            if is_approved:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Registration submitted! Your account is pending admin approval.', 'info')
                return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'danger')
    
    return render_template('auth/register.html')

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', user=current_user)

@auth_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')

        # Check if new username or email already exist
        if username != current_user.username and User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('auth.edit_profile'))

        if email != current_user.email and User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('auth.edit_profile'))

        current_user.username = username
        current_user.email = email

        try:
            db.session.commit()
            flash('Your profile has been updated.', 'success')
            return redirect(url_for('auth.profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {e}', 'danger')

    return render_template('auth/edit_profile.html', user=current_user)

@auth_bp.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        print(f"Current password entered: {current_password}")
        print(f"New password entered: {new_password}")
        print(f"Confirm password entered: {confirm_password}")

        if not current_user.check_password(current_password):
            print("Incorrect current password")
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('auth.change_password'))

        if new_password != confirm_password:
            print("New passwords do not match")
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('auth.change_password'))

        current_user.set_password(new_password)
        
        try:
            db.session.commit()
            print("Password changed successfully")
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('auth.profile'))
        except Exception as e:
            db.session.rollback()
            print(f"Error changing password: {e}")
            flash(f'Error changing password: {e}', 'danger')
    
    return render_template('auth/change_password.html')

