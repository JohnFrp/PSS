# init_database.py
from app import create_app, db, User, Medication, Sale

app = create_app()

with app.app_context():
    try:
        # Drop all tables (be careful - this will delete all data!)
        db.drop_all()
        print("Dropped all tables")
        
        # Create all tables
        db.create_all()
        print("Created all tables")
        
        # Create admin user
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
        print("Created admin user: username='admin', password='admin123'")
        
        print("Database initialization complete!")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")