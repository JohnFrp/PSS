# check_database.py
from app import create_app, db
from sqlalchemy import inspect

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print("Tables in database:", tables)
    
    # Check if users table exists and has the right columns
    if 'users' in tables:
        columns = [col['name'] for col in inspector.get_columns('users')]
        print("Columns in users table:", columns)