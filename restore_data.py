# restore_data.py
from app import create_app, db, User, Medication, Sale
from datetime import datetime
import json

app = create_app()

def restore_from_backup(backup_file_path):
    with app.app_context():
        try:
            # Read the backup file
            with open(backup_file_path, 'r') as f:
                backup_data = json.load(f)
            
            # Restore users
            users_restored = 0
            for user_data in backup_data.get('users', []):
                try:
                    user = User(
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password_hash'],
                        role=user_data['role'],
                        is_active=user_data.get('is_active', True),
                        is_approved=user_data.get('is_approved', True)
                    )
                    if 'created_at' in user_data and user_data['created_at']:
                        user.created_at = datetime.fromisoformat(user_data['created_at'].replace('Z', '+00:00'))
                    db.session.add(user)
                    users_restored += 1
                except Exception as e:
                    print(f"Error restoring user {user_data.get('username', 'unknown')}: {str(e)}")
            
            # Restore medications
            meds_restored = 0
            for med_data in backup_data.get('medications', []):
                try:
                    medication = Medication(
                        name=med_data['name'],
                        generic_name=med_data.get('generic_name', ''),
                        manufacturer=med_data.get('manufacturer', ''),
                        price=med_data['price'],
                        stock_quantity=med_data['stock_quantity'],
                        category=med_data.get('category', ''),
                        barcode=med_data.get('barcode', ''),
                        deleted=med_data.get('deleted', False)
                    )
                    if med_data.get('expiry_date'):
                        medication.expiry_date = datetime.fromisoformat(med_data['expiry_date'].split('T')[0]).date()
                    if 'created_at' in med_data and med_data['created_at']:
                        medication.created_at = datetime.fromisoformat(med_data['created_at'].replace('Z', '+00:00'))
                    db.session.add(medication)
                    meds_restored += 1
                except Exception as e:
                    print(f"Error restoring medication {med_data.get('name', 'unknown')}: {str(e)}")
            
            # Restore sales
            sales_restored = 0
            for sale_data in backup_data.get('sales', []):
                try:
                    sale = Sale(
                        transaction_id=sale_data['transaction_id'],
                        medication_id=sale_data['medication_id'],
                        quantity=sale_data['quantity'],
                        total_price=sale_data['total_price']
                    )
                    if 'sale_date' in sale_data and sale_data['sale_date']:
                        sale.sale_date = datetime.fromisoformat(sale_data['sale_date'].replace('Z', '+00:00'))
                    db.session.add(sale)
                    sales_restored += 1
                except Exception as e:
                    print(f"Error restoring sale {sale_data.get('transaction_id', 'unknown')}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            print(f"Data restored successfully! Users: {users_restored}, Medications: {meds_restored}, Sales: {sales_restored}")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error restoring data: {str(e)}")

if __name__ == "__main__":
    backup_file_path = input("Enter the path to your backup file: ")
    restore_from_backup(backup_file_path)