import os
from urllib.parse import quote_plus

password = "Johnh4k3r@123"
encoded_password = quote_plus(password)
# Database URI
DATABASE_URI = DATABASE_URI = f"postgresql://postgres.okwpnjobjxrcxhtzvysw:{encoded_password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres"

SECRET_KEY = os.environ.get('SECRET_KEY', 'pharmacy-pos-secret-key')
SQLALCHEMY_DATABASE_URI = DATABASE_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False