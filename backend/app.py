# app.py - Flask Backend with JWT Authentication and Firebase
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
from functools import wraps
import re

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

# Enable CORS for all routes
CORS(app)

# Initialize Firebase Admin SDK
try:
    # For local development, you'll need to download your Firebase service account key
    # and place it in the project directory
    cred = credentials.Certificate('firebase-service-account-key.json')
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase initialized successfully!")
except Exception as e:
    print(f"Firebase initialization error: {e}")
    # For demo purposes, we'll continue without Firebase
    db = None

# Helper Functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format"""
    pattern = r'^[\+]?[1-9][\d]{0,15}$'
    return re.match(pattern, phone.replace(' ', '').replace('-', '')) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Check password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token(user_id, email):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=7),  # Token expires in 7 days
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        payload = verify_token(token)
        if payload is None:
            return jsonify({'message': 'Token is invalid or expired'}), 401
        
        # Add user info to request context
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated_function

# Routes

@app.route('/', methods=['GET'])
def home():
    """Health check endpoint"""
    return jsonify({
        'message': 'Smart Attendance System API',
        'status': 'running',
        'version': '1.0.0',
        'firebase_connected': db is not None
    })

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field.capitalize()} is required'}), 400
        
        name = data['name'].strip()
        email = data['email'].strip().lower()
        phone = data['phone'].strip()
        password = data['password']
        
        # Validate input formats
        if not validate_email(email):
            return jsonify({'message': 'Invalid email format'}), 400
        
        if not validate_phone(phone):
            return jsonify({'message': 'Invalid phone number format'}), 400
        
        is_valid, password_message = validate_password(password)
        if not is_valid:
            return jsonify({'message': password_message}), 400
        
        if db is None:
            return jsonify({'message': 'Database connection not available'}), 500
        
        # Check if user already exists
        users_ref = db.collection('users')
        existing_user = users_ref.where('email', '==', email).limit(1).get()
        
        if len(existing_user) > 0:
            return jsonify({'message': 'User with this email already exists'}), 409
        
        # Hash password
        hashed_password = hash_password(password)
        
        # Create user document
        user_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_active': True,
            'role': 'user'  # Default role
        }
        
        # Add user to Firestore
        doc_ref = users_ref.add(user_data)
        user_id = doc_ref[1].id
        
        return jsonify({
            'message': 'User created successfully',
            'user_id': user_id
        }), 201
        
    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        
        if not validate_email(email):
            return jsonify({'message': 'Invalid email format'}), 400
        
        if db is None:
            return jsonify({'message': 'Database connection not available'}), 500
        
        # Find user by email
        users_ref = db.collection('users')
        user_query = users_ref.where('email', '==', email).limit(1).get()
        
        if len(user_query) == 0:
            return jsonify({'message': 'Invalid email or password'}), 401
        
        user_doc = user_query[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id
        
        # Check if user is active
        if not user_data.get('is_active', True):
            return jsonify({'message': 'Account is deactivated'}), 401
        
        # Verify password
        if not check_password(password, user_data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Generate JWT token
        token = generate_token(user_id, email)
        
        # Update last login time
        users_ref.document(user_id).update({
            'last_login': datetime.utcnow()
        })
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user_id,
                'name': user_data['name'],
                'email': user_data['email'],
                'phone': user_data['phone'],
                'role': user_data.get('role', 'user')
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/profile', methods=['GET'])
@token_required
def get_profile():
    """Get user profile (protected route)"""
    try:
        user_id = request.current_user['user_id']
        
        if db is None:
            return jsonify({'message': 'Database connection not available'}), 500
        
        # Get user document
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({'message': 'User not found'}), 404
        
        user_data = user_doc.to_dict()
        
        # Remove sensitive information
        user_data.pop('password', None)
        user_data['id'] = user_id
        
        return jsonify({
            'user': user_data
        }), 200
        
    except Exception as e:
        print(f"Profile fetch error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/update-profile', methods=['PUT'])
@token_required
def update_profile():
    """Update user profile (protected route)"""
    try:
        user_id = request.current_user['user_id']
        data = request.get_json()
        
        if db is None:
            return jsonify({'message': 'Database connection not available'}), 500
        
        # Fields that can be updated
        updatable_fields = ['name', 'phone']
        update_data = {}
        
        for field in updatable_fields:
            if field in data:
                if field == 'phone' and not validate_phone(data[field]):
                    return jsonify({'message': 'Invalid phone number format'}), 400
                update_data[field] = data[field].strip() if isinstance(data[field], str) else data[field]
        
        if not update_data:
            return jsonify({'message': 'No valid fields to update'}), 400
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Update user document
        db.collection('users').document(user_id).update(update_data)
        
        return jsonify({
            'message': 'Profile updated successfully'
        }), 200
        
    except Exception as e:
        print(f"Profile update error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password():
    """Change user password (protected route)"""
    try:
        user_id = request.current_user['user_id']
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['current_password', 'new_password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field.replace("_", " ").title()} is required'}), 400
        
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Validate new password
        is_valid, password_message = validate_password(new_password)
        if not is_valid:
            return jsonify({'message': password_message}), 400
        
        if db is None:
            return jsonify({'message': 'Database connection not available'}), 500
        
        # Get user document
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({'message': 'User not found'}), 404
        
        user_data = user_doc.to_dict()
        
        # Verify current password
        if not check_password(current_password, user_data['password']):
            return jsonify({'message': 'Current password is incorrect'}), 401
        
        # Hash new password
        hashed_new_password = hash_password(new_password)
        
        # Update password
        db.collection('users').document(user_id).update({
            'password': hashed_new_password,
            'updated_at': datetime.utcnow()
        })
        
        return jsonify({
            'message': 'Password changed successfully'
        }), 200
        
    except Exception as e:
        print(f"Password change error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'message': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create tables or initialize database if needed
    print("Starting Smart Attendance System API...")
    print("Make sure to:")
    print("1. Install required packages: pip install flask flask-cors firebase-admin PyJWT bcrypt")
    print("2. Download your Firebase service account key and save as 'firebase-service-account-key.json'")
    print("3. Update the SECRET_KEY in production")
    
    app.run(debug=True, host='0.0.0.0', port=5000)