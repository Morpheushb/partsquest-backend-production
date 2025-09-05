from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os
from datetime import datetime, timedelta
import jwt
from functools import wraps

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
database_url = os.environ.get('DATABASE_URL')
print(f"DATABASE_URL from environment: {database_url}")

# Handle PostgreSQL SSL requirements for Render
if database_url and database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql://', 1)
    if '?sslmode=' not in database_url:
        database_url += '?sslmode=require'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'sslmode': 'require'
    }
}

# Initialize extensions
db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    subscription_status = db.Column(db.String(20), default='inactive')
    stripe_customer_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'company': self.company,
            'phone': self.phone,
            'subscription_status': self.subscription_status,
            'created_at': self.created_at.isoformat()
        }

class PartRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    part_number = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    quantity = db.Column(db.Integer)
    target_price = db.Column(db.Float)
    urgency = db.Column(db.String(20))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'part_number': self.part_number,
            'description': self.description,
            'quantity': self.quantity,
            'target_price': self.target_price,
            'urgency': self.urgency,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vin = db.Column(db.String(17))
    year = db.Column(db.String(4), nullable=False)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50))
    trim = db.Column(db.String(50))
    engine = db.Column(db.String(100))
    transmission = db.Column(db.String(50))
    mileage = db.Column(db.Integer)
    nickname = db.Column(db.String(100))
    license_plate = db.Column(db.String(20))
    customer_name = db.Column(db.String(100))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'vin': self.vin,
            'year': self.year,
            'make': self.make,
            'model': self.model,
            'trim': self.trim,
            'engine': self.engine,
            'transmission': self.transmission,
            'mileage': self.mileage,
            'nickname': self.nickname,
            'license_plate': self.license_plate,
            'customer_name': self.customer_name,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

# JWT Token Functions
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': 'User not found'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Subscription required decorator
def subscription_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.subscription_status != 'active':
            return jsonify({'error': 'Active subscription required to access this feature'}), 403
        
        return f(current_user, *args, **kwargs)
    return decorated

# Vehicle limit checking
def get_user_subscription_plan(user):
    """Get user's subscription plan based on their Stripe subscription"""
    # This would normally query Stripe, but for now we'll use a simple mapping
    # based on subscription_status or could be enhanced with actual Stripe data
    if user.subscription_status == 'active':
        # For now, assume 'professional' plan for active users
        # This should be enhanced to get actual plan from Stripe
        return 'professional'
    return 'test'

def check_vehicle_limit(user):
    """Check if user can add more vehicles based on their subscription plan"""
    vehicle_count = Vehicle.query.filter_by(user_id=user.id).count()
    
    limits = {
        'test': 1,
        'starter': 10,
        'professional': 25,
        'fleet': 50,
        'enterprise': float('inf')
    }
    
    user_plan = get_user_subscription_plan(user)
    limit = limits.get(user_plan, 1)
    
    return vehicle_count < limit, vehicle_count, limit

# NUCLEAR BACKEND PROTECTION - Block revenue leak at API level
@app.before_request
def enforce_subscription_at_api_level():
    """
    Global protection against subscription bypass.
    Even if frontend is cached/bypassed, backend will block access.
    """
    # Skip check for public endpoints
    public_endpoints = [
        '/api/login', '/api/register', '/api/health', 
        '/api/admin/check-users', '/api/admin/fix-subscription-status',
        '/', '/favicon.ico'
    ]
    
    # Skip if accessing public endpoint
    if request.path in public_endpoints:
        return
    
    # Skip if not an API endpoint
    if not request.path.startswith('/api/'):
        return
    
    # For all protected API endpoints, verify subscription
    print(f"🚨 BACKEND PROTECTION - Checking access to: {request.path}")
    
    # Get current user from token
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header:
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            pass
    
    if not token:
        print(f"🚨 BACKEND PROTECTION - No token for: {request.path}")
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        if not user:
            print(f"🚨 BACKEND PROTECTION - Invalid user for: {request.path}")
            return jsonify({'error': 'Invalid user'}), 401
        
        print(f"🚨 BACKEND PROTECTION - User {user.email} accessing {request.path}")
        print(f"🚨 BACKEND PROTECTION - Subscription status: {user.subscription_status}")
        
        # Block access for non-active users to protected endpoints
        if user.subscription_status != 'active':
            print(f"🚨 BACKEND PROTECTION - BLOCKING ACCESS! User has '{user.subscription_status}' status")
            return jsonify({
                'error': 'Active subscription required',
                'subscription_status': user.subscription_status,
                'message': 'Please upgrade your subscription to access this feature'
            }), 402  # Payment Required
        
        print(f"✅ BACKEND PROTECTION - Access granted to active user")
        
    except jwt.ExpiredSignatureError:
        print(f"🚨 BACKEND PROTECTION - Expired token for: {request.path}")
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        print(f"🚨 BACKEND PROTECTION - Invalid token for: {request.path}")
        return jsonify({'error': 'Invalid token'}), 401

# Routes
@app.route('/')
def home():
    return jsonify({
        'message': 'PartsQuest API is running',
        'version': '1.0.0',
        'status': 'healthy'
    })

@app.route('/api/health')
def health_check():
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'unknown'
    }
    
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        health_status['database'] = 'connected'
    except Exception as e:
        health_status['database'] = f'error: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    return jsonify(health_status)

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            company=data.get('company', ''),
            phone=data.get('phone', '')
        )
        user.set_password(data['password'])
        
        # Create Stripe customer
        try:
            stripe_customer = stripe.Customer.create(
                email=user.email,
                name=f"{user.first_name} {user.last_name}",
                metadata={'user_id': str(user.id)}
            )
            user.stripe_customer_id = stripe_customer.id
        except Exception as e:
            print(f"Stripe customer creation failed: {e}")
        
        db.session.add(user)
        db.session.commit()
        
        # Generate token
        token = generate_token(user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        token = generate_token(user.id)
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_dict()})

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'company', 'phone']
        for field in allowed_fields:
            if field in data:
                setattr(current_user, field, data[field])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/part-requests', methods=['POST'])
@token_required
@subscription_required
def create_part_request(current_user):
    try:
        data = request.get_json()
        
        if not data.get('part_number'):
            return jsonify({'error': 'Part number is required'}), 400
        
        part_request = PartRequest(
            user_id=current_user.id,
            part_number=data['part_number'],
            description=data.get('description', ''),
            quantity=data.get('quantity', 1),
            target_price=data.get('target_price'),
            urgency=data.get('urgency', 'normal')
        )
        
        db.session.add(part_request)
        db.session.commit()
        
        return jsonify({
            'message': 'Part request created successfully',
            'part_request': part_request.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/part-requests', methods=['GET'])
@token_required
@subscription_required
def get_part_requests(current_user):
    try:
        part_requests = PartRequest.query.filter_by(user_id=current_user.id).order_by(PartRequest.created_at.desc()).all()
        return jsonify({
            'part_requests': [pr.to_dict() for pr in part_requests]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stripe/config', methods=['GET'])
def get_stripe_config():
    return jsonify({
        'publishable_key': STRIPE_PUBLISHABLE_KEY
    })

@app.route('/api/stripe/create-checkout-session', methods=['POST'])
@token_required
def create_checkout_session(current_user):
    try:
        data = request.get_json()
        price_id = data.get('price_id')
        
        if not price_id:
            return jsonify({'error': 'Price ID is required'}), 400
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=current_user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.host_url + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'cancel',
            metadata={
                'user_id': str(current_user.id)
            }
        )
        
        return jsonify({
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.environ.get('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']
        
        # Update user subscription status
        user = User.query.get(user_id)
        if user:
            user.subscription_status = 'active'
            db.session.commit()
    
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    # For production deployment (Gunicorn)
    with app.app_context():
        db.create_all()


# Admin endpoints for debugging and fixing subscription statuses
@app.route('/api/admin/check-users', methods=['GET'])
def check_users():
    """Check all users and their subscription status"""
    try:
        users = User.query.all()
        user_data = []
        
        for user in users:
            user_data.append({
                'id': user.id,
                'email': user.email,
                'subscription_status': user.subscription_status,
                'created_at': user.created_at.isoformat()
            })
        
        return jsonify({
            'total_users': len(users),
            'users': user_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Vehicle Management API Endpoints

@app.route('/api/vehicles', methods=['GET'])
@token_required
def get_vehicles(current_user):
    """Get all vehicles for the current user"""
    try:
        vehicles = Vehicle.query.filter_by(user_id=current_user.id).order_by(Vehicle.created_at.desc()).all()
        return jsonify({
            'vehicles': [vehicle.to_dict() for vehicle in vehicles],
            'count': len(vehicles)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vehicles', methods=['POST'])
@token_required
def create_vehicle(current_user):
    """Create a new vehicle"""
    try:
        # Check vehicle limit
        can_add, current_count, limit = check_vehicle_limit(current_user)
        if not can_add:
            return jsonify({
                'error': f'Vehicle limit reached. Your plan allows {limit} vehicles, you currently have {current_count}.',
                'current_count': current_count,
                'limit': limit
            }), 403
        
        data = request.get_json()
        
        # Validate required fields
        if not data.get('year') or not data.get('make'):
            return jsonify({'error': 'Year and make are required'}), 400
        
        vehicle = Vehicle(
            user_id=current_user.id,
            vin=data.get('vin', '').upper() if data.get('vin') else None,
            year=data.get('year'),
            make=data.get('make'),
            model=data.get('model'),
            trim=data.get('trim'),
            engine=data.get('engine'),
            transmission=data.get('transmission'),
            mileage=data.get('mileage'),
            nickname=data.get('nickname'),
            license_plate=data.get('license_plate'),
            customer_name=data.get('customer_name'),
            notes=data.get('notes')
        )
        
        db.session.add(vehicle)
        db.session.commit()
        
        return jsonify({
            'message': 'Vehicle created successfully',
            'vehicle': vehicle.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/vehicles/<int:vehicle_id>', methods=['PUT'])
@token_required
def update_vehicle(current_user, vehicle_id):
    """Update a vehicle"""
    try:
        vehicle = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
        if not vehicle:
            return jsonify({'error': 'Vehicle not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'vin' in data:
            vehicle.vin = data['vin'].upper() if data['vin'] else None
        if 'year' in data:
            vehicle.year = data['year']
        if 'make' in data:
            vehicle.make = data['make']
        if 'model' in data:
            vehicle.model = data['model']
        if 'trim' in data:
            vehicle.trim = data['trim']
        if 'engine' in data:
            vehicle.engine = data['engine']
        if 'transmission' in data:
            vehicle.transmission = data['transmission']
        if 'mileage' in data:
            vehicle.mileage = data['mileage']
        if 'nickname' in data:
            vehicle.nickname = data['nickname']
        if 'license_plate' in data:
            vehicle.license_plate = data['license_plate']
        if 'customer_name' in data:
            vehicle.customer_name = data['customer_name']
        if 'notes' in data:
            vehicle.notes = data['notes']
        
        vehicle.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Vehicle updated successfully',
            'vehicle': vehicle.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/vehicles/<int:vehicle_id>', methods=['DELETE'])
@token_required
def delete_vehicle(current_user, vehicle_id):
    """Delete a vehicle"""
    try:
        vehicle = Vehicle.query.filter_by(id=vehicle_id, user_id=current_user.id).first()
        if not vehicle:
            return jsonify({'error': 'Vehicle not found'}), 404
        
        db.session.delete(vehicle)
        db.session.commit()
        
        return jsonify({'message': 'Vehicle deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/vehicles/vin-decode', methods=['POST'])
@token_required
def decode_vin(current_user):
    """Decode VIN using NHTSA API"""
    try:
        data = request.get_json()
        vin = data.get('vin', '').replace(' ', '').upper()
        
        if len(vin) != 17:
            return jsonify({'error': 'VIN must be exactly 17 characters'}), 400
        
        # Call NHTSA API
        import requests
        response = requests.get(
            f'https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json',
            timeout=10
        )
        
        if response.status_code != 200:
            return jsonify({'error': 'Failed to decode VIN'}), 500
        
        nhtsa_data = response.json()
        
        if not nhtsa_data.get('Results') or not nhtsa_data['Results'][0]:
            return jsonify({'error': 'VIN not found in database'}), 404
        
        result = nhtsa_data['Results'][0]
        
        # Extract relevant data
        vehicle_data = {
            'vin': vin,
            'year': result.get('ModelYear', ''),
            'make': result.get('Make', ''),
            'model': result.get('Model', ''),
            'trim': result.get('Trim', ''),
            'engine': result.get('EngineModel', ''),
            'transmission': result.get('TransmissionStyle', ''),
            'body_class': result.get('BodyClass', ''),
            'fuel_type': result.get('FuelTypePrimary', '')
        }
        
        return jsonify({
            'message': 'VIN decoded successfully',
            'vehicle_data': vehicle_data
        })
        
    except requests.RequestException as e:
        return jsonify({'error': f'Failed to connect to VIN decoder: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vehicles/bulk', methods=['POST'])
@token_required
def bulk_create_vehicles(current_user):
    """Create multiple vehicles from CSV data"""
    try:
        data = request.get_json()
        vehicles_data = data.get('vehicles', [])
        
        if not vehicles_data:
            return jsonify({'error': 'No vehicle data provided'}), 400
        
        # Check if adding these vehicles would exceed limit
        can_add, current_count, limit = check_vehicle_limit(current_user)
        if current_count + len(vehicles_data) > limit:
            return jsonify({
                'error': f'Adding {len(vehicles_data)} vehicles would exceed your limit of {limit}. You currently have {current_count} vehicles.',
                'current_count': current_count,
                'limit': limit,
                'requested': len(vehicles_data)
            }), 403
        
        created_vehicles = []
        errors = []
        
        for i, vehicle_data in enumerate(vehicles_data):
            try:
                if not vehicle_data.get('year') or not vehicle_data.get('make'):
                    errors.append(f'Row {i+1}: Year and make are required')
                    continue
                
                vehicle = Vehicle(
                    user_id=current_user.id,
                    vin=vehicle_data.get('vin', '').upper() if vehicle_data.get('vin') else None,
                    year=vehicle_data.get('year'),
                    make=vehicle_data.get('make'),
                    model=vehicle_data.get('model'),
                    trim=vehicle_data.get('trim'),
                    engine=vehicle_data.get('engine'),
                    transmission=vehicle_data.get('transmission'),
                    mileage=vehicle_data.get('mileage'),
                    nickname=vehicle_data.get('nickname'),
                    license_plate=vehicle_data.get('license_plate'),
                    customer_name=vehicle_data.get('customer_name'),
                    notes=vehicle_data.get('notes')
                )
                
                db.session.add(vehicle)
                created_vehicles.append(vehicle)
                
            except Exception as e:
                errors.append(f'Row {i+1}: {str(e)}')
        
        if created_vehicles:
            db.session.commit()
        
        return jsonify({
            'message': f'Successfully created {len(created_vehicles)} vehicles',
            'created_count': len(created_vehicles),
            'error_count': len(errors),
            'errors': errors,
            'vehicles': [vehicle.to_dict() for vehicle in created_vehicles]
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fix-subscription-status', methods=['POST'])
def fix_subscription_status():
    """One-time fix to change all 'free' users to 'inactive'"""
    try:
        free_users = User.query.filter_by(subscription_status='free').all()
        count = len(free_users)
        
        for user in free_users:
            user.subscription_status = 'inactive'
        
        db.session.commit()
        
        return jsonify({
            'fixed': count,
            'message': f'Updated {count} users from free to inactive'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)


@app.route('/api/extract-vin', methods=['POST'])
@token_required
@subscription_required
def extract_vin_from_image(current_user):
    """Extract VIN from uploaded image using OpenAI Vision API"""
    try:
        data = request.get_json()
        image_data = data.get('image_data')
        
        if not image_data:
            return jsonify({'error': 'No image data provided'}), 400
        
        # Import OpenAI here to avoid import errors if not available
        try:
            import openai
        except ImportError:
            return jsonify({'error': 'OpenAI library not available'}), 500
        
        # Set up OpenAI client
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        if not openai_api_key:
            return jsonify({'error': 'OpenAI API key not configured'}), 500
        
        client = openai.OpenAI(api_key=openai_api_key)
        
        # Call OpenAI Vision API
        response = client.chat.completions.create(
            model="gpt-4-vision-preview",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Please extract the VIN (Vehicle Identification Number) from this image. The VIN should be exactly 17 characters long and contain only letters and numbers (no I, O, or Q). Return only the VIN number, nothing else."
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_data}"
                            }
                        }
                    ]
                }
            ],
            max_tokens=50
        )
        
        extracted_text = response.choices[0].message.content.strip()
        
        # Validate extracted VIN
        import re
        vin_pattern = r'^[A-HJ-NPR-Z0-9]{17}$'
        if re.match(vin_pattern, extracted_text, re.IGNORECASE):
            return jsonify({'vin': extracted_text.upper()})
        else:
            return jsonify({'error': 'Could not extract a valid VIN from the image'}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error processing image: {str(e)}'}), 500

