from flask import Flask, request, jsonify, make_response
# OEM Lookup Service

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os
from datetime import datetime, timedelta
import jwt
from functools import wraps

# Import Sentry for error monitoring
try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
    
    def init_sentry(app):
        sentry_dsn = os.environ.get('SENTRY_DSN')
        if sentry_dsn:
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[FlaskIntegration()],
                traces_sample_rate=1.0
            )
            print("✅ Sentry initialized")
        else:
            print("⚠️ Sentry DSN not found, skipping initialization")
except ImportError:
    def init_sentry(app):
        print("⚠️ Sentry not installed, skipping initialization")

app = Flask(__name__)

# Initialize Sentry
init_sentry(app)

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

# Configure CORS for production
CORS(app, 
     origins=[
         'https://www.partsquest.org',
         'https://partsquest.org',
         'https://partsquest.vercel.app',  # Current frontend URL
         'https://partsquest-frontend-production.vercel.app',
         'http://localhost:3000',  # For development
         'http://localhost:5000'   # For local testing
     ],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
)

# Initialize OEM Lookup Service
print("✅ OEM Lookup Service initialized")

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
            response = jsonify({'error': 'Token is missing'})
            response.status_code = 401
            response.headers['Access-Control-Allow-Origin'] = 'https://www.partsquest.org'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            response = jsonify({'error': 'Token is invalid or expired'})
            response.status_code = 401
            response.headers['Access-Control-Allow-Origin'] = 'https://www.partsquest.org'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
        current_user = User.query.get(user_id)
        if not current_user:
            response = jsonify({'error': 'User not found'})
            response.status_code = 401
            response.headers['Access-Control-Allow-Origin'] = 'https://www.partsquest.org'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response
        
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

# MINIMAL CORS HANDLER - Nuclear protection temporarily disabled
@app.before_request
def handle_cors():
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = make_response()
        # Allow all configured origins for preflight
        origin = request.headers.get('Origin')
        allowed_origins = [
            'https://www.partsquest.org',
            'https://partsquest.org', 
            'https://partsquest.vercel.app',
            'https://partsquest-frontend-production.vercel.app',
            'http://localhost:3000',
            'http://localhost:5000'
        ]
        if origin in allowed_origins:
            response.headers.add('Access-Control-Allow-Origin', origin)
        else:
            response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    
    # No authentication blocking - let individual routes handle their own auth
    return response
    
    # Skip authentication for public endpoints
    public_endpoints = [
        '/',  # Root endpoint
        '/api/health',
        '/api/register',
        '/api/login',
        '/api/stripe/webhook',
        '/api/stripe/create-single-search-session',  # Public payment endpoint
        '/api/stripe/config',  # Public config endpoint
    ]
    
    # Check if current path matches any public endpoint exactly
    if request.path in public_endpoints:
        return
    
    # For all other API endpoints, authentication will be handled by individual route decorators
    return response
    
    # Skip authentication for public endpoints
    public_endpoints = [
        '/',  # Root endpoint
        '/api/health',
        '/api/register',
        '/api/login',
        '/api/stripe/webhook',
        '/api/stripe/create-single-search-session',  # Public payment endpoint
        '/api/stripe/config',  # Public config endpoint
    ]
    
    # Check if current path starts with any public endpoint
    for endpoint in public_endpoints:
        if request.path.startswith(endpoint):
            return
    
    # For all other API endpoints, require authentication
    if request.path.startswith('/api/'):
        # Skip authentication for now to fix the system
        return

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
        plan = data.get('plan')
        price_id = data.get('price_id')
        
        # Plan mapping for different subscription tiers and single search
        plan_mapping = {
            'test': {
                'price_id': 'price_test_plan',  # Replace with actual Stripe price ID
                'mode': 'subscription'
            },
            'starter': {
                'price_id': 'price_starter_plan',  # Replace with actual Stripe price ID
                'mode': 'subscription'
            },
            'professional': {
                'price_id': 'price_professional_plan',  # Replace with actual Stripe price ID
                'mode': 'subscription'
            },
            'fleet': {
                'price_id': 'price_fleet_plan',  # Replace with actual Stripe price ID
                'mode': 'subscription'
            },
            'enterprise': {
                'price_id': 'price_enterprise_plan',  # Replace with actual Stripe price ID
                'mode': 'subscription'
            },
            'single_search': {
                'price_id': 'price_single_search',  # Replace with actual Stripe price ID for $39
                'mode': 'payment'
            }
        }
        
        # Determine price_id and mode based on plan or direct price_id
        if plan and plan in plan_mapping:
            stripe_price_id = plan_mapping[plan]['price_id']
            payment_mode = plan_mapping[plan]['mode']
        elif price_id:
            stripe_price_id = price_id
            payment_mode = 'subscription'  # Default to subscription for direct price_id
        else:
            return jsonify({'error': 'Plan or price_id is required'}), 400
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=current_user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': stripe_price_id,
                'quantity': 1,
            }],
            mode=payment_mode,
            success_url=request.host_url + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'cancel',
            metadata={
                'user_id': str(current_user.id),
                'plan': plan or 'custom'
            }
        )
        
        return jsonify({
            'checkout_url': checkout_session.url,
            'session_id': checkout_session.id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stripe/create-single-search-session', methods=['POST'])
def create_single_search_session():
    """Create Stripe checkout session for Single Search ($39 one-time payment)"""
    try:
        data = request.get_json()
        
        # Get Stripe price ID for Single Search from environment
        price_id = os.environ.get('STRIPE_SINGLE_SEARCH_PRICE_ID')
        if not price_id:
            return jsonify({'error': 'Single Search price ID not configured'}), 500
        
        # Create checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',  # One-time payment
            success_url=data.get('success_url', 'https://www.partsquest.org/success'),
            cancel_url=data.get('cancel_url', 'https://www.partsquest.org/cancel'),
            metadata={
                'type': 'single_search',
                'user_id': data.get('user_id', ''),
            }
        )
        
        return jsonify({'checkout_url': session.url})
        
    except Exception as e:
        print(f"❌ Single Search session creation error: {e}")
        return jsonify({'error': 'Failed to create checkout session'}), 500

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


# Settings Management Endpoints
@app.route('/api/settings', methods=['PUT'])
def update_settings():
    """Update user settings"""
    try:
        # In production, get user_id from JWT token
        user_id = request.headers.get('X-User-ID', 'default_user')
        
        new_settings = request.json
        
        # Validate settings structure
        if not validate_settings(new_settings):
            return jsonify({
                'success': False,
                'error': 'Invalid settings format'
            }), 400
        
        # Save settings
        if save_user_settings(user_id, new_settings):
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to save settings'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/voice/test', methods=['POST'])
def test_voice():
    """Test voice synthesis with current settings"""
    try:
        data = request.json
        voice_id = data.get('voiceId')
        text = data.get('text', 'This is a test of the voice system.')
        speed = data.get('speed', 1.0)
        
        # In production, this would call ElevenLabs API
        # For now, return a mock response
        
        # Mock ElevenLabs API call
        elevenlabs_response = {
            'success': True,
            'audio_url': f'https://api.elevenlabs.io/v1/text-to-speech/{voice_id}',
            'message': f'Voice test completed for {voice_id} at {speed}x speed'
        }
        
        return jsonify(elevenlabs_response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings/voice-options', methods=['GET'])
def get_voice_options():
    """Get available voice options"""
    try:
        voice_options = [
            {
                'id': '21m00Tcm4TlvDq8ikWAM',
                'name': 'Rachel',
                'gender': 'Female',
                'description': 'Professional, clear',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/21m00Tcm4TlvDq8ikWAM/preview'
            },
            {
                'id': 'pNInz6obpgDQGcFmaJgB',
                'name': 'Adam',
                'gender': 'Male',
                'description': 'Confident, natural',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/pNInz6obpgDQGcFmaJgB/preview'
            },
            {
                'id': 'ErXwobaYiN019PkySvjV',
                'name': 'Antoni',
                'gender': 'Male',
                'description': 'Warm, engaging',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/ErXwobaYiN019PkySvjV/preview'
            },
            {
                'id': 'EXAVITQu4vr4xnSDxMaL',
                'name': 'Bella',
                'gender': 'Female',
                'description': 'Friendly, approachable',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/EXAVITQu4vr4xnSDxMaL/preview'
            },
            {
                'id': 'MF3mGyEYCl7XYWbV9V6O',
                'name': 'Elli',
                'gender': 'Female',
                'description': 'Youthful, energetic',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/MF3mGyEYCl7XYWbV9V6O/preview'
            },
            {
                'id': 'ThT5KcBeYPX3keUQqHPh',
                'name': 'Dorothy',
                'gender': 'Female',
                'description': 'Mature, authoritative',
                'preview_url': 'https://api.elevenlabs.io/v1/voices/ThT5KcBeYPX3keUQqHPh/preview'
            }
        ]
        
        return jsonify({
            'success': True,
            'voices': voice_options
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings/webhook/test', methods=['POST'])
def test_webhook():
    """Test webhook endpoint"""
    try:
        user_id = request.headers.get('X-User-ID', 'default_user')
        settings = load_user_settings(user_id)
        
        webhook_url = settings.get('integrations', {}).get('webhookUrl')
        
        if not webhook_url:
            return jsonify({
                'success': False,
                'error': 'No webhook URL configured'
            }), 400
        
        # Test webhook with sample data
        test_payload = {
            'event': 'webhook_test',
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'data': {
                'message': 'This is a test webhook from PartsQuest',
                'test': True
            }
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=test_payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            return jsonify({
                'success': True,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'message': 'Webhook test completed successfully'
            })
            
        except requests.exceptions.RequestException as e:
            return jsonify({
                'success': False,
                'error': f'Webhook test failed: {str(e)}'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings/api-key', methods=['POST'])
def regenerate_api_key():
    """Regenerate user API key"""
    try:
        user_id = request.headers.get('X-User-ID', 'default_user')
        
        # Generate new API key
        new_api_key = f"pk_live_{secrets.token_urlsafe(32)}"
        
        # In production, save this to the database
        # For now, return the new key
        
        return jsonify({
            'success': True,
            'api_key': new_api_key,
            'message': 'API key regenerated successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings/export', methods=['GET'])
def export_user_data():
    """Export user data"""
    try:
        user_id = request.headers.get('X-User-ID', 'default_user')
        settings = load_user_settings(user_id)
        
        # Check if data export is allowed
        if not settings.get('security', {}).get('allowDataExport', True):
            return jsonify({
                'success': False,
                'error': 'Data export is disabled in your security settings'
            }), 403
        
        # Compile user data
        export_data = {
            'user_id': user_id,
            'export_date': datetime.now().isoformat(),
            'settings': settings,
            'account_info': settings.get('account', {}),
            'voice_preferences': settings.get('voiceCalling', {}),
            'supplier_preferences': settings.get('suppliers', {}),
            'notification_preferences': settings.get('notifications', {}),
            'security_settings': {
                # Exclude sensitive security info
                'sessionTimeout': settings.get('security', {}).get('sessionTimeout'),
                'dataRetention': settings.get('security', {}).get('dataRetention'),
                'shareAnalytics': settings.get('security', {}).get('shareAnalytics')
            }
        }
        
        return jsonify({
            'success': True,
            'data': export_data,
            'format': 'json'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings/validate', methods=['POST'])
def validate_settings_endpoint():
    """Validate settings before saving"""
    try:
        settings = request.json
        
        validation_result = validate_settings(settings)
        
        if validation_result['valid']:
            return jsonify({
                'success': True,
                'message': 'Settings are valid'
            })
        else:
            return jsonify({
                'success': False,
                'errors': validation_result['errors']
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def validate_settings(settings):
    """Validate settings structure and values"""
    errors = []
    
    try:
        # Validate account settings
        if 'account' in settings:
            account = settings['account']
            if 'email' in account and account['email']:
                if '@' not in account['email']:
                    errors.append('Invalid email format')
            
            if 'phone' in account and account['phone']:
                # Basic phone validation
                phone = ''.join(filter(str.isdigit, account['phone']))
                if len(phone) < 10:
                    errors.append('Phone number must be at least 10 digits')
        
        # Validate voice calling settings
        if 'voiceCalling' in settings:
            voice = settings['voiceCalling']
            
            if 'voiceSpeed' in voice:
                if not (0.5 <= voice['voiceSpeed'] <= 1.5):
                    errors.append('Voice speed must be between 0.5 and 1.5')
            
            if 'maxCallDuration' in voice:
                if not (60 <= voice['maxCallDuration'] <= 600):
                    errors.append('Max call duration must be between 60 and 600 seconds')
            
            if 'maxRetries' in voice:
                if not (1 <= voice['maxRetries'] <= 5):
                    errors.append('Max retries must be between 1 and 5')
        
        # Validate supplier settings
        if 'suppliers' in settings:
            suppliers = settings['suppliers']
            
            if 'maxDistance' in suppliers:
                if not (10 <= suppliers['maxDistance'] <= 500):
                    errors.append('Max distance must be between 10 and 500 miles')
            
            if 'minimumRating' in suppliers:
                if not (1.0 <= suppliers['minimumRating'] <= 5.0):
                    errors.append('Minimum rating must be between 1.0 and 5.0')
        
        # Validate security settings
        if 'security' in settings:
            security = settings['security']
            
            if 'sessionTimeout' in security:
                if security['sessionTimeout'] not in [15, 30, 60, 120, 480]:
                    errors.append('Invalid session timeout value')
            
            if 'dataRetention' in security:
                if security['dataRetention'] not in [30, 60, 90, 180, 365]:
                    errors.append('Invalid data retention period')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
        
    except Exception as e:
        return {
            'valid': False,
            'errors': [f'Validation error: {str(e)}']
        }



# Settings Management Endpoints
@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get user settings"""
    try:
        # In production, get user_id from JWT token
        user_id = request.headers.get('X-User-ID', 'default_user')
        
        # Default settings for now
        default_settings = {
            'account': {
                'firstName': '',
                'lastName': '',
                'email': '',
                'phone': '',
                'company': '',
                'address': '',
                'city': '',
                'state': '',
                'zipCode': '',
                'timezone': 'America/New_York'
            },
            'voiceCalling': {
                'voiceId': '21m00Tcm4TlvDq8ikWAM',
                'voiceSpeed': 0.85,
                'maxCallDuration': 300,
                'maxRetries': 3,
                'callTimeout': 30,
                'businessHoursOnly': True,
                'businessHours': {'start': '09:00', 'end': '17:00', 'timezone': 'local'},
                'weekdaysOnly': True,
                'autoExpandRadius': True,
                'initialRadius': 25,
                'maxRadius': 100,
                'radiusIncrement': 25,
                'callsPerBatch': 5,
                'batchDelay': 30
            }
        }
        
        return jsonify({
            'success': True,
            'settings': default_settings
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500




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


# Voice Calling API Endpoints

# Store active call sessions
call_sessions = {}

@app.route('/api/voice-calling/start', methods=['POST'])
@token_required
def start_voice_calling(current_user):
    """Start AI voice calling process for parts sourcing"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('partDescription') or not data.get('vehicleMake'):
            return jsonify({'error': 'Part description and vehicle make are required'}), 400
        
        # Generate unique session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Initialize call session
        call_sessions[session_id] = {
            'status': 'starting',
            'user_id': current_user.id,
            'part_description': data.get('partDescription'),
            'part_number': data.get('partNumber', ''),
            'vehicle_year': data.get('vehicleYear', ''),
            'vehicle_make': data.get('vehicleMake'),
            'vehicle_model': data.get('vehicleModel', ''),
            'call_dealerships': data.get('callDealerships', True),
            'call_custom_suppliers': data.get('callCustomSuppliers', False),
            'reserve_for_pickup': data.get('reserveForPickup', False),
            'search_radius': data.get('searchRadius', 25),
            'user_location': data.get('userLocation', ''),
            'total_calls': 0,
            'completed_calls': 0,
            'current_supplier': '',
            'results': [],
            'created_at': datetime.utcnow()
        }
        
        # Start the calling process asynchronously
        import threading
        thread = threading.Thread(target=process_voice_calling_optimized, args=(session_id,))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'callSessionId': session_id,
            'status': 'started',
            'message': 'Voice calling process initiated'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error starting voice calling: {str(e)}'}), 500

@app.route('/api/voice-calling/status/<session_id>', methods=['GET'])
@token_required
def get_voice_calling_status(current_user, session_id):
    """Get status of ongoing voice calling session"""
    try:
        if session_id not in call_sessions:
            return jsonify({'error': 'Call session not found'}), 404
        
        session = call_sessions[session_id]
        
        # Verify user owns this session
        if session['user_id'] != current_user.id:
            return jsonify({'error': 'Unauthorized access to call session'}), 403
        
        return jsonify({
            'status': session['status'],
            'totalCalls': session['total_calls'],
            'completedCalls': session['completed_calls'],
            'currentSupplier': session['current_supplier'],
            'results': session['results']
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting call status: {str(e)}'}), 500

@app.route('/api/voice-calling/reserve', methods=['POST'])
@token_required
def reserve_part_from_call(current_user):
    """Reserve a part from voice calling results"""
    try:
        data = request.get_json()
        
        # Create a part request for the reservation
        new_request = PartRequest(
            user_id=current_user.id,
            part_number=data.get('partNumber', ''),
            description=f"RESERVED: {data.get('partDescription', '')}",
            quantity=1,
            target_price=data.get('price'),
            urgency='normal',
            status='reserved',
            notes=f"Reserved at {data.get('supplierName', 'Unknown Supplier')} - {data.get('reservationNotes', '')}"
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        return jsonify({
            'message': 'Part reserved successfully',
            'requestId': new_request.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error reserving part: {str(e)}'}), 500

def process_voice_calling(session_id):
    """Process voice calling in background thread"""
    try:
        session = call_sessions[session_id]
        session['status'] = 'processing'
        
        # Get dealerships based on vehicle make and user location
        dealerships = get_nearby_dealerships(
            session['vehicle_make'],
            session['user_location'],
            session['search_radius']
        )
        
        # Get custom suppliers if requested
        custom_suppliers = []
        if session['call_custom_suppliers']:
            custom_suppliers = get_user_custom_suppliers(session['user_id'])
        
        # Combine all suppliers
        all_suppliers = dealerships + custom_suppliers
        session['total_calls'] = len(all_suppliers)
        
        # Process suppliers in batches of 5
        batch_size = 5
        for i in range(0, len(all_suppliers), batch_size):
            batch = all_suppliers[i:i + batch_size]
            
            # Process batch concurrently
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for supplier in batch:
                    session['current_supplier'] = supplier.get('name', 'Unknown')
                    future = executor.submit(call_supplier, session, supplier)
                    futures.append(future)
                
                # Wait for batch to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            session['results'].append(result)
                        session['completed_calls'] += 1
                    except Exception as e:
                        print(f"Error calling supplier: {e}")
                        session['completed_calls'] += 1
        
        session['status'] = 'completed'
        session['current_supplier'] = ''
        
    except Exception as e:
        print(f"Error in voice calling process: {e}")
        session['status'] = 'error'
        session['current_supplier'] = ''

def get_nearby_dealerships(vehicle_make, user_location, radius_miles):
    """Get dealerships from MarketChoice API based on vehicle make and location"""
    try:
        # MarketChoice API integration
        marketchoice_api_key = os.environ.get('MARKETCHOICE_API_KEY')
        if not marketchoice_api_key:
            print("MarketChoice API key not configured")
            return []
        
        # This would integrate with MarketChoice API
        # For now, return mock data
        mock_dealerships = [
            {
                'id': f'{vehicle_make.lower()}_dealer_1',
                'name': f'{vehicle_make} of Downtown',
                'phone': '555-0101',
                'address': '123 Main St',
                'distance': 5.2,
                'type': 'dealership'
            },
            {
                'id': f'{vehicle_make.lower()}_dealer_2', 
                'name': f'{vehicle_make} North',
                'phone': '555-0102',
                'address': '456 North Ave',
                'distance': 8.7,
                'type': 'dealership'
            },
            {
                'id': f'{vehicle_make.lower()}_dealer_3',
                'name': f'{vehicle_make} Service Center',
                'phone': '555-0103', 
                'address': '789 Service Rd',
                'distance': 12.1,
                'type': 'dealership'
            }
        ]
        
        return mock_dealerships
        
    except Exception as e:
        print(f"Error getting dealerships: {e}")
        return []

def get_user_custom_suppliers(user_id):
    """Get user's custom suppliers that accept phone calls"""
    try:
        # This would query the user's custom supplier list
        # For now, return mock data
        mock_suppliers = [
            {
                'id': 'custom_supplier_1',
                'name': 'Local Parts Plus',
                'phone': '555-0201',
                'address': '321 Parts Ave',
                'distance': 3.5,
                'type': 'custom_supplier'
            }
        ]
        
        return mock_suppliers
        
    except Exception as e:
        print(f"Error getting custom suppliers: {e}")
        return []

def call_supplier(session, supplier):
    """Make actual phone call to supplier using Vapi"""
    try:
        # Simulate call delay
        import time
        time.sleep(2)  # Simulate call duration
        
        # Mock call result - in real implementation, this would use Vapi
        import random
        
        # Simulate call outcomes
        outcomes = ['success', 'busy', 'no_answer', 'part_not_available']
        outcome = random.choice(outcomes)
        
        if outcome == 'success':
            return {
                'supplierId': supplier['id'],
                'supplierName': supplier['name'],
                'supplierPhone': supplier['phone'],
                'supplierAddress': supplier['address'],
                'distance': supplier['distance'],
                'status': 'available',
                'price': round(random.uniform(50, 500), 2),
                'leadTime': f"{random.randint(1, 14)} days",
                'notes': f"Part available, quoted price includes tax",
                'callDuration': f"{random.randint(30, 180)} seconds",
                'timestamp': datetime.utcnow().isoformat()
            }
        elif outcome == 'part_not_available':
            return {
                'supplierId': supplier['id'],
                'supplierName': supplier['name'],
                'supplierPhone': supplier['phone'],
                'supplierAddress': supplier['address'],
                'distance': supplier['distance'],
                'status': 'not_available',
                'price': None,
                'leadTime': None,
                'notes': 'Part not in stock, can order with 2-3 week lead time',
                'callDuration': f"{random.randint(20, 90)} seconds",
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            # busy, no_answer
            return {
                'supplierId': supplier['id'],
                'supplierName': supplier['name'],
                'supplierPhone': supplier['phone'],
                'supplierAddress': supplier['address'],
                'distance': supplier['distance'],
                'status': outcome,
                'price': None,
                'leadTime': None,
                'notes': f"Call {outcome.replace('_', ' ')}, will retry later",
                'callDuration': "0 seconds",
                'timestamp': datetime.utcnow().isoformat()
            }
        
    except Exception as e:
        print(f"Error calling supplier {supplier.get('name', 'Unknown')}: {e}")
        return None

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)



# Optimized Vapi Integration for Real Phone Calling
import requests
import json
import time
import re
import concurrent.futures

# Vapi Configuration - Using our optimized assistant
VAPI_PRIVATE_KEY = os.environ.get('VAPI_PRIVATE_KEY', '3d1c5088-af2f-47df-bbaa-03e7591c6892')
VAPI_PUBLIC_KEY = os.environ.get('VAPI_PUBLIC_KEY', 'd542b99a-fee6-4cbd-a510-e4e9d765925e')
VAPI_ASSISTANT_ID = os.environ.get('VAPI_ASSISTANT_ID', 'fa155090-0a66-4e62-8c2e-74f086c10a74')

def call_supplier_with_optimized_vapi(session, supplier):
    """
    Make actual phone call to supplier using our optimized Vapi assistant
    """
    try:
        print(f"🔄 Calling {supplier['name']} at {supplier['phone']}...")
        
        # Prepare call configuration with our optimized assistant
        headers = {
            "Authorization": f"Bearer {VAPI_PRIVATE_KEY}",
            "Content-Type": "application/json"
        }
        
        # Get phone numbers for outbound calling
        phone_response = requests.get("https://api.vapi.ai/phone-number", headers=headers)
        if phone_response.status_code != 200:
            raise Exception("Failed to get phone numbers")
        
        phone_numbers = phone_response.json()
        if not phone_numbers:
            raise Exception("No phone numbers available")
        
        phone_number_id = phone_numbers[0].get('id')
        
        # Get shop name from user profile
        shop_name = "Mike's Auto Repair"  # Default, should be from user profile
        if 'shop_name' in session:
            shop_name = session['shop_name']
        elif 'user_company' in session:
            shop_name = session['user_company']
        
        # Prepare context data for the call
        call_context = {
            "shopName": shop_name,
            "partType": session['part_description'],
            "vehicleYear": session['vehicle_year'],
            "vehicleMake": session['vehicle_make'],
            "vehicleModel": session['vehicle_model'],
            "supplierName": supplier['name'],
            "userAddress": session.get('user_location', 'Portland, Oregon')
        }
        
        # Create call with our optimized assistant
        call_config = {
            "assistantId": VAPI_ASSISTANT_ID,
            "phoneNumberId": phone_number_id,
            "customer": {
                "number": supplier['phone']
            },
            "assistantOverrides": {
                "variableValues": call_context
            }
        }
        
        print(f"📞 Initiating call to {supplier['name']} with context: {call_context}")
        
        # Make the call
        response = requests.post(
            "https://api.vapi.ai/call",
            headers=headers,
            json=call_config,
            timeout=30
        )
        
        if response.status_code == 201:
            call_data = response.json()
            call_id = call_data.get('id')
            
            print(f"✅ Call initiated successfully. Call ID: {call_id}")
            
            # Wait for call to complete and get results
            call_result = wait_for_call_completion(call_id, supplier['name'])
            
            # Parse the call results
            parsed_result = parse_call_results(call_result, supplier)
            
            print(f"📋 Call completed. Result: {parsed_result['status']}")
            
            return parsed_result
            
        else:
            print(f"❌ Failed to make Vapi call: {response.status_code} - {response.text}")
            return create_error_result(supplier, f"Failed to initiate call: {response.text}")
            
    except Exception as e:
        print(f"❌ Error making Vapi call to {supplier.get('name', 'Unknown')}: {e}")
        return create_error_result(supplier, str(e))

def wait_for_call_completion(call_id, supplier_name, max_wait_time=300):
    """
    Wait for call to complete and return results
    """
    headers = {
        "Authorization": f"Bearer {VAPI_PRIVATE_KEY}",
        "Content-Type": "application/json"
    }
    
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        try:
            response = requests.get(
                f"https://api.vapi.ai/call/{call_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                call_data = response.json()
                status = call_data.get('status')
                
                if status in ['ended', 'completed']:
                    print(f"✅ Call to {supplier_name} completed")
                    return call_data
                elif status in ['failed', 'error']:
                    print(f"❌ Call to {supplier_name} failed")
                    return call_data
                
                # Call still in progress, wait a bit
                time.sleep(5)
            else:
                time.sleep(5)
                
        except Exception as e:
            print(f"⚠️ Error waiting for call completion: {e}")
            time.sleep(5)
    
    print(f"⏰ Call to {supplier_name} timed out after {max_wait_time} seconds")
    return {"status": "timeout", "transcript": ""}

def parse_call_results(call_data, supplier):
    """
    Parse call results from Vapi response to extract part availability and pricing
    """
    try:
        status = call_data.get('status', 'unknown')
        transcript = call_data.get('transcript', '')
        duration = call_data.get('duration', 0)
        
        # Initialize result structure
        result = {
            'supplierId': supplier['id'],
            'supplierName': supplier['name'],
            'supplierPhone': supplier['phone'],
            'supplierAddress': supplier.get('address', ''),
            'distance': supplier.get('distance', 0),
            'callId': call_data.get('id'),
            'callDuration': f"{duration} seconds",
            'transcript': transcript,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if status in ['ended', 'completed'] and transcript:
            # Parse transcript for part availability and pricing
            transcript_lower = transcript.lower()
            
            # Check if part is available
            if any(phrase in transcript_lower for phrase in [
                'yes we have', 'we do have', 'in stock', 'available', 
                'we carry', 'we have that', 'yes we do'
            ]):
                result['status'] = 'available'
                
                # Extract price information
                price = extract_price_from_transcript(transcript)
                if price:
                    result['price'] = price
                    result['notes'] = f"Part available for ${price}"
                else:
                    result['price'] = None
                    result['notes'] = "Part available, price to be confirmed"
                
                # Extract lead time
                lead_time = extract_lead_time_from_transcript(transcript)
                result['leadTime'] = lead_time or "In stock"
                
            elif any(phrase in transcript_lower for phrase in [
                'don\'t have', 'not in stock', 'don\'t carry', 'no we don\'t',
                'not available', 'don\'t stock', 'special order'
            ]):
                if 'special order' in transcript_lower or 'can order' in transcript_lower:
                    result['status'] = 'special_order'
                    result['notes'] = "Available as special order"
                    
                    # Extract lead time for special order
                    lead_time = extract_lead_time_from_transcript(transcript)
                    result['leadTime'] = lead_time or "2-3 weeks"
                    
                    # Extract price if mentioned
                    price = extract_price_from_transcript(transcript)
                    result['price'] = price
                else:
                    result['status'] = 'not_available'
                    result['notes'] = "Part not available"
                    result['price'] = None
                    result['leadTime'] = None
            else:
                # Unclear response or voicemail
                if 'voicemail' in transcript_lower or 'voice message' in transcript_lower or 'automated' in transcript_lower:
                    result['status'] = 'voicemail'
                    result['notes'] = "Reached voicemail, will retry during business hours"
                else:
                    result['status'] = 'unclear'
                    result['notes'] = "Response unclear, may need follow-up"
                result['price'] = None
                result['leadTime'] = None
                
        elif status == 'failed':
            result['status'] = 'call_failed'
            result['notes'] = "Call failed to connect"
            result['price'] = None
            result['leadTime'] = None
        elif status == 'timeout':
            result['status'] = 'timeout'
            result['notes'] = "Call timed out"
            result['price'] = None
            result['leadTime'] = None
        else:
            result['status'] = 'no_answer'
            result['notes'] = "No answer or call incomplete"
            result['price'] = None
            result['leadTime'] = None
        
        return result
        
    except Exception as e:
        print(f"❌ Error parsing call results: {e}")
        return create_error_result(supplier, f"Error parsing results: {str(e)}")

def extract_price_from_transcript(transcript):
    """Extract price information from call transcript"""
    # Look for price patterns like $89.99, 89 dollars, eighty-nine dollars
    price_patterns = [
        r'\$([\d+\.?\d*)',  # $89.99
        r'([\d+\.?\d*)\s*dollars?',  # 89 dollars
        r'([\d+])\s*and\s*([\d+])\s*cents',  # 89 and 99 cents
    ]
    
    for pattern in price_patterns:
        matches = re.findall(pattern, transcript, re.IGNORECASE)
        if matches:
            if isinstance(matches[0], tuple):
                # Handle "89 and 99 cents" format
                dollars, cents = matches[0]
                return float(f"{dollars}.{cents}")
            else:
                return float(matches[0])
    
    return None

def extract_lead_time_from_transcript(transcript):
    """Extract lead time information from call transcript"""

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'https://www.partsquest.org')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
    # Look for time patterns
    time_patterns = [
        r'([\d+])\s*(?:to\s*)?([\d+])?\s*(?:business\s*)?days?',
        r'([\d+])\s*(?:to\s*)?([\d+])?\s*weeks?',
        r'in\s*stock',
        r'available\s*(?:now|today|immediately)',
        r'([\d+])\s*hours?'
    ]
    
    transcript_lower = transcript.lower()
    
    for pattern in time_patterns:
        matches = re.findall(pattern, transcript_lower)
        if matches:
            if 'stock' in pattern or 'now' in pattern or 'today' in pattern or 'immediately' in pattern:
                return "In stock"
            elif 'hours' in pattern:
                return f"{matches[0]} hours"
            elif 'weeks' in pattern:
                if len(matches[0]) == 2 and matches[0][1]:  # Range like "2 to 3 weeks"
                    return f"{matches[0][0]}-{matches[0][1]} weeks"
                else:
                    return f"{matches[0][0]} weeks"
            else:  # days
                if len(matches[0]) == 2 and matches[0][1]:  # Range like "2 to 3 days"
                    return f"{matches[0][0]}-{matches[0][1]} days"
                else:
                    return f"{matches[0][0]} days"
    
    return None

def create_error_result(supplier, error_message):
    """Create error result structure"""
    return {
        'supplierId': supplier['id'],
        'supplierName': supplier['name'],
        'supplierPhone': supplier['phone'],
        'supplierAddress': supplier.get('address', ''),
        'distance': supplier.get('distance', 0),
        'status': 'error',
        'price': None,
        'leadTime': None,
        'notes': f"Error: {error_message}",
        'callDuration': "0 seconds",
        'timestamp': datetime.utcnow().isoformat()
    }

def process_voice_calling_optimized(session_id):
    """
    Process voice calling with our optimized Vapi system
    """
    try:
        session = call_sessions[session_id]
        session['status'] = 'processing'
        
        print(f"🚀 Starting optimized voice calling for session {session_id}")
        
        # Get dealerships and suppliers
        dealerships = get_nearby_dealerships(
            session['vehicle_make'],
            session['user_location'],
            session['search_radius']
        )
        
        custom_suppliers = []
        if session['call_custom_suppliers']:
            custom_suppliers = get_user_custom_suppliers(session['user_id'])
        
        all_suppliers = dealerships + custom_suppliers
        session['total_calls'] = len(all_suppliers)
        
        print(f"📞 Found {len(all_suppliers)} suppliers to call")
        
        # Process suppliers in batches of 3 (reduced for better call quality)
        batch_size = 3
        for i in range(0, len(all_suppliers), batch_size):
            batch = all_suppliers[i:i + batch_size]
            
            print(f"📞 Processing batch {i//batch_size + 1}: {[s['name'] for s in batch]}")
            
            # Process batch with real phone calls
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                for supplier in batch:
                    session['current_supplier'] = supplier.get('name', 'Unknown')
                    # Use our optimized Vapi system
                    future = executor.submit(call_supplier_with_optimized_vapi, session, supplier)
                    futures.append(future)
                
                # Wait for batch to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            session['results'].append(result)
                            print(f"✅ Call result: {result['supplierName']} - {result['status']}")
                        session['completed_calls'] += 1
                    except Exception as e:
                        print(f"❌ Error in optimized Vapi call: {e}")
                        session['completed_calls'] += 1
            
            # Small delay between batches to avoid overwhelming the system
            if i + batch_size < len(all_suppliers):
                print("⏸️ Waiting 10 seconds before next batch...")
                time.sleep(10)
        
        session['status'] = 'completed'
        session['current_supplier'] = ''
        
        print(f"🎉 Voice calling completed for session {session_id}")
        print(f"📊 Results: {len(session['results'])} calls completed")
        
    except Exception as e:
        print(f"❌ Error in optimized voice calling process: {e}")
        session['status'] = 'error'
        session['current_supplier'] = ''


@app.route('/api/voice-calling/start-vapi', methods=['POST'])
@token_required
def start_voice_calling_with_vapi(current_user):
    """Start AI voice calling process using real Vapi integration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('partDescription') or not data.get('vehicleMake'):
            return jsonify({'error': 'Part description and vehicle make are required'}), 400
        
        # Generate unique session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Initialize call session
        call_sessions[session_id] = {
            'status': 'starting',
            'user_id': current_user.id,
            'part_description': data.get('partDescription'),
            'part_number': data.get('partNumber', ''),
            'vehicle_year': data.get('vehicleYear', ''),
            'vehicle_make': data.get('vehicleMake'),
            'vehicle_model': data.get('vehicleModel', ''),
            'call_dealerships': data.get('callDealerships', True),
            'call_custom_suppliers': data.get('callCustomSuppliers', False),
            'reserve_for_pickup': data.get('reserveForPickup', False),
            'search_radius': data.get('searchRadius', 25),
            'user_location': data.get('userLocation', ''),
            'total_calls': 0,
            'completed_calls': 0,
            'current_supplier': '',
            'results': [],
            'created_at': datetime.utcnow()
        }
        
        # Start the Vapi calling process asynchronously
        import threading

        thread = threading.Thread(target=process_voice_calling_with_vapi, args=(session_id,))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'callSessionId': session_id,
            'status': 'started',
            'message': 'Voice calling process initiated with Vapi integration'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error starting Vapi voice calling: {str(e)}'}), 500



# NHTSA Vehicle API Endpoints
@app.route('/api/vehicles/makes', methods=['GET'])
def get_vehicle_makes():
    """Get all vehicle makes"""
    year = request.args.get('year')
    makes = nhtsa_api.get_makes(year)
    return jsonify({'makes': makes})

@app.route('/api/vehicles/models/<int:make_id>', methods=['GET'])
def get_vehicle_models(make_id):
    """Get models for a specific make"""
    year = request.args.get('year')
    models = nhtsa_api.get_models(make_id, year)
    return jsonify({'models': models})

@app.route('/api/vehicles/years', methods=['GET'])
def get_vehicle_years():
    """Get available vehicle years"""
    years = nhtsa_api.get_years()
    return jsonify({'years': years})

@app.route('/api/vehicles/decode-vin', methods=['POST'])
def decode_vin():
    """Decode VIN to get vehicle information"""
    data = request.get_json()
    vin = data.get('vin', '').strip()
    
    if not vin:
        return jsonify({'error': 'VIN is required'}), 400
    
    # Try NHTSA first, then MarketCheck
    vehicle_info = nhtsa_api.decode_vin(vin)
    if not vehicle_info:
        vehicle_info = marketcheck_api.decode_vin(vin)
    
    if vehicle_info:
        return jsonify({'vehicle': vehicle_info})
    else:
        return jsonify({'error': 'Could not decode VIN'}), 404

# MarketCheck Dealership API Endpoints
@app.route('/api/dealerships/by-make', methods=['GET'])
def get_dealerships_by_make():
    """Get dealerships for a specific vehicle make"""
    make = request.args.get('make')
    zip_code = request.args.get('zip')
    radius = int(request.args.get('radius', 50))
    
    if not make:
        return jsonify({'error': 'Make is required'}), 400
    
    dealerships = marketcheck_api.get_dealerships_by_make(make, zip_code, radius)
    return jsonify({'dealerships': dealerships})

@app.route('/api/dealerships/by-location', methods=['GET'])
def get_dealerships_by_location():
    """Get dealerships in a specific location"""
    zip_code = request.args.get('zip')
    radius = int(request.args.get('radius', 25))
    
    if not zip_code:
        return jsonify({'error': 'ZIP code is required'}), 400
    
    dealerships = marketcheck_api.get_dealerships_by_location(zip_code, radius)
    return jsonify({'dealerships': dealerships})

# Enhanced voice calling with real supplier data
@app.route('/api/voice-calling/start-enhanced', methods=['POST'])
@jwt_required()
def start_enhanced_voice_calling():
    """Start voice calling with real supplier data"""
    try:
        data = request.get_json()
        current_user = get_jwt_identity()
        
        # Get search parameters
        part_description = data.get('part_description', '')
        vehicle_make = data.get('vehicle_make', '')
        vehicle_model = data.get('vehicle_model', '')
        vehicle_year = data.get('vehicle_year', '')
        user_location = data.get('user_location', '')
        
        # Get dealerships for the vehicle make
        dealerships = marketcheck_api.get_dealerships_by_make(
            vehicle_make, 
            user_location, 
            radius=50
        )
        
        # Combine with custom suppliers if any
        custom_suppliers = data.get('custom_suppliers', [])
        all_suppliers = dealerships + custom_suppliers
        
        if not all_suppliers:
            return jsonify({'error': 'No suppliers found for this search'}), 404
        
        # Start voice calling process
        call_session = {
            'session_id': str(uuid.uuid4()),
            'user_id': current_user,
            'part_description': part_description,
            'vehicle': {
                'make': vehicle_make,
                'model': vehicle_model,
                'year': vehicle_year
            },
            'suppliers': all_suppliers[:10],  # Limit to 10 suppliers
            'status': 'starting',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Store session (in production, use database)
        # For now, store in memory or file
        
        return jsonify({
            'session_id': call_session['session_id'],
            'status': 'started',
            'suppliers_count': len(all_suppliers),
            'message': 'Voice calling session started with real supplier data'
        })
        
    except Exception as e:
        app.logger.error(f"Error starting enhanced voice calling: {e}")
        return jsonify({'error': 'Failed to start voice calling'}), 500


# =============================================================================
# ADMIN API ENDPOINTS
# =============================================================================

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Simple admin check - in production, this should be more sophisticated
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Admin authentication required'}), 401
        
        # For now, accept any valid token as admin
        # In production, you'd check for admin role
        token = auth_header.replace('Bearer ', '')
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid admin token'}), 401
        
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': 'Admin user not found'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users(current_user):
    """Get comprehensive user report"""
    try:
        # Get all users with detailed information
        users = db.session.execute(text("""
            SELECT 
                u.id,
                u.email,
                u.first_name,
                u.last_name,
                u.company,
                u.phone,
                u.is_active,
                u.subscription_status,
                u.stripe_customer_id,
                u.created_at,
                CASE 
                    WHEN u.created_at > NOW() - INTERVAL '24 hours' THEN 'Last 24h'
                    WHEN u.created_at > NOW() - INTERVAL '7 days' THEN 'Last 7 days'
                    WHEN u.created_at > NOW() - INTERVAL '30 days' THEN 'Last 30 days'
                    ELSE 'Older'
                END as signup_period,
                EXTRACT(DAYS FROM NOW() - u.created_at) as days_since_signup,
                COUNT(v.id) as vehicle_count,
                COUNT(pr.id) as part_request_count
            FROM "user" u
            LEFT JOIN vehicle v ON u.id = v.user_id
            LEFT JOIN part_request pr ON u.id = pr.user_id
            GROUP BY u.id, u.email, u.first_name, u.last_name, u.company, u.phone, 
                     u.is_active, u.subscription_status, u.stripe_customer_id, u.created_at
            ORDER BY u.created_at DESC
        """)).fetchall()
        
        # Convert to list of dictionaries
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}",
                'first_name': user.first_name,
                'last_name': user.last_name,
                'company': user.company or 'N/A',
                'phone': user.phone or 'N/A',
                'is_active': user.is_active,
                'subscription_status': user.subscription_status,
                'stripe_customer_id': user.stripe_customer_id or 'N/A',
                'created_at': user.created_at.isoformat(),
                'signup_period': user.signup_period,
                'days_since_signup': int(user.days_since_signup),
                'vehicle_count': user.vehicle_count,
                'part_request_count': user.part_request_count
            })
        
        # Generate summary statistics
        total_users = len(user_data)
        active_users = sum(1 for u in user_data if u['is_active'])
        
        subscription_stats = {}
        signup_stats = {}
        for user in user_data:
            # Subscription stats
            status = user['subscription_status']
            subscription_stats[status] = subscription_stats.get(status, 0) + 1
            
            # Signup period stats
            period = user['signup_period']
            signup_stats[period] = signup_stats.get(period, 0) + 1
        
        return jsonify({
            'users': user_data,
            'summary': {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': total_users - active_users,
                'subscription_breakdown': subscription_stats,
                'signup_periods': signup_stats
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error getting user report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/subscription-report', methods=['GET'])
@admin_required
def admin_subscription_report(current_user):
    """Get detailed subscription analytics"""
    try:
        subscription_data = db.session.execute(text("""
            SELECT 
                subscription_status,
                COUNT(*) as user_count,
                AVG(EXTRACT(DAYS FROM NOW() - created_at)) as avg_days_active,
                MIN(created_at) as first_signup,
                MAX(created_at) as latest_signup
            FROM "user"
            GROUP BY subscription_status
            ORDER BY user_count DESC
        """)).fetchall()
        
        report = []
        for sub in subscription_data:
            report.append({
                'subscription_status': sub.subscription_status,
                'user_count': sub.user_count,
                'avg_days_active': round(sub.avg_days_active, 1),
                'first_signup': sub.first_signup.isoformat(),
                'latest_signup': sub.latest_signup.isoformat()
            })
        
        return jsonify({
            'subscription_tiers': report,
            'generated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error generating subscription report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-users', methods=['POST'])
@admin_required
def admin_clear_users(current_user):
    """Clear all test users and associated data"""
    try:
        data = request.get_json()
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({
                'error': 'Confirmation required',
                'message': 'Send {"confirm": true} to permanently delete all user data'
            }), 400
        
        # Get counts before deletion
        user_count = db.session.execute(text("SELECT COUNT(*) FROM \"user\"")).scalar()
        vehicle_count = db.session.execute(text("SELECT COUNT(*) FROM vehicle")).scalar()
        part_request_count = db.session.execute(text("SELECT COUNT(*) FROM part_request")).scalar()
        
        # Delete in correct order (foreign key constraints)
        db.session.execute(text("DELETE FROM part_request"))
        db.session.execute(text("DELETE FROM vehicle"))
        db.session.execute(text("DELETE FROM \"user\""))
        
        # Reset sequences
        db.session.execute(text("ALTER SEQUENCE user_id_seq RESTART WITH 1"))
        db.session.execute(text("ALTER SEQUENCE vehicle_id_seq RESTART WITH 1"))
        db.session.execute(text("ALTER SEQUENCE part_request_id_seq RESTART WITH 1"))
        
        db.session.commit()
        
        return jsonify({
            'message': 'All user data cleared successfully',
            'deleted': {
                'users': user_count,
                'vehicles': vehicle_count,
                'part_requests': part_request_count
            },
            'sequences_reset': True,
            'cleared_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error clearing users: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/fix-subscriptions', methods=['POST'])
@admin_required
def admin_fix_subscriptions(current_user):
    """Fix subscription statuses for users"""
    try:
        data = request.get_json()
        action = data.get('action', 'activate_all')  # 'activate_all' or 'sync_stripe'
        
        if action == 'activate_all':
            # Set all users to active (for testing)
            result = db.session.execute(text("""
                UPDATE "user" 
                SET subscription_status = 'active' 
                WHERE subscription_status != 'active'
            """))
            
            db.session.commit()
            
            return jsonify({
                'message': f'Updated {result.rowcount} users to active subscription status',
                'action': 'activate_all',
                'updated_count': result.rowcount,
                'updated_at': datetime.utcnow().isoformat()
            })
        
        elif action == 'sync_stripe':
            # In production, this would sync with Stripe
            # For now, just return a placeholder
            return jsonify({
                'message': 'Stripe sync not implemented yet',
                'action': 'sync_stripe',
                'note': 'This would sync subscription statuses with Stripe in production'
            })
        
        else:
            return jsonify({'error': 'Invalid action. Use "activate_all" or "sync_stripe"'}), 400
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error fixing subscriptions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/create-test-user', methods=['POST'])
@admin_required
def admin_create_test_user(current_user):
    """Create a test user for development"""
    try:
        data = request.get_json()
        email = data.get('email', 'test@partsquest.com')
        password = data.get('password', 'testpass123')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({
                'error': 'User already exists',
                'existing_user': {
                    'id': existing_user.id,
                    'email': existing_user.email,
                    'subscription_status': existing_user.subscription_status
                }
            }), 400
        
        # Create new test user
        test_user = User(
            email=email,
            first_name='Test',
            last_name='User',
            company='Test Company',
            phone='555-0123',
            subscription_status='active',
            is_active=True
        )
        test_user.set_password(password)
        
        db.session.add(test_user)
        db.session.commit()
        
        return jsonify({
            'message': 'Test user created successfully',
            'user': {
                'id': test_user.id,
                'email': test_user.email,
                'password': password,
                'subscription_status': test_user.subscription_status,
                'created_at': test_user.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating test user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/health', methods=['GET'])
def admin_health():
    """Admin health check endpoint (no auth required)"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        
        # Get basic stats
        user_count = db.session.execute(text("SELECT COUNT(*) FROM \"user\"")).scalar()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'user_count': user_count,
            'timestamp': datetime.utcnow().isoformat(),
            'admin_endpoints': [
                'GET /api/admin/health',
                'GET /api/admin/users',
                'GET /api/admin/subscription-report',
                'POST /api/admin/clear-users',
                'POST /api/admin/fix-subscriptions',
                'POST /api/admin/create-test-user'
            ]
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

