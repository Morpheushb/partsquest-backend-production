from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS
CORS(app, 
     origins=["https://partsquest-frontend-production.vercel.app", "http://localhost:3000"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Global database connection (will be initialized lazily)
db = None

def init_database():
    """Initialize database connection lazily"""
    global db
    if db is not None:
        return db
        
    try:
        from flask_sqlalchemy import SQLAlchemy
        
        # Get DATABASE_URL from environment
        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            logger.error("DATABASE_URL environment variable not set")
            return None
            
        # Add SSL requirement if not present
        if '?sslmode=' not in database_url:
            database_url += '?sslmode=require'
            
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        db = SQLAlchemy(app)
        logger.info("Database initialized successfully")
        return db
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return None

@app.route('/')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "message": "PartsQuest Backend is running",
        "database_status": "connected" if db else "not_connected"
    })

@app.route('/api/health')
def api_health():
    """API health check"""
    # Try to initialize database
    db_instance = init_database()
    
    return jsonify({
        "status": "healthy",
        "api": "operational",
        "database": "connected" if db_instance else "disconnected"
    })

@app.route('/api/test-db')
def test_database():
    """Test database connection"""
    db_instance = init_database()
    
    if not db_instance:
        return jsonify({
            "status": "error",
            "message": "Database not available"
        }), 500
        
    try:
        # Test a simple query
        result = db_instance.engine.execute("SELECT 1")
        return jsonify({
            "status": "success",
            "message": "Database connection successful"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Database connection failed: {str(e)}"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
