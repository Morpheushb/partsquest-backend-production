#!/usr/bin/env python3
"""
Minimal PartsQuest Backend - Deployment Test Version
This version strips down to bare essentials to identify deployment issues
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import os

# Create Flask app
app = Flask(__name__)

# Configure CORS
CORS(app, origins=[
    'https://www.partsquest.org',
    'https://partsquest.org', 
    'https://partsquest.vercel.app',
    'http://localhost:3000'
])

@app.route('/')
def health_check():
    """Basic health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'PartsQuest Backend - Minimal Test Version',
        'version': '1.0.0'
    })

@app.route('/api/health')
def api_health():
    """API health check"""
    return jsonify({
        'api_status': 'operational',
        'environment': os.environ.get('RENDER_SERVICE_NAME', 'local'),
        'timestamp': '2025-09-10'
    })

@app.route('/api/test')
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({
        'test': 'success',
        'message': 'Minimal backend is working'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

