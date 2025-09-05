#!/usr/bin/env python3
"""
Script to check and fix user subscription statuses in the database
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add the app directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the app and models
from app import app, db, User

def check_user_statuses():
    """Check all user subscription statuses"""
    with app.app_context():
        users = User.query.all()
        print(f"Total users: {len(users)}")
        
        status_counts = {}
        for user in users:
            status = user.subscription_status
            status_counts[status] = status_counts.get(status, 0) + 1
            print(f"User {user.email}: {status}")
        
        print("\nStatus summary:")
        for status, count in status_counts.items():
            print(f"  {status}: {count}")

def fix_free_users():
    """Fix users with 'free' status to 'inactive'"""
    with app.app_context():
        free_users = User.query.filter_by(subscription_status='free').all()
        print(f"Found {len(free_users)} users with 'free' status")
        
        for user in free_users:
            print(f"Fixing user {user.email}: free -> inactive")
            user.subscription_status = 'inactive'
        
        db.session.commit()
        print(f"Fixed {len(free_users)} users")

if __name__ == "__main__":
    print("Checking user subscription statuses...")
    check_user_statuses()
    
    print("\nFixing users with 'free' status...")
    fix_free_users()
    
    print("\nRechecking after fix...")
    check_user_statuses()

