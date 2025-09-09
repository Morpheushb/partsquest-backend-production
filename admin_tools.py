#!/usr/bin/env python3
"""
PartsQuest Admin Tools
Provides administrative functions for user management, data cleanup, and reporting
"""

import os
import sys
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import pandas as pd

# Add the current directory to path to import models
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql://', 1)
    if '?sslmode=' not in database_url:
        database_url += '?sslmode=require'

# Create engine and session
engine = create_engine(database_url, echo=False)
Session = sessionmaker(bind=engine)

class PartsQuestAdmin:
    def __init__(self):
        self.session = Session()
        print("🔧 PartsQuest Admin Tools initialized")
    
    def __del__(self):
        if hasattr(self, 'session'):
            self.session.close()
    
    def clear_test_users(self, confirm=False):
        """Clear all test users and their associated data"""
        if not confirm:
            print("⚠️  This will permanently delete all users and their data!")
            print("⚠️  To confirm, call: admin.clear_test_users(confirm=True)")
            return
        
        try:
            # Get count of users before deletion
            user_count = self.session.execute(text("SELECT COUNT(*) FROM \"user\"")).scalar()
            vehicle_count = self.session.execute(text("SELECT COUNT(*) FROM vehicle")).scalar()
            part_request_count = self.session.execute(text("SELECT COUNT(*) FROM part_request")).scalar()
            
            print(f"📊 Current data:")
            print(f"   Users: {user_count}")
            print(f"   Vehicles: {vehicle_count}")
            print(f"   Part Requests: {part_request_count}")
            
            # Delete in correct order (foreign key constraints)
            self.session.execute(text("DELETE FROM part_request"))
            self.session.execute(text("DELETE FROM vehicle"))
            self.session.execute(text("DELETE FROM \"user\""))
            
            # Reset sequences
            self.session.execute(text("ALTER SEQUENCE user_id_seq RESTART WITH 1"))
            self.session.execute(text("ALTER SEQUENCE vehicle_id_seq RESTART WITH 1"))
            self.session.execute(text("ALTER SEQUENCE part_request_id_seq RESTART WITH 1"))
            
            self.session.commit()
            
            print("✅ All test data cleared successfully!")
            print("✅ Database sequences reset")
            
        except Exception as e:
            self.session.rollback()
            print(f"❌ Error clearing test data: {e}")
    
    def get_user_report(self):
        """Generate comprehensive user report"""
        try:
            query = text("""
                SELECT 
                    id,
                    email,
                    first_name,
                    last_name,
                    company,
                    phone,
                    is_active,
                    subscription_status,
                    stripe_customer_id,
                    created_at,
                    CASE 
                        WHEN created_at > NOW() - INTERVAL '24 hours' THEN 'Last 24h'
                        WHEN created_at > NOW() - INTERVAL '7 days' THEN 'Last 7 days'
                        WHEN created_at > NOW() - INTERVAL '30 days' THEN 'Last 30 days'
                        ELSE 'Older'
                    END as signup_period,
                    EXTRACT(DAYS FROM NOW() - created_at) as days_since_signup
                FROM "user"
                ORDER BY created_at DESC
            """)
            
            result = self.session.execute(query)
            users = result.fetchall()
            
            if not users:
                print("📊 No users found in database")
                return []
            
            # Convert to list of dictionaries for easier handling
            user_data = []
            for user in users:
                user_data.append({
                    'ID': user.id,
                    'Email': user.email,
                    'Name': f"{user.first_name} {user.last_name}",
                    'Company': user.company or 'N/A',
                    'Phone': user.phone or 'N/A',
                    'Active': '✅' if user.is_active else '❌',
                    'Subscription': user.subscription_status,
                    'Stripe ID': user.stripe_customer_id or 'N/A',
                    'Signup Date': user.created_at.strftime('%Y-%m-%d %H:%M'),
                    'Signup Period': user.signup_period,
                    'Days Active': int(user.days_since_signup)
                })
            
            return user_data
            
        except Exception as e:
            print(f"❌ Error generating user report: {e}")
            return []
    
    def print_user_report(self):
        """Print formatted user report"""
        users = self.get_user_report()
        
        if not users:
            return
        
        print("=" * 120)
        print("📊 PARTSQUEST USER REPORT")
        print("=" * 120)
        
        # Summary statistics
        total_users = len(users)
        active_users = sum(1 for u in users if u['Active'] == '✅')
        subscription_stats = {}
        for user in users:
            status = user['Subscription']
            subscription_stats[status] = subscription_stats.get(status, 0) + 1
        
        print(f"📈 SUMMARY:")
        print(f"   Total Users: {total_users}")
        print(f"   Active Users: {active_users}")
        print(f"   Inactive Users: {total_users - active_users}")
        print()
        
        print(f"💳 SUBSCRIPTION BREAKDOWN:")
        for status, count in subscription_stats.items():
            percentage = (count / total_users) * 100
            print(f"   {status.title()}: {count} ({percentage:.1f}%)")
        print()
        
        # Signup periods
        signup_stats = {}
        for user in users:
            period = user['Signup Period']
            signup_stats[period] = signup_stats.get(period, 0) + 1
        
        print(f"📅 SIGNUP PERIODS:")
        for period, count in signup_stats.items():
            percentage = (count / total_users) * 100
            print(f"   {period}: {count} ({percentage:.1f}%)")
        print()
        
        # Detailed user list
        print("👥 USER DETAILS:")
        print("-" * 120)
        
        # Header
        print(f"{'ID':<4} {'Email':<30} {'Name':<25} {'Company':<20} {'Status':<8} {'Subscription':<12} {'Days':<6} {'Signup Date':<16}")
        print("-" * 120)
        
        # User rows
        for user in users:
            print(f"{user['ID']:<4} {user['Email'][:29]:<30} {user['Name'][:24]:<25} {user['Company'][:19]:<20} {user['Active']:<8} {user['Subscription']:<12} {user['Days Active']:<6} {user['Signup Date']:<16}")
        
        print("=" * 120)
    
    def get_subscription_report(self):
        """Generate subscription tier analysis"""
        try:
            query = text("""
                SELECT 
                    subscription_status,
                    COUNT(*) as user_count,
                    AVG(EXTRACT(DAYS FROM NOW() - created_at)) as avg_days_active,
                    MIN(created_at) as first_signup,
                    MAX(created_at) as latest_signup
                FROM "user"
                GROUP BY subscription_status
                ORDER BY user_count DESC
            """)
            
            result = self.session.execute(query)
            subscriptions = result.fetchall()
            
            print("=" * 80)
            print("💳 SUBSCRIPTION TIER ANALYSIS")
            print("=" * 80)
            
            for sub in subscriptions:
                print(f"📊 {sub.subscription_status.upper()}")
                print(f"   Users: {sub.user_count}")
                print(f"   Avg Days Active: {sub.avg_days_active:.1f}")
                print(f"   First Signup: {sub.first_signup.strftime('%Y-%m-%d')}")
                print(f"   Latest Signup: {sub.latest_signup.strftime('%Y-%m-%d')}")
                print()
            
        except Exception as e:
            print(f"❌ Error generating subscription report: {e}")
    
    def export_user_data(self, filename=None):
        """Export user data to CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"partsquest_users_{timestamp}.csv"
        
        users = self.get_user_report()
        
        if not users:
            print("❌ No user data to export")
            return
        
        try:
            df = pd.DataFrame(users)
            df.to_csv(filename, index=False)
            print(f"✅ User data exported to: {filename}")
            print(f"📊 Exported {len(users)} user records")
            
        except Exception as e:
            print(f"❌ Error exporting user data: {e}")
    
    def fix_subscription_status(self):
        """Fix subscription status for users who should be active"""
        try:
            # For now, let's set all users to 'active' for testing
            # In production, this would check with Stripe
            
            result = self.session.execute(text("""
                UPDATE "user" 
                SET subscription_status = 'active' 
                WHERE subscription_status != 'active'
            """))
            
            self.session.commit()
            
            print(f"✅ Updated {result.rowcount} users to active subscription status")
            
        except Exception as e:
            self.session.rollback()
            print(f"❌ Error fixing subscription status: {e}")
    
    def create_test_user(self, email="test@partsquest.com", password="testpass123"):
        """Create a test user for development"""
        try:
            from werkzeug.security import generate_password_hash
            
            # Check if user already exists
            existing = self.session.execute(text("SELECT id FROM \"user\" WHERE email = :email"), {"email": email}).fetchone()
            
            if existing:
                print(f"⚠️  User {email} already exists with ID: {existing.id}")
                return existing.id
            
            # Create new test user
            password_hash = generate_password_hash(password)
            
            result = self.session.execute(text("""
                INSERT INTO "user" (email, password_hash, first_name, last_name, company, phone, subscription_status, is_active, created_at)
                VALUES (:email, :password_hash, 'Test', 'User', 'Test Company', '555-0123', 'active', true, NOW())
                RETURNING id
            """), {
                "email": email,
                "password_hash": password_hash
            })
            
            user_id = result.fetchone().id
            self.session.commit()
            
            print(f"✅ Test user created successfully!")
            print(f"   Email: {email}")
            print(f"   Password: {password}")
            print(f"   User ID: {user_id}")
            print(f"   Subscription: active")
            
            return user_id
            
        except Exception as e:
            self.session.rollback()
            print(f"❌ Error creating test user: {e}")
            return None

def main():
    """Main function for command-line usage"""
    admin = PartsQuestAdmin()
    
    print("🔧 PartsQuest Admin Tools")
    print("Available commands:")
    print("  admin.print_user_report()           - Show detailed user report")
    print("  admin.get_subscription_report()     - Show subscription analysis")
    print("  admin.export_user_data()            - Export users to CSV")
    print("  admin.clear_test_users(confirm=True) - Clear all test data")
    print("  admin.fix_subscription_status()     - Fix subscription statuses")
    print("  admin.create_test_user()             - Create test user")
    print()
    
    # Auto-generate report
    admin.print_user_report()
    admin.get_subscription_report()
    
    return admin

if __name__ == "__main__":
    admin = main()

