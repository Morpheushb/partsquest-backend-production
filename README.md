# PartsQuest Backend API

A Flask-based REST API for the PartsQuest SaaS platform, providing user authentication, part request management, and Stripe payment integration.

## Features

- User registration and authentication with JWT tokens
- Part request management system
- Stripe payment integration for subscriptions
- PostgreSQL database integration
- CORS support for frontend integration
- Docker containerization for easy deployment

## API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `GET /api/profile` - Get user profile (authenticated)
- `PUT /api/profile` - Update user profile (authenticated)

### Part Requests
- `POST /api/part-requests` - Create new part request (authenticated)
- `GET /api/part-requests` - Get user's part requests (authenticated)

### Stripe Integration
- `GET /api/stripe/config` - Get Stripe publishable key
- `POST /api/stripe/create-checkout-session` - Create payment session (authenticated)
- `POST /api/stripe/webhook` - Handle Stripe webhooks

### Health Check
- `GET /` - API status
- `GET /api/health` - Health check endpoint

## Environment Variables

Required environment variables:

```
DATABASE_URL=postgresql://username:password@host:port/database
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
SECRET_KEY=your-secret-key
PORT=5000
```

## Deployment

This application is configured for deployment on Render.com using Docker.

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables in `.env` file

3. Run the application:
```bash
python app.py
```

### Docker Deployment

```bash
docker build -t partsquest-backend .
docker run -p 5000:5000 partsquest-backend
```

## Database Schema

### Users Table
- id (Primary Key)
- email (Unique)
- password_hash
- first_name, last_name
- company, phone
- subscription_status
- stripe_customer_id
- created_at

### Part Requests Table
- id (Primary Key)
- user_id (Foreign Key)
- part_number
- description
- quantity
- target_price
- urgency
- status
- created_at

## Security

- Passwords are hashed using Werkzeug's security functions
- JWT tokens for authentication with 7-day expiration
- CORS configured for cross-origin requests
- Input validation on all endpoints
- Stripe webhook signature verification

