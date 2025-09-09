# Sentry Configuration for PartsQuest Backend
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

def init_sentry(app):
    """Initialize Sentry for Flask application"""
    
    sentry_logging = LoggingIntegration(
        level=logging.INFO,        # Capture info and above as breadcrumbs
        event_level=logging.ERROR  # Send errors as events
    )
    
    sentry_sdk.init(
        dsn="https://2bc3e3c19ce7f9f32731fbd7472d7e75@o4509975362142208.ingest.us.sentry.io/4509975365943296",
        integrations=[
            FlaskIntegration(transaction_style='endpoint'),
            sentry_logging,
        ],
        traces_sample_rate=1.0,
        environment=app.config.get('ENV', 'development'),
        before_send=filter_errors,
    )
    
    app.logger.info("Sentry initialized for PartsQuest backend")

def filter_errors(event, hint):
    """Filter out development and non-critical errors"""
    if event.get('environment') == 'development':
        return None
    
    # Filter out common non-critical errors
    if 'exc_info' in hint:
        exc_type, exc_value, tb = hint['exc_info']
        if isinstance(exc_value, (KeyboardInterrupt, SystemExit)):
            return None
    
    return event
