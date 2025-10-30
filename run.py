#!/usr/bin/env python3
"""
CodeConnect - Social Coding Platform
Entry point for the application
"""
import os
from app import app, socketio, db # Import from the app file

# Optional: Load environment variables if using a .env file locally
# from dotenv import load_dotenv
# load_dotenv()

def create_db():
    """Creates database tables if they don't exist."""
    with app.app_context():
        print("Checking/creating database tables...")
        try:
            db.create_all()
            print("Database tables checked/created.")
        except Exception as e:
            print(f"Error creating database tables: {e}")
            # Consider exiting if DB creation fails and is critical
            # exit(1)

if __name__ == '__main__':
    create_db() # Create tables before running

    print("Starting CodeConnect server...")
    print(f" * Environment: {os.environ.get('FLASK_CONFIG', 'default')}")
    print(f" * Debug mode: {app.config['DEBUG']}")
    print("Visit http://localhost:5000 (or configured host/port) to access")

    # Use debug setting from config
    # SECURITY WARNING: DO NOT use allow_unsafe_werkzeug=True in production!
    # It disables security features of the development server.
    socketio.run(
        app,
        debug=app.config['DEBUG'],
        host='0.0.0.0', # Listen on all network interfaces
        port=5000,
        allow_unsafe_werkzeug=app.config['DEBUG'] # Needed for Werkzeug>=2.1 debug reloader with SocketIO
    )