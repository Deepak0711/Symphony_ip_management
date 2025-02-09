#!/bin/bash

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create database & admin user
echo "Setting up the database..."
python3 database_setup.py

# Run the Flask app
echo "Starting Flask server..."
flask run --host=0.0.0.0 --port=5000