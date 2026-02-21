# stem is optional; the application can operate without a Tor control connection
try:
    from argon2.exceptions import VerifyMismatchError
    from argon2 import PasswordHasher
    from stem.connection import AuthenticationFailure, authenticate_cookie
    from stem.control import Controller
except ImportError:  # pragma: no cover - dependencies missing during tests
    AuthenticationFailure = Exception
    def authenticate_cookie(controller, path): return None
    Controller = None

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, session, jsonify, url_for, redirect, render_template, flash, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import string
import random
import os

# --- Flask App Setup ---
app = Flask(__name__)

def connect_to_tor():
    """Connect to a local Tor control socket and create an ephemeral hidden service.
    The function sets ``app.tor_service`` so that callers can later remove the
    service if needed.  It **does not** start the Flask server itself; the
    caller is responsible for invoking ``app.run`` so that the controller
    context is not held for the duration of the HTTP server.
    If the `stem` package or controller functionality is unavailable the
    call becomes a no-op and the application will still run in "non-Tor"
    mode.
    """

    if Controller is None:
        print("stem library not available; skipping Tor connection.")
        return

    socket_path = "/var/run/tor/control"
    try:
        print(f"Connecting to Tor control socket at {socket_path}...")
        # Use Controller.from_socket_file instead of Controller.from_port
        with Controller.from_socket_file(path=socket_path) as controller:
            print("Successfully connected to Tor control socket.")
            try:
                controller.authenticate()  # Try authenticating without a cookie first for sockets
                print("Successfully authenticated with Tor.")
            except AuthenticationFailure:
                print("Simple authentication failed, trying cookie...")
                cookie_path = "/var/lib/tor/control_auth_cookie"
                authenticate_cookie(controller, cookie_path)
                print("Successfully authenticated with Tor using cookie.")

            tor_version = controller.get_version()
            print(f"Connected to Tor version: {tor_version}")

            # Create a hidden service
            print("Creating hidden service...")
            service = controller.create_ephemeral_hidden_service(
                {80: 5000},  # Map onion port 80 to local port 5000
                await_publication=True  # Wait for the service to be published
            )

            onion_host = service.service_id + ".onion"
            print(f"Hidden service available at: http://{onion_host}")

            # Store the service so we can close it later
            app.tor_service = service
    except Exception as e:
        print(f"Could not connect to Tor control socket: {e}")
        print("Is Tor running? Are you running this script with 'sudo' in Tails?")

# --- Main Execution ---
if __name__ == "__main__":
    # ensure database tables are created before the first request
    with app.app_context():
        db.create_all()

    try:
        connect_to_tor()
        # start the Flask app after the hidden service has been created
        app.run(port=5000)
    finally:
        if hasattr(app, 'tor_service'):
            print("Closing hidden service...")
            app.tor_service.remove()
