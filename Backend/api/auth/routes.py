from functools import wraps
from flask import Blueprint, request, jsonify, make_response, g
from Backend.services.authentication_service import (
    AuthenticationService,
    UserNotFound,
    AuthenticationError,
    InvalidTokenError,
    PasswordPolicyError,
    UserAlreadyExistsError # Though not directly handled in these routes, good to have for context
)

# Instantiate the AuthenticationService
# For now, it uses its default in-memory user store.
auth_service = AuthenticationService()

# Create a Flask Blueprint
auth_bp = Blueprint('auth_bp', __name__, url_prefix='/auth')

# Token Required Decorator
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return make_response(jsonify({"error": "Token is missing!"}), 401)

        try:
            payload = auth_service.verify_token(token)
            g.current_user_id = payload.get("user_id")
            if not g.current_user_id: # Should not happen if verify_token is correct
                 return make_response(jsonify({"error": "Token is invalid, user_id missing!"}), 401)
        except InvalidTokenError as e:
            return make_response(jsonify({"error": "Token is invalid or expired!", "details": str(e)}), 401)
        
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username_or_email') or not data.get('password'):
        return make_response(jsonify({"error": "Missing username/email or password"}), 400)

    username_or_email = data.get('username_or_email')
    password = data.get('password')

    try:
        token = auth_service.login_user(username_or_email, password)
        # Audit Hook Placeholder for successful login is already in the service
        return make_response(jsonify({"token": token}), 200)
    except (AuthenticationError, UserNotFound):
        # Audit Hook Placeholder for failed login is already in the service
        return make_response(jsonify({"error": "Invalid credentials"}), 401)
    except Exception as e:
        # Generic error handler for unexpected issues
        print(f"ERROR [Login Endpoint]: Unexpected error: {e}") # For server logs
        return make_response(jsonify({"error": "An unexpected error occurred"}), 500)

@auth_bp.route('/logout', methods=['POST'])
@token_required # Optional: can be protected to log which user is logging out
def logout():
    # For stateless JWT, logout is primarily client-side (deleting the token).
    # This endpoint can be used for audit logging.
    user_id_logging_out = getattr(g, 'current_user_id', 'Unknown user - token not processed or not required for logout')
    print(f"AUDIT: Logout attempt by user_id: {user_id_logging_out}") # Audit Hook Placeholder
    return make_response(jsonify({"message": "Logout successful"}), 200)

@auth_bp.route('/register', methods=['POST']) # Added as per AuthenticationService capabilities
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return make_response(jsonify({"error": "Missing username, email, or password"}), 400)

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    roles = data.get('roles', ['Scientist']) # Default role
    department = data.get('department')
    profile_info = data.get('profile_info', {})

    try:
        user = auth_service.register_user(
            username, email, password, roles, department, **profile_info
        )
        # Audit Hook Placeholder is in the service
        return make_response(jsonify({
            "message": "User registered successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "roles": user.roles,
                "department": user.department
            }
        }), 201)
    except UserAlreadyExistsError as e:
        return make_response(jsonify({"error": str(e)}), 409) # 409 Conflict
    except PasswordPolicyError as e:
        return make_response(jsonify({"error": "Password does not meet policy requirements", "details": str(e)}), 400)
    except Exception as e:
        print(f"ERROR [Register Endpoint]: Unexpected error: {e}")
        return make_response(jsonify({"error": "An unexpected error occurred during registration"}), 500)


@auth_bp.route('/password-reset-request', methods=['POST'])
def password_reset_request():
    data = request.get_json()
    if not data or not data.get('email'):
        return make_response(jsonify({"error": "Email is required"}), 400)

    email = data.get('email')
    try:
        # The service currently returns the token for simulation,
        # but the API should not expose it.
        # The service also handles the "UserNotFound" case by returning a generic message
        # and logging, so we don't need to catch UserNotFound here explicitly for that.
        # The service method already prints a simulation of sending an email.
        message_or_token = auth_service.request_password_reset(email)
        
        # If the service method were to raise UserNotFound instead of returning a generic message:
        # except UserNotFound:
        #     return make_response(jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200)
        
        # For now, we assume the service's behavior of returning a string (either token or message)
        # and we will always return a generic success message to the client.
        return make_response(jsonify({"message": "If your email is registered, you will receive a password reset link (simulated)."}), 200)
    except Exception as e:
        print(f"ERROR [Password Reset Request Endpoint]: Unexpected error: {e}")
        return make_response(jsonify({"error": "An unexpected error occurred"}), 500)


@auth_bp.route('/password-reset', methods=['POST'])
def password_reset():
    data = request.get_json()
    if not data or not data.get('reset_token') or not data.get('new_password'):
        return make_response(jsonify({"error": "Missing reset token or new password"}), 400)

    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    try:
        auth_service.reset_password(reset_token, new_password)
        # Audit Hook Placeholder is in the service
        return make_response(jsonify({"message": "Password has been reset successfully"}), 200)
    except InvalidTokenError as e:
        return make_response(jsonify({"error": "Invalid or expired token", "details": str(e)}), 400)
    except PasswordPolicyError as e:
        # The service's PasswordPolicyError already contains a descriptive message
        return make_response(jsonify({"error": "Password does not meet policy requirements", "details": str(e)}), 400)
    except UserNotFound as e: # Should not happen if token is valid, but good to catch
        return make_response(jsonify({"error": "User not found for the given token", "details": str(e)}), 404)
    except Exception as e:
        print(f"ERROR [Password Reset Endpoint]: Unexpected error: {e}")
        return make_response(jsonify({"error": "An unexpected error occurred"}), 500)


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    current_user_id = getattr(g, 'current_user_id', None)
    if not current_user_id: # Should be caught by decorator, but defensive check
        return make_response(jsonify({"error": "Unauthorized - user ID not found in token context"}), 401)

    try:
        profile_data = auth_service.get_user_profile(current_user_id)
        # Audit Hook Placeholder is in the service
        return make_response(jsonify(profile_data), 200)
    except UserNotFound:
        return make_response(jsonify({"error": "User profile not found"}), 404)
    except Exception as e:
        print(f"ERROR [Get Profile Endpoint]: Unexpected error: {e}")
        return make_response(jsonify({"error": "An unexpected error occurred"}), 500)


@auth_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile():
    current_user_id = getattr(g, 'current_user_id', None)
    if not current_user_id: # Should be caught by decorator
        return make_response(jsonify({"error": "Unauthorized - user ID not found in token context"}), 401)

    data = request.get_json()
    if not data:
        return make_response(jsonify({"error": "No data provided for update"}), 400)

    # Extract allowed fields for update.
    # Roles, email, username changes are typically handled by separate, more privileged endpoints.
    # is_active might also be admin-only. The service handles what can be updated.
    allowed_updates = {}
    if 'department' in data:
        allowed_updates['department'] = data['department']
    if 'profile_info' in data: # The service expects profile_info as kwargs
        for key, value in data['profile_info'].items():
            allowed_updates[key] = value
    
    # Example for is_active if it were allowed to be updated by users directly via this endpoint
    # if 'is_active' in data and isinstance(data['is_active'], bool):
    #    allowed_updates['is_active'] = data['is_active']


    if not allowed_updates:
        return make_response(jsonify({"error": "No updatable fields provided or invalid fields"}), 400)

    try:
        updated_user = auth_service.update_user_profile(current_user_id, **allowed_updates)
        # Audit Hook Placeholder is in the service

        # Return the updated profile (excluding sensitive info, handled by service's get_user_profile logic if we called that)
        # For now, construct a safe response based on what update_user_profile returns.
        # The current auth_service.update_user_profile returns the User object.
        # We should use get_user_profile to ensure consistent output.
        profile_data = auth_service.get_user_profile(updated_user.id)
        return make_response(jsonify(profile_data), 200)
    except UserNotFound:
        return make_response(jsonify({"error": "User not found"}), 404)
    except Exception as e:
        print(f"ERROR [Update Profile Endpoint]: Unexpected error: {e}")
        return make_response(jsonify({"error": "An unexpected error occurred"}), 500)

# Example of how to register this blueprint in your main app.py (for context, not part of this file)
# from flask import Flask
# from Backend.api.auth.routes import auth_bp
#
# app = Flask(__name__)
# app.register_blueprint(auth_bp) # Default prefix is /auth as defined in Blueprint
#
# if __name__ == '__main__':
#     # You would also need to set a JWT_SECRET_KEY for the auth_service if it were loaded from config
#     # For example: auth_service.JWT_SECRET_KEY = "your-app-secret-key"
#     # This is currently hardcoded in authentication_service.py for simplicity.
#     app.run(debug=True)
