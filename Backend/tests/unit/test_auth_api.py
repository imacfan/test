import unittest
from unittest.mock import patch, MagicMock
import json
from flask import Flask, jsonify, g


# Import the Blueprint and service-related exceptions
from Backend.api.auth.routes import auth_bp
from Backend.services.authentication_service import (
    AuthenticationService, # We will be mocking this
    UserNotFound,
    AuthenticationError,
    InvalidTokenError,
    PasswordPolicyError,
    UserAlreadyExistsError
)

# Placeholder User class for mocking service responses
class MockUser:
    def __init__(self, id="test_id", username="testuser", email="test@example.com", roles=None, department=None, **kwargs):
        self.id = id
        self.username = username
        self.email = email
        self.roles = roles if roles else ["Scientist"]
        self.department = department
        self.profile_info = kwargs


class TestAuthAPI(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key' # Needed for session context if any, good practice
        
        # Register the blueprint
        self.app.register_blueprint(auth_bp)
        
        self.client = self.app.test_client()

        # Patch the auth_service instance used by the blueprint
        # The patch target string is '<module_name_where_auth_service_is_defined>.auth_service'
        # In our case, it's 'Backend.api.auth.routes.auth_service'
        self.mock_auth_service_patch = patch('Backend.api.auth.routes.auth_service')
        self.mock_auth_service = self.mock_auth_service_patch.start()
        
        # Add cleanup for the patch
        self.addCleanup(self.mock_auth_service_patch.stop)


    # 1. POST /auth/register
    def test_register_successful(self):
        mock_user_instance = MockUser(id="new_id", username="newuser", email="new@example.com")
        self.mock_auth_service.register_user.return_value = mock_user_instance
        
        response = self.client.post('/auth/register', json={
            "username": "newuser", "email": "new@example.com", "password": "ValidPassword123!"
        })
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["message"], "User registered successfully")
        self.assertEqual(data["user"]["username"], "newuser")
        self.mock_auth_service.register_user.assert_called_once_with(
            "newuser", "new@example.com", "ValidPassword123!", ['Scientist'], None, **{}
        )

    def test_register_user_already_exists(self):
        self.mock_auth_service.register_user.side_effect = UserAlreadyExistsError("Username 'existinguser' already exists.")
        response = self.client.post('/auth/register', json={
            "username": "existinguser", "email": "existing@example.com", "password": "ValidPassword123!"
        })
        self.assertEqual(response.status_code, 409)
        data = response.get_json()
        self.assertIn("Username 'existinguser' already exists.", data["error"])

    def test_register_password_policy_error(self):
        self.mock_auth_service.register_user.side_effect = PasswordPolicyError("Password too short.")
        response = self.client.post('/auth/register', json={
            "username": "testuser", "email": "test@example.com", "password": "short"
        })
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Password does not meet policy requirements", data["error"])
        self.assertIn("Password too short.", data["details"])

    def test_register_missing_fields(self):
        response = self.client.post('/auth/register', json={"username": "testuser"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Missing username, email, or password", data["error"])


    # 2. POST /auth/login
    def test_login_successful(self):
        self.mock_auth_service.login_user.return_value = "mock_jwt_token"
        response = self.client.post('/auth/login', json={
            "username_or_email": "testuser", "password": "ValidPassword123!"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["token"], "mock_jwt_token")
        self.mock_auth_service.login_user.assert_called_once_with("testuser", "ValidPassword123!")

    def test_login_invalid_credentials(self):
        self.mock_auth_service.login_user.side_effect = AuthenticationError("Invalid credentials")
        response = self.client.post('/auth/login', json={
            "username_or_email": "testuser", "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertEqual(data["error"], "Invalid credentials")

    def test_login_user_not_found(self): # Service raises AuthenticationError or UserNotFound, API maps to 401
        self.mock_auth_service.login_user.side_effect = UserNotFound("User not found")
        response = self.client.post('/auth/login', json={
            "username_or_email": "nouser", "password": "password"
        })
        self.assertEqual(response.status_code, 401) # API groups these into "Invalid credentials"
        data = response.get_json()
        self.assertEqual(data["error"], "Invalid credentials")

    def test_login_missing_fields(self):
        response = self.client.post('/auth/login', json={"username_or_email": "testuser"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Missing username/email or password", data["error"])


    # 3. POST /auth/logout
    def test_logout(self):
        # For stateless JWT, logout is simple. If token_required, mock verify_token
        # Assuming token_required is on logout, we need to mock verify_token
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id_for_logout"}
        
        response = self.client.post('/auth/logout', headers={"Authorization": "Bearer faketoken"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["message"], "Logout successful")
        # If token_required is not on logout, remove verify_token mock and header


    # 4. POST /auth/password-reset-request
    def test_password_reset_request_successful(self):
        # Current service returns the token string for simulation or a message
        self.mock_auth_service.request_password_reset.return_value = "mock_reset_token_or_message"
        response = self.client.post('/auth/password-reset-request', json={"email": "test@example.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("If your email is registered, you will receive a password reset link (simulated).", data["message"])
        self.mock_auth_service.request_password_reset.assert_called_once_with("test@example.com")

    def test_password_reset_request_missing_email(self):
        response = self.client.post('/auth/password-reset-request', json={})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["error"], "Email is required")


    # 5. POST /auth/password-reset
    def test_password_reset_successful(self):
        self.mock_auth_service.reset_password.return_value = True
        response = self.client.post('/auth/password-reset', json={
            "reset_token": "valid_token", "new_password": "NewValidPassword123!"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["message"], "Password has been reset successfully")
        self.mock_auth_service.reset_password.assert_called_once_with("valid_token", "NewValidPassword123!")

    def test_password_reset_invalid_token(self):
        self.mock_auth_service.reset_password.side_effect = InvalidTokenError("Invalid token")
        response = self.client.post('/auth/password-reset', json={
            "reset_token": "invalid_token", "new_password": "NewValidPassword123!"
        })
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Invalid or expired token", data["error"])
        self.assertIn("Invalid token", data["details"])


    def test_password_reset_password_policy_error(self):
        self.mock_auth_service.reset_password.side_effect = PasswordPolicyError("Password too weak.")
        response = self.client.post('/auth/password-reset', json={
            "reset_token": "valid_token", "new_password": "weak"
        })
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Password does not meet policy requirements", data["error"])
        self.assertIn("Password too weak.", data["details"])

    def test_password_reset_missing_fields(self):
        response = self.client.post('/auth/password-reset', json={"reset_token": "token"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Missing reset token or new password", data["error"])


    # 6. GET /auth/profile (Protected Route)
    def test_get_profile_successful(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id", "username": "testuser"}
        mock_profile_data = {"id": "test_user_id", "username": "testuser", "email": "test@example.com"}
        self.mock_auth_service.get_user_profile.return_value = mock_profile_data
        
        response = self.client.get('/auth/profile', headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["username"], "testuser")
        self.mock_auth_service.verify_token.assert_called_once_with("valid_token")
        self.mock_auth_service.get_user_profile.assert_called_once_with("test_user_id")

    def test_get_profile_invalid_token(self):
        self.mock_auth_service.verify_token.side_effect = InvalidTokenError("Token expired")
        response = self.client.get('/auth/profile', headers={"Authorization": "Bearer invalid_token"})
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn("Token is invalid or expired!", data["error"])

    def test_get_profile_missing_token(self):
        response = self.client.get('/auth/profile') # No Authorization header
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertEqual(data["error"], "Token is missing!")

    def test_get_profile_user_not_found(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id"}
        self.mock_auth_service.get_user_profile.side_effect = UserNotFound("User not found")
        response = self.client.get('/auth/profile', headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertEqual(data["error"], "User profile not found")

    # 7. PUT /auth/profile (Protected Route)
    def test_update_profile_successful(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id"}
        
        # Mock the User object returned by update_user_profile
        updated_user_mock = MockUser(id="test_user_id", department="NewDept", profile_info={"location": "Site B"})
        self.mock_auth_service.update_user_profile.return_value = updated_user_mock
        
        # Mock get_user_profile which is called after update to serialize response
        self.mock_auth_service.get_user_profile.return_value = {
            "id": "test_user_id", "department": "NewDept", "profile_info": {"location": "Site B"}
        }

        update_data = {"department": "NewDept", "profile_info": {"location": "Site B"}}
        response = self.client.put('/auth/profile', json=update_data, headers={"Authorization": "Bearer valid_token"})
        
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["department"], "NewDept")
        self.assertEqual(data["profile_info"]["location"], "Site B")
        
        self.mock_auth_service.verify_token.assert_called_once_with("valid_token")
        # The route extracts 'department' and 'profile_info' items separately
        self.mock_auth_service.update_user_profile.assert_called_once_with(
            "test_user_id", department="NewDept", location="Site B" # profile_info items become kwargs
        )
        self.mock_auth_service.get_user_profile.assert_called_once_with("test_user_id")


    def test_update_profile_invalid_token(self):
        self.mock_auth_service.verify_token.side_effect = InvalidTokenError("Token invalid")
        response = self.client.put('/auth/profile', json={"department": "NewDept"}, headers={"Authorization": "Bearer invalid_token"})
        self.assertEqual(response.status_code, 401)

    def test_update_profile_user_not_found(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id"}
        self.mock_auth_service.update_user_profile.side_effect = UserNotFound("User not found")
        response = self.client.put('/auth/profile', json={"department": "NewDept"}, headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertEqual(data["error"], "User not found") # This comes from the service exception

    def test_update_profile_no_data(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id"}
        response = self.client.put('/auth/profile', json={}, headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("No data provided for update", data["error"])

    def test_update_profile_no_updatable_fields(self):
        self.mock_auth_service.verify_token.return_value = {"user_id": "test_user_id"}
        response = self.client.put('/auth/profile', json={"invalid_field": "value"}, headers={"Authorization": "Bearer valid_token"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("No updatable fields provided or invalid fields", data["error"])


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
