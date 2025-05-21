import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
import jwt # For checking JWT content

from Backend.services.authentication_service import (
    AuthenticationService,
    User, # Using the actual User class from the service file for integration testing within the service
    AuthenticationError,
    UserNotFound,
    InvalidTokenError,
    PasswordPolicyError,
    UserAlreadyExistsError,
    JWT_SECRET_KEY, # Import for token decoding in tests
    JWT_ALGORITHM,  # Import for token decoding in tests
    JWT_EXPIRATION_DELTA,
    PASSWORD_RESET_TOKEN_EXPIRATION_DELTA
)

# Helper to create a User instance easily
def create_test_user_instance(username="testuser", email="test@example.com", password="ValidPassword123!", roles=None, **kwargs):
    if roles is None:
        roles = ["Scientist"]
    return User(username=username, email=email, password=password, roles=roles, **kwargs)


class TestAuthenticationService(unittest.TestCase):

    def setUp(self):
        # Create a new service instance for each test to ensure isolation
        self.auth_service = AuthenticationService(user_store={}) # Start with an empty user store

    # 1. User Registration Tests
    @patch('builtins.print') # Mock print for audit logs
    def test_register_user_successful(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!", ["Scientist"], department="Lab")
        self.assertIn("testuser", self.auth_service.users)
        self.assertEqual(self.auth_service.users["testuser"].email, "test@example.com")
        self.assertEqual(self.auth_service.users["testuser"].department, "Lab")
        self.assertTrue(self.auth_service.users["testuser"].check_password("ValidPassword123!"))
        mock_print.assert_any_call("AUDIT: User 'testuser' registered successfully. Email: test@example.com, Roles: ['Scientist']")

    @patch('builtins.print')
    def test_register_user_existing_username(self, mock_print):
        self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        with self.assertRaises(UserAlreadyExistsError):
            self.auth_service.register_user("testuser", "another@example.com", "ValidPassword123!")

    @patch('builtins.print')
    def test_register_user_existing_email(self, mock_print):
        self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        with self.assertRaises(UserAlreadyExistsError):
            self.auth_service.register_user("anotheruser", "test@example.com", "ValidPassword123!")

    @patch('builtins.print')
    def test_register_user_password_policy_short(self, mock_print):
        with self.assertRaisesRegex(PasswordPolicyError, "Minimum 12 chars"):
            self.auth_service.register_user("testuser", "test@example.com", "Short1!")

    @patch('builtins.print')
    def test_register_user_password_policy_no_upper(self, mock_print):
        with self.assertRaisesRegex(PasswordPolicyError, "1 uppercase"):
            self.auth_service.register_user("testuser", "test@example.com", "noupper1!long")

    @patch('builtins.print')
    def test_register_user_password_policy_no_lower(self, mock_print):
        with self.assertRaisesRegex(PasswordPolicyError, "1 lowercase"):
            self.auth_service.register_user("testuser", "test@example.com", "NOLOWER1!LONG")
    
    @patch('builtins.print')
    def test_register_user_password_policy_no_digit(self, mock_print):
        with self.assertRaisesRegex(PasswordPolicyError, "1 digit"):
            self.auth_service.register_user("testuser", "test@example.com", "NoDigitUpper!Long")

    @patch('builtins.print')
    def test_register_user_password_policy_no_special(self, mock_print):
        with self.assertRaisesRegex(PasswordPolicyError, "1 special char"):
            self.auth_service.register_user("testuser", "test@example.com", "NoSpecial1UpperLong")

    # 2. User Login Tests
    @patch('builtins.print')
    def test_login_user_successful_username(self, mock_print):
        self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        token = self.auth_service.login_user("testuser", "ValidPassword123!")
        self.assertIsNotNone(token)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        self.assertEqual(payload["username"], "testuser")
        self.assertIn("Scientist", payload["roles"])
        self.assertIn("user_id", payload)
        self.assertIn("exp", payload)
        mock_print.assert_any_call("AUDIT: Successful login for user 'testuser'. Token generated.")

    @patch('builtins.print')
    def test_login_user_successful_email(self, mock_print):
        self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        token = self.auth_service.login_user("test@example.com", "ValidPassword123!")
        self.assertIsNotNone(token)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        self.assertEqual(payload["username"], "testuser") # Assuming username is part of payload
        mock_print.assert_any_call("AUDIT: Successful login for user 'testuser'. Token generated.")

    @patch('builtins.print')
    def test_login_user_incorrect_password(self, mock_print):
        self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        with self.assertRaisesRegex(AuthenticationError, "Invalid username or password."):
            self.auth_service.login_user("testuser", "WrongPassword!")
        mock_print.assert_any_call("AUDIT: Failed login attempt for user 'testuser' (incorrect password).")

    @patch('builtins.print')
    def test_login_user_non_existent_user(self, mock_print):
        with self.assertRaisesRegex(UserNotFound, "User 'nonexistent' not found."):
            self.auth_service.login_user("nonexistent", "SomePassword")
        mock_print.assert_any_call("AUDIT: Failed login attempt for non-existent user 'nonexistent'.")
    
    @patch('builtins.print')
    def test_login_user_inactive(self, mock_print):
        user = self.auth_service.register_user("inactiveuser", "inactive@example.com", "ValidPassword123!")
        user.is_active = False # Deactivate user
        self.auth_service.users["inactiveuser"] = user # Ensure updated user is in store
        self.auth_service.users_by_id[user.id] = user
        self.auth_service.users_by_email[user.email] = user

        with self.assertRaisesRegex(AuthenticationError, "User account 'inactiveuser' is inactive."):
            self.auth_service.login_user("inactiveuser", "ValidPassword123!")
        mock_print.assert_any_call("AUDIT: Failed login attempt for inactive user 'inactiveuser'.")


    # 3. Token Verification Tests
    @patch('builtins.print')
    def test_verify_token_successful(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        token = self.auth_service.login_user("testuser", "ValidPassword123!")
        payload = self.auth_service.verify_token(token)
        self.assertEqual(payload["user_id"], user.id)
        self.assertEqual(payload["username"], "testuser")

    @patch('builtins.print')
    def test_verify_token_expired(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        # Create an expired token
        expired_payload = {
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles,
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1), # Expired
            "iat": datetime.now(timezone.utc) - JWT_EXPIRATION_DELTA - timedelta(seconds=1)
        }
        expired_token = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        with self.assertRaisesRegex(InvalidTokenError, "Token has expired."):
            self.auth_service.verify_token(expired_token)
        mock_print.assert_any_call("AUDIT: Token verification failed: Expired token.")

    @patch('builtins.print')
    def test_verify_token_invalid_signature(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        payload = {
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles,
            "exp": datetime.now(timezone.utc) + JWT_EXPIRATION_DELTA,
            "iat": datetime.now(timezone.utc)
        }
        invalid_token = jwt.encode(payload, "wrong-secret-key", algorithm=JWT_ALGORITHM)
        with self.assertRaisesRegex(InvalidTokenError, "Invalid token: Signature verification failed"):
            self.auth_service.verify_token(invalid_token)
        mock_print.assert_any_call("AUDIT: Token verification failed: Invalid token (Signature verification failed).")

    @patch('builtins.print')
    def test_verify_token_user_not_found_or_inactive(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        token = self.auth_service.login_user("testuser", "ValidPassword123!")
        
        # Simulate user deleted after token generation
        del self.auth_service.users["testuser"]
        del self.auth_service.users_by_id[user.id]
        del self.auth_service.users_by_email[user.email]
        
        with self.assertRaisesRegex(InvalidTokenError, "User not found or inactive."):
            self.auth_service.verify_token(token)


    # 4. Password Reset Request Tests
    @patch('builtins.print')
    def test_request_password_reset_successful(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        reset_token_or_msg = self.auth_service.request_password_reset("test@example.com")
        self.assertIsNotNone(reset_token_or_msg) # In simulation, this is the token
        # Check if token is stored (internal check)
        self.assertIn(reset_token_or_msg, self.auth_service.password_reset_tokens)
        self.assertEqual(self.auth_service.password_reset_tokens[reset_token_or_msg]["user_id"], user.id)
        mock_print.assert_any_call(f"SIMULATE_EMAIL: Send password reset token {reset_token_or_msg} to test@example.com")
        mock_print.assert_any_call("AUDIT: Password reset requested for user 'testuser'. Token: " + reset_token_or_msg)


    @patch('builtins.print')
    def test_request_password_reset_non_existent_email(self, mock_print):
        response_message = self.auth_service.request_password_reset("nonexistent@example.com")
        self.assertEqual(response_message, "If an account with that email exists, a password reset link has been sent.")
        mock_print.assert_any_call("AUDIT: Password reset requested for non-existent email 'nonexistent@example.com'.")

    @patch('builtins.print')
    def test_request_password_reset_inactive_user(self, mock_print):
        user = self.auth_service.register_user("inactiveuser", "inactive@example.com", "ValidPassword123!")
        user.is_active = False
        self.auth_service.users["inactiveuser"] = user
        self.auth_service.users_by_id[user.id] = user
        self.auth_service.users_by_email[user.email] = user

        response_message = self.auth_service.request_password_reset("inactive@example.com")
        self.assertEqual(response_message, "If an account with that email exists and is active, a password reset link has been sent.")
        mock_print.assert_any_call("AUDIT: Password reset requested for inactive user 'inactiveuser'.")


    # 5. Password Reset Tests
    @patch('builtins.print')
    def test_reset_password_successful(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        reset_token = self.auth_service.request_password_reset("test@example.com") # This is the token in simulation
        
        success = self.auth_service.reset_password(reset_token, "NewSecureP@ss1")
        self.assertTrue(success)
        self.assertTrue(self.auth_service.users["testuser"].check_password("NewSecureP@ss1"))
        self.assertNotIn(reset_token, self.auth_service.password_reset_tokens) # Token invalidated
        mock_print.assert_any_call("AUDIT: Password successfully reset for user 'testuser'.")

    @patch('builtins.print')
    def test_reset_password_invalid_token(self, mock_print):
        with self.assertRaisesRegex(InvalidTokenError, "Invalid or expired reset token."):
            self.auth_service.reset_password("invalidtoken", "NewSecureP@ss1")
        mock_print.assert_any_call("AUDIT: Password reset attempt with invalid token 'invalidtoken'.")

    @patch('builtins.print')
    def test_reset_password_expired_token(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        reset_token = self.auth_service.request_password_reset("test@example.com")
        # Manually expire the token
        self.auth_service.password_reset_tokens[reset_token]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        
        with self.assertRaisesRegex(InvalidTokenError, "Reset token has expired."):
            self.auth_service.reset_password(reset_token, "NewSecureP@ss1")
        mock_print.assert_any_call(f"AUDIT: Password reset attempt with expired token '{reset_token}'.")
        self.assertNotIn(reset_token, self.auth_service.password_reset_tokens) # Expired token should be cleaned up

    @patch('builtins.print')
    def test_reset_password_policy_fail(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!")
        reset_token = self.auth_service.request_password_reset("test@example.com")
        with self.assertRaisesRegex(PasswordPolicyError, "New password does not meet complexity requirements"):
            self.auth_service.reset_password(reset_token, "weak")
        # Token should still be valid as password policy check happens before user update
        self.assertIn(reset_token, self.auth_service.password_reset_tokens)

    # 6. Profile Management Tests
    @patch('builtins.print')
    def test_get_user_profile_successful(self, mock_print):
        user = self.auth_service.register_user(
            "testuser", "test@example.com", "ValidPassword123!", 
            department="R&D", profile_info={"lab_id": "L101"}
        )
        profile = self.auth_service.get_user_profile(user.id)
        self.assertEqual(profile["username"], "testuser")
        self.assertEqual(profile["email"], "test@example.com")
        self.assertEqual(profile["department"], "R&D")
        self.assertEqual(profile["profile_info"]["lab_id"], "L101")
        self.assertNotIn("hashed_password", profile) # Ensure sensitive data is not in profile
        mock_print.assert_any_call(f"AUDIT: Profile retrieved for user ID '{user.id}'.")

    @patch('builtins.print')
    def test_get_user_profile_not_found(self, mock_print):
        with self.assertRaisesRegex(UserNotFound, "User with ID 'nonexistentid' not found."):
            self.auth_service.get_user_profile("nonexistentid")

    @patch('builtins.print')
    def test_update_user_profile_successful(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!", department="OldDept")
        original_updated_at = user.updated_at
        
        updated_user = self.auth_service.update_user_profile(
            user.id, department="NewDept", location="Building A", is_active=False
        )
        self.assertEqual(updated_user.department, "NewDept")
        self.assertEqual(updated_user.profile_info.get("location"), "Building A")
        self.assertFalse(updated_user.is_active)
        self.assertGreater(updated_user.updated_at, original_updated_at)
        
        # Verify in store
        self.assertEqual(self.auth_service.users_by_id[user.id].department, "NewDept")
        mock_print.assert_any_call(f"AUDIT: Profile updated for user ID '{user.id}'. Changes: department='NewDept', profile_kwargs='{{'location': 'Building A'}}', is_active='False'")

    @patch('builtins.print')
    def test_update_user_profile_no_changes(self, mock_print):
        user = self.auth_service.register_user("testuser", "test@example.com", "ValidPassword123!", department="DeptA")
        original_updated_at = user.updated_at
        
        # Call update with same department, no other profile_kwargs
        updated_user = self.auth_service.update_user_profile(user.id, department="DeptA")
        self.assertEqual(updated_user.updated_at, original_updated_at) # No change, so timestamp shouldn't update
        mock_print.assert_any_call(f"AUDIT: Profile update requested for user ID '{user.id}', but no changes were made.")


    @patch('builtins.print')
    def test_update_user_profile_not_found(self, mock_print):
        with self.assertRaisesRegex(UserNotFound, "User with ID 'nonexistentid' not found."):
            self.auth_service.update_user_profile("nonexistentid", department="SomeDept")

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
