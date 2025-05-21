import uuid
import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from werkzeug.security import generate_password_hash, check_password_hash # Already in user.py but good to have for context

# Assuming User model is available, for now define a placeholder or import if structure allows
# from Backend.models.user import User
# Placeholder User class if Backend.models.user is not yet integrated or for standalone testing
class User:
    def __init__(
        self,
        username: str,
        email: str,
        password: str, # Plain password, will be hashed by set_password
        roles: List[str],
        department: Optional[str] = None,
        is_active: bool = True,
        profile_info: Optional[Dict[str, Any]] = None,
    ):
        self.id = str(uuid.uuid4())
        self.username = username
        self.email = email
        self.hashed_password = "" # Will be set by set_password
        self.set_password(password)
        self.roles = roles
        self.department = department
        self.is_active = is_active
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        self.profile_info = profile_info if profile_info else {}

    def set_password(self, password: str) -> None:
        self.hashed_password = generate_password_hash(password)
        self.updated_at = datetime.now(timezone.utc)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.hashed_password, password)

    def __repr__(self):
        return f"<User {self.username}>"

# Custom Exceptions
class AuthenticationError(Exception):
    pass

class UserNotFound(Exception):
    pass

class InvalidTokenError(Exception):
    pass

class PasswordPolicyError(Exception):
    pass

class UserAlreadyExistsError(Exception):
    pass

# Configuration (replace with actual config loading later)
JWT_SECRET_KEY = "your-super-secret-key-for-jwt" # Replace with a strong, unique key
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = timedelta(hours=1)
PASSWORD_RESET_TOKEN_EXPIRATION_DELTA = timedelta(hours=1)


class AuthenticationService:
    def __init__(self, user_store: Optional[Dict[str, User]] = None):
        """
        Initialize with a user_store.
        For now, user_store can be a dictionary.
        """
        self.users: Dict[str, User] = user_store if user_store is not None else {} # username: User_object
        self.users_by_id: Dict[str, User] = {user.id: user for user in self.users.values()}
        self.users_by_email: Dict[str, User] = {user.email: user for user in self.users.values()}
        self.password_reset_tokens: Dict[str, Dict[str, Any]] = {} # token: {"user_id": user_id, "expires_at": datetime}

    def _validate_password_policy(self, password: str) -> bool:
        """
        Validates password against policy:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character (e.g., !@#$%^&*)
        """
        if len(password) < 12:
            return False
        if not any(char.islower() for char in password):
            return False
        if not any(char.isupper() for char in password):
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(not char.isalnum() for char in password): # Checks for special characters
            return False
        return True

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: Optional[List[str]] = None,
        department: Optional[str] = None,
        **profile_kwargs: Any
    ) -> User:
        if roles is None:
            roles = ["Scientist"] # Default role

        if username in self.users:
            raise UserAlreadyExistsError(f"Username '{username}' already exists.")
        if email in self.users_by_email:
            raise UserAlreadyExistsError(f"Email '{email}' already exists.")

        if not self._validate_password_policy(password):
            raise PasswordPolicyError(
                "Password does not meet complexity requirements: "
                "Minimum 12 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char."
            )

        new_user = User(
            username=username,
            email=email,
            password=password, # User class's __init__ will call set_password
            roles=roles,
            department=department,
            profile_info=profile_kwargs
        )
        self.users[username] = new_user
        self.users_by_id[new_user.id] = new_user
        self.users_by_email[email] = new_user

        print(f"AUDIT: User '{username}' registered successfully. Email: {email}, Roles: {roles}") # Audit Hook Placeholder
        return new_user

    def login_user(self, username_or_email: str, password: str) -> str:
        user = self.users.get(username_or_email)
        if not user:
            user = self.users_by_email.get(username_or_email)

        if not user:
            print(f"AUDIT: Failed login attempt for non-existent user '{username_or_email}'.") # Audit Hook Placeholder
            raise UserNotFound(f"User '{username_or_email}' not found.")

        if not user.is_active:
            print(f"AUDIT: Failed login attempt for inactive user '{user.username}'.") # Audit Hook Placeholder
            raise AuthenticationError(f"User account '{user.username}' is inactive.")

        if not user.check_password(password):
            print(f"AUDIT: Failed login attempt for user '{user.username}' (incorrect password).") # Audit Hook Placeholder
            raise AuthenticationError("Invalid username or password.")

        payload = {
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles,
            "exp": datetime.now(timezone.utc) + JWT_EXPIRATION_DELTA,
            "iat": datetime.now(timezone.utc)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        print(f"AUDIT: Successful login for user '{user.username}'. Token generated.") # Audit Hook Placeholder
        return token

    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            # Check if user still exists and is active
            user = self.users_by_id.get(payload.get("user_id"))
            if not user or not user.is_active:
                raise InvalidTokenError("User not found or inactive.")
            return payload
        except jwt.ExpiredSignatureError:
            print("AUDIT: Token verification failed: Expired token.") # Audit Hook Placeholder
            raise InvalidTokenError("Token has expired.")
        except jwt.InvalidTokenError as e:
            print(f"AUDIT: Token verification failed: Invalid token ({e}).") # Audit Hook Placeholder
            raise InvalidTokenError(f"Invalid token: {e}")

    def request_password_reset(self, email: str) -> str:
        user = self.users_by_email.get(email)
        if not user:
            # Still return a success-like message to prevent email enumeration
            print(f"AUDIT: Password reset requested for non-existent email '{email}'.") # Audit Hook Placeholder
            return "If an account with that email exists, a password reset link has been sent."

        if not user.is_active:
            print(f"AUDIT: Password reset requested for inactive user '{user.username}'.") # Audit Hook Placeholder
            return "If an account with that email exists and is active, a password reset link has been sent."

        # Invalidate previous tokens for this user
        for token_val, token_data in list(self.password_reset_tokens.items()):
            if token_data["user_id"] == user.id:
                del self.password_reset_tokens[token_val]

        reset_token = str(uuid.uuid4()) # Simple random token
        expires_at = datetime.now(timezone.utc) + PASSWORD_RESET_TOKEN_EXPIRATION_DELTA
        self.password_reset_tokens[reset_token] = {"user_id": user.id, "expires_at": expires_at}

        print(f"AUDIT: Password reset requested for user '{user.username}'. Token: {reset_token}") # Audit Hook Placeholder
        # Simulate sending email:
        print(f"SIMULATE_EMAIL: Send password reset token {reset_token} to {email}")
        return reset_token # In a real app, you'd send an email and return a success message.

    def reset_password(self, reset_token: str, new_password: str) -> bool:
        token_data = self.password_reset_tokens.get(reset_token)

        if not token_data:
            print(f"AUDIT: Password reset attempt with invalid token '{reset_token}'.") # Audit Hook Placeholder
            raise InvalidTokenError("Invalid or expired reset token.")

        if token_data["expires_at"] < datetime.now(timezone.utc):
            del self.password_reset_tokens[reset_token]
            print(f"AUDIT: Password reset attempt with expired token '{reset_token}'.") # Audit Hook Placeholder
            raise InvalidTokenError("Reset token has expired.")

        if not self._validate_password_policy(new_password):
            raise PasswordPolicyError(
                "New password does not meet complexity requirements: "
                "Minimum 12 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char."
            )

        user = self.users_by_id.get(token_data["user_id"])
        if not user:
            # Should not happen if token was valid, but good to check
            del self.password_reset_tokens[reset_token]
            print(f"AUDIT: User not found for valid reset token '{reset_token}'. This is unexpected.") # Audit Hook Placeholder
            raise UserNotFound("User associated with token not found.")

        user.set_password(new_password)
        # Update user in stores if necessary (depends on how User objects are managed)
        self.users[user.username] = user
        self.users_by_email[user.email] = user

        del self.password_reset_tokens[reset_token] # Invalidate token

        print(f"AUDIT: Password successfully reset for user '{user.username}'.") # Audit Hook Placeholder
        return True

    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        user = self.users_by_id.get(user_id)
        if not user:
            raise UserNotFound(f"User with ID '{user_id}' not found.")

        # Return a dictionary excluding sensitive data
        profile = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "department": user.department,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
            "profile_info": user.profile_info
        }
        print(f"AUDIT: Profile retrieved for user ID '{user_id}'.") # Audit Hook Placeholder
        return profile

    def update_user_profile(
        self,
        user_id: str,
        department: Optional[str] = None,
        is_active: Optional[bool] = None, # Admins might change this
        **profile_kwargs: Any
    ) -> User:
        user = self.users_by_id.get(user_id)
        if not user:
            raise UserNotFound(f"User with ID '{user_id}' not found.")

        updated = False
        if department is not None and user.department != department:
            user.department = department
            updated = True
        
        if profile_kwargs:
            for key, value in profile_kwargs.items():
                # Simple update, could be more sophisticated (e.g. nested dict updates)
                user.profile_info[key] = value
                updated = True
        
        # Example of a restricted field update (is_active)
        # In a real scenario, this might be role-protected
        if is_active is not None and user.is_active != is_active:
            user.is_active = is_active
            updated = True


        if updated:
            user.updated_at = datetime.now(timezone.utc)
            # Re-index if username or email could change (not allowed here for simplicity)
            self.users[user.username] = user # Ensure main user dict is updated
            self.users_by_email[user.email] = user # Ensure email dict is updated

            print(f"AUDIT: Profile updated for user ID '{user_id}'. Changes: department='{department}', profile_kwargs='{profile_kwargs}', is_active='{is_active}'") # Audit Hook Placeholder
        else:
            print(f"AUDIT: Profile update requested for user ID '{user_id}', but no changes were made.")

        return user

# Example Usage (for testing the service directly)
if __name__ == '__main__':
    auth_service = AuthenticationService()

    # Test Password Policy
    print("Testing password policy:")
    valid_pass = "Str0ngP@sswOrd123"
    invalid_pass_short = "Short1!"
    invalid_pass_no_upper = "noupper1!"
    invalid_pass_no_lower = "NOLOWER1!"
    invalid_pass_no_digit = "NoDigitUpper!"
    invalid_pass_no_special = "NoSpecial1Upper"

    print(f"'{valid_pass}' is valid: {auth_service._validate_password_policy(valid_pass)}")
    print(f"'{invalid_pass_short}' is valid: {auth_service._validate_password_policy(invalid_pass_short)}")
    print(f"'{invalid_pass_no_upper}' is valid: {auth_service._validate_password_policy(invalid_pass_no_upper)}")
    print(f"'{invalid_pass_no_lower}' is valid: {auth_service._validate_password_policy(invalid_pass_no_lower)}")
    print(f"'{invalid_pass_no_digit}' is valid: {auth_service._validate_password_policy(invalid_pass_no_digit)}")
    print(f"'{invalid_pass_no_special}' is valid: {auth_service._validate_password_policy(invalid_pass_no_special)}")


    print("\n--- Register User ---")
    try:
        user_jane = auth_service.register_user(
            "jane_doe", "jane.doe@example.com", "ValidPass123!", roles=["Scientist", "Editor"], department="R&D", lab_id="LAB001"
        )
        print(f"Registered: {user_jane.username}, ID: {user_jane.id}")
        user_john = auth_service.register_user(
            "john_smith", "john.smith@example.com", "AnotherGoodPass456#", roles=["ReadOnly"], department="QA"
        )
        print(f"Registered: {user_john.username}, ID: {user_john.id}")
    except (UserAlreadyExistsError, PasswordPolicyError) as e:
        print(f"Error registering user: {e}")

    try:
        auth_service.register_user("jane_doe", "other@example.com", "ValidPass123!")
    except UserAlreadyExistsError as e:
        print(f"Error (expected): {e}")

    try:
        auth_service.register_user("test_user", "jane.doe@example.com", "ValidPass123!")
    except UserAlreadyExistsError as e:
        print(f"Error (expected): {e}")
    
    try:
        auth_service.register_user("weak_pass_user", "weak@example.com", "weak")
    except PasswordPolicyError as e:
        print(f"Error (expected): {e}")


    print("\n--- Login User ---")
    try:
        token = auth_service.login_user("jane_doe", "ValidPass123!")
        print(f"Login successful for jane_doe. Token: {token[:30]}...") # Print part of token
        
        # Test login with email
        token_email_login = auth_service.login_user("john.smith@example.com", "AnotherGoodPass456#")
        print(f"Login successful for john.smith@example.com. Token: {token_email_login[:30]}...")

    except (UserNotFound, AuthenticationError) as e:
        print(f"Login failed: {e}")

    try:
        auth_service.login_user("jane_doe", "wrongpassword")
    except AuthenticationError as e:
        print(f"Login failed (expected): {e}")

    try:
        auth_service.login_user("no_such_user", "some_password")
    except UserNotFound as e:
        print(f"Login failed (expected): {e}")
        
    # Make john_smith inactive and try to login
    if 'john_smith' in auth_service.users:
        auth_service.users['john_smith'].is_active = False
        print(f"\nDeactivated user: {auth_service.users['john_smith'].username}")
        try:
            auth_service.login_user("john_smith", "AnotherGoodPass456#")
        except AuthenticationError as e:
            print(f"Login failed for inactive user (expected): {e}")
        auth_service.users['john_smith'].is_active = True # Reactivate for other tests


    print("\n--- Verify Token ---")
    if 'token' in locals():
        try:
            payload = auth_service.verify_token(token)
            print(f"Token verified. Payload: {payload}")
            user_id_from_token = payload["user_id"]

            # Test expired token
            short_lived_token = jwt.encode(
                {"user_id": user_id_from_token, "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
                JWT_SECRET_KEY,
                algorithm=JWT_ALGORITHM
            )
            try:
                auth_service.verify_token(short_lived_token)
            except InvalidTokenError as e:
                print(f"Token verification failed for expired token (expected): {e}")
            
            # Test invalid signature token
            invalid_signature_token = jwt.encode(
                {"user_id": user_id_from_token, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                "wrong-secret-key",
                algorithm=JWT_ALGORITHM
            )
            try:
                auth_service.verify_token(invalid_signature_token)
            except InvalidTokenError as e:
                print(f"Token verification failed for invalid signature (expected): {e}")

        except InvalidTokenError as e:
            print(f"Token verification failed: {e}")


    print("\n--- Password Reset ---")
    try:
        reset_token_jane = auth_service.request_password_reset("jane.doe@example.com")
        print(f"Password reset token for jane.doe: {reset_token_jane}")

        reset_success = auth_service.reset_password(reset_token_jane, "NewSecureP@ss1")
        print(f"Password reset successful for jane.doe: {reset_success}")

        # Try logging in with new password
        new_token = auth_service.login_user("jane_doe", "NewSecureP@ss1")
        print(f"Login with new password successful for jane_doe. Token: {new_token[:30]}...")

        # Try to use the same reset token again
        try:
            auth_service.reset_password(reset_token_jane, "AnotherNewP@ss2")
        except InvalidTokenError as e:
            print(f"Password reset with used token failed (expected): {e}")
            
        # Test reset with invalid password policy
        reset_token_john = auth_service.request_password_reset("john.smith@example.com")
        try:
            auth_service.reset_password(reset_token_john, "short")
        except PasswordPolicyError as e:
            print(f"Password reset with weak password failed (expected): {e}")


    except (UserNotFound, InvalidTokenError, PasswordPolicyError) as e:
        print(f"Password reset process failed: {e}")


    print("\n--- Get User Profile ---")
    if 'user_id_from_token' in locals():
        try:
            profile = auth_service.get_user_profile(user_id_from_token)
            print(f"Profile for user {user_id_from_token}: {profile}")
        except UserNotFound as e:
            print(f"Error getting profile: {e}")

    print("\n--- Update User Profile ---")
    if 'user_jane' in locals() and user_jane:
        try:
            updated_user = auth_service.update_user_profile(
                user_jane.id,
                department="Advanced R&D",
                location="Building C",
                contact_number="555-0101"
            )
            print(f"Updated user: {updated_user.username}, Department: {updated_user.department}, Profile Info: {updated_user.profile_info}")
            
            # Verify update
            profile_after_update = auth_service.get_user_profile(user_jane.id)
            print(f"Profile after update: {profile_after_update}")

            # Test updating is_active
            auth_service.update_user_profile(user_jane.id, is_active=False)
            print(f"User jane_doe is_active: {auth_service.users_by_id[user_jane.id].is_active}")
            try:
                auth_service.login_user("jane_doe", "NewSecureP@ss1")
            except AuthenticationError as e:
                print(f"Login failed for inactive user jane_doe (expected): {e}")
            auth_service.update_user_profile(user_jane.id, is_active=True) # Set back to active

        except UserNotFound as e:
            print(f"Error updating profile: {e}")
    
    print("\n--- Test Non-existent user operations ---")
    try:
        auth_service.get_user_profile("non_existent_id")
    except UserNotFound as e:
        print(f"Get profile for non-existent user (expected): {e}")
    
    try:
        auth_service.update_user_profile("non_existent_id", department="SomeDept")
    except UserNotFound as e:
        print(f"Update profile for non-existent user (expected): {e}")

    print("\n--- Test request password reset for non-existent user ---")
    # This should not raise an error but return a generic message
    reset_msg_non_existent = auth_service.request_password_reset("nosuchuser@example.com")
    print(f"Password reset request for non-existent email: {reset_msg_non_existent}")

    print("\n--- Testing registration of user with existing username/email (again for sanity) ---")
    try:
        auth_service.register_user(
            "jane_doe", "new_email@example.com", "ValidPass123!", roles=["Tester"]
        )
    except UserAlreadyExistsError as e:
        print(f"Error (expected - username exists): {e}")

    try:
        auth_service.register_user(
            "new_user_name", "jane.doe@example.com", "ValidPass123!", roles=["Tester"]
        )
    except UserAlreadyExistsError as e:
        print(f"Error (expected - email exists): {e}")

    print("\nAuthentication Service tests complete.")
