import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from werkzeug.security import generate_password_hash, check_password_hash

class User:
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        roles: List[str],
        department: Optional[str] = None,
        is_active: bool = True,
        profile_info: Optional[Dict[str, Any]] = None,
    ):
        self.id = uuid.uuid4()  # Using UUID for primary key
        self.username = username
        self.email = email
        self.hashed_password = self.set_password(password)
        self.roles = roles
        self.department = department
        self.is_active = is_active
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.profile_info = profile_info if profile_info else {}

    def set_password(self, password: str) -> str:
        """Hashes the provided password and stores it."""
        self.hashed_password = generate_password_hash(password)
        self.updated_at = datetime.utcnow()
        return self.hashed_password

    def check_password(self, password: str) -> bool:
        """Verifies the provided password against the stored hash."""
        return check_password_hash(self.hashed_password, password)

    def __repr__(self):
        return f"<User {self.username}>"

if __name__ == '__main__':
    # Example Usage (Optional: for testing the model directly)
    user1 = User(
        username="admin_user",
        email="admin@example.com",
        password="securepassword123",
        roles=["Administrator"],
        department="IT",
        profile_info={"authorized_report_types": ["TypeA", "TypeB"]}
    )
    print(f"User ID: {user1.id}")
    print(f"Username: {user1.username}")
    print(f"Email: {user1.email}")
    print(f"Roles: {user1.roles}")
    print(f"Department: {user1.department}")
    print(f"Is Active: {user1.is_active}")
    print(f"Created At: {user1.created_at}")
    print(f"Updated At: {user1.updated_at}")
    print(f"Profile Info: {user1.profile_info}")
    print(f"Password matches 'securepassword123': {user1.check_password('securepassword123')}")
    print(f"Password matches 'wrongpassword': {user1.check_password('wrongpassword')}")

    user1.set_password("newpassword456")
    print(f"Password matches 'newpassword456' after reset: {user1.check_password('newpassword456')}")
    print(f"Updated At after password reset: {user1.updated_at}")

    # Example of a ReadOnly user
    user2 = User(
        username="readonly_user",
        email="readonly@example.com",
        password="readonlypassword",
        roles=["ReadOnly"],
        is_active=True
    )
    print(f"\nUser 2 Username: {user2.username}")
    print(f"User 2 Roles: {user2.roles}")
    print(f"User 2 Department: {user2.department}") # Should be None
    print(f"User 2 Profile Info: {user2.profile_info}") # Should be {}
