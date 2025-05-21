import requests
import streamlit as st

# Ensure this is created at the root of the Frontend directory,
# so it can be imported as `from utils.api_client import api_login`
# from `Frontend.pages.login.01_Login_Page.py`
BACKEND_URL = "http://localhost:5000/auth" # Assuming backend runs on port 5000

def api_login(username_or_email, password):
    try:
        response = requests.post(
            f"{BACKEND_URL}/login",
            json={"username_or_email": username_or_email, "password": password},
            timeout=10 # Adding a timeout for robustness
        )
        response.raise_for_status() # Raises an HTTPError for bad responses (4XX or 5XX)
        return response.json() # Should contain the token
    except requests.exceptions.HTTPError as http_err:
        error_message = "Login failed."
        try:
            # Try to parse JSON error from response
            error_data = http_err.response.json()
            error_message = error_data.get("error", f"HTTP error: {http_err.response.status_code}")
        except ValueError:
            # If response is not JSON, use the text part of the response
            error_message = http_err.response.text if http_err.response.text else f"HTTP error: {http_err.response.status_code}"
        # st.error(error_message) # Let the caller page handle UI updates
        return {"error": error_message, "status_code": http_err.response.status_code if http_err.response is not None else 500}
    except requests.exceptions.ConnectionError as conn_err:
        # st.error(f"Connection error: Could not connect to the server at {BACKEND_URL}. Please ensure the backend is running.")
        return {"error": f"Connection error: Could not connect to the server. Please check your connection or contact support.", "status_code": 503}
    except requests.exceptions.Timeout as timeout_err:
        # st.error("Login request timed out. Please try again.")
        return {"error": "Login request timed out. Please try again.", "status_code": 408}
    except requests.exceptions.RequestException as req_err:
        # st.error(f"Login request failed: {req_err}")
        return {"error": f"An unexpected error occurred during the login request: {req_err}", "status_code": 500}
    except Exception as ex: # Catch any other unexpected errors during the request or JSON parsing
        # st.error(f"An unexpected error occurred: {ex}")
        return {"error": f"An unexpected error occurred: {ex}", "status_code": 500}

# Add other API client functions here later (e.g., for password reset)

# Example test (not part of the module typically, but for quick verification)
if __name__ == '__main__':
    # This part will not run when imported by Streamlit
    # You would need to run this script directly and have a backend running
    # print("Testing api_login (ensure backend is running on http://localhost:5000)...")
    
    # # Test successful login (replace with actual test user from your backend)
    # # Assuming you registered a user 'testuser' with password 'Test@1234'
    # # result = api_login("testuser", "Test@1234")
    # # if "token" in result:
    # #     print(f"Login successful. Token: {result['token']}")
    # # else:
    # #     print(f"Login failed. Error: {result.get('error')}")

    # # Test failed login (wrong password)
    # result_fail = api_login("testuser", "wrongpassword")
    # if "error" in result_fail:
    #     print(f"Login failed as expected. Error: {result_fail.get('error')}, Status: {result_fail.get('status_code')}")
    # else:
    #     print(f"Login succeeded unexpectedly: {result_fail}")

    # Test non-existent user
    # result_no_user = api_login("nouser", "somepassword")
    # if "error" in result_no_user:
    #      print(f"Login failed for non-existent user as expected. Error: {result_no_user.get('error')}, Status: {result_no_user.get('status_code')}")
    # else:
    #      print(f"Login succeeded unexpectedly for non-existent user: {result_no_user}")
    pass

def api_request_password_reset(email: str):
    try:
        response = requests.post(
            f"{BACKEND_URL}/password-reset-request",
            json={"email": email},
            timeout=10
        )
        response.raise_for_status()
        # The backend currently returns a generic message OR the token for simulation.
        # For a real app, it should always return a generic message.
        # For this assignment, the backend returns the token if the user exists.
        # The API client will pass this through.
        api_response_data = response.json()
        message = api_response_data.get("message", "Password reset request processed.")

        # If the backend sends back the token in the response (as per current auth_service simulation for existing users)
        if "token" in api_response_data: # This is specific to the simulated environment
             return {"success": True, "message": message, "simulated_token": api_response_data["token"]}
        
        # If the backend sends back the actual message (e.g. "If an account with that email exists...")
        return {"success": True, "message": message}

    except requests.exceptions.HTTPError as http_err:
        error_message = "Password reset request failed."
        try:
            error_data = http_err.response.json()
            error_message = error_data.get("error", f"HTTP error: {http_err.response.status_code}")
        except ValueError:
            error_message = http_err.response.text if http_err.response.text else f"HTTP error: {http_err.response.status_code}"
        return {"error": error_message, "status_code": http_err.response.status_code if http_err.response is not None else 500}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error: Could not connect to the server.", "status_code": 503}
    except requests.exceptions.Timeout:
        return {"error": "Password reset request timed out.", "status_code": 408}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"An unexpected error occurred: {req_err}", "status_code": 500}
    except Exception as ex:
        return {"error": f"An unexpected error occurred: {ex}", "status_code": 500}

def api_reset_password(reset_token: str, new_password: str):
    try:
        response = requests.post(
            f"{BACKEND_URL}/password-reset",
            json={"reset_token": reset_token, "new_password": new_password},
            timeout=10
        )
        response.raise_for_status()
        return {"success": True, "message": response.json().get("message", "Password has been reset successfully!")}
    except requests.exceptions.HTTPError as http_err:
        error_message = "Password reset failed."
        try:
            error_data = http_err.response.json()
            # Backend might return specific errors in "error" or "details"
            if "details" in error_data: # PasswordPolicyError from backend
                 error_message = error_data.get("details")
            else:
                 error_message = error_data.get("error", f"HTTP error: {http_err.response.status_code}")

        except ValueError:
            error_message = http_err.response.text if http_err.response.text else f"HTTP error: {http_err.response.status_code}"
        return {"error": error_message, "status_code": http_err.response.status_code if http_err.response is not None else 500}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error: Could not connect to the server.", "status_code": 503}
    except requests.exceptions.Timeout:
        return {"error": "Password reset timed out.", "status_code": 408}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"An unexpected error occurred: {req_err}", "status_code": 500}
    except Exception as ex:
        return {"error": f"An unexpected error occurred: {ex}", "status_code": 500}
