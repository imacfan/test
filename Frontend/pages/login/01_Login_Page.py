import streamlit as st
from Frontend.utils.api_client import api_login # Corrected import path

# --- Page Configuration ---
st.set_page_config(
    page_title="Sun Pharma - Login",
    page_icon="☀️", # Example: Sun icon, or use a path to an image file
    layout="centered"
)

# --- Page Content ---

# 1. Title and Branding
st.markdown("<h1 style='text-align: center;'>Sun Pharma</h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Technical Report Writing Tool Login</h2>", unsafe_allow_html=True)
st.markdown("---") # Visual separator

# Check if user is already logged in
if 'auth_token' in st.session_state and st.session_state.auth_token:
    st.success(f"You are already logged in as **{st.session_state.user_info.get('username', 'user')}**.")
    st.write("Navigate to other pages using the sidebar.")
    if st.button("Logout"):
        del st.session_state.auth_token
        if 'user_info' in st.session_state:
            del st.session_state.user_info
        st.rerun() # Use st.rerun() to refresh the page state after logout
else:
    # 3. Layout: Centered form using st.container()
    with st.container():
        st.markdown("<br>", unsafe_allow_html=True) # Adding some space

        # 4. Form Fields
        with st.form(key="login_form"):
            username_or_email = st.text_input("Username or Email", key="username_email")
            password = st.text_input("Password", type="password", key="password")
            remember_me = st.checkbox("Remember me", key="remember_me") # UI element for now

            # 5. Login Button
            login_button = st.form_submit_button(label="Login")

        # 7. API Interaction
        if login_button:
            if not username_or_email or not password:
                st.error("Please enter both username/email and password.")
            else:
                with st.spinner("Attempting login..."):
                    login_response = api_login(username_or_email, password)

                if login_response and "token" in login_response:
                    st.session_state.auth_token = login_response["token"]
                    # For now, store basic info. A real app might decode JWT for roles, username (if not returned directly)
                    # but decoding JWT on frontend is not best practice. Assume backend provides some user info.
                    # Let's assume the login response also includes some user details or we fetch them.
                    # For this example, we'll just use the username_or_email if it's not an email.
                    st.session_state.user_info = {
                        "username": username_or_email.split('@')[0] if '@' not in username_or_email else "User", # Simplified
                        "token_details": login_response # Store the whole response if needed for other info
                    }
                    st.success("Login Successful!")
                    st.balloons()
                    # Consider st.switch_page("pages/02_Dashboard.py") or similar for actual navigation
                    # For now, just rerun to show the "already logged in" message
                    st.rerun()
                elif login_response and "error" in login_response:
                    status_code = login_response.get("status_code")
                    error_msg = login_response.get("error", "An unknown error occurred.")
                    if status_code == 401:
                         st.error(f"Login Failed: Invalid username or password.")
                    elif status_code == 503 or status_code == 408:
                         st.error(error_msg) # Use the message from api_client
                    else:
                         st.error(f"Login Failed: {error_msg}")
                else:
                    st.error("Login Failed: An unexpected error occurred. Please try again.")

    st.markdown("---") # Visual separator
    # 6. Password Recovery Link
    # This could navigate to another Streamlit page or show a modal/form section.
    # For now, a placeholder link.
    st.markdown("<div style='text-align: center;'>[Forgot Password?](#)</div>", unsafe_allow_html=True)
    # Or, to link to another page (if it exists):
    # st.page_link("pages/password_recovery/02_Password_Recovery.py", label="Forgot Password?")

# Simple footer (optional)
st.markdown("<br><br><hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: small;'>© Sun Pharmaceutical Industries Ltd.</p>", unsafe_allow_html=True)
