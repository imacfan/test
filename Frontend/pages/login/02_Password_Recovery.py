import streamlit as st
from Frontend.utils.api_client import api_request_password_reset, api_reset_password

# --- Page Configuration ---
st.set_page_config(
    page_title="Password Recovery - Sun Pharma",
    page_icon="☀️",
    layout="centered"
)

# --- Initialize Session State ---
if 'reset_step' not in st.session_state:
    st.session_state.reset_step = "request_token"
if 'reset_token_from_simulated_email' not in st.session_state:
    st.session_state.reset_token_from_simulated_email = ""

# --- Page Content ---
st.markdown("<h1 style='text-align: center;'>Sun Pharma</h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Password Recovery</h2>", unsafe_allow_html=True)
st.markdown("---")

# --- Step 1: Request Password Reset Token ---
if st.session_state.reset_step == "request_token":
    st.subheader("Request Password Reset")
    with st.form(key="request_reset_form"):
        email = st.text_input("Enter your account email", key="reset_email")
        submit_request_button = st.form_submit_button(label="Send Reset Link")

    if submit_request_button:
        if not email:
            st.error("Please enter your email address.")
        else:
            with st.spinner("Requesting password reset..."):
                response = api_request_password_reset(email)
            
            if response and response.get("success"):
                st.success(response.get("message", "Password reset email sent (simulated). Please check your inbox for the reset token."))
                # IMPORTANT: For simulation, we store the token. In a real app, user gets it from email.
                if "simulated_token" in response: # Token is returned by backend for existing user in current simulation
                    st.session_state.reset_token_from_simulated_email = response["simulated_token"]
                    st.info(f"For simulation purposes, your reset token is: {response['simulated_token']}. In a real application, you would receive this via email.")
                
                st.session_state.reset_step = "submit_new_password"
                st.rerun()
            elif response and response.get("error"):
                st.error(f"Failed to request password reset: {response.get('error')}")
            else:
                st.error("An unexpected error occurred while requesting password reset.")

# --- Step 2: Submit New Password ---
elif st.session_state.reset_step == "submit_new_password":
    st.subheader("Reset Your Password")
    
    # Retrieve the simulated token if available
    simulated_token_value = st.session_state.get('reset_token_from_simulated_email', '')

    with st.form(key="reset_password_form"):
        reset_token = st.text_input(
            "Enter the reset token received", 
            value=simulated_token_value, 
            key="reset_token_input",
            help="This is pre-filled for simulation if a token was generated in the previous step."
        )
        new_password = st.text_input("Enter new password", type="password", key="new_password")
        confirm_new_password = st.text_input("Confirm new password", type="password", key="confirm_new_password")
        
        submit_password_button = st.form_submit_button(label="Reset Password")

    if submit_password_button:
        if not reset_token or not new_password or not confirm_new_password:
            st.error("Please fill in all fields.")
        elif new_password != confirm_new_password:
            st.error("New passwords do not match.")
        else:
            with st.spinner("Resetting password..."):
                response = api_reset_password(reset_token, new_password)
            
            if response and response.get("success"):
                st.success(response.get("message", "Password has been reset successfully!"))
                st.balloons()
                # Clear session state related to password reset
                if 'reset_step' in st.session_state:
                    del st.session_state.reset_step
                if 'reset_token_from_simulated_email' in st.session_state:
                    del st.session_state.reset_token_from_simulated_email
                
                st.info("You can now login with your new password.")
                # Provide a clear way back to login
                if st.button("Go to Login Page"):
                    st.switch_page("pages/login/01_Login_Page.py") # Preferred way to navigate
                st.session_state.reset_step = "completed" # Mark as completed to prevent re-run issues
                st.rerun() # Rerun to clear the form and show the login button
            elif response and response.get("error"):
                st.error(f"Failed to reset password: {response.get('error')}")
            else:
                st.error("An unexpected error occurred while resetting the password.")

elif st.session_state.reset_step == "completed":
    st.success("Password reset process completed.")
    st.markdown("You can now attempt to log in with your new password.")
    if st.button("Go to Login Page"):
        st.switch_page("pages/login/01_Login_Page.py")


# --- Navigation ---
st.markdown("---")
st.page_link("pages/login/01_Login_Page.py", label="Back to Login")

# Simple footer (optional)
st.markdown("<br><br><hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: small;'>© Sun Pharmaceutical Industries Ltd.</p>", unsafe_allow_html=True)
