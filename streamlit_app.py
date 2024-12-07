import streamlit as st
from datetime import datetime
import requests

# GitHub configuration
GITHUB_REPO_URL = "https://github.com/anonymousdev0101/encryptedchat/blob/main/messages.txt"
GITHUB_TOKEN = "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"  # Replace with your GitHub token

# User credentials
USER_ACCOUNTS = {
    "admin": "123",
    "user": "123"
}

# Helper function to load messages from GitHub
def load_messages():
    try:
        response = requests.get(GITHUB_REPO_URL, headers={"Authorization": f"token {GITHUB_TOKEN}"})
        if response.status_code == 200:
            file_content = response.json()["content"]
            sha = response.json()["sha"]
            return file_content.splitlines(), sha
        else:
            return [], None
    except Exception as e:
        st.error(f"Failed to load messages: {e}")
        return [], None

# Helper function to save a message to GitHub
def save_message(message, sha):
    try:
        # Add the new message
        existing_messages, _ = load_messages()
        existing_messages.append(message)
        updated_content = "\n".join(existing_messages)

        # Save updated content to GitHub
        data = {
            "message": "Update chat messages",
            "content": updated_content,
            "sha": sha,
        }
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        response = requests.put(GITHUB_REPO_URL, json=data, headers=headers)

        if response.status_code == 200:
            return True
        else:
            st.error("Failed to save message to GitHub.")
            return False
    except Exception as e:
        st.error(f"Error saving message: {e}")
        return False

# Streamlit app starts here
st.title("Encrypted Chat App")

# Login functionality
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in USER_ACCOUNTS and USER_ACCOUNTS[username] == password:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials. Try again.")
else:
    # Chat room
    st.subheader("Chat Room")
    messages, sha = load_messages()

    # Display chat history
    if messages:
        for message in messages:
            st.write(message)

    # Input for new messages
    new_message = st.text_input("Enter your message")
    if st.button("Send"):
        if new_message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_message = f"{timestamp} | {st.session_state.username}: {new_message}"
            if save_message(full_message, sha):
                st.success("Message sent successfully!")
        else:
            st.warning("Message cannot be empty.")

    # Logout
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.success("Logged out successfully.")
