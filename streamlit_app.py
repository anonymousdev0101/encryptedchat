import streamlit as st
from datetime import datetime
import requests

# GitHub configuration
GITHUB_REPO_URL = "https://api.github.com/repos/anonymousdev0101/encryptedchat/contents/messages.txt"
GITHUB_TOKEN = "your_github_personal_access_token"  # Replace with your GitHub token

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
            content = response.json().get("content", "")
            messages = content.encode("utf-8").decode("base64").splitlines()
            return messages
        else:
            return []
    except Exception as e:
        st.error(f"Failed to load messages: {e}")
        return []

# Helper function to save a message to GitHub
def save_message(message):
    try:
        # Load existing messages
        response = requests.get(GITHUB_REPO_URL, headers={"Authorization": f"token {GITHUB_TOKEN}"})
        if response.status_code == 200:
            existing_content = response.json().get("content", "")
            sha = response.json()["sha"]
            existing_messages = existing_content.encode("utf-8").decode("base64").splitlines()
        else:
            existing_messages = []
            sha = None

        # Append the new message
        existing_messages.append(message)
        updated_content = "\n".join(existing_messages).encode("utf-8").encode("base64")

        # Save updated content to GitHub
        data = {
            "message": "Update chat messages",
            "content": updated_content,
        }
        if sha:
            data["sha"] = sha
        save_response = requests.put(GITHUB_REPO_URL, json=data, headers={"Authorization": f"token {GITHUB_TOKEN}"})

        if save_response.status_code == 200:
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
    messages = load_messages()

    # Display chat history
    for message in messages:
        st.write(message)

    # Input for new messages
    new_message = st.text_input("Enter your message")
    if st.button("Send"):
        if new_message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_message = f"{timestamp} | {st.session_state.username}: {new_message}"
            if save_message(full_message):
                st.success("Message sent successfully!")
        else:
            st.warning("Message cannot be empty.")

    # Logout
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.success("Logged out successfully.")
