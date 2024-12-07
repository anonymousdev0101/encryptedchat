import streamlit as st
from datetime import datetime
import requests
import base64

# GitHub configuration
GITHUB_REPO_URL = "https://api.github.com/repos/anonymousdev0101/encryptedchat/contents/messages.txt"
GITHUB_TOKEN = "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"  # Replace with your new GitHub token

# User credentials
USER_ACCOUNTS = {
    "admin": "123",
    "user": "123"
}

# Helper function to load messages from GitHub
def load_messages():
    try:
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        response = requests.get(GITHUB_REPO_URL, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            file_content = base64.b64decode(data["content"]).decode("utf-8")  # Decode Base64 content from GitHub
            sha = data["sha"]
            return file_content.splitlines(), sha
        elif response.status_code == 404:
            # If the file doesn't exist yet, return an empty list and no sha
            st.info("File not found, creating new one.")
            return [], None
        elif response.status_code == 401:
            st.error("Unauthorized: Invalid GitHub token or insufficient permissions. Please check token permissions.")
            return [], None
        else:
            st.error(f"Failed to load messages. Status code: {response.status_code}")
            return [], None
    except Exception as e:
        st.error(f"Failed to load messages: {e}")
        return [], None

# Helper function to save a message to GitHub
def save_message(message, sha):
    try:
        # Load the existing messages
        existing_messages, _ = load_messages()
        existing_messages.append(message)  # Add the new message to the list
        updated_content = "\n".join(existing_messages)

        # Convert the content to Base64 encoding for GitHub API
        updated_content_base64 = base64.b64encode(updated_content.encode("utf-8")).decode("utf-8")

        # Prepare data for the GitHub API
        data = {
            "message": "Update chat messages",
            "content": updated_content_base64,
            "sha": sha,  # Ensure you're using the correct sha value for the update
        }
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        response = requests.put(GITHUB_REPO_URL, json=data, headers=headers)

        if response.status_code == 200:
            return True
        elif response.status_code == 401:
            st.error("Unauthorized: Invalid GitHub token or insufficient permissions. Check token and repository permissions.")
            return False
        else:
            st.error(f"Failed to save message to GitHub. Status code: {response.status_code}")
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
