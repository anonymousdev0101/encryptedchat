import streamlit as st
from datetime import datetime
import requests

# Define a simple user database (for demo purposes)
USER_ACCOUNTS = {
    "admin": "123",
    "user": "123"
}

# GitHub file for saving chat history
GITHUB_REPO_URL = "https://api.github.com/repos/anonymousdev0101/Savedata/contents/data.txt"
GITHUB_TOKEN = "your_github_personal_access_token"  # Replace with your GitHub token

# Helper function to load messages from GitHub
def load_messages():
    try:
        response = requests.get(GITHUB_REPO_URL, headers={"Authorization": f"token {GITHUB_TOKEN}"})
        if response.status_code == 200:
            content = response.json().get("content", "")
            messages = content.encode("utf-8").decode("base64").splitlines()
            return messages
        else:
            st.error("Failed to load messages.")
            return []
    except Exception as e:
        st.error(f"Error loading messages: {e}")
        return []

# Helper function to save a message to GitHub
def save_message(message):
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_message = f"{current_time}: {message}"
        
        # Load existing messages
        existing_messages = load_messages()
        existing_messages.append(new_message)
        updated_content = "\n".join(existing_messages).encode("utf-8").encode("base64")
        
        # Update file on GitHub
        sha = requests.get(GITHUB_REPO_URL, headers={"Authorization": f"token {GITHUB_TOKEN}"}).json()["sha"]
        response = requests.put(
            GITHUB_REPO_URL,
            json={
                "message": "Update chat messages",
                "content": updated_content,
                "sha": sha
            },
            headers={"Authorization": f"token {GITHUB_TOKEN}"}
        )
        if response.status_code == 200:
            st.success("Message saved successfully.")
        else:
            st.error("Failed to save message.")
    except Exception as e:
        st.error(f"Error saving message: {e}")

# Streamlit app
st.title("Encrypted Chat App")

# Login form
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
    # Display chat history
    st.subheader("Chat Room")
    messages = load_messages()
    for message in messages:
        st.write(message)
    
    # Message input
    new_message = st.text_input("Enter your message")
    if st.button("Send"):
        if new_message:
            save_message(f"{st.session_state.username}: {new_message}")
        else:
            st.warning("Message cannot be empty.")

    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.success("Logged out successfully.")
