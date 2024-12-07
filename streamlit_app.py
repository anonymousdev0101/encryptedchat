import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import requests
from github import Github

# Function to hash passwords
def hash_password(password):
    salt = b"some_random_salt"  # Use a unique salt for each user in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())  # Derive the password hash
    return base64.b64encode(hashed_password).decode('utf-8')  # Return base64 encoded hash

# Function to verify if entered password matches the stored hash
def verify_password(stored_hash, password):
    decoded_hash = base64.b64decode(stored_hash.encode('utf-8'))
    salt = b"some_random_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(decoded_hash, password.encode())
        return True
    except Exception:
        return False

# Dummy user data (hashed password for security)
USER_ACCOUNTS = {
    'admin': hash_password('123'),
    'user': hash_password('123')
}

# Function to encrypt the message
def encrypt_message(message, key="secretkey"):
    # Simple encryption method using a XOR-based scheme
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(message))
    return encrypted

# Function to decrypt the message
def decrypt_message(encrypted_message, key="secretkey"):
    decrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted_message))
    return decrypted

# Streamlit Interface
def main():
    st.title("Encrypted Chat App")
    st.write("Welcome! Please log in to access the chat.")

    # Login form
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        login_button = st.form_submit_button("Login")

    # If login is successful
    if login_button:
        if username in USER_ACCOUNTS and verify_password(USER_ACCOUNTS[username], password):
            st.success("Login successful!")
            chat_interface(username)
        else:
            st.error("Invalid credentials. Try again.")

# Chat Interface for logged-in users
def chat_interface(username):
    st.write(f"Hello, {username}!")
    
    # Display old messages
    display_messages()

    # Input area for new messages
    message = st.text_input("Type a message")

    if st.button("Send Message"):
        if message:
            encrypted_message = encrypt_message(message)
            save_message_to_github(username, encrypted_message)
            st.success("Message sent!")
        else:
            st.error("Please enter a message.")

# Function to display old messages from GitHub
def display_messages():
    # Use GitHub API to fetch messages from a file
    try:
        g = Github("your_github_token")  # Replace with your GitHub token
        repo = g.get_user().get_repo('Savedata')  # Replace with your repository
        file_content = repo.get_contents("messages.txt")
        messages = file_content.decoded_content.decode("utf-8").splitlines()

        for msg in messages:
            decrypted_msg = decrypt_message(msg)
            st.write(decrypted_msg)
    except Exception as e:
        st.error(f"Error retrieving messages: {e}")

# Function to save the encrypted message to GitHub
def save_message_to_github(username, encrypted_message):
    try:
        g = Github("your_github_token")  # Replace with your GitHub token
        repo = g.get_user().get_repo('Savedata')  # Replace with your repository
        file_content = repo.get_contents("messages.txt")
        existing_messages = file_content.decoded_content.decode("utf-8")

        # Append new encrypted message
        updated_messages = existing_messages + "\n" + encrypted_message

        # Update the file on GitHub
        repo.update_file("messages.txt", "Updating messages", updated_messages, file_content.sha)
    except Exception as e:
        st.error(f"Error saving message: {e}")

if __name__ == "__main__":
    main()
