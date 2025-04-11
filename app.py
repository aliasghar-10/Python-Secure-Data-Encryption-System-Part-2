import streamlit as st
import hashlib
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time

# Security Configuration
ITERATIONS = 100000
SALT = b'salt_123'  # Production में unique salt use करें

# Session State Initialization
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

if 'admin_hash' not in st.session_state:
    st.session_state.admin_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        b'admin123',  # Default admin password
        SALT, 
        ITERATIONS
    )

cipher = Fernet(st.session_state.fernet_key)

# Advanced Hashing Functions
def hash_passkey(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# Encryption/Decryption Functions
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# UI Components
def password_strength(passkey):
    if len(passkey) < 8:
        return "🟥 Weak (Min 8 characters)"
    elif not any(c.isupper() for c in passkey):
        return "🟧 Medium (Add uppercase)"
    elif not any(c.isdigit() for c in passkey):
        return "🟨 Strong (Add numbers)"
    return "🟩 Excellent!"

# Streamlit UI
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="wide")

with st.sidebar:
    st.header("Navigation")
    menu = ["Home", "Store Data", "Retrieve Data", "Admin Login"]
    if st.session_state.failed_attempts >= 3:
        st.error("🔒 Account Locked")
        choice = "Admin Login"
    else:
        choice = st.radio("Menu", menu, label_visibility="collapsed")

# Main Content Area
st.title("🔐 Digital Secure Vault")
st.markdown("---")

if choice == "Home":
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📌 Quick Actions")
        st.button("🚀 Store New Secret", help="Encrypt and save new data")
        st.button("🔍 Retrieve Secret", help="Decrypt existing data")
        
    with col2:
        st.subheader("🔒 Security Status")
        st.success(f"🛡️ Active Encryption: Fernet (AES-128-CBC)")
        st.info(f"🔑 Failed Attempts: {st.session_state.failed_attempts}/3")
        st.progress(st.session_state.failed_attempts/3)

elif choice == "Store Data":
    with st.form("store_form"):
        st.subheader("🔒 Encrypt New Data")
        
        col1, col2 = st.columns(2)
        with col1:
            user_data = st.text_area("Secret Data", height=200, 
                                    placeholder="Enter sensitive information here...")
            
        with col2:
            passkey = st.text_input("Encryption Passphrase", type="password")
            if passkey:
                st.caption(password_strength(passkey))
            st.write("### Security Tips:")
            st.markdown("- Use a mix of uppercase, numbers and symbols\n- Minimum 12 characters recommended\n- Never reuse passwords")

        if st.form_submit_button("🔒 Encrypt & Store", help="Data will be encrypted immediately"):
            if user_data and passkey:
                data_id = str(uuid.uuid4())
                encrypted_text = encrypt_data(user_data)
                hashed_passkey = hash_passkey(passkey)
                
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "timestamp": time.time()
                }
                
                st.success("✅ Data encrypted successfully!")
                st.balloons()
                st.code(f"Data ID: {data_id}", language="plaintext")
                st.warning("❗ Save this ID securely - it cannot be recovered!")
            else:
                st.error("❌ All fields are required!")

elif choice == "Retrieve Data":
    with st.form("retrieve_form"):
        st.subheader("🔓 Decrypt Existing Data")
        
        data_id = st.text_input("Enter Data ID", 
                              placeholder="Paste your Data ID here...")
        passkey = st.text_input("Decryption Passphrase", type="password")
        
        if st.form_submit_button("🔑 Decrypt Now"):
            if data_id and passkey:
                if data_id not in st.session_state.stored_data:
                    st.error("❌ Invalid Data ID")
                else:
                    data_entry = st.session_state.stored_data[data_id]
                    try:
                        if hash_passkey(passkey) == data_entry["passkey"]:
                            decrypted_text = decrypt_data(data_entry["encrypted_text"])
                            st.session_state.failed_attempts = 0
                            
                            with st.expander("Decrypted Content", expanded=True):
                                st.text_area("", decrypted_text, height=200, 
                                           label_visibility="collapsed")
                        else:
                            raise ValueError("Invalid passkey")
                    except:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        if remaining > 0:
                            st.error(f"❌ Access Denied! {remaining} attempts remaining")
                        else:
                            st.session_state.failed_attempts = 3
                            st.rerun()
            else:
                st.error("❌ Both fields are required!")

elif choice == "Admin Login":
    with st.form("admin_form"):
        st.subheader("🛡️ Administrator Override")
        admin_pass = st.text_input("Master Password", type="password")
        
        if st.form_submit_button("⚡ Authenticate"):
            admin_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                admin_pass.encode(), 
                SALT, 
                ITERATIONS
            )
            if admin_hash == st.session_state.admin_hash:
                st.session_state.failed_attempts = 0
                st.success("✅ Authentication Successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("❌ Invalid Master Password")

# Security Footer
st.markdown("---")
footer_cols = st.columns(3)
with footer_cols[0]:
    st.markdown("### 🔒 Encryption\nFernet (AES-128-CBC)")
with footer_cols[1]:
    st.markdown("### 🛡️ Hashing\nPBKDF2-SHA256")
with footer_cols[2]:
    st.markdown("### 🚨 Security\n3 Attempt Lockout")

# Hide Streamlit Defaults
hide_st_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
.st-emotion-cache-1y4p8pa {padding: 2rem 1rem;}
</style>
"""
st.markdown(hide_st_style, unsafe_allow_html=True)