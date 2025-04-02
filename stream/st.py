import streamlit as st
import os
import base64
import json
import hashlib
import time
import random
import string
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import re
import uuid
from datetime import datetime
import heapq
import pickle
from io import BytesIO

# Initialize session state if not exists
if 'user_data' not in st.session_state:
    st.session_state.user_data = {
        'users': {
            'admin': {
                'password': hashlib.sha256('admin123'.encode()).hexdigest(),
                'role': 'admin',
                'score': 100
            },
            'user1': {
                'password': hashlib.sha256('user123'.encode()).hexdigest(),
                'role': 'user',
                'score': 50
            }
        }
    }

if 'files' not in st.session_state:
    st.session_state.files = {}

if 'merkle_trees' not in st.session_state:
    st.session_state.merkle_trees = {}

if 'access_logs' not in st.session_state:
    st.session_state.access_logs = []

if 'random_pool' not in st.session_state:
    st.session_state.random_pool = []

if 'logged_in_user' not in st.session_state:
    st.session_state.logged_in_user = None

if 'current_page' not in st.session_state:
    st.session_state.current_page = 'login'

# Download necessary NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

# -------------- Utilities --------------

def generate_random_bytes(length=32):
    """Generate random bytes for cryptographic purposes."""
    if len(st.session_state.random_pool) >= length:
        # Use collected randomness
        random_data = ''.join(st.session_state.random_pool[:length])
        st.session_state.random_pool = st.session_state.random_pool[length:]
    else:
        # Fallback to system randomness
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    return hashlib.sha256(random_data.encode()).digest()

def simulate_quantum_key_generation(key_size=256):
    """Simulate quantum computing key generation."""
    # Simulate qubits
    qubits = []
    for _ in range(key_size):
        # Simulate superposition and measurement
        qubit = random.choice([0, 1])
        qubits.append(qubit)
    
    # Convert binary to bytes
    binary_string = ''.join(map(str, qubits))
    key_bytes = int(binary_string, 2).to_bytes((len(binary_string) + 7) // 8, byteorder='big')
    
    # Hash for uniform distribution
    return hashlib.sha256(key_bytes).digest()

def collect_randomness(event_data):
    """Collect random data from user events."""
    # In a real app, this would be from mouse movements, timings, etc.
    # Here we simulate by adding the event data to the pool
    st.session_state.random_pool.append(str(event_data) + str(time.time()))
    if len(st.session_state.random_pool) > 1000:
        st.session_state.random_pool = st.session_state.random_pool[-1000:]

# -------------- Encryption Framework --------------

class EncryptionFramework:
    @staticmethod
    def analyze_file(file_data, filename):
        """Analyze file to determine best encryption method."""
        file_size = len(file_data)
        file_extension = os.path.splitext(filename)[1].lower()
        
        # Simple AI decision logic based on file characteristics
        if file_size < 1024 * 1024:  # Less than 1MB
            if file_extension in ['.txt', '.csv', '.json']:
                return 'AES-256-GCM'  # For small text files
            else:
                return 'AES-256-CBC'  # For small binary files
        elif file_size < 10 * 1024 * 1024:  # Less than 10MB
            return 'ChaCha20-Poly1305'  # For medium-sized files
        else:
            return 'Kyber-768'  # For large files, use quantum-resistant encryption
    
    @staticmethod
    def encrypt_file(file_data, method, user):
        """Encrypt file using the specified method."""
        # Generate key using collected randomness or quantum simulation
        if random.random() < 0.5:  # 50% chance to use quantum simulation
            key = simulate_quantum_key_generation()
        else:
            key = generate_random_bytes()
            
        iv = os.urandom(16)  # Initialization vector
        
        if method == 'AES-256-GCM':
            # AES in GCM mode (provides authentication)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            tag = encryptor.tag
            metadata = {'iv': base64.b64encode(iv).decode(), 'tag': base64.b64encode(tag).decode()}
            
        elif method == 'AES-256-CBC':
            # AES in CBC mode with HMAC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = file_data + b'\0' * (16 - len(file_data) % 16)  # Simple padding
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Add HMAC for authentication
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_data)
            tag = h.finalize()
            metadata = {'iv': base64.b64encode(iv).decode(), 'tag': base64.b64encode(tag).decode()}
            
        elif method == 'ChaCha20-Poly1305':
            # Since we're using cryptography library, simulate ChaCha20
            cipher = Cipher(algorithms.ChaCha20(key, iv[:12]), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            
            # Simulate Poly1305 with HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_data)
            tag = h.finalize()
            metadata = {'nonce': base64.b64encode(iv[:12]).decode(), 'tag': base64.b64encode(tag).decode()}
            
        elif method == 'Kyber-768':
            # Simulate Kyber (a lattice-based post-quantum algorithm)
            # In reality, we'd use a proper implementation of Kyber
            # Here we simulate with RSA + AES for hybrid encryption
            
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Encrypt file with AES
            aes_key = generate_random_bytes()
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            tag = encryptor.tag
            
            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Store private key (in a real system, this would be securely shared with authorized users)
            # For simulation, we just store it
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            metadata = {
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(tag).decode(),
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'private_key': base64.b64encode(private_key_pem).decode()
            }
        
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'encryption_method': method,
            'key': base64.b64encode(key).decode(),
            'metadata': metadata,
            'encrypted_by': user,
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def decrypt_file(encrypted_file_info, authorized=True):
        """Decrypt file using stored encryption info."""
        if not authorized:
            return None, "Access denied"
        
        try:
            encrypted_data = base64.b64decode(encrypted_file_info['encrypted_data'])
            key = base64.b64decode(encrypted_file_info['key'])
            method = encrypted_file_info['encryption_method']
            metadata = encrypted_file_info['metadata']
            
            if method == 'AES-256-GCM':
                iv = base64.b64decode(metadata['iv'])
                tag = base64.b64decode(metadata['tag'])
                
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                
            elif method == 'AES-256-CBC':
                iv = base64.b64decode(metadata['iv'])
                stored_tag = base64.b64decode(metadata['tag'])
                
                # Verify HMAC first
                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                h.update(encrypted_data)
                try:
                    h.verify(stored_tag)
                except Exception:
                    return None, "File integrity check failed"
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Remove padding
                decrypted_data = padded_data.rstrip(b'\0')
                
            elif method == 'ChaCha20-Poly1305':
                nonce = base64.b64decode(metadata['nonce'])
                stored_tag = base64.b64decode(metadata['tag'])
                
                # Verify HMAC first
                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                h.update(encrypted_data)
                try:
                    h.verify(stored_tag)
                except Exception:
                    return None, "File integrity check failed"
                
                cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                
            elif method == 'Kyber-768':
                # In our simulation, we're using RSA+AES
                iv = base64.b64decode(metadata['iv'])
                tag = base64.b64decode(metadata['tag'])
                encrypted_key = base64.b64decode(metadata['encrypted_key'])
                private_key_pem = base64.b64decode(metadata['private_key'])
                
                # Load private key
                private_key = serialization.load_pem_private_key(
                    private_key_pem,
                    password=None,
                    backend=default_backend()
                )
                
                # Decrypt AES key
                aes_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt file with AES
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            return decrypted_data, "Decryption successful"
        
        except Exception as e:
            return None, f"Decryption failed: {str(e)}"

# -------------- Merkle Tree Implementation --------------

class MerkleTree:
    def __init__(self, data_blocks=None):
        self.leaves = []
        self.nodes = []
        if data_blocks:
            self.build_tree(data_blocks)
    
    def build_tree(self, data_blocks):
        """Build a Merkle tree from data blocks."""
        # Create leaf nodes
        self.leaves = [hashlib.sha256(block.encode() if isinstance(block, str) else block).hexdigest() for block in data_blocks]
        
        # Build the tree
        self.nodes = self.leaves.copy()
        while len(self.nodes) > 1:
            level = []
            # Process pairs
            for i in range(0, len(self.nodes), 2):
                if i + 1 < len(self.nodes):
                    combined = self.nodes[i] + self.nodes[i+1]
                else:
                    # Odd node, duplicate it
                    combined = self.nodes[i] + self.nodes[i]
                level.append(hashlib.sha256(combined.encode()).hexdigest())
            self.nodes = level
    
    def get_root(self):
        """Get the Merkle root."""
        if not self.nodes:
            return None
        return self.nodes[0]
    
    def verify_block(self, block_index, block_data, proof):
        """Verify a block is in the tree."""
        # Calculate hash of the block
        block_hash = hashlib.sha256(block_data.encode() if isinstance(block_data, str) else block_data).hexdigest()
        
        # Verify against the proof
        current_hash = block_hash
        for sibling_hash, is_left in proof:
            if is_left:
                current_hash = hashlib.sha256((sibling_hash + current_hash).encode()).hexdigest()
            else:
                current_hash = hashlib.sha256((current_hash + sibling_hash).encode()).hexdigest()
        
        return current_hash == self.get_root()
    
    def generate_proof(self, block_index):
        """Generate a proof for a specific block."""
        if block_index >= len(self.leaves):
            return None
        
        proof = []
        idx = block_index
        level_size = len(self.leaves)
        level_offset = 0
        
        while level_size > 1:
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            
            if sibling_idx < level_size:
                sibling_hash = self.leaves[level_offset + sibling_idx]
                proof.append((sibling_hash, idx % 2 == 1))
            
            # Move to parent level
            idx = idx // 2
            level_offset += level_size
            level_size = (level_size + 1) // 2
        
        return proof

# -------------- NLP Permissions System --------------

class NLPPermissions:
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
    
    def process_command(self, command, current_user, target_file=None):
        """Process natural language command for permissions."""
        # Tokenize and clean command
        tokens = word_tokenize(command.lower())
        tokens = [word for word in tokens if word.isalpha() and word not in self.stop_words]
        
        # Extract action and subjects
        action = None
        users = []
        permissions = []
        
        # Keywords for actions
        grant_keywords = ['grant', 'give', 'allow', 'share', 'let']
        revoke_keywords = ['revoke', 'remove', 'deny', 'stop', 'prevent']
        view_keywords = ['view', 'see', 'read', 'access']
        edit_keywords = ['edit', 'modify', 'change', 'write', 'update']
        
        # Identify action
        for word in tokens:
            if word in grant_keywords:
                action = 'grant'
            elif word in revoke_keywords:
                action = 'revoke'
        
        # Extract users and permissions
        for i, word in enumerate(tokens):
            # Look for usernames (simplified for demo)
            if word in st.session_state.user_data['users'] and word not in users:
                users.append(word)
            
            # Look for permission types
            if word in view_keywords or (i > 0 and tokens[i-1] in view_keywords):
                permissions.append('read')
            if word in edit_keywords or (i > 0 and tokens[i-1] in edit_keywords):
                permissions.append('write')
        
        # If no specific permissions mentioned, assume both read and write
        if not permissions and action:
            permissions = ['read', 'write']
        
        # Return structured command
        return {
            'action': action,
            'users': users,
            'permissions': list(set(permissions)),  # Remove duplicates
            'file': target_file,
            'status': 'valid' if action and users else 'invalid',
            'current_user': current_user
        }
    
    def execute_permission_command(self, command_info):
        """Execute the parsed permission command."""
        if command_info['status'] == 'invalid':
            return False, "Invalid command. Please specify action and users."
        
        if not command_info['file'] or command_info['file'] not in st.session_state.files:
            return False, "File not found."
        
        # Check if current user has permission to modify file permissions
        file_info = st.session_state.files[command_info['file']]
        if command_info['current_user'] != file_info['owner'] and command_info['current_user'] != 'admin':
            return False, "You don't have permission to modify access rights for this file."
        
        # Process permissions
        for user in command_info['users']:
            if user not in st.session_state.user_data['users']:
                continue
                
            if 'permissions' not in file_info:
                file_info['permissions'] = {}
                
            if command_info['action'] == 'grant':
                if user not in file_info['permissions']:
                    file_info['permissions'][user] = []
                    
                for perm in command_info['permissions']:
                    if perm not in file_info['permissions'][user]:
                        file_info['permissions'][user].append(perm)
                        
            elif command_info['action'] == 'revoke':
                if user in file_info['permissions']:
                    for perm in command_info['permissions']:
                        if perm in file_info['permissions'][user]:
                            file_info['permissions'][user].remove(perm)
                    
                    # If no permissions left, remove user from permissions
                    if not file_info['permissions'][user]:
                        del file_info['permissions'][user]
        
        # Update file info
        st.session_state.files[command_info['file']] = file_info
        
        return True, f"Permission {command_info['action']}ed successfully."

# -------------- User Scoring System --------------

class UserScoring:
    @staticmethod
    def update_user_score(username, action_type, file_info=None):
        """Update user score based on their actions."""
        if username not in st.session_state.user_data['users']:
            return
        
        user = st.session_state.user_data['users'][username]
        
        # Base points for different actions
        points = 0
        
        if action_type == 'upload':
            points = 10
        elif action_type == 'download':
            points = 2
        elif action_type == 'share':
            points = 5
        elif action_type == 'grant_permission':
            points = 3
        elif action_type == 'revoke_permission':
            points = 1
        elif action_type == 'delete':
            points = -2
        
        # Adjust based on file characteristics if available
        if file_info:
            # Larger files get more points
            file_size = len(base64.b64decode(file_info['encrypted_data']))
            size_factor = min(file_size / (1024 * 1024), 5)  # Cap at 5MB for scoring
            points *= (1 + 0.1 * size_factor)
            
            # More secure encryption methods get more points
            if file_info['encryption_method'] == 'Kyber-768':
                points *= 1.5
            elif file_info['encryption_method'] == 'ChaCha20-Poly1305':
                points *= 1.3
            elif file_info['encryption_method'] == 'AES-256-GCM':
                points *= 1.2
        
        # Update score
        user['score'] = max(0, user['score'] + points)

# -------------- UI Components --------------

def render_login_page():
    """Render the login page."""
    st.title("Secure File Management System")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if username in st.session_state.user_data['users']:
                stored_hash = st.session_state.user_data['users'][username]['password']
                input_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if input_hash == stored_hash:
                    st.session_state.logged_in_user = username
                    st.session_state.current_page = 'dashboard'
                    st.experimental_rerun()
                else:
                    st.error("Invalid password")
            else:
                st.error("User not found")
    
    with col2:
        st.subheader("Register")
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.button("Register"):
            if new_username in st.session_state.user_data['users']:
                st.error("Username already exists")
            elif new_password != confirm_password:
                st.error("Passwords don't match")
            else:
                st.session_state.user_data['users'][new_username] = {
                    'password': hashlib.sha256(new_password.encode()).hexdigest(),
                    'role': 'user',
                    'score': 0
                }
                st.success("Registration successful! You can now log in.")

def render_navigation():
    """Render navigation menu."""
    cols = st.columns([1, 1, 1, 1, 1])
    
    with cols[0]:
        if st.button("Dashboard"):
            st.session_state.current_page = 'dashboard'
            st.experimental_rerun()
    
    with cols[1]:
        if st.button("Upload File"):
            st.session_state.current_page = 'upload'
            st.experimental_rerun()
    
    with cols[2]:
        if st.button("My Files"):
            st.session_state.current_page = 'files'
            st.experimental_rerun()
    
    with cols[3]:
        if st.button("Analytics"):
            st.session_state.current_page = 'analytics'
            st.experimental_rerun()
    
    with cols[4]:
        if st.button("Logout"):
            st.session_state.logged_in_user = None
            st.session_state.current_page = 'login'
            st.experimental_rerun()

def render_dashboard():
    """Render the main dashboard."""
    st.title("Secure File Management Dashboard")
    st.subheader(f"Welcome, {st.session_state.logged_in_user}!")
    
    render_navigation()
    
    # Show user stats
    user = st.session_state.user_data['users'][st.session_state.logged_in_user]
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.metric("User Score", f"{user['score']:.1f} points")
        
        # Show owned files count
        owned_files = sum(1 for file_info in st.session_state.files.values() 
                         if file_info['owner'] == st.session_state.logged_in_user)
        st.metric("Files Owned", owned_files)
    
    with col2:
        st.metric("User Role", user['role'].capitalize())
        
        # Show accessible files count
        accessible_files = sum(1 for file_name, file_info in st.session_state.files.items() 
                             if has_access(st.session_state.logged_in_user, file_name))
        st.metric("Accessible Files", accessible_files)
    
    # Recent Activity
    st.subheader("Recent Activity")
    
    user_logs = [log for log in st.session_state.access_logs if log['user'] == st.session_state.logged_in_user]
    if user_logs:
        recent_logs = sorted(user_logs, key=lambda x: x['timestamp'], reverse=True)[:5]
        
        for log in recent_logs:
            action_color = "blue" if log['action'] in ['upload', 'download'] else "green"
            st.markdown(f"<span style='color:{action_color}'>{log['action'].upper()}</span>: {log['filename']} at {log['timestamp']}", unsafe_allow_html=True)
    else:
        st.info("No recent activity")
    
    # Generate some random entropy for our encryption keys
    # In a real app, we'd collect this from user interactions
    collect_randomness(time.time())

def render_upload_page():
    """Render the file upload page."""
    st.title("Upload and Encrypt Files")
    
    render_navigation()
    
    uploaded_file = st.file_uploader("Choose a file", type=None)
    
    if uploaded_file is not None:
        # Read file and analyze for encryption
        file_data = uploaded_file.read()
        file_name = uploaded_file.name
        
        # AI-based encryption method selection
        encryption_framework = EncryptionFramework()
        method = encryption_framework.analyze_file(file_data, file_name)
        
        st.write(f"File size: {len(file_data) / 1024:.2f} KB")
        st.write(f"Recommended encryption method: {method}")
        
        # Let user override if desired
        selected_method = st.selectbox(
            "Select encryption method:",
            ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305', 'Kyber-768'],
            index=['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305', 'Kyber-768'].index(method)
        )
        
        if st.button("Upload and Encrypt"):
            with st.spinner("Encrypting and uploading file..."):
                # Encrypt the file
                encrypted_info = encryption_framework.encrypt_file(file_data, selected_method, st.session_state.logged_in_user)
                
                # Generate unique file ID
                file_id = str(uuid.uuid4())
                file_key = f"{file_id}_{file_name}"
                
                # Store file information
                st.session_state.files[file_key] = {
                    'encrypted_info': encrypted_info,
                    'original_name': file_name,
                    'upload_time': datetime.now().isoformat(),
                    'owner': st.session_state.logged_in_user,
                    'permissions': {}  # Will be populated by NLP commands
                }
                
                # Create Merkle tree for access tracking
                merkle_data = [
                    f"file:{file_key}",
                    f"uploader:{st.session_state.logged_in_user}",
                    f"time:{datetime.now().isoformat()}"
                ]
                merkle_tree = MerkleTree(merkle_data)
                st.session_state.merkle_trees[file_key] = merkle_tree
                
                # Log the action
                log_action(st.session_state.logged_in_user, 'upload', file_key)
                
                # Update user score
                UserScoring.update_user_score(
                    st.session_state.logged_in_user, 
                    'upload', 
                    st.session_state.files[file_key]['encrypted_info']
                )
                
                st.success(f"File {file_name} encrypted with {selected_method} and uploaded successfully!")
                
                # Show encryption details
                st.subheader("Encryption Details")
                st.json({
                    'method': selected_method,
                    'timestamp': encrypted_info['timestamp'],
                    'encrypted_by': encrypted_info['encrypted_by'],
                    'file_id': file_id
                })

def render_files_page():
    """Render the files management page."""
    st.title("File Management")
    
    render_navigation()
    
    # Show accessible files
    st.subheader("Your Files")
    
    # Filter files accessible to the current user
    accessible_files = {
        file_name: file_info for file_name, file_info in st.session_state.files.items()
        if has_access(st.session_state.logged_in_user, file_name)
    }
    
    if not accessible_files:
        st.info("You don't have any files yet.")
    else:
       # Create tabs for different file views
        tabs = st.tabs(["All Files", "Owned Files", "Shared Files"])
        
        with tabs[0]:
            render_file_list(accessible_files, "all")
        
        with tabs[1]:
            owned_files = {name: info for name, info in accessible_files.items() 
                          if info['owner'] == st.session_state.logged_in_user}
            render_file_list(owned_files, "owned")
        
        with tabs[2]:
            shared_files = {name: info for name, info in accessible_files.items() 
                           if info['owner'] != st.session_state.logged_in_user}
            render_file_list(shared_files, "shared")
    
    # NLP Permissions section
    st.subheader("Manage Permissions with Natural Language")
    st.write("Example commands: 'Grant read and write access to user1 for file X' or 'Revoke write access from user1 for file Y'")
    
    selected_file = st.selectbox(
        "Select file to manage:",
        options=list(accessible_files.keys()),
        format_func=lambda x: st.session_state.files[x]['original_name'],
        key="perm_file_select"
    ) if accessible_files else None
    
    if selected_file:
        st.write(f"Current permissions for {st.session_state.files[selected_file]['original_name']}:")
        
        # Display current permissions
        file_info = st.session_state.files[selected_file]
        if 'permissions' in file_info and file_info['permissions']:
            for user, perms in file_info['permissions'].items():
                st.write(f"- {user}: {', '.join(perms)}")
        else:
            st.write("- No permissions set. Only the owner has access.")
        
        # NLP command input
        nl_command = st.text_input("Enter permission command:", 
                                  placeholder="e.g., Grant read access to user1")
        
        if nl_command and st.button("Execute Command"):
            nlp = NLPPermissions()
            command_info = nlp.process_command(nl_command, st.session_state.logged_in_user, selected_file)
            
            success, message = nlp.execute_permission_command(command_info)
            
            if success:
                st.success(message)
                
                # Log action and update user score
                action_type = 'grant_permission' if command_info['action'] == 'grant' else 'revoke_permission'
                log_action(st.session_state.logged_in_user, action_type, selected_file)
                UserScoring.update_user_score(st.session_state.logged_in_user, action_type)
            else:
                st.error(message)

def render_file_list(files, view_type):
    """Render a list of files with actions."""
    if not files:
        st.info(f"No {'files' if view_type == 'all' else view_type + ' files'} available.")
        return
    
    for file_name, file_info in files.items():
        with st.expander(file_info['original_name']):
            cols = st.columns([3, 1, 1, 1])
            
            # File info column
            with cols[0]:
                st.write(f"Owner: {file_info['owner']}")
                st.write(f"Uploaded: {file_info['upload_time']}")
                st.write(f"Encryption: {file_info['encrypted_info']['encryption_method']}")
            
            # Download button
            with cols[1]:
                if st.button("Download", key=f"dl_{file_name}"):
                    download_file(file_name)
            
            # Access history button
            with cols[2]:
                if st.button("Access History", key=f"history_{file_name}"):
                    view_access_history(file_name)
            
            # Delete button (only for owner)
            with cols[3]:
                if file_info['owner'] == st.session_state.logged_in_user:
                    if st.button("Delete", key=f"del_{file_name}"):
                        if delete_file(file_name):
                            st.experimental_rerun()

def download_file(file_name):
    """Download and decrypt a file."""
    if file_name not in st.session_state.files:
        st.error("File not found.")
        return
    
    file_info = st.session_state.files[file_name]
    
    # Check access
    if not has_access(st.session_state.logged_in_user, file_name, 'read'):
        st.error("You don't have permission to download this file.")
        return
    
    # Decrypt file
    decrypted_data, message = EncryptionFramework.decrypt_file(
        file_info['encrypted_info'],
        authorized=True
    )
    
    if decrypted_data is None:
        st.error(message)
        return
    
    # Record access in Merkle tree
    if file_name in st.session_state.merkle_trees:
        access_data = [
            f"file:{file_name}",
            f"accessor:{st.session_state.logged_in_user}",
            f"action:download",
            f"time:{datetime.now().isoformat()}"
        ]
        new_tree = MerkleTree(access_data)
        st.session_state.merkle_trees[file_name] = new_tree
    
    # Log the action
    log_action(st.session_state.logged_in_user, 'download', file_name)
    
    # Update user score
    UserScoring.update_user_score(
        st.session_state.logged_in_user, 
        'download', 
        file_info['encrypted_info']
    )
    
    # Provide download link
    st.download_button(
        label="Click to download",
        data=decrypted_data,
        file_name=file_info['original_name'],
        mime="application/octet-stream"
    )
    
    st.success(f"File {file_info['original_name']} decrypted successfully!")

def view_access_history(file_name):
    """View access history for a file."""
    if file_name not in st.session_state.files:
        st.error("File not found.")
        return
    
    file_info = st.session_state.files[file_name]
    
    # Check if user has permission to view history
    if file_info['owner'] != st.session_state.logged_in_user and st.session_state.logged_in_user != 'admin':
        st.error("You don't have permission to view access history.")
        return
    
    # Get logs for this file
    file_logs = [log for log in st.session_state.access_logs if log['filename'] == file_name]
    
    if not file_logs:
        st.info("No access history available for this file.")
        return
    
    # Show logs
    st.subheader(f"Access History for {file_info['original_name']}")
    
    # Create DataFrame for better display
    log_data = [{
        'Time': log['timestamp'],
        'User': log['user'],
        'Action': log['action'].capitalize()
    } for log in file_logs]
    
    log_df = pd.DataFrame(log_data)
    st.dataframe(log_df)
    
    # Show Merkle root for integrity verification
    if file_name in st.session_state.merkle_trees:
        merkle_root = st.session_state.merkle_trees[file_name].get_root()
        st.write(f"Merkle Root (Integrity Verification): {merkle_root}")

def delete_file(file_name):
    """Delete a file."""
    if file_name not in st.session_state.files:
        st.error("File not found.")
        return False
    
    file_info = st.session_state.files[file_name]
    
    # Check if user has permission to delete
    if file_info['owner'] != st.session_state.logged_in_user and st.session_state.logged_in_user != 'admin':
        st.error("You don't have permission to delete this file.")
        return False
    
    # Delete file
    del st.session_state.files[file_name]
    
    # Update Merkle trees
    if file_name in st.session_state.merkle_trees:
        del st.session_state.merkle_trees[file_name]
    
    # Log the action
    log_action(st.session_state.logged_in_user, 'delete', file_name)
    
    # Update user score
    UserScoring.update_user_score(st.session_state.logged_in_user, 'delete')
    
    st.success(f"File {file_info['original_name']} deleted successfully.")
    return True

def render_analytics_page():
    """Render the analytics dashboard."""
    st.title("Analytics Dashboard")
    
    render_navigation()
    
    # Create tabs for different analytics views
    tabs = st.tabs(["Encryption Methods", "User Activity", "File Access", "User Scores"])
    
    with tabs[0]:
        st.subheader("Encryption Method Distribution")
        
        # Count encryption methods
        encryption_counts = {}
        file_sizes = {}
        
        for file_info in st.session_state.files.values():
            method = file_info['encrypted_info']['encryption_method']
            
            if method not in encryption_counts:
                encryption_counts[method] = 0
                file_sizes[method] = []
                
            encryption_counts[method] += 1
            
            # Calculate original file size (approximate from encrypted data)
            encrypted_data = base64.b64decode(file_info['encrypted_info']['encrypted_data'])
            file_sizes[method].append(len(encrypted_data) / 1024)  # KB
        
        # Create chart data
        if encryption_counts:
            # Method frequency pie chart
            fig1, ax1 = plt.subplots()
            ax1.pie(
                encryption_counts.values(), 
                labels=encryption_counts.keys(),
                autopct='%1.1f%%', 
                startangle=90
            )
            ax1.axis('equal')
            st.pyplot(fig1)
            
            # Method vs file size box plot
            if sum(len(sizes) for sizes in file_sizes.values()) > 1:
                fig2, ax2 = plt.subplots()
                ax2.boxplot([sizes for sizes in file_sizes.values() if sizes])
                ax2.set_xticklabels([method for method, sizes in file_sizes.items() if sizes])
                ax2.set_ylabel('File Size (KB)')
                ax2.set_title('File Size Distribution by Encryption Method')
                st.pyplot(fig2)
        else:
            st.info("No files have been uploaded yet.")
    
    with tabs[1]:
        st.subheader("User Activity Timeline")
        
        if st.session_state.access_logs:
            # Prepare data
            df = pd.DataFrame([{
                'timestamp': datetime.fromisoformat(log['timestamp']),
                'user': log['user'],
                'action': log['action']
            } for log in st.session_state.access_logs])
            
            # Group by day and action
            df['date'] = df['timestamp'].dt.date
            activity_by_day = df.groupby(['date', 'action']).size().unstack().fillna(0)
            
            # Plot
            fig, ax = plt.subplots(figsize=(10, 6))
            activity_by_day.plot(kind='bar', stacked=True, ax=ax)
            ax.set_ylabel('Number of Actions')
            ax.set_title('User Activity Over Time')
            st.pyplot(fig)
            
            # Top users
            st.subheader("Most Active Users")
            user_activity = df.groupby('user').size().sort_values(ascending=False)
            
            fig2, ax2 = plt.subplots()
            user_activity.plot(kind='bar', ax=ax2)
            ax2.set_ylabel('Number of Actions')
            ax2.set_title('User Activity')
            st.pyplot(fig2)
        else:
            st.info("No user activity recorded yet.")
    
    with tabs[2]:
        st.subheader("File Access Patterns")
        
        if st.session_state.files and st.session_state.access_logs:
            # Filter logs for file access
            file_logs = [log for log in st.session_state.access_logs 
                        if log['action'] in ['upload', 'download', 'delete']]
            
            if file_logs:
                # Create dataframe
                df = pd.DataFrame([{
                    'filename': log['filename'],
                    'original_name': st.session_state.files[log['filename']]['original_name'] 
                               if log['filename'] in st.session_state.files else 'Deleted File',
                    'action': log['action']
                } for log in file_logs])
                
                # File access counts
                file_access = df.groupby(['original_name', 'action']).size().unstack().fillna(0)
                
                # Plot
                fig, ax = plt.subplots(figsize=(10, 6))
                file_access.plot(kind='barh', stacked=True, ax=ax)
                ax.set_xlabel('Number of Actions')
                ax.set_title('File Access Patterns')
                st.pyplot(fig)
            else:
                st.info("No file access logs recorded yet.")
        else:
            st.info("No files or access logs recorded yet.")
    
    with tabs[3]:
        st.subheader("User Scores")
        
        # Get all user scores
        user_scores = {user: data['score'] 
                      for user, data in st.session_state.user_data['users'].items()}
        
        if user_scores:
            # Create series and sort
            scores_series = pd.Series(user_scores).sort_values(ascending=False)
            
            # Plot
            fig, ax = plt.subplots()
            scores_series.plot(kind='bar', ax=ax)
            ax.set_ylabel('Score')
            ax.set_title('User Scores')
            st.pyplot(fig)
            
            # Show leaderboard
            st.subheader("Leaderboard")
            leaderboard = pd.DataFrame({
                'User': scores_series.index,
                'Score': scores_series.values
            })
            st.dataframe(leaderboard)
        else:
            st.info("No user scores available.")

# -------------- Helper Functions --------------

def has_access(username, file_name, permission_type='read'):
    """Check if user has access to a file."""
    if file_name not in st.session_state.files:
        return False
    
    file_info = st.session_state.files[file_name]
    
    # Owner has all permissions
    if file_info['owner'] == username:
        return True
    
    # Admin has all permissions
    if username == 'admin':
        return True
    
    # Check explicit permissions
    if 'permissions' in file_info and username in file_info['permissions']:
        return permission_type in file_info['permissions'][username]
    
    return False

def log_action(username, action, filename):
    """Log a user action."""
    st.session_state.access_logs.append({
        'user': username,
        'action': action,
        'filename': filename,
        'timestamp': datetime.now().isoformat()
    })

# -------------- Main App --------------

def main():
    st.set_page_config(
        page_title="Secure File Management System",
        page_icon="🔒",
        layout="wide"
    )
    
    # Check for login
    if st.session_state.logged_in_user is None:
        render_login_page()
    else:
        # Dispatch to appropriate page
        if st.session_state.current_page == 'dashboard':
            render_dashboard()
        elif st.session_state.current_page == 'upload':
            render_upload_page()
        elif st.session_state.current_page == 'files':
            render_files_page()
        elif st.session_state.current_page == 'analytics':
            render_analytics_page()
        else:
            render_dashboard()

if __name__ == "__main__":
    main() # Create tabs for different file views