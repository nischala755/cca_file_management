from flask import Flask, request, jsonify, render_template, send_from_directory, session
from flask_cors import CORS
import os
import json
from werkzeug.utils import secure_filename
import encryption
import access_control
import merkle_tree
import logging
from datetime import datetime
import uuid
import base64

# Initialize Flask app
app = Flask(__name__, static_folder='../static', template_folder='../templates')
CORS(app)  # Enable CORS for all routes

# Load configuration
with open('../config.json') as config_file:
    config = json.load(config_file)

# Configure app
app.config['UPLOAD_FOLDER'] = '../static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.secret_key = config['app_secret']

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('../static/logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='../static/logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
merkle_system = merkle_tree.MerkleTree()
access_system = access_control.AccessControlSystem()
entropy_pool = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    result = access_system.register_user(username, password)
    return jsonify(result)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    result = access_system.authenticate_user(username, password)
    if result['status'] == 'success':
        session['user'] = username
    return jsonify(result)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    user_id = session.get('user', 'anonymous')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Generate unique file ID
    file_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{file_id}_{original_filename}")
    
    # Save file temporarily
    file.save(temp_path)
    
    # Analyze file and select encryption method
    file_size = os.path.getsize(temp_path)
    file_type = os.path.splitext(original_filename)[1]
    encryption_method, reason = encryption.analyze_and_select_method(temp_path, file_size, file_type)
    
    # Generate encryption key using collected entropy
    if entropy_pool:
        entropy = ''.join(entropy_pool)
        key = hashlib.sha256(entropy.encode()).digest()
        entropy_pool.clear()
    else:
        key = encryption.generate_aes_key()
    
    # Encrypt file
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{original_filename}.enc")
    with open(temp_path, 'rb') as f:
        data = f.read()
        if encryption_method == encryption.EncryptionMethods.AES_256_GCM:
            encrypted_data = encryption.encrypt_with_aes_gcm(data, key)
        else:
            encrypted_data = encryption.encrypt_with_aes_cbc(data, key)
    
    # Save encrypted file
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Store encryption key
    key_id = encryption.store_key(key, "aes", file_id)
    
    # Add to Merkle tree
    file_hash = merkle_system.hash_data(encrypted_data)
    merkle_system.log_file_access(encrypted_path, user_id, "upload", file_hash)
    
    # Clean up temporary file
    os.remove(temp_path)
    
    # Update user score
    access_system.update_user_score(user_id, 'upload', file_size)
    
    return jsonify({
        'success': True,
        'file_id': file_id,
        'original_filename': original_filename,
        'encryption_method': encryption_method,
        'encryption_reason': reason,
        'merkle_root': merkle_system.get_merkle_root(encrypted_path)
    })

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    user_id = session.get('user', 'anonymous')
    
    # Find the encrypted file
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.startswith(file_id) and filename.endswith('.enc'):
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            original_filename = filename[len(file_id)+1:-4]  # Remove file_id_ prefix and .enc suffix
            break
    else:
        return jsonify({'error': 'File not found'}), 404
    
    # Check permissions
    if not access_system.check_permission(encrypted_path, user_id, 'read'):
        return jsonify({'error': 'Permission denied'}), 403
    
    # Verify file integrity
    integrity_result = merkle_system.verify_file_integrity(encrypted_path)
    if not integrity_result['valid']:
        return jsonify({'error': 'File integrity check failed'}), 400
    
    # Retrieve encryption key
    key = encryption.retrieve_key("aes", file_id)
    
    # Decrypt file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
        try:
            decrypted_data = encryption.decrypt_with_aes_gcm(encrypted_data, key)
        except:
            decrypted_data = encryption.decrypt_with_aes_cbc(encrypted_data, key)
    
    # Save decrypted file temporarily
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{original_filename}")
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    # Log access
    merkle_system.log_file_access(encrypted_path, user_id, "download")
    
    # Update user score
    access_system.update_user_score(user_id, 'download', len(decrypted_data))
    
    # Send file
    return send_from_directory(
        os.path.dirname(temp_path),
        os.path.basename(temp_path),
        as_attachment=True,
        download_name=original_filename
    )

@app.route('/api/files', methods=['GET'])
def list_files():
    user_id = session.get('user', 'anonymous')
    files = []
    
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.enc'):
            file_id = filename.split('_')[0]
            original_filename = filename[len(file_id)+1:-4]
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if access_system.check_permission(file_path, user_id, 'read'):
                file_info = {
                    'file_id': file_id,
                    'filename': original_filename,
                    'size': os.path.getsize(file_path),
                    'merkle_root': merkle_system.get_merkle_root(file_path),
                    'history': merkle_system.get_file_history(file_path)
                }
                files.append(file_info)
    
    return jsonify({'files': files})

@app.route('/api/permissions', methods=['POST'])
def manage_permissions():
    data = request.json
    user_id = session.get('user', 'anonymous')
    command = data.get('command', '')
    
    result = access_system.process_permission_command(command)
    return jsonify(result)

@app.route('/api/entropy', methods=['POST'])
def collect_entropy():
    """Collect entropy from client-side events"""
    data = request.json
    entropy = data.get('entropy', '')
    if entropy:
        entropy_pool.append(entropy)
    return jsonify({'success': True})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics for dashboard"""
    user_id = session.get('user', 'anonymous')
    
    stats = {
        'user_score': access_system.get_user_score(user_id),
        'encryption_methods': {},
        'access_history': [],
        'merkle_stats': {}
    }
    
    # Collect encryption method statistics
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.enc'):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file_size = os.path.getsize(file_path)
            file_type = os.path.splitext(filename[:-4])[1]
            method, _ = encryption.analyze_and_select_method(file_path, file_size, file_type)
            
            if method in stats['encryption_methods']:
                stats['encryption_methods'][method] += 1
            else:
                stats['encryption_methods'][method] = 1
    
    # Get Merkle tree statistics
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith('.enc'):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if access_system.check_permission(file_path, user_id, 'read'):
                merkle_stats = merkle_system.get_tree_stats(file_path)
                stats['merkle_stats'][filename] = merkle_stats
    
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)