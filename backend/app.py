from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import json
from werkzeug.utils import secure_filename
import encryption
import access_control
import merkle_tree
import logging
from datetime import datetime
import uuid

app = Flask(__name__, static_folder='../static', template_folder='../templates')

# Load configuration
with open('../config.json') as config_file:
    config = json.load(config_file)

# Configure app
app.config['UPLOAD_FOLDER'] = '../static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.secret_key = config['app_secret']

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('../static/logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='../static/logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Merkle tree for file tracking
file_merkle_tree = merkle_tree.FileMerkleTree()

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Generate a unique ID for the file
    file_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{original_filename}")
    
    # Save the uploaded file temporarily
    file.save(file_path)
    
    # Analyze file and select encryption method
    file_size = os.path.getsize(file_path)
    file_type = os.path.splitext(original_filename)[1]
    
    encryption_method, reason = encryption.analyze_and_select_method(file_path, file_size, file_type)
    
    # Encrypt the file
    encrypted_file_path = encryption.encrypt_file(file_path, encryption_method)
    
    # Add file to merkle tree for integrity tracking
    file_hash = merkle_tree.hash_file(encrypted_file_path)
    file_merkle_tree.add_file(file_id, file_hash)
    
    # Record file metadata
    user_id = request.form.get('user_id', 'anonymous')
    metadata = {
        'file_id': file_id,
        'original_filename': original_filename,
        'encryption_method': encryption_method,
        'encryption_reason': reason,
        'upload_time': datetime.now().isoformat(),
        'uploader': user_id,
        'size': file_size,
        'file_type': file_type,
        'permissions': [],
        'access_history': []
    }
    
    # Save metadata
    with open(f"../static/logs/{file_id}_metadata.json", 'w') as f:
        json.dump(metadata, f)
    
    # Remove the original unencrypted file
    if os.path.exists(file_path) and file_path != encrypted_file_path:
        os.remove(file_path)
    
    # Update user score based on upload activity
    access_control.update_user_score(user_id, 'upload', file_size)
    
    return jsonify({
        'success': True,
        'file_id': file_id,
        'original_filename': original_filename,
        'encryption_method': encryption_method,
        'encryption_reason': reason
    })

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    # Get user ID from request
    user_id = request.args.get('user_id', 'anonymous')
    
    # Check if metadata exists
    metadata_path = f"../static/logs/{file_id}_metadata.json"
    if not os.path.exists(metadata_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Load metadata
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # Check permissions
    if not access_control.check_permission(user_id, file_id, 'read'):
        return jsonify({'error': 'Permission denied'}), 403
    
    # Find the encrypted file
    filename = f"{file_id}_{metadata['original_filename']}"
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.enc")
    
    if not os.path.exists(encrypted_file_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Verify file integrity using merkle tree
    current_hash = merkle_tree.hash_file(encrypted_file_path)
    if not file_merkle_tree.verify_file(file_id, current_hash):
        return jsonify({'error': 'File integrity verification failed'}), 400
    
    # Decrypt the file to a temporary location
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{filename}")
    encryption_method = metadata['encryption_method']
    
    try:
        decrypted_file_path = encryption.decrypt_file(encrypted_file_path, encryption_method, temp_path)
        
        # Log access
        metadata['access_history'].append({
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'action': 'download'
        })
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        # Update user score
        access_control.update_user_score(user_id, 'download', os.path.getsize(decrypted_file_path))
        
        return send_from_directory(
            os.path.dirname(decrypted_file_path),
            os.path.basename(decrypted_file_path),
            as_attachment=True,
            download_name=metadata['original_filename']
        )
    
    except Exception as e:
        logger.error(f"Error decrypting file: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500
    finally:
        # Clean up the temporary decrypted file
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/api/files', methods=['GET'])
def list_files():
    user_id = request.args.get('user_id', 'anonymous')
    files = []
    
    # Get all metadata files
    for filename in os.listdir('../static/logs'):
        if filename.endswith('_metadata.json'):
            with open(os.path.join('../static/logs', filename), 'r') as f:
                metadata = json.load(f)
                
                # Only show files the user has access to
                if metadata['uploader'] == user_id or access_control.check_permission(user_id, metadata['file_id'], 'read'):
                    files.append({
                        'file_id': metadata['file_id'],
                        'filename': metadata['original_filename'],
                        'upload_time': metadata['upload_time'],
                        'size': metadata['size'],
                        'encryption': metadata['encryption_method'],
                        'uploader': metadata['uploader']
                    })
    
    return jsonify({'files': files})

@app.route('/api/permissions', methods=['POST'])
def manage_permissions():
    data = request.json
    file_id = data.get('file_id')
    owner_id = data.get('user_id')
    command = data.get('command', '')
    
    # Load metadata to check ownership
    metadata_path = f"../static/logs/{file_id}_metadata.json"
    if not os.path.exists(metadata_path):
        return jsonify({'error': 'File not found'}), 404
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # Only file owner can modify permissions
    if metadata['uploader'] != owner_id:
        return jsonify({'error': 'Only the file owner can modify permissions'}), 403
    
    # Process the natural language command
    try:
        result = access_control.process_permission_command(command, file_id, metadata)
        
        # Save updated metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        return jsonify({'success': True, 'result': result})
    
    except Exception as e:
        logger.error(f"Error processing permission command: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/user/score/<user_id>', methods=['GET'])
def get_user_score(user_id):
    score = access_control.get_user_score(user_id)
    return jsonify({'user_id': user_id, 'score': score})

@app.route('/api/file/integrity/<file_id>', methods=['GET'])
def check_file_integrity(file_id):
    # Find the encrypted file
    metadata_path = f"../static/logs/{file_id}_metadata.json"
    if not os.path.exists(metadata_path):
        return jsonify({'error': 'File not found'}), 404
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    filename = f"{file_id}_{metadata['original_filename']}"
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.enc")
    
    if not os.path.exists(encrypted_file_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Verify file integrity using merkle tree
    current_hash = merkle_tree.hash_file(encrypted_file_path)
    integrity_verified = file_merkle_tree.verify_file(file_id, current_hash)
    
    return jsonify({
        'file_id': file_id,
        'filename': metadata['original_filename'],
        'integrity_verified': integrity_verified
    })

@app.route('/api/generate_entropy', methods=['POST'])
def collect_entropy():
    """Collect entropy from client-side events for key generation"""
    events_data = request.json.get('events', [])
    
    if not events_data:
        return jsonify({'error': 'No entropy data provided'}), 400
    
    # Process entropy data
    entropy = encryption.process_entropy(events_data)
    
    # Generate a session token using the entropy
    session_token = encryption.generate_session_token(entropy)
    
    return jsonify({'token': session_token})

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get statistics for the dashboard"""
    stats = {
        'encryption_methods': {},
        'file_types': {},
        'users': {},
        'activity': []
    }
    
    # Process all metadata files
    for filename in os.listdir('../static/logs'):
        if filename.endswith('_metadata.json'):
            with open(os.path.join('../static/logs', filename), 'r') as f:
                metadata = json.load(f)
                
                # Count encryption methods
                enc_method = metadata['encryption_method']
                stats['encryption_methods'][enc_method] = stats['encryption_methods'].get(enc_method, 0) + 1
                
                # Count file types
                file_type = metadata['file_type']
                stats['file_types'][file_type] = stats['file_types'].get(file_type, 0) + 1
                
                # Count users
                user = metadata['uploader']
                stats['users'][user] = stats['users'].get(user, 0) + 1
                
                # Recent activity (last 10 events)
                if 'access_history' in metadata:
                    for access in metadata['access_history'][-5:]:
                        stats['activity'].append({
                            'file': metadata['original_filename'],
                            'user': access['user_id'],
                            'action': access['action'],
                            'time': access['timestamp']
                        })
    
    # Sort activities by time (newest first)
    stats['activity'] = sorted(stats['activity'], 
                               key=lambda x: x['time'], 
                               reverse=True)[:10]
    
    return jsonify(stats)

if __name__ == '__main__':
    app.run(debug=config.get('debug', False), host='0.0.0.0', port=5000)