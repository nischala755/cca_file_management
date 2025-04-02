import os
import json
import hashlib
import base64
import random
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sys
import importlib.util
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration
with open('../config.json') as config_file:
    CONFIG = json.load(config_file)

# Constants
KEY_DIRECTORY = '../static/logs/keys/'
os.makedirs(KEY_DIRECTORY, exist_ok=True)

# Import quantum-resistant algorithms if available
try:
    # Try to import Kyber
    spec = importlib.util.find_spec('models.kyber')
    if spec is not None:
        kyber = importlib.import_module('models.kyber')
        KYBER_AVAILABLE = True
    else:
        KYBER_AVAILABLE = False
    
    # Try to import NTRU
    spec = importlib.util.find_spec('models.ntru')
    if spec is not None:
        ntru = importlib.import_module('models.ntru')
        NTRU_AVAILABLE = True
    else:
        NTRU_AVAILABLE = False
except ImportError:
    KYBER_AVAILABLE = False
    NTRU_AVAILABLE = False

class EncryptionMethods:
    AES_256_GCM = "AES-256-GCM"
    AES_256_CBC = "AES-256-CBC"
    RSA_OAEP = "RSA-OAEP"
    HYBRID_AES_RSA = "Hybrid-AES-RSA"
    KYBER = "Kyber" if KYBER_AVAILABLE else None
    NTRU = "NTRU" if NTRU_AVAILABLE else None

def analyze_and_select_method(file_path, file_size, file_type):
    """
    Analyze the file and select the optimal encryption method
    """
    # Define file type categories
    text_types = ['.txt', '.md', '.csv', '.json', '.xml', '.html', '.css', '.js', '.py']
    binary_types = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz']
    media_types = ['.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.wav', '.avi']
    
    # Define size thresholds (in bytes)
    small_size = 1 * 1024 * 1024  # 1 MB
    medium_size = 10 * 1024 * 1024  # 10 MB
    
    # AI-based decision making
    # Note: This is a simplified decision tree; in a real AI system,
    # you would use more sophisticated machine learning.
    
    # For highly sensitive small files
    if CONFIG.get("high_security", False) and file_size < small_size:
        # Prefer quantum-resistant for highest security if available
        if KYBER_AVAILABLE:
            return EncryptionMethods.KYBER, "Quantum-resistant encryption selected for small, sensitive file"
        else:
            return EncryptionMethods.AES_256_GCM, "AES-256-GCM selected for small, sensitive file (Quantum-resistant unavailable)"
    
    # For small text files
    if file_size < small_size and file_type.lower() in text_types:
        return EncryptionMethods.AES_256_CBC, "AES-256-CBC selected for small text file for optimal performance"
    
    # For small binary files
    elif file_size < small_size and file_type.lower() in binary_types:
        return EncryptionMethods.AES_256_GCM, "AES-256-GCM selected for small binary file for better integrity protection"
    
    # For medium-sized files
    elif small_size <= file_size < medium_size:
        return EncryptionMethods.HYBRID_AES_RSA, "Hybrid AES-RSA selected for medium-sized file for balanced security and speed"
    
    # For large media files that need streaming access
    elif file_size >= medium_size and file_type.lower() in media_types:
        return EncryptionMethods.AES_256_GCM, "AES-256-GCM selected for large media file for streaming capability"
    
    # For large files with high security requirements
    elif file_size >= medium_size and CONFIG.get("high_security", False):
        if NTRU_AVAILABLE:
            return EncryptionMethods.NTRU, "NTRU quantum-resistant encryption selected for large sensitive file"
        else:
            return EncryptionMethods.HYBRID_AES_RSA, "Hybrid AES-RSA selected for large sensitive file (Quantum-resistant unavailable)"
    
    # Default for large files
    elif file_size >= medium_size:
        return EncryptionMethods.HYBRID_AES_RSA, "Hybrid AES-RSA selected for large file (default choice)"
    
    # Default fallback
    else:
        return EncryptionMethods.AES_256_CBC, "AES-256-CBC selected as default encryption method"

def generate_aes_key():
    """Generate a random AES-256 key"""
    return os.urandom(32)  # 256 bits = 32 bytes

def generate_rsa_keypair():
    """Generate an RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def store_key(key_data, key_type, identifier):
    """Store encryption keys securely"""
    if key_type == "aes":
        # Store AES key
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_aes.key")
        with open(key_path, 'wb') as key_file:
            key_file.write(key_data)
    elif key_type == "rsa_private":
        # Store RSA private key
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_rsa_private.pem")
        pem = key_data.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, 'wb') as key_file:
            key_file.write(pem)
    elif key_type == "rsa_public":
        # Store RSA public key
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_rsa_public.pem")
        pem = key_data.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(key_path, 'wb') as key_file:
            key_file.write(pem)
    
    return key_path

def retrieve_key(key_type, identifier):
    """Retrieve stored encryption keys"""
    if key_type == "aes":
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_aes.key")
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    elif key_type == "rsa_private":
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_rsa_private.pem")
        with open(key_path, 'rb') as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    elif key_type == "rsa_public":
        key_path = os.path.join(KEY_DIRECTORY, f"{identifier}_rsa_public.pem")
        with open(key_path, 'rb') as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

def encrypt_with_aes_cbc(data, key):
    """Encrypt data using AES CBC mode"""
    iv = os.urandom(16)  # 128-bit initialization vector
    
    # Pad the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Create the cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

def decrypt_with_aes_cbc(encrypted_data, key):
    """Decrypt data using AES CBC mode"""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create the cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

def encrypt_with_aes_gcm(data, key):
    """Encrypt data using AES GCM mode (authenticated encryption)"""
    iv = os.urandom(12)  # 96-bit nonce recommended for GCM
    
    # Create the cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Return IV + tag + ciphertext
    return iv + encryptor.tag + ciphertext

def decrypt_with_aes_gcm(encrypted_data, key):
    """Decrypt data using AES GCM mode"""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]  # 16-byte authentication tag
    ciphertext = encrypted_data[28:]
    
    # Create the cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return data

def encrypt_with_rsa(data, public_key):
    """Encrypt data using RSA"""
    # RSA has size limitations, so this is suitable for small data only
    ciphertext = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_rsa(ciphertext, private_key):
    """Decrypt data using RSA"""
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def encrypt_hybrid(data, rsa_public_key):
    """Hybrid encryption: AES for data, RSA for the AES key"""
    # Generate a random AES key
    aes_key = generate_aes_key()
    
    # Encrypt the data with AES
    encrypted_data = encrypt_with_aes_gcm(data, aes_key)
    
    # Encrypt the AES key with RSA
    encrypted_key = encrypt_with_rsa(aes_key, rsa_public_key)
    
    # Combine the encrypted key and encrypted data
    # First 4 bytes: length of encrypted key
    key_length = len(encrypted_key).to_bytes(4, byteorder='big')
    
    return key_length + encrypted_key + encrypted_data

def decrypt_hybrid(encrypted_data, rsa_private_key):
    """Decrypt data that was encrypted with hybrid encryption"""
    # Extract the key length
    key_length = int.from_bytes(encrypted_data[:4], byteorder='big')
    
    # Extract and decrypt the AES key
    encrypted_key = encrypted_data[4:4+key_length]
    aes_key = decrypt_with_rsa(encrypted_key, rsa_private_key)
    
    # Extract and decrypt the data
    encrypted_aes_data = encrypted_data[4+key_length:]
    data = decrypt_with_aes_gcm(encrypted_aes_data, aes_key)
    
    return data

def encrypt_file(file_path, encryption_method):
    """Encrypt a file using the specified method"""
    # Generate a unique identifier for the file
    file_id = os.path.basename(file_path).split('_')[0]
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    encrypted_file_path = f"{file_path}.enc"
    
    if encryption_method == EncryptionMethods.AES_256_CBC:
        # Generate and store AES key
        aes_key = generate_aes_key()
        store_key(aes_key, "aes", file_id)
        
        # Encrypt the data
        encrypted_data = encrypt_with_aes_cbc(data, aes_key)
        
        # Write encrypted data to file
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
            
    elif encryption_method == EncryptionMethods.AES_256_GCM:
        # Generate and store AES key
        aes_key = generate_aes_key()
        store_key(aes_key, "aes", file_id)
        
        # Encrypt the data
        encrypted_data = encrypt_with_aes_gcm(data, aes_key)
        
        # Write encrypted data to file
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
            
    elif encryption_method == EncryptionMethods.RSA_OAEP:
        # Generate and store RSA key pair
        private_key, public_key = generate_rsa_keypair()
        store_key(private_key, "rsa_private", file_id)
        store_key(public_key, "rsa_public", file_id)
        
        # Due to RSA size limitations, encrypt in chunks
        chunk_size = 190  # Safe size for RSA-2048 with OAEP padding
        encrypted_chunks = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted_chunk = encrypt_with_rsa(chunk, public_key)
            
            # Store the length of each encrypted chunk (for decryption)
            length = len(encrypted_chunk).to_bytes(2, byteorder='big')
            encrypted_chunks.append(length + encrypted_chunk)
        
        # Combine all encrypted chunks
        encrypted_data = b''.join(encrypted_chunks)
        
        # Write encrypted data to file
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
            
    elif encryption_method == EncryptionMethods.HYBRID_AES_RSA:
        # Generate and store RSA key pair
        private_key, public_key = generate_rsa_keypair()
        store_key(private_key, "rsa_private", file_id)
        store_key(public_key, "rsa_public", file_id)
        
        # Encrypt using hybrid approach
        encrypted_data = encrypt_hybrid(data, public_key)
        
        # Write encrypted data to file
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
            
    elif encryption_method == EncryptionMethods.KYBER and KYBER_AVAILABLE:
        # Use Kyber quantum-resistant encryption
        try:
            # Generate Kyber keys
            public_key, private_key = kyber.generate_keypair()
            
            # Save keys
            kyber_key_path = os.path.join(KEY_DIRECTORY, f"{file_id}_kyber.keys")
            kyber.save_keys(public_key, private_key, kyber_key_path)
            
            # Encrypt the data - Kyber can only encrypt small amounts of data,
            # so use it to encrypt an AES key
            aes_key = generate_aes_key()
            cipher_text = kyber.encrypt(public_key, aes_key)
            
            # Encrypt actual data with AES
            aes_encrypted = encrypt_with_aes_gcm(data, aes_key)
            
            # Combine Kyber-encrypted key with AES-encrypted data
            key_length = len(cipher_text).to_bytes(4, byteorder='big')
            encrypted_data = key_length + cipher_text + aes_encrypted
            
            # Write to file
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            logger.error(f"Kyber encryption failed: {str(e)}")
            # Fall back to hybrid encryption
            logger.info("Falling back to hybrid AES-RSA encryption")
            return encrypt_file(file_path, EncryptionMethods.HYBRID_AES_RSA)
            
    elif encryption_method == EncryptionMethods.NTRU and NTRU_AVAILABLE:
        # Use NTRU quantum-resistant encryption
        try:
            # Generate NTRU keys
            public_key, private_key = ntru.generate_keypair()
            
            # Save keys
            ntru_key_path = os.path.join(KEY_DIRECTORY, f"{file_id}_ntru.keys")
            ntru.save_keys(public_key, private_key, ntru_key_path)
            
            # NTRU also has limitations on data size, so use it for key encryption
            aes_key = generate_aes_key()
            cipher_text = ntru.encrypt(public_key, aes_key)
            
            # Encrypt actual data with AES
            aes_encrypted = encrypt_with_aes_gcm(data, aes_key)
            
            # Combine NTRU-encrypted key with AES-encrypted data
            key_length = len(cipher_text).to_bytes(4, byteorder='big')
            encrypted_data = key_length + cipher_text + aes_encrypted
            
            # Write to file
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            logger.error(f"NTRU encryption failed: {str(e)}")
            # Fall back to hybrid encryption
            logger.info("Falling back to hybrid AES-RSA encryption")
            return encrypt_file(file_path, EncryptionMethods.HYBRID_AES_RSA)
    
    else:
        # Default to AES-CBC if method not recognized
        logger.warning(f"Encryption method {encryption_method} not recognized, using AES-CBC")
        return encrypt_file(file_path, EncryptionMethods.AES_256_CBC)
    
    return encrypted_file_path

def decrypt_file(encrypted_file_path, encryption_method, output_path=None):
    """Decrypt a file using the specified method"""
    # Extract file ID from the filename
    file_id = os.path.basename(encrypted_file_path).split('_')[0]
    
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # If no output path specified, create one based on input
    if output_path is None:
        output_path = encrypted_file_path[:-4]  # Remove .enc extension
    
    if encryption_method == EncryptionMethods.AES_256_CBC:
        # Retrieve the AES key
        aes_key = retrieve_key("aes", file_id)
        
        # Decrypt the data
        data = decrypt_with_aes_cbc(encrypted_data, aes_key)
        
    elif encryption_method == EncryptionMethods.AES_256_GCM:
        # Retrieve the AES key
        aes_key = retrieve_key("aes", file_id)
        
        # Decrypt the data
        data = decrypt_with_aes_gcm(encrypted_data, aes_key)
        
    elif encryption_method == EncryptionMethods.RSA_OAEP:
        # Retrieve the RSA private key
        private_key = retrieve_key("rsa_private", file_id)
        
        # RSA decryption needs to be done in chunks
        data = b''
        offset = 0
        
        while offset < len(encrypted_data):
            # Read chunk length
            chunk_length = int.from_bytes(encrypted_data[offset:offset+2], byteorder='big')
            offset += 2
            
            # Read and decrypt chunk
            encrypted_chunk = encrypted_data[offset:offset+chunk_length]
            offset += chunk_length
            
            decrypted_chunk = decrypt_with_rsa(encrypted_chunk, private_key)
            data += decrypted_chunk
        
    elif encryption_method == EncryptionMethods.HYBRID_AES_RSA:
        # Retrieve the RSA private key
        private_key = retrieve_key("rsa_private", file_id)
        
        # Decrypt using hybrid approach
        data = decrypt_hybrid(encrypted_data, private_key)
        
    elif encryption_method == EncryptionMethods.KYBER and KYBER_AVAILABLE:
        try:
            # Load Kyber keys
            kyber_key_path = os.path.join(KEY_DIRECTORY, f"{file_id}_kyber.keys")
            public_key, private_key = kyber.load_keys(kyber_key_path)
            
            # Extract key length and encrypted key
            key_length = int.from_bytes(encrypted_data[:4], byteorder='big')
            encrypted_key = encrypted_data[4:4+key_length]
            
            # Decrypt the AES key
            aes_key = kyber.decrypt(private_key, encrypted_key)
            
            # Decrypt the data with AES
            aes_encrypted = encrypted_data[4+key_length:]
            data = decrypt_with_aes_gcm(aes_encrypted, aes_key)
            
        except Exception as e:
            logger.error(f"Kyber decryption failed: {str(e)}")
            raise
            
    elif encryption_method == EncryptionMethods.NTRU and NTRU_AVAILABLE:
        try:
            # Load NTRU keys
            ntru_key_path = os.path.join(KEY_DIRECTORY, f"{file_id}_ntru.keys")
            public_key, private_key = ntru.load_keys(ntru_key_path)
            
            # Extract key length and encrypted key
            key_length = int.from_bytes(encrypted_data[:4], byteorder='big')
            encrypted_key = encrypted_data[4:4+key_length]
            
            # Decrypt the AES key
            aes_key = ntru.decrypt(private_key, encrypted_key)
            
            # Decrypt the data with AES
            aes_encrypted = encrypted_data[4+key_length:]
            data = decrypt_with_aes_gcm(aes_encrypted, aes_key)
            
        except Exception as e:
            logger.error(f"NTRU decryption failed: {str(e)}")
            raise
    
    else:
        # If method not recognized, try all methods
        logger.warning(f"Encryption method {encryption_method} not recognized, trying all methods")
        
        # Try AES-CBC first
        try:
            logger.info("Trying AES-CBC decryption")
            return decrypt_file(encrypted_file_path, EncryptionMethods.AES_256_CBC, output_path)
        except Exception:
            pass
        
        # Try AES-GCM next
        try:
            logger.info("Trying AES-GCM decryption")
            return decrypt_file(encrypted_file_path, EncryptionMethods.AES_256_GCM, output_path)
        except Exception:
            pass
        
        # Try Hybrid AES-RSA
        try:
            logger.info("Trying Hybrid AES-RSA decryption")
            return decrypt_file(encrypted_file_path, EncryptionMethods.HYBRID_AES_RSA, output_path)
        except Exception:
            pass
        
        # If all fail, raise an error
        raise ValueError("Could not decrypt file with any known method")
    
    # Write decrypted data to file
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return output_path

def process_entropy(events_data):
    """Process entropy from client-side events"""
    # Combine all event data into a single string
    combined_data = ""
    for event in events_data:
        if isinstance(event, dict):
            # Extract relevant properties from event objects
            properties = []
            if 'timestamp' in event:
                properties.append(str(event['timestamp']))
            if 'x' in event and 'y' in event:
                properties.append(f"{event['x']},{event['y']}")
            if 'key' in event:
                properties.append(event['key'])
                
            combined_data += "".join(properties)
        else:
            combined_data += str(event)
    
    # Add current time and random value for additional entropy
    current_time = str(time.time())
    random_value = str(random.randint(0, 1000000))
    
    combined_data += current_time + random_value
    
    # Hash the combined data to create high-quality entropy
    entropy_hash = hashlib.sha512(combined_data.encode()).digest()
    
    return entropy_hash

def generate_session_token(entropy):
    """Generate a session token using provided entropy"""
    # Mix in some additional entropy
    extra_entropy = os.urandom(16)
    combined = entropy + extra_entropy
    
    # Hash and encode
    token_hash = hashlib.sha256(combined).digest()
    token = base64.urlsafe_b64encode(token_hash).decode('utf-8').rstrip('=')
    
    return token

def simulate_qubit_key_generation(entropy_source=None):
    """
    Simulate quantum key generation using classical randomness
    This is a simplified simulation for educational purposes
    """
    if entropy_source is None:
        # Use system randomness if no entropy provided
        entropy = os.urandom(32)
    else:
        # Use provided entropy
        entropy = entropy_source[:32]
    
    # Simulate measurement of qubits in random bases
    key_bits = []
    bases = []
    
    for byte in entropy:
        # Each byte gives us 8 simulated qubits
        for i in range(8):
            # Extract bit at position i
            bit = (byte >> i) & 1
            
            # Randomly choose a measurement basis (0 = Z basis, 1 = X basis)
            basis = random.randint(0, 1)
            
            # If X basis is chosen, apply a "Hadamard transform" (simulated)
            if basis == 1:
                # 50% chance to flip the bit in X basis
                if random.random() < 0.5:
                    bit = 1 - bit
            
            key_bits.append(bit)
            bases.append(basis)
    
    # Convert bit array to bytes
    bit_count = len(key_bits)
    byte_count = (bit_count + 7) // 8
    
    key_bytes = bytearray(byte_count)
    for i in range(bit_count):
        if key_bits[i]:
            key_bytes[i // 8] |= 1 << (i % 8)
    
    return bytes(key_bytes), bases