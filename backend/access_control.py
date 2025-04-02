import json
import re
import os
import datetime
import hashlib
from collections import defaultdict
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

class AccessControlSystem:
    def __init__(self, config_path='config.json'):
        self.users = {}
        self.permissions = defaultdict(dict)
        self.user_scores = defaultdict(lambda: 100)  # Default score of 100 for new users
        self.access_logs = defaultdict(list)
        self.nlp_model = None
        self.vectorizer = None
        
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Ensure directories exist
        os.makedirs(self.config.get('log_dir', 'static/logs'), exist_ok=True)
        
        # Initialize or load NLP model
        self._init_nlp_model()
    
    def _init_nlp_model(self):
        """Initialize or load the NLP model for permission commands"""
        model_path = 'models/nlp_permission_model.joblib'
        vectorizer_path = 'models/nlp_vectorizer.joblib'
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            self.nlp_model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
        else:
            # Train a simple model with example permission commands
            self._train_nlp_model()
    
    def _train_nlp_model(self):
        """Train a basic NLP model for permission interpretation"""
        # Example training data
        commands = [
            "give access to file.txt for user1",
            "grant user2 permission to read document.pdf",
            "allow user3 to edit presentation.ppt",
            "remove access to config.json from user4",
            "revoke write permission from user5 for code.py",
            "deny user6 access to secret.txt",
            "make file.txt public",
            "set private access for credentials.json",
            "share report.xlsx with user7",
            "add admin privileges to user8",
            "make user9 owner of project.zip",
            "give read-only access to user10 for database.sql"
        ]
        
        labels = [
            "grant", "grant", "grant", "revoke", "revoke", "revoke",
            "public", "private", "grant", "admin", "owner", "read-only"
        ]
        
        # Create and train model
        self.vectorizer = CountVectorizer()
        X = self.vectorizer.fit_transform(commands)
        self.nlp_model = MultinomialNB()
        self.nlp_model.fit(X, labels)
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.nlp_model, 'models/nlp_permission_model.joblib')
        joblib.dump(self.vectorizer, 'models/nlp_vectorizer.joblib')
    
    def interpret_permission_command(self, command):
        """Use NLP to interpret natural language permission commands"""
        if not self.nlp_model:
            return {"status": "error", "message": "NLP model not initialized"}
        
        # Preprocess command
        command = command.lower().strip()
        
        # Extract action type using NLP
        X = self.vectorizer.transform([command])
        action_type = self.nlp_model.predict(X)[0]
        
        # Extract user and file using regex patterns
        user_match = re.search(r'user\d+|admin', command)
        file_match = re.search(r'[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+', command)
        
        user = user_match.group(0) if user_match else None
        file = file_match.group(0) if file_match else None
        
        # Determine permission level
        permission_level = "read"  # Default
        if "write" in command or "edit" in command:
            permission_level = "write"
        if "admin" in command or "owner" in command:
            permission_level = "admin"
        if "read-only" in command:
            permission_level = "read"
        
        return {
            "action": action_type,
            "user": user,
            "file": file,
            "permission": permission_level
        }
    
    def register_user(self, username, password, role="user"):
        """Register a new user"""
        if username in self.users:
            return {"status": "error", "message": "User already exists"}
        
        # Hash password with salt
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        self.users[username] = {
            "password_hash": key.hex(),
            "salt": salt.hex(),
            "role": role,
            "created_at": datetime.datetime.now().isoformat(),
            "last_login": None
        }
        
        return {"status": "success", "message": f"User {username} registered successfully"}
    
    def authenticate_user(self, username, password):
        """Authenticate a user with username and password"""
        if username not in self.users:
            return {"status": "error", "message": "User not found"}
        
        user_data = self.users[username]
        salt = bytes.fromhex(user_data["salt"])
        stored_key = bytes.fromhex(user_data["password_hash"])
        
        # Check password
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        if key == stored_key:
            # Update last login
            self.users[username]["last_login"] = datetime.datetime.now().isoformat()
            return {"status": "success", "message": "Authentication successful", "role": user_data["role"]}
        else:
            return {"status": "error", "message": "Invalid password"}
    
    def process_permission_command(self, command):
        """Process a natural language permission command"""
        parsed = self.interpret_permission_command(command)
        
        if parsed["action"] == "grant":
            return self.grant_permission(parsed["file"], parsed["user"], parsed["permission"])
        elif parsed["action"] == "revoke":
            return self.revoke_permission(parsed["file"], parsed["user"])
        elif parsed["action"] == "public":
            return self.set_public_access(parsed["file"])
        elif parsed["action"] == "private":
            return self.set_private_access(parsed["file"])
        elif parsed["action"] == "admin":
            return self.set_admin_access(parsed["file"], parsed["user"])
        elif parsed["action"] == "owner":
            return self.set_owner_access(parsed["file"], parsed["user"])
        else:
            return {"status": "error", "message": f"Unknown action type: {parsed['action']}"}
    
    def grant_permission(self, file_path, username, permission_type="read"):
        """Grant a user permission to a file"""
        if username not in self.users:
            return {"status": "error", "message": f"User {username} does not exist"}
        
        self.permissions[file_path][username] = permission_type
        self._log_permission_change(file_path, username, f"granted_{permission_type}")
        
        return {
            "status": "success", 
            "message": f"Granted {permission_type} permission to {username} for {file_path}"
        }
    
    def revoke_permission(self, file_path, username):
        """Revoke a user's permission to a file"""
        if file_path in self.permissions and username in self.permissions[file_path]:
            del self.permissions[file_path][username]
            self._log_permission_change(file_path, username, "revoked")
            return {
                "status": "success", 
                "message": f"Revoked permission from {username} for {file_path}"
            }
        else:
            return {
                "status": "error", 
                "message": f"No permission found for {username} on {file_path}"
            }
    
    def set_public_access(self, file_path):
        """Make a file publicly accessible"""
        self.permissions[file_path]["*"] = "read"  # * indicates public access
        self._log_permission_change(file_path, "public", "set_public")
        return {"status": "success", "message": f"Set public access for {file_path}"}
    
    def set_private_access(self, file_path):
        """Make a file private (remove public access)"""
        if file_path in self.permissions and "*" in self.permissions[file_path]:
            del self.permissions[file_path]["*"]
            self._log_permission_change(file_path, "public", "set_private")
            return {"status": "success", "message": f"Set private access for {file_path}"}
        else:
            return {"status": "warning", "message": f"File {file_path} was already private"}
    
    def set_admin_access(self, file_path, username):
        """Set admin permissions for a user on a file"""
        if username not in self.users:
            return {"status": "error", "message": f"User {username} does not exist"}
        
        self.permissions[file_path][username] = "admin"
        self._log_permission_change(file_path, username, "set_admin")
        return {
            "status": "success", 
            "message": f"Set admin access for {username} on {file_path}"
        }
    
    def set_owner_access(self, file_path, username):
        """Set owner permissions for a user on a file"""
        if username not in self.users:
            return {"status": "error", "message": f"User {username} does not exist"}
        
        self.permissions[file_path][username] = "owner"
        self._log_permission_change(file_path, username, "set_owner")
        return {
            "status": "success", 
            "message": f"Set owner access for {username} on {file_path}"
        }
    
    def check_permission(self, file_path, username, required_permission="read"):
        """Check if a user has permission to access a file"""
        # Admin users have access to everything
        if username in self.users and self.users[username]["role"] == "admin":
            return True
        
        # Check public access
        if file_path in self.permissions and "*" in self.permissions[file_path]:
            if required_permission == "read" and self.permissions[file_path]["*"] == "read":
                return True
        
        # Check specific user permissions
        if file_path in self.permissions and username in self.permissions[file_path]:
            user_permission = self.permissions[file_path][username]
            
            # Owner and admin can do anything
            if user_permission in ["owner", "admin"]:
                return True
            
            # Write permission also grants read
            if required_permission == "read" and user_permission == "write":
                return True
            
            # Exact permission match
            if required_permission == user_permission:
                return True
        
        return False
    
    def log_file_access(self, file_path, username, action, success=True):
        """Log file access attempt"""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "user": username,
            "file": file_path,
            "action": action,
            "success": success
        }
        
        self.access_logs[file_path].append(log_entry)
        
        # Update user score based on access
        self._update_user_score(username, action, success)
        
        # Write to log file
        log_dir = self.config.get("log_dir", "static/logs")
        log_file = os.path.join(log_dir, "access_log.json")
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r+') as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
                    logs.append(log_entry)
                    f.seek(0)
                    json.dump(logs, f, indent=2)
            else:
                with open(log_file, 'w') as f:
                    json.dump([log_entry], f, indent=2)
        except Exception as e:
            print(f"Error writing to log file: {e}")
        
        return log_entry
    
    def _log_permission_change(self, file_path, username, action):
        """Log permission changes"""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "file": file_path,
            "user": username,
            "action": action
        }
        
        # Write to permission log file
        log_dir = self.config.get("log_dir", "static/logs")
        log_file = os.path.join(log_dir, "permission_log.json")
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r+') as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
                    logs.append(log_entry)
                    f.seek(0)
                    json.dump(logs, f, indent=2)
            else:
                with open(log_file, 'w') as f:
                    json.dump([log_entry], f, indent=2)
        except Exception as e:
            print(f"Error writing to permission log file: {e}")
    
    def _update_user_score(self, username, action, success):
        """Update user score based on access patterns"""
        if username not in self.users:
            return
        
        # Basic scoring system
        if not success:
            # Unauthorized access attempts decrease score
            self.user_scores[username] -= 5
        elif action == "read":
            # Normal reads are neutral
            pass
        elif action == "write":
            # Successful writes slightly increase score
            self.user_scores[username] += 1
        elif action == "delete":
            # Deletions are monitored but neutral
            pass
        
        # Ensure score stays in reasonable range
        self.user_scores[username] = max(0, min(self.user_scores[username], 100))
    
    def get_user_score(self, username):
        """Get the current score for a user"""
        if username not in self.users:
            return {"status": "error", "message": f"User {username} does not exist"}
        
        return {
            "status": "success", 
            "user": username, 
            "score": self.user_scores[username]
        }
    
    def get_file_permissions(self, file_path):
        """Get all permissions for a specific file"""
        if file_path not in self.permissions:
            return {"status": "error", "message": f"No permissions found for {file_path}"}
        
        return {
            "status": "success", 
            "file": file_path, 
            "permissions": self.permissions[file_path]
        }
    
    def get_user_permissions(self, username):
        """Get all files a user has access to"""
        if username not in self.users:
            return {"status": "error", "message": f"User {username} does not exist"}
        
        user_files = {}
        for file_path, perms in self.permissions.items():
            if username in perms:
                user_files[file_path] = perms[username]
            elif "*" in perms:  # Public access
                user_files[file_path] = perms["*"]
        
        return {
            "status": "success", 
            "user": username, 
            "permissions": user_files
        }
    
    def get_file_access_logs(self, file_path, limit=10):
        """Get access logs for a specific file"""
        if file_path not in self.access_logs:
            return {"status": "warning", "message": f"No access logs found for {file_path}"}
        
        logs = sorted(
            self.access_logs[file_path],
            key=lambda x: x["timestamp"],
            reverse=True
        )[:limit]
        
        return {
            "status": "success", 
            "file": file_path, 
            "logs": logs
        }
    
    def save_state(self):
        """Save the current state to disk"""
        state = {
            "users": self.users,
            "permissions": dict(self.permissions),
            "user_scores": dict(self.user_scores)
        }
        
        try:
            with open('backend/access_control_state.json', 'w') as f:
                json.dump(state, f, indent=2)
            return {"status": "success", "message": "Access control state saved"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to save state: {str(e)}"}
    
    def load_state(self):
        """Load state from disk"""
        try:
            if os.path.exists('backend/access_control_state.json'):
                with open('backend/access_control_state.json', 'r') as f:
                    state = json.load(f)
                
                self.users = state.get("users", {})
                self.permissions = defaultdict(dict, state.get("permissions", {}))
                
                # Convert user_scores back to defaultdict
                scores = state.get("user_scores", {})
                self.user_scores = defaultdict(lambda: 100)
                for user, score in scores.items():
                    self.user_scores[user] = score
                
                return {"status": "success", "message": "Access control state loaded"}
            else:
                return {"status": "warning", "message": "No saved state found"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to load state: {str(e)}"}