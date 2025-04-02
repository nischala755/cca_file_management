import hashlib
import json
import os
import datetime
from collections import defaultdict

class MerkleNode:
    def __init__(self, value, left=None, right=None):
        self.value = value  # Hash value
        self.left = left    # Left child
        self.right = right  # Right child

class MerkleTree:
    def __init__(self, config_path='config.json'):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # Initialize file access histories
        self.file_histories = defaultdict(list)
        
        # Initialize trees dictionary to store Merkle trees for each file
        self.trees = {}
        
        # Log directory
        self.log_dir = self.config.get('log_dir', 'static/logs')
        os.makedirs(self.log_dir, exist_ok=True)
    
    def hash_data(self, data):
        """Hash data using SHA-256"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            data = json.dumps(data, sort_keys=True).encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()
    
    def build_merkle_tree(self, data_items):
        """Build a Merkle tree from a list of data items"""
        if not data_items:
            return None
        
        # Create leaf nodes by hashing each data item
        leaf_nodes = [MerkleNode(self.hash_data(item)) for item in data_items]
        return self._build_tree_from_nodes(leaf_nodes)
    
    def _build_tree_from_nodes(self, nodes):
        """Recursively build tree from nodes"""
        if len(nodes) == 1:
            return nodes[0]
        
        # Handle odd number of nodes by duplicating the last one
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        
        # Pair nodes and create parent nodes
        parent_nodes = []
        for i in range(0, len(nodes), 2):
            left_node = nodes[i]
            right_node = nodes[i + 1]
            combined_hash = self.hash_data(left_node.value + right_node.value)
            parent_node = MerkleNode(combined_hash, left_node, right_node)
            parent_nodes.append(parent_node)
        
        # Recursively build parent levels
        return self._build_tree_from_nodes(parent_nodes)
    
    def verify_data_integrity(self, file_path, data):
        """Verify if data matches what's recorded in the Merkle tree"""
        if file_path not in self.trees:
            return {"status": "error", "message": "No Merkle tree found for this file"}
        
        root_hash = self.trees[file_path].value
        data_hash = self.hash_data(data)
        
        # For single-item trees, just compare with the root
        if not self.trees[file_path].left and not self.trees[file_path].right:
            is_valid = data_hash == root_hash
            return {
                "status": "success", 
                "valid": is_valid,
                "message": "Data integrity verified" if is_valid else "Data integrity check failed"
            }
        
        # For multi-item trees, we need the path to verify
        # This is a simplified verification that just checks if the hash exists in the tree
        found = self._find_hash_in_tree(self.trees[file_path], data_hash)
        
        return {
            "status": "success", 
            "valid": found,
            "message": "Data integrity verified" if found else "Data integrity check failed"
        }
    
    def _find_hash_in_tree(self, node, target_hash):
        """Find if a hash exists in the tree"""
        if not node:
            return False
        
        if node.value == target_hash:
            return True
        
        return (self._find_hash_in_tree(node.left, target_hash) or 
                self._find_hash_in_tree(node.right, target_hash))
    
    def get_merkle_root(self, file_path):
        """Get the Merkle root hash for a file"""
        if file_path not in self.trees:
            return None
        
        return self.trees[file_path].value
    
    def log_file_access(self, file_path, user, action, data_hash=None):
        """Log file access and update Merkle tree"""
        timestamp = datetime.datetime.now().isoformat()
        
        # Create access record
        access_record = {
            "timestamp": timestamp,
            "user": user,
            "action": action,
            "file_path": file_path
        }
        
        if data_hash:
            access_record["data_hash"] = data_hash
        else:
            # If no hash provided, try to read and hash the file
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                access_record["data_hash"] = self.hash_data(file_content)
            except Exception as e:
                access_record["error"] = f"Could not hash file: {str(e)}"
        
        # Add to file history
        self.file_histories[file_path].append(access_record)
        
        # Update Merkle tree for this file
        self.trees[file_path] = self.build_merkle_tree(self.file_histories[file_path])
        
        # Write access record to log file
        self._write_to_log(access_record)
        
        return {
            "status": "success",
            "message": f"Access logged for {file_path}",
            "merkle_root": self.get_merkle_root(file_path)
        }
    
    def _write_to_log(self, access_record):
        """Write access record to log file"""
        log_file = os.path.join(self.log_dir, "merkle_access_log.json")
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r+') as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
                    logs.append(access_record)
                    f.seek(0)
                    json.dump(logs, f, indent=2)
            else:
                with open(log_file, 'w') as f:
                    json.dump([access_record], f, indent=2)
        except Exception as e:
            print(f"Error writing to Merkle log file: {str(e)}")
    
    def get_file_history(self, file_path):
        """Get access history for a file"""
        if file_path not in self.file_histories:
            return {"status": "warning", "message": "No history found for this file"}
        
        return {
            "status": "success",
            "file_path": file_path,
            "history": self.file_histories[file_path],
            "merkle_root": self.get_merkle_root(file_path)
        }
    
    def generate_merkle_proof(self, file_path, index):
        """Generate Merkle proof for a specific access record"""
        if file_path not in self.file_histories:
            return {"status": "error", "message": "No history found for this file"}
        
        if index >= len(self.file_histories[file_path]):
            return {"status": "error", "message": "Invalid index for file history"}
        
        # This would normally generate a Merkle proof with all sibling hashes
        # For simplicity, we're just returning the record hash and the root hash
        record = self.file_histories[file_path][index]
        record_hash = self.hash_data(record)
        
        return {
            "status": "success",
            "file_path": file_path,
            "record_hash": record_hash,
            "root_hash": self.get_merkle_root(file_path),
            "record": record
        }
    
    def verify_file_integrity(self, file_path, file_content=None):
        """Verify the integrity of a file against its most recent recorded state"""
        if file_path not in self.file_histories:
            return {"status": "error", "message": "No history found for this file"}
        
        # Get the most recent record with a data hash
        recent_records = [r for r in self.file_histories[file_path] 
                         if "data_hash" in r]
        
        if not recent_records:
            return {"status": "error", "message": "No data hash records found for this file"}
        
        most_recent = sorted(recent_records, key=lambda x: x["timestamp"])[-1]
        stored_hash = most_recent["data_hash"]
        
        # If file content is provided, use it; otherwise, try to read the file
        if file_content is None:
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
            except Exception as e:
                return {
                    "status": "error", 
                    "message": f"Could not read file: {str(e)}"
                }
        
        # Calculate current hash
        current_hash = self.hash_data(file_content)
        
        # Compare hashes
        is_valid = current_hash == stored_hash
        
        return {
            "status": "success",
            "valid": is_valid,
            "message": "File integrity verified" if is_valid else "File integrity check failed",
            "stored_hash": stored_hash,
            "current_hash": current_hash,
            "last_verified": most_recent["timestamp"]
        }
    
    def save_state(self):
        """Save the current state to disk"""
        # Can't directly serialize tree objects, so we'll save histories
        state = {
            "file_histories": dict(self.file_histories)
        }
        
        try:
            with open('backend/merkle_tree_state.json', 'w') as f:
                json.dump(state, f, indent=2)
            return {"status": "success", "message": "Merkle tree state saved"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to save state: {str(e)}"}
    
    def load_state(self):
        """Load state from disk and rebuild trees"""
        try:
            if os.path.exists('backend/merkle_tree_state.json'):
                with open('backend/merkle_tree_state.json', 'r') as f:
                    state = json.load(f)
                
                # Load histories
                self.file_histories = defaultdict(list)
                for file_path, history in state.get("file_histories", {}).items():
                    self.file_histories[file_path] = history
                
                # Rebuild all trees
                for file_path in self.file_histories:
                    self.trees[file_path] = self.build_merkle_tree(self.file_histories[file_path])
                
                return {"status": "success", "message": "Merkle tree state loaded"}
            else:
                return {"status": "warning", "message": "No saved state found"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to load state: {str(e)}"}
    
    # Helper methods for visualization
    def get_tree_structure(self, file_path):
        """Get tree structure for visualization"""
        if file_path not in self.trees:
            return {"status": "error", "message": "No Merkle tree found for this file"}
        
        tree_data = self._serialize_tree(self.trees[file_path])
        
        return {
            "status": "success",
            "file_path": file_path,
            "tree": tree_data
        }
    
    def _serialize_tree(self, node, level=0, position=0):
        """Serialize tree for visualization"""
        if not node:
            return None
        
        result = {
            "hash": node.value[:8] + "...",  # Abbreviated hash for display
            "level": level,
            "position": position
        }
        
        if node.left:
            result["left"] = self._serialize_tree(node.left, level + 1, position * 2)
        
        if node.right:
            result["right"] = self._serialize_tree(node.right, level + 1, position * 2 + 1)
        
        return result
    
    def get_tree_stats(self, file_path):
        """Get statistics about the Merkle tree"""
        if file_path not in self.trees:
            return {"status": "error", "message": "No Merkle tree found for this file"}
        
        height = self._get_tree_height(self.trees[file_path])
        node_count = self._count_nodes(self.trees[file_path])
        leaf_count = len(self.file_histories[file_path])
        
        return {
            "status": "success",
            "file_path": file_path,
            "tree_height": height,
            "node_count": node_count,
            "leaf_count": leaf_count,
            "access_count": len(self.file_histories[file_path]),
            "root_hash": self.get_merkle_root(file_path)
        }
    
    def _get_tree_height(self, node):
        """Get height of tree"""
        if not node:
            return 0
        
        left_height = self._get_tree_height(node.left)
        right_height = self._get_tree_height(node.right)
        
        return max(left_height, right_height) + 1
    
    def _count_nodes(self, node):
        """Count nodes in tree"""
        if not node:
            return 0
        
        return 1 + self._count_nodes(node.left) + self._count_nodes(node.right)