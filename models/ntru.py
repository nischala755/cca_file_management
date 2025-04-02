"""
Implementation of NTRU post-quantum cryptographic algorithm.
This is a simplified implementation for educational purposes.
"""

import os
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class NTRU:
    def __init__(self, n=443, p=3, q=2048):
        """
        Initialize NTRU with parameters.
        
        Args:
            n (int): Polynomial degree
            p (int): Small modulus
            q (int): Large modulus
        """
        self.n = n  # Degree of polynomial
        self.p = p  # Small modulus
        self.q = q  # Large modulus
    
    def _poly_mul(self, a, b):
        """
        Multiply two polynomials in Z_q[x]/(x^n - 1).
        
        Args:
            a, b: Coefficient lists of polynomials
            
        Returns:
            list: Coefficient list of product polynomial
        """
        result = [0] * self.n
        
        for i in range(self.n):
            for j in range(self.n):
                result[(i + j) % self.n] = (result[(i + j) % self.n] + a[i] * b[j]) % self.q
                
        return result
    
    def _poly_inv(self, poly, modulus):
        """
        Find the inverse of a polynomial mod (x^n - 1) and modulus.
        This is a simplified version using extended Euclidean algorithm.
        
        Args:
            poly: Coefficient list of polynomial
            modulus: Integer modulus
            
        Returns:
            list: Coefficient list of inverse polynomial or None if not invertible
        """
        # In a real implementation, this would use the extended Euclidean algorithm
        # For this simplified version, we just return a random polynomial
        # This is NOT correct for actual use
        return [np.random.randint(0, modulus) for _ in range(self.n)]
    
    def keygen(self):
        """
        Generate an NTRU key pair.
        
        Returns:
            tuple: (public_key, private_key)
        """
        # Sample small polynomials f and g
        f = [np.random.randint(-1, 2) for _ in range(self.n)]
        g = [np.random.randint(-1, 2) for _ in range(self.n)]
        
        # Compute f_q = f^-1 mod q
        f_q = self._poly_inv(f, self.q)
        
        if f_q is None:
            # If f is not invertible, try again
            return self.keygen()
        
        # Compute h = p * g * f_q mod q
        g_scaled = [(self.p * coeff) % self.q for coeff in g]
        h = self._poly_mul(g_scaled, f_q)
        
        public_key = h
        private_key = f
        
        return public_key, private_key
    
    def encrypt(self, public_key, message):
        """
        Encrypt a message using NTRU.
        
        Args:
            public_key: NTRU public key
            message: Bit string to encrypt (should be converted to polynomial)
            
        Returns:
            list: Encrypted polynomial
        """
        # Convert message to polynomial with coefficients in {0, 1, ..., p-1}
        if isinstance(message, bytes):
            # Convert bytes to a list of coefficients
            m = []
            for byte in message:
                for i in range(8):
                    bit = (byte >> i) & 1
                    m.append(bit)
            
            # Pad or truncate to length n
            if len(m) < self.n:
                m.extend([0] * (self.n - len(m)))
            else:
                m = m[:self.n]
        else:
            m = message
        
        # Sample random polynomial r with small coefficients
        r = [np.random.randint(-1, 2) for _ in range(self.n)]
        
        # Compute e = (r * h + m) mod q
        r_h = self._poly_mul(r, public_key)
        e = [(r_h[i] + m[i]) % self.q for i in range(self.n)]
        
        return e
    
    def decrypt(self, private_key, ciphertext):
        """
        Decrypt a ciphertext using NTRU.
        
        Args:
            private_key: NTRU private key
            ciphertext: Encrypted polynomial
            
        Returns:
            list: Decrypted message
        """
        # Compute a = f * e mod q
        a = self._poly_mul(private_key, ciphertext)
        
        # Center coefficients around 0
        a = [(coeff if coeff <= self.q // 2 else coeff - self.q) for coeff in a]
        
        # Reduce mod p
        m = [coeff % self.p for coeff in a]
        
        return m
    
    def encrypt_bytes(self, public_key, message_bytes):
        """
        Encrypt bytes using NTRU.
        
        Args:
            public_key: NTRU public key
            message_bytes: Bytes to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        # Simple encryption - in a real implementation, we would use proper
        # padding and multiple NTRU operations for longer messages
        encrypted_poly = self.encrypt(public_key, message_bytes)
        
        # Convert polynomial to bytes
        result = bytearray()
        for i in range(0, self.n, 4):
            chunk = encrypted_poly[i:i+4]
            if len(chunk) < 4:
                chunk.extend([0] * (4 - len(chunk)))
            
            value = chunk[0] | (chunk[1] << 16) | (chunk[2] << 32) | (chunk[3] << 48)
            result.extend(value.to_bytes(8, byteorder='little'))
            
        return bytes(result)
    
    def decrypt_bytes(self, private_key, ciphertext_bytes):
        """
        Decrypt bytes using NTRU.
        
        Args:
            private_key: NTRU private key
            ciphertext_bytes: Encrypted bytes
            
        Returns:
            bytes: Decrypted message
        """
        # Convert bytes to polynomial
        ciphertext = []
        for i in range(0, len(ciphertext_bytes), 8):
            chunk = int.from_bytes(ciphertext_bytes[i:i+8], byteorder='little')
            ciphertext.extend([
                chunk & 0xFFFF,
                (chunk >> 16) & 0xFFFF,
                (chunk >> 32) & 0xFFFF,
                (chunk >> 48) & 0xFFFF
            ])
        
        ciphertext = ciphertext[:self.n]
        
        # Decrypt
        decrypted_poly = self.decrypt(private_key, ciphertext)
        
        # Convert polynomial to bytes
        result = bytearray()
        for i in range(0, min(len(decrypted_poly), self.n), 8):
            byte = 0
            for j in range(min(8, len(decrypted_poly) - i)):
                if decrypted_poly[i + j] == 1:
                    byte |= (1 << j)
            result.append(byte)
            
        return bytes(result)

def test_ntru():
    """Test the NTRU implementation."""
    ntru = NTRU(n=443, p=3, q=2048)
    
    # Generate key pair
    pk, sk = ntru.keygen()
    
    # Test message
    message = b"This is a test message for NTRU encryption."
    
    # Encrypt
    ciphertext = ntru.encrypt_bytes(pk, message)
    
    # Decrypt
    decrypted = ntru.decrypt_bytes(sk, ciphertext)
    
    print("Original message:", message)
    print("Decrypted message:", decrypted)
    print("Decryption successful:", message[:len(decrypted)] == decrypted)
    
    return message[:len(decrypted)] == decrypted

if __name__ == "__main__":
    test_ntru()