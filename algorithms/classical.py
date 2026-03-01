"""
Classical encryption algorithms: Playfair, Hill, Vigenère, Rail Fence, Columnar Transposition
"""
import numpy as np
import re
from typing import List, Tuple


class PlayfairCipher:
    """Playfair cipher implementation."""
    
    def __init__(self, key: str):
        """Initialize Playfair cipher with a key.
        
        Args:
            key: Keyword for generating the Playfair matrix (letters only)
        """
        self.key = self._prepare_key(key.upper())
        self.matrix = self._generate_matrix()
        self.positions = self._generate_position_map()
    
    def _prepare_key(self, key: str) -> str:
        """Remove duplicates and non-letters from key, replace J with I."""
        key = key.replace('J', 'I')
        seen = set()
        result = []
        for char in key:
            if char.isalpha() and char not in seen:
                seen.add(char)
                result.append(char)
        return ''.join(result)
    
    def _generate_matrix(self) -> List[List[str]]:
        """Generate 5x5 Playfair matrix."""
        # Start with key letters
        chars = list(self.key)
        
        # Add remaining letters (excluding J)
        for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if char not in chars:
                chars.append(char)
        
        # Create 5x5 matrix
        matrix = []
        for i in range(5):
            matrix.append(chars[i*5:(i+1)*5])
        return matrix
    
    def _generate_position_map(self) -> dict:
        """Create a map of letter positions in the matrix."""
        positions = {}
        for i in range(5):
            for j in range(5):
                positions[self.matrix[i][j]] = (i, j)
        return positions
    
    def _prepare_text(self, text: str) -> str:
        """Prepare text for encryption (uppercase, no spaces, handle doubles)."""
        text = text.upper().replace('J', 'I')
        text = ''.join(filter(str.isalpha, text))
        
        # Split into digraphs, inserting X between doubles
        result = []
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                result.append(text[i] + 'X')
                i += 1
            elif text[i] == text[i+1]:
                result.append(text[i] + 'X')
                i += 1
            else:
                result.append(text[i] + text[i+1])
                i += 2
        
        return ''.join(result)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Playfair cipher."""
        prepared = self._prepare_text(plaintext)
        result = []
        
        for i in range(0, len(prepared), 2):
            a, b = prepared[i], prepared[i+1]
            row_a, col_a = self.positions[a]
            row_b, col_b = self.positions[b]
            
            if row_a == row_b:
                # Same row: shift right
                result.append(self.matrix[row_a][(col_a + 1) % 5])
                result.append(self.matrix[row_b][(col_b + 1) % 5])
            elif col_a == col_b:
                # Same column: shift down
                result.append(self.matrix[(row_a + 1) % 5][col_a])
                result.append(self.matrix[(row_b + 1) % 5][col_b])
            else:
                # Rectangle: swap columns
                result.append(self.matrix[row_a][col_b])
                result.append(self.matrix[row_b][col_a])
        
        return ''.join(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Playfair cipher."""
        ciphertext = ciphertext.upper().replace(' ', '')
        result = []
        
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i+1]
            row_a, col_a = self.positions[a]
            row_b, col_b = self.positions[b]
            
            if row_a == row_b:
                # Same row: shift left
                result.append(self.matrix[row_a][(col_a - 1) % 5])
                result.append(self.matrix[row_b][(col_b - 1) % 5])
            elif col_a == col_b:
                # Same column: shift up
                result.append(self.matrix[(row_a - 1) % 5][col_a])
                result.append(self.matrix[(row_b - 1) % 5][col_b])
            else:
                # Rectangle: swap columns
                result.append(self.matrix[row_a][col_b])
                result.append(self.matrix[row_b][col_a])
        
        return ''.join(result)


class HillCipher:
    """Hill cipher implementation (2x2 matrix)."""
    
    def __init__(self, key_matrix: List[List[int]]):
        """Initialize Hill cipher with a key matrix.
        
        Args:
            key_matrix: 2x2 matrix of integers for encryption
        """
        self.key_matrix = np.array(key_matrix)
        if self.key_matrix.shape != (2, 2):
            raise ValueError("Key matrix must be 2x2")
        
        # Calculate determinant and check if it's coprime with 26
        det = int(np.linalg.det(self.key_matrix)) % 26
        if self._gcd(det, 26) != 1:
            raise ValueError("Key matrix determinant must be coprime with 26")
        
        self.inv_key_matrix = self._matrix_mod_inv(self.key_matrix, 26)
    
    def _gcd(self, a: int, b: int) -> int:
        """Calculate greatest common divisor."""
        while b:
            a, b = b, a % b
        return a
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular multiplicative inverse."""
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError("Modular inverse does not exist")
    
    def _matrix_mod_inv(self, matrix: np.ndarray, modulus: int) -> np.ndarray:
        """Calculate modular inverse of 2x2 matrix."""
        det = int(np.linalg.det(matrix)) % modulus
        det_inv = self._mod_inverse(det, modulus)
        
        # For 2x2 matrix: [[a,b],[c,d]] -> [[d,-b],[-c,a]]
        inv = np.array([[matrix[1,1], -matrix[0,1]], 
                       [-matrix[1,0], matrix[0,0]]])
        
        return (det_inv * inv) % modulus
    
    def _text_to_numbers(self, text: str) -> List[int]:
        """Convert text to numbers (A=0, B=1, ...)."""
        text = text.upper()
        return [ord(char) - ord('A') for char in text if char.isalpha()]
    
    def _numbers_to_text(self, numbers: List[int]) -> str:
        """Convert numbers back to text."""
        return ''.join(chr(num + ord('A')) for num in numbers)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Hill cipher."""
        numbers = self._text_to_numbers(plaintext)
        
        # Pad if odd length
        if len(numbers) % 2 != 0:
            numbers.append(ord('X') - ord('A'))
        
        result = []
        for i in range(0, len(numbers), 2):
            vector = np.array([numbers[i], numbers[i+1]])
            encrypted = np.dot(self.key_matrix, vector) % 26
            result.extend(encrypted.tolist())
        
        return self._numbers_to_text(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Hill cipher."""
        numbers = self._text_to_numbers(ciphertext)
        
        result = []
        for i in range(0, len(numbers), 2):
            vector = np.array([numbers[i], numbers[i+1]])
            decrypted = np.dot(self.inv_key_matrix, vector) % 26
            result.extend([int(x) for x in decrypted])
        
        return self._numbers_to_text(result)


class VigenereCipher:
    """Vigenère cipher implementation."""
    
    def __init__(self, key: str):
        """Initialize Vigenère cipher with a key.
        
        Args:
            key: Keyword for encryption (letters only)
        """
        self.key = ''.join(filter(str.isalpha, key.upper()))
        if not self.key:
            raise ValueError("Key must contain at least one letter")
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Vigenère cipher."""
        plaintext = plaintext.upper()
        result = []
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                # Shift by key letter
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                encrypted = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
                result.append(encrypted)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Vigenère cipher."""
        ciphertext = ciphertext.upper()
        result = []
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                # Shift back by key letter
                shift = ord(self.key[key_index % len(self.key)]) - ord('A')
                decrypted = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
                result.append(decrypted)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)


class DoubleRailFenceCipher:
    """Double Rail Fence cipher (rail fence applied twice)."""
    
    def __init__(self, rails1: int, rails2: int):
        """Initialize Double Rail Fence cipher.
        
        Args:
            rails1: Number of rails for first pass
            rails2: Number of rails for second pass
        """
        if rails1 < 2 or rails2 < 2:
            raise ValueError("Number of rails must be at least 2")
        self.rails1 = rails1
        self.rails2 = rails2
    
    def _rail_fence_encrypt(self, text: str, rails: int) -> str:
        """Single rail fence encryption."""
        if len(text) == 0:
            return text
        
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        return ''.join([''.join(rail) for rail in fence])
    
    def _rail_fence_decrypt(self, text: str, rails: int) -> str:
        """Single rail fence decryption."""
        if len(text) == 0:
            return text
        
        # Calculate lengths of each rail
        fence = [[] for _ in range(rails)]
        rail_lengths = [0] * rails
        rail = 0
        direction = 1
        
        for _ in text:
            rail_lengths[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        # Fill fence with characters
        index = 0
        for i in range(rails):
            fence[i] = list(text[index:index + rail_lengths[i]])
            index += rail_lengths[i]
        
        # Read in zigzag pattern
        result = []
        rail = 0
        direction = 1
        
        for _ in text:
            result.append(fence[rail].pop(0))
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        
        return ''.join(result)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt using double rail fence."""
        # Remove spaces for cleaner encryption
        plaintext = plaintext.replace(' ', '')
        # First pass
        temp = self._rail_fence_encrypt(plaintext, self.rails1)
        # Second pass
        return self._rail_fence_encrypt(temp, self.rails2)
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt using double rail fence."""
        # Reverse order: second pass first
        temp = self._rail_fence_decrypt(ciphertext, self.rails2)
        # Then first pass
        return self._rail_fence_decrypt(temp, self.rails1)


class DoubleColumnarTransposition:
    """Double Columnar Transposition cipher."""
    
    def __init__(self, key1: str, key2: str):
        """Initialize Double Columnar Transposition cipher.
        
        Args:
            key1: First keyword
            key2: Second keyword
        """
        self.key1 = key1.upper()
        self.key2 = key2.upper()
        self.order1 = self._get_column_order(self.key1)
        self.order2 = self._get_column_order(self.key2)
    
    def _get_column_order(self, key: str) -> List[int]:
        """Get column order based on alphabetical sorting of key."""
        indexed_key = [(char, i) for i, char in enumerate(key)]
        sorted_key = sorted(indexed_key)
        return [i for _, i in sorted_key]
    
    def _get_inverse_order(self, order: List[int]) -> List[int]:
        """Get inverse permutation of column order."""
        inverse = [0] * len(order)
        for i, val in enumerate(order):
            inverse[val] = i
        return inverse
    
    def _columnar_encrypt(self, text: str, order: List[int], key_len: int) -> str:
        """Single columnar transposition encryption."""
        # Pad text to fill the grid
        padding_needed = (key_len - len(text) % key_len) % key_len
        text += 'X' * padding_needed
        
        # Create grid
        num_rows = len(text) // key_len
        grid = [text[i*key_len:(i+1)*key_len] for i in range(num_rows)]
        
        # Read columns in order
        result = []
        for col_idx in order:
            for row in grid:
                if col_idx < len(row):
                    result.append(row[col_idx])
        
        return ''.join(result)
    
    def _columnar_decrypt(self, text: str, order: List[int], key_len: int) -> str:
        """Single columnar transposition decryption."""
        num_rows = len(text) // key_len
        if len(text) % key_len != 0:
            # Handle padding
            num_rows +=1
        
        # Create empty grid
        grid = [['' for _ in range(key_len)] for _ in range(num_rows)]
        
        # Get inverse order to know which columns were filled in which order
        inverse_order = self._get_inverse_order(order)
        
        # Fill columns in the order they were written during encryption
        text_idx = 0
        for write_order_idx in range(key_len):
            # Find which original column position this corresponds to
            col_idx = order[write_order_idx]
            for row in range(num_rows):
                if text_idx < len(text):
                    grid[row][col_idx] = text[text_idx]
                    text_idx += 1
        
        # Read rows
        result = []
        for row in grid:
            result.extend(row)
        
        return ''.join(result).rstrip('X')
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt using double columnar transposition."""
        # Remove spaces
        plaintext = plaintext.replace(' ', '').upper()
        # First pass
        temp = self._columnar_encrypt(plaintext, self.order1, len(self.key1))
        # Second pass
        return self._columnar_encrypt(temp, self.order2, len(self.key2))
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt using double columnar transposition."""
        # Reverse order: second pass first
        temp = self._columnar_decrypt(ciphertext, self.order2, len(self.key2))
        # Then first pass
        return self._columnar_decrypt(temp, self.order1, len(self.key1))
