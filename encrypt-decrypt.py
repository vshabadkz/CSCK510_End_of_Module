import sys
import random
import time
import unicodedata
from PyPDF2 import PdfReader

class CustomADFGVX:
    def __init__(self, key, keyword):
        self.chars = 'ADFGVX'
        self.key = key
        self.keyword = keyword.upper()
        
    def get_coordinates(self, char):
        pos = self.key.find(char)
        if pos == -1:
            return None
        return (pos // 6, pos % 6)
        
    def get_char(self, row, col):
        return self.key[row * 6 + col]
        
    def encrypt(self, text):
        # First substitution
        intermediate = ''
        for char in text:
            coords = self.get_coordinates(char)
            if coords:
                intermediate += self.chars[coords[0]] + self.chars[coords[1]]
            
        # Columnar transposition
        columns = [''] * len(self.keyword)
        col_index = 0
        for char in intermediate:
            columns[col_index] += char
            col_index = (col_index + 1) % len(self.keyword)
            
        # Sort columns according to keyword
        sorted_cols = [col for _, col in sorted(zip(self.keyword, columns))]
        return ''.join(sorted_cols)
        
    def decrypt(self, text):
        # Reverse columnar transposition
        col_length = len(text) // len(self.keyword)
        remainder = len(text) % len(self.keyword)
        
        columns = [''] * len(self.keyword)
        pos = 0
        
        # Reconstruct columns
        sorted_indices = [i for i, _ in sorted(enumerate(self.keyword), key=lambda x: x[1])]
        for idx in sorted_indices:
            length = col_length + (1 if idx < remainder else 0)
            columns[idx] = text[pos:pos + length]
            pos += length
            
        # Read off original text
        intermediate = ''
        for i in range(max(len(c) for c in columns)):
            for j in range(len(columns)):
                if i < len(columns[j]):
                    intermediate += columns[j][i]
                    
        # Reverse substitution
        result = ''
        for i in range(0, len(intermediate), 2):
            if i + 1 < len(intermediate):
                row = self.chars.index(intermediate[i])
                col = self.chars.index(intermediate[i + 1])
                result += self.get_char(row, col)
                
        return result

def normalize_char(c):
    """Normalize a single character, converting accented characters to their base form"""
    # Decompose the character into its base form and combining marks
    normalized = unicodedata.normalize('NFKD', c)
    # Keep only the base character (remove combining marks)
    base_char = ''.join(c for c in normalized if not unicodedata.combining(c))
    return base_char

def normalise_text(text):
    """Normalize text, handling accented characters properly"""
    result = ''
    for c in text:
        # First normalize any accented characters
        norm_c = normalize_char(c)
        # Then keep only alphanumeric characters and convert to uppercase
        for base_c in norm_c:
            if base_c.isalnum():
                result += base_c.upper()
    return result

def generate_square(initialisation_vector):
    """Generate the substitution square using the initialization vector"""
    random.seed(initialisation_vector)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.sample(alphabet, len(alphabet)))

def analyze_text_differences(text, label="Text"):
    """Analyze and print text characteristics"""
    total_chars = len(text)
    alpha_chars = sum(c.isalnum() for c in text)
    special_chars = total_chars - alpha_chars
    
    print(f"\n=== Analysis of {label} ===")
    print(f"Total characters: {total_chars}")
    print(f"Alphanumeric characters: {alpha_chars}")
    print(f"Special characters: {special_chars}")
    print(f"First 50 characters: {text[:50]}")
    special_sample = [c for c in text[:1000] if not c.isalnum()][:10]
    print(f"Sample special chars: {special_sample}")

def main():
    # Check command line arguments
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    # Get command line arguments
    pdf_file = sys.argv[1]
    initialisation_vector = sys.argv[2]
    keyword = sys.argv[3]

    # Initialize cipher
    square = generate_square(initialisation_vector)
    cipher = CustomADFGVX(square, keyword)

    try:
        start_time = time.time()

        # Read PDF file
        reader = PdfReader(pdf_file)
        extracted_text = ""
        for page in reader.pages:
            extracted_text += page.extract_text()

        # Analyze and process text
        analyze_text_differences(extracted_text, "Extracted Text")
        print("\nSample of original text with potential special characters:")
        special_chars = [c for c in extracted_text[:1000] if unicodedata.combining(c) or ord(c) > 127]
        print(f"Special characters found: {special_chars}")

        normalised_text = normalise_text(extracted_text)
        analyze_text_differences(normalised_text, "Normalized Text")

        encrypted_text = cipher.encrypt(normalised_text)
        analyze_text_differences(encrypted_text, "Encrypted Text")

        decrypted_text = cipher.decrypt(encrypted_text)
        analyze_text_differences(decrypted_text, "Decrypted Text")

        # Compare results
        if normalised_text == decrypted_text:
            print("\nComparison: Decrypted text matches the original text.")
        else:
            print("\nComparison: Decrypted text does NOT match the original text.")
            mismatches = [(i, n, d) for i, (n, d) in enumerate(zip(normalised_text, decrypted_text)) if n != d]
            if mismatches:
                print(f"Found {len(mismatches)} mismatches. First few:")
                for i, n, d in mismatches[:3]:
                    context_original = normalised_text[max(0, i-5):i+15]
                    context_decrypted = decrypted_text[max(0, i-5):i+15]
                    print(f"\nPosition {i}:")
                    print(f"Original context: {context_original}")
                    print(f"Decrypted context: {context_decrypted}")

        # Print execution time
        end_time = time.time()
        elapsed_time_ms = (end_time - start_time) * 1000
        print(f"\nExecution time: {elapsed_time_ms:.2f} ms")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()