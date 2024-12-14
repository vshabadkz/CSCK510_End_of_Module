import sys
import time
import unicodedata
import random
from PyPDF2 import PdfReader
from secretpy import (
    ADFGVX, 
    ColumnarTransposition, 
    Zigzag,
    CryptMachine
)
from statistics import mean, stdev

def normalize_char(c):
    """Normalize a single character, converting accented characters to their base form"""
    normalized = unicodedata.normalize('NFKD', c)
    base_char = ''.join(c for c in normalized if not unicodedata.combining(c))
    return base_char

def normalise_text(text):
    """Normalize text, handling accented characters properly"""
    result = ''
    for c in text:
        norm_c = normalize_char(c)
        for base_c in norm_c:
            if base_c.isalpha():
                result += base_c.lower()
    return result

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

def generate_polybius_square(init_vector):
    """Generate a randomized polybius square using the initialization vector"""
    random.seed(init_vector)
    chars = list("abcdefghijklmnopqrstuvwxyz")
    random.shuffle(chars)
    return "".join(chars)

def measure_performance(cipher_name, cm, text, num_runs=30):
    """Measure encryption and decryption performance"""
    encrypt_times = []
    decrypt_times = []
    encrypted_text = None
    
    for _ in range(num_runs):
        # Measure encryption
        start_time = time.time()
        encrypted_text = cm.encrypt(text)
        encrypt_time = (time.time() - start_time) * 1000
        encrypt_times.append(encrypt_time)
        
        # Measure decryption
        start_time = time.time()
        decrypted_text = cm.decrypt(encrypted_text)
        decrypt_time = (time.time() - start_time) * 1000
        decrypt_times.append(decrypt_time)
        
        # Verify correctness
        if decrypted_text != text:
            print(f"\nWarning: {cipher_name} decryption mismatch!")
    
    return {
        'name': cipher_name,
        'encrypt_avg': mean(encrypt_times),
        'encrypt_std': stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
        'decrypt_avg': mean(decrypt_times),
        'decrypt_std': stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
        'encrypted_length': len(encrypted_text) if encrypted_text else 0
    }

def print_performance_results(results):
    """Print performance comparison results"""
    print("\n=== Performance Comparison ===")
    print(f"{'Cipher':<20} {'Encryption (ms)':<25} {'Decryption (ms)':<25} {'Output Length':<15}")
    print("-" * 85)
    
    for result in results:
        encrypt_stats = f"{result['encrypt_avg']:.2f} ± {result['encrypt_std']:.2f}"
        decrypt_stats = f"{result['decrypt_avg']:.2f} ± {result['decrypt_std']:.2f}"
        print(f"{result['name']:<20} {encrypt_stats:<25} {decrypt_stats:<25} {result['encrypted_length']:<15}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    pdf_file = sys.argv[1]
    init_vector = sys.argv[2]
    keyword = sys.argv[3].lower()

    try:
        # Read and normalize input text
        reader = PdfReader(pdf_file)
        extracted_text = ""
        for page in reader.pages:
            extracted_text += page.extract_text()

        analyze_text_differences(extracted_text, "Extracted Text")
        normalised_text = normalise_text(extracted_text)
        analyze_text_differences(normalised_text, "Normalized Text")

        # Initialize ciphers with their required key types
        ciphers = [
            ('ADFGVX', ADFGVX(), generate_polybius_square(init_vector), keyword),
            ('Columnar', ColumnarTransposition(), None, keyword),
            ('Railfence', Zigzag(), None, 3)  # Using fixed rail count of 3
        ]

        # Measure performance for each cipher
        results = []
        for name, cipher, alphabet, key in ciphers:
            cm = CryptMachine(cipher)
            cm.set_key(key)
            if alphabet:
                cm.set_alphabet(alphabet)
            
            result = measure_performance(name, cm, normalised_text)
            results.append(result)

        # Print performance comparison
        print_performance_results(results)

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()