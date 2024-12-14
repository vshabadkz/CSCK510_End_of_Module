import sys
import time
import unicodedata
import random
from PyPDF2 import PdfReader
from secretpy import ADFGVX, CryptMachine, alphabets as al

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
            if base_c.isalpha():  # Changed to only accept alphabetic characters
                result += base_c.lower()  # Changed to lowercase to match SecretPy's default
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
    special_sample = [c for c in text[:1000] if not c.isalnum()][:10]
    print(f"Sample special chars: {special_sample}")

def generate_polybius_square(init_vector):
    """Generate a randomized polybius square using the initialization vector"""
    random.seed(init_vector)
    # Using lowercase letters and digits for the polybius square
    chars = list("abcdefghijklmnopqrstuvwxyz")
    random.shuffle(chars)
    return "".join(chars)

def main():
    # Check command line arguments
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    # Get command line arguments
    pdf_file = sys.argv[1]
    init_vector = sys.argv[2]
    keyword = sys.argv[3].lower()  # Changed to lowercase to match SecretPy's default

    try:
        start_time = time.time()

        # Initialize the cipher with the polybius square
        cipher = ADFGVX()
        cm = CryptMachine(cipher)
        
        # Set the keyword for columnar transposition
        cm.set_key(keyword)
        
        # Generate and set the polybius square
        polybius_square = generate_polybius_square(init_vector)
        cm.set_alphabet(polybius_square)

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

        print("\nPolybius Square being used:")
        print(polybius_square)
        print("\nKeyword being used:")
        print(keyword)

        # Encrypt using SecretPy's ADFGVX
        encrypted_text = cm.encrypt(normalised_text)
        analyze_text_differences(encrypted_text, "Encrypted Text")

        # Decrypt using SecretPy's ADFGVX
        decrypted_text = cm.decrypt(encrypted_text)
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