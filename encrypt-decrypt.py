import sys
import time
import unicodedata
import random
from PyPDF2 import PdfReader
from secretpy import ADFGVX, CryptMachine

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

def main():
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    pdf_file = sys.argv[1]
    init_vector = sys.argv[2]
    keyword = sys.argv[3].lower()

    try:
        start_time = time.time()

        cipher = ADFGVX()
        cm = CryptMachine(cipher)
        cm.set_key(keyword)
        cm.set_alphabet(generate_polybius_square(init_vector))

        reader = PdfReader(pdf_file)
        extracted_text = ""
        for page in reader.pages:
            extracted_text += page.extract_text()

        analyze_text_differences(extracted_text, "Extracted Text")
        normalised_text = normalise_text(extracted_text)
        analyze_text_differences(normalised_text, "Normalized Text")

        encrypted_text = cm.encrypt(normalised_text)
        analyze_text_differences(encrypted_text, "Encrypted Text")

        decrypted_text = cm.decrypt(encrypted_text)
        analyze_text_differences(decrypted_text, "Decrypted Text")

        if normalised_text == decrypted_text:
            print("\nComparison: Decrypted text matches the original text.")
        else:
            print("\nComparison: Decrypted text does NOT match the original text.")

        end_time = time.time()
        elapsed_time_ms = (end_time - start_time) * 1000
        print(f"\nExecution time: {elapsed_time_ms:.2f} ms")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()