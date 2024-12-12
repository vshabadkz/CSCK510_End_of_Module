import sys
import random
import time
from PyPDF2 import PdfReader
from pycipher import ADFGVX

def generate_square(initialisation_vector):
    random.seed(initialisation_vector)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    shuffled = ''.join(random.sample(alphabet, len(alphabet)))
    return shuffled

def normalise_text(text):
    # Keep only alphanumeric characters and convert to uppercase
    return ''.join(filter(str.isalnum, text.upper()))

def adfgvx_encrypt(plaintext, square, keyword):
    # Real ADFGVX encryption implementation using the pycipher library
    cipher = ADFGVX(key=square, keyword=keyword)
    return cipher.encipher(plaintext)

def adfgvx_decrypt(ciphertext, square, keyword):
    # Real ADFGVX decryption implementation using the pycipher library
    cipher = ADFGVX(key=square, keyword=keyword)
    return cipher.decipher(ciphertext)

def main():
    # Check if the required arguments are provided
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    # Get the command-line arguments
    pdf_file = sys.argv[1]
    initialisation_vector = sys.argv[2]
    keyword = sys.argv[3]

    # Generate the square using the initialization vector
    square = generate_square(initialisation_vector)

    try:
        start_time = time.time()  # Start timing

        # Create a PdfReader object
        reader = PdfReader(pdf_file)

        # Extract text from all pages
        extracted_text = ""
        for page in reader.pages:
            extracted_text += page.extract_text()

        # Normalise the text by keeping only alphanumeric characters
        normalised_text = normalise_text(extracted_text)

        # Encrypt and decrypt the normalised text
        encrypted_text = adfgvx_encrypt(normalised_text, square, keyword)
        decrypted_text = adfgvx_decrypt(encrypted_text, square, keyword)

        # Compare the normalised text with the decrypted text
        if normalised_text == decrypted_text:
            print("Comparison: Decrypted text matches the original text.")
        else:
            print("Comparison: Decrypted text does NOT match the original text.")

        end_time = time.time()  # End timing
        elapsed_time_ms = (end_time - start_time) * 1000
        print(f"Execution time: {elapsed_time_ms:.2f} ms")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
