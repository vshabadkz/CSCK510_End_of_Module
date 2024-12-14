import sys
import time
import unicodedata
import random
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from PyPDF2 import PdfReader
from secretpy import (
    ADFGVX, 
    ColumnarTransposition, 
    Zigzag,
    CryptMachine
)
from statistics import mean, stdev
from tabulate import tabulate
from itertools import permutations, product
import string

def normalize_text(text):
    """Normalize text, handling accented characters properly"""
    result = ''
    for c in text:
        normalized = unicodedata.normalize('NFKD', c)
        for base_c in normalized:
            if not unicodedata.combining(base_c) and base_c.isalpha():
                result += base_c.lower()
    return result

def generate_polybius_square(init_vector):
    """Generate a randomized polybius square using the initialization vector"""
    random.seed(init_vector)
    chars = list("abcdefghijklmnopqrstuvwxyz")
    random.shuffle(chars)
    return "".join(chars)

def validate_decryption(original_text, decrypted_text):
    """Compare decrypted text with original to validate cryptanalysis"""
    return original_text == decrypted_text

def measure_encryption(cipher_name, cm, text, num_runs):
    """Stage 1: Measure encryption performance"""
    encryption_times = []
    encrypted_texts = []
    
    print(f"\n{'='*20} Stage 1: Encryption - {cipher_name} {'='*20}")
    print(f"Performing {num_runs} encryption runs...")
    
    for run in range(num_runs):
        start_time = time.time()
        encrypted_text = cm.encrypt(text)
        encrypt_time = (time.time() - start_time) * 1000
        encryption_times.append(encrypt_time)
        encrypted_texts.append(encrypted_text)
    
    avg_time = mean(encryption_times)
    std_time = stdev(encryption_times)
    print(f"Average encryption time: {avg_time:.2f}ms")
    print(f"Standard deviation: {std_time:.2f}ms")
    
    return encrypted_texts, encryption_times

def measure_decryption(cipher_name, cm, encrypted_texts, num_runs):
    """Stage 2: Measure decryption performance"""
    decryption_times = []
    
    print(f"\n{'='*20} Stage 2: Decryption - {cipher_name} {'='*20}")
    print(f"Performing {num_runs} decryption runs...")
    
    for run in range(num_runs):
        start_time = time.time()
        decrypted_text = cm.decrypt(encrypted_texts[run])
        decrypt_time = (time.time() - start_time) * 1000
        decryption_times.append(decrypt_time)
    
    avg_time = mean(decryption_times)
    std_time = stdev(decryption_times)
    print(f"Average decryption time: {avg_time:.2f}ms")
    print(f"Standard deviation: {std_time:.2f}ms")
    
    return decryption_times

def analyze_railfence(encrypted_text, original_text):
    """Cryptanalyze Rail Fence cipher and validate results"""
    start_time = time.time()
    cipher = Zigzag()
    
    # Try all possible rails
    for rails in range(2, 11):
        cm = CryptMachine(cipher)
        cm.set_key(rails)
        try:
            decrypted = cm.decrypt(encrypted_text)
            if validate_decryption(original_text, decrypted):
                return (time.time() - start_time) * 1000, rails, True
        except:
            continue
    
    return (time.time() - start_time) * 1000, None, False

def analyze_columnar(encrypted_text, original_text):
    """Cryptanalyze Columnar Transposition and validate results"""
    start_time = time.time()
    cipher = ColumnarTransposition()
    
    # Try keys up to length 5
    for length in range(2, 6):
        for perm in permutations(range(length)):
            key = ''.join(string.ascii_lowercase[i] for i in perm)
            cm = CryptMachine(cipher)
            cm.set_key(key)
            try:
                decrypted = cm.decrypt(encrypted_text)
                if validate_decryption(original_text, decrypted):
                    return (time.time() - start_time) * 1000, key, True
            except:
                continue
    
    return (time.time() - start_time) * 1000, None, False

def analyze_adfgvx(encrypted_text, original_text):
    """Cryptanalyze ADFGVX cipher and validate results"""
    start_time = time.time()
    cipher = ADFGVX()
    
    # Try different key lengths
    for key_length in range(2, 6):
        # Try possible keys
        for key in [''.join(p) for p in permutations(string.ascii_lowercase[:key_length])]:
            # Try different polybius squares
            for _ in range(100):  # Limit number of square attempts
                square = ''.join(random.sample(string.ascii_lowercase, 26))
                cm = CryptMachine(cipher)
                cm.set_key(key)
                cm.set_alphabet(square)
                try:
                    decrypted = cm.decrypt(encrypted_text)
                    if validate_decryption(original_text, decrypted):
                        return (time.time() - start_time) * 1000, (key, square), True
                except:
                    continue
    
    return (time.time() - start_time) * 1000, None, False

def measure_cryptanalysis(cipher_name, encrypted_texts, original_text, num_runs):
    """Stage 3: Perform cryptanalysis with validation"""
    cryptanalysis_times = []
    successful_runs = 0
    
    print(f"\n{'='*20} Stage 3: Cryptanalysis - {cipher_name} {'='*20}")
    print(f"Performing {num_runs} cryptanalysis runs with result validation...")
    
    for run in range(num_runs):
        if cipher_name == 'ADFGVX':
            time_taken, params, success = analyze_adfgvx(encrypted_texts[run], original_text)
            if run == 0:
                print(f"Found correct key parameters: {params if success else 'FAILED'}")
        elif cipher_name == 'Columnar':
            time_taken, key, success = analyze_columnar(encrypted_texts[run], original_text)
            if run == 0:
                print(f"Found correct key: {key if success else 'FAILED'}")
        else:  # Railfence
            time_taken, rails, success = analyze_railfence(encrypted_texts[run], original_text)
            if run == 0:
                print(f"Found correct rails: {rails if success else 'FAILED'}")
        
        if success:
            successful_runs += 1
        cryptanalysis_times.append(time_taken)
    
    avg_time = mean(cryptanalysis_times)
    std_time = stdev(cryptanalysis_times)
    print(f"Average cryptanalysis time: {avg_time:.2f}ms")
    print(f"Standard deviation: {std_time:.2f}ms")
    print(f"Success rate: {successful_runs}/{num_runs} ({successful_runs/num_runs*100:.1f}%)")
    
    return cryptanalysis_times

def create_comparison_visualizations(results_data, num_runs):
    """Stage 4: Create visualizations and comparison table"""
    print(f"\n{'='*20} Stage 4: Comparison Analysis {'='*20}")
    
    df = pd.DataFrame(results_data)
    
    # Create visualization
    plt.figure(figsize=(15, 5))
    
    # Encryption comparison
    plt.subplot(1, 3, 1)
    sns.boxplot(x='cipher', y='encrypt_time', data=df)
    plt.title('Encryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    # Decryption comparison
    plt.subplot(1, 3, 2)
    sns.boxplot(x='cipher', y='decrypt_time', data=df)
    plt.title('Decryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    # Cryptanalysis comparison
    plt.subplot(1, 3, 3)
    sns.boxplot(x='cipher', y='cryptanalysis_time', data=df)
    plt.title('Cryptanalysis Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    plt.tight_layout()
    plt.savefig('cipher_comparison.png')
    print(f"\nVisualization saved as 'cipher_comparison.png' ({num_runs} runs per cipher)")

    # Calculate and display statistics table
    stats = []
    for cipher in df['cipher'].unique():
        cipher_data = df[df['cipher'] == cipher]
        stats.append({
            'Cipher': cipher,
            'Encrypt Median (ms)': f"{cipher_data['encrypt_time'].median():.2f}",
            'Encrypt StdDev': f"{cipher_data['encrypt_time'].std():.2f}",
            'Decrypt Median (ms)': f"{cipher_data['decrypt_time'].median():.2f}",
            'Decrypt StdDev': f"{cipher_data['decrypt_time'].std():.2f}",
            'Cryptanalysis Median (ms)': f"{cipher_data['cryptanalysis_time'].median():.2f}",
            'Cryptanalysis StdDev': f"{cipher_data['cryptanalysis_time'].std():.2f}"
        })
    
    print("\nStatistical Summary:")
    print(tabulate(stats, headers='keys', tablefmt='pretty', numalign='right'))

def main():
    if len(sys.argv) != 5:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword> <num_runs>")
        sys.exit(1)

    pdf_file = sys.argv[1]
    init_vector = sys.argv[2]
    keyword = sys.argv[3].lower()
    
    try:
        num_runs = int(sys.argv[4])
        if num_runs <= 0:
            raise ValueError("Number of runs must be positive")
    except ValueError as e:
        print(f"Error: Invalid number of runs - {e}")
        sys.exit(1)

    try:
        # Read and normalize input text
        reader = PdfReader(pdf_file)
        normalised_text = normalize_text(''.join(page.extract_text() for page in reader.pages))

        # Initialize ciphers
        ciphers = [
            ('ADFGVX', ADFGVX(), generate_polybius_square(init_vector), keyword),
            ('Columnar', ColumnarTransposition(), None, keyword),
            ('Railfence', Zigzag(), None, 3)
        ]

        # Store all results
        all_results = []

        # Process each cipher through all stages
        for name, cipher, alphabet, key in ciphers:
            cm = CryptMachine(cipher)
            cm.set_key(key)
            if alphabet:
                cm.set_alphabet(alphabet)

            # Stage 1: Encryption
            encrypted_texts, encryption_times = measure_encryption(name, cm, normalised_text, num_runs)
            
            # Stage 2: Decryption
            decryption_times = measure_decryption(name, cm, encrypted_texts, num_runs)
            
            # Stage 3: Cryptanalysis
            cryptanalysis_times = measure_cryptanalysis(name, encrypted_texts, 
                                                      normalised_text, num_runs)

            # Store results
            for i in range(num_runs):
                all_results.append({
                    'cipher': name,
                    'run': i + 1,
                    'encrypt_time': encryption_times[i],
                    'decrypt_time': decryption_times[i],
                    'cryptanalysis_time': cryptanalysis_times[i]
                })

        # Stage 4: Create visualizations and comparison table
        create_comparison_visualizations(all_results, num_runs)

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
