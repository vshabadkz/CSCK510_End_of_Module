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

def measure_performance(cipher_name, cm, text, num_runs=30):
    """Measure encryption and decryption performance"""
    performance_data = []
    
    print(f"\nTesting {cipher_name} cipher...")
    for run in range(num_runs):
        # Measure encryption
        start_time = time.time()
        encrypted_text = cm.encrypt(text)
        encrypt_time = (time.time() - start_time) * 1000
        
        # Measure decryption
        start_time = time.time()
        decrypted_text = cm.decrypt(encrypted_text)
        decrypt_time = (time.time() - start_time) * 1000
        
        # Verify correctness
        if decrypted_text != text:
            print(f"Warning: {cipher_name} decryption mismatch in run {run + 1}!")
        
        performance_data.append({
            'cipher': cipher_name,
            'run': run + 1,
            'encrypt_time': encrypt_time,
            'decrypt_time': decrypt_time
        })
    
    return performance_data

def create_visualizations_and_stats(all_performance_data, num_runs):
    """Create statistical visualizations and summary using seaborn"""
    df = pd.DataFrame(all_performance_data)
    
    # Create visualization
    plt.figure(figsize=(12, 5))
    
    # Encryption/Decryption comparison plot
    plt.subplot(1, 2, 1)
    sns.boxplot(x='cipher', y='encrypt_time', data=df)
    plt.title('Encryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    plt.subplot(1, 2, 2)
    sns.boxplot(x='cipher', y='decrypt_time', data=df)
    plt.title('Decryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    plt.tight_layout()
    plt.savefig('cipher_performance.png')
    print(f"\nVisualization saved as 'cipher_performance.png' (based on {num_runs} runs)")

    # Calculate statistics
    stats = []
    for cipher in df['cipher'].unique():
        cipher_data = df[df['cipher'] == cipher]
        stats.append({
            'Cipher': cipher,
            'Encryption Median (ms)': f"{cipher_data['encrypt_time'].median():.2f}",
            'Encryption StdDev (ms)': f"{cipher_data['encrypt_time'].std():.2f}",
            'Decryption Median (ms)': f"{cipher_data['decrypt_time'].median():.2f}",
            'Decryption StdDev (ms)': f"{cipher_data['decrypt_time'].std():.2f}"
        })
    
    # Print beautiful table
    print("\n" + "="*100)
    print(f"CIPHER PERFORMANCE COMPARISON ({num_runs} runs per cipher)")
    print("="*100)
    print(tabulate(stats, headers='keys', tablefmt='pretty', numalign='right'))
    print("="*100)

def main():
    if len(sys.argv) != 4:
        print("Usage: python encrypt-decrypt.py <pdf_file> <initialisation_vector> <keyword>")
        sys.exit(1)

    pdf_file = sys.argv[1]
    init_vector = sys.argv[2]
    keyword = sys.argv[3].lower()
    num_runs = 30  # Number of test runs per cipher

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

        # Measure performance
        all_performance_data = []
        for name, cipher, alphabet, key in ciphers:
            cm = CryptMachine(cipher)
            cm.set_key(key)
            if alphabet:
                cm.set_alphabet(alphabet)
            
            performance_data = measure_performance(name, cm, normalised_text, num_runs)
            all_performance_data.extend(performance_data)

        # Create visualizations and print statistics
        create_visualizations_and_stats(all_performance_data, num_runs)

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()