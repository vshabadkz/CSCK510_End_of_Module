import time
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os
import random
import string
from math import sqrt, ceil
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor

# Parameters
NUM_ITERATIONS = 10  # Reduced number of iterations for faster execution
NUM_CORES = os.cpu_count()  # Dynamically retrieve the number of cores

# Results storage
results = []

# Helper Functions
def time_execution(func, *args, iterations=NUM_ITERATIONS):
    """Measure the average execution time of a function over multiple iterations."""
    start = time.time()
    for _ in range(iterations):
        func(*args)
    elapsed_time = (time.time() - start) * 1000 / iterations
    return elapsed_time

def generate_random_text(length):
    """Generate a random alphanumeric string of a given length."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def create_matrix(text, key_length, fill_empty=False):
    """Create a matrix for transposition ciphers."""
    rows = -(-len(text) // key_length)  # Ceiling division
    matrix = [list(text[i:i + key_length]) for i in range(0, len(text), key_length)]
    if fill_empty and len(matrix[-1]) < key_length:
        matrix[-1].extend(['_'] * (key_length - len(matrix[-1])))
    return matrix

def generate_substitution_map():
    """Generate a random substitution map for ADFGVX."""
    alphabet = string.ascii_lowercase + string.digits
    adfgvx_set = "ADFGVX"
    substitution_map = {char: random.choice(adfgvx_set) + random.choice(adfgvx_set) for char in alphabet}
    return substitution_map

def reverse_substitution_map(substitution_map):
    """Generate the reverse substitution map."""
    return {v: k for k, v in substitution_map.items()}

# Cipher Implementations
def columnar_encrypt(text, key_length):
    """Perform Columnar Transposition Encryption."""
    matrix = create_matrix(text, key_length)
    return ''.join(row[col] for col in range(key_length) for row in matrix if col < len(row))

def columnar_decrypt(ciphertext, key_length):
    """Perform Columnar Transposition Decryption."""
    rows = -(-len(ciphertext) // key_length)
    matrix = [[''] * key_length for _ in range(rows)]
    idx = 0
    for col in range(key_length):
        for row in range(rows):
            if idx < len(ciphertext):
                matrix[row][col] = ciphertext[idx]
                idx += 1
    return ''.join(''.join(row) for row in matrix).strip('_')

def rail_fence_encrypt(text, key_length):
    """Perform Rail Fence Encryption."""
    fence = [[] for _ in range(key_length)]
    rail, direction = 0, 1
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(ciphertext, key_length):
    """Perform Rail Fence Decryption."""
    fence = [[] for _ in range(key_length)]
    rail, direction = 0, 1
    for _ in ciphertext:
        fence[rail].append(None)
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1
    idx = 0
    for row in fence:
        for i in range(len(row)):
            row[i] = ciphertext[idx]
            idx += 1
    plaintext, rail, direction = [], 0, 1
    for _ in ciphertext:
        plaintext.append(fence[rail].pop(0))
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1
    return ''.join(plaintext)

def adfgvx_encrypt_wrapped(text, key_length, substitution_map):
    """Wrapper for ADFGVX encryption to make it picklable."""
    substituted_text = ''.join(substitution_map.get(char, char) for char in text)
    ciphertext = columnar_encrypt(substituted_text, key_length)
    return ciphertext, ceil(sqrt(len(substituted_text)))

def adfgvx_decrypt_wrapped(ciphertext, key_length, substitution_map):
    """Wrapper for ADFGVX decryption to make it picklable."""
    reverse_map = reverse_substitution_map(substitution_map)
    substituted_text = columnar_decrypt(ciphertext, key_length)
    plaintext = ''.join(reverse_map.get(substituted_text[i:i+2], '') for i in range(0, len(substituted_text), 2))
    return plaintext

# Analysis Function
def process_cipher_analysis(args):
    """Process a single cipher analysis task."""
    cipher_name, encrypt_fn, decrypt_fn, text_length, key_length, substitution_map = args
    text = generate_random_text(text_length)
    if cipher_name == "ADFGVX":
        ciphertext, square_dim = encrypt_fn(text, key_length, substitution_map)
    else:
        ciphertext = encrypt_fn(text, key_length)
        square_dim = None
    encrypt_time = time_execution(encrypt_fn, text, key_length, substitution_map) if cipher_name == "ADFGVX" else time_execution(encrypt_fn, text, key_length)
    decrypt_time = time_execution(decrypt_fn, ciphertext, key_length, substitution_map) if cipher_name == "ADFGVX" else time_execution(decrypt_fn, ciphertext, key_length)
    return [
        {
            "Cipher": cipher_name,
            "Text Length": text_length,
            "Key Length": key_length,
            "Square Dimension": square_dim,
            "Phase": "Encryption",
            "Time (ms)": encrypt_time,
        },
        {
            "Cipher": cipher_name,
            "Text Length": text_length,
            "Key Length": key_length,
            "Square Dimension": square_dim,
            "Phase": "Decryption",
            "Time (ms)": decrypt_time,
        },
    ]

def analyse_ciphers(text_lengths, key_lengths):
    """Analyse and compare the performance of all ciphers using parallel processing."""
    substitution_map = generate_substitution_map()

    ciphers = {
        "Columnar": (columnar_encrypt, columnar_decrypt),
        "Rail Fence": (rail_fence_encrypt, rail_fence_decrypt),
        "ADFGVX": (adfgvx_encrypt_wrapped, adfgvx_decrypt_wrapped),
    }

    tasks = []
    for cipher_name, (encrypt_fn, decrypt_fn) in ciphers.items():
        for text_length in text_lengths:
            for key_length in key_lengths:
                if key_length > text_length:
                    continue  # Skip invalid cases
                tasks.append((cipher_name, encrypt_fn, decrypt_fn, text_length, key_length, substitution_map))

    # Use parallel processing to run tasks
    with ProcessPoolExecutor(max_workers=NUM_CORES) as executor:
        for result_set in tqdm(executor.map(process_cipher_analysis, tasks), total=len(tasks)):
            results.extend(result_set)


# Visualisation
def visualise_results(df):
    """Visualise and save performance analysis plots."""
    sns.set_style("whitegrid")
    fig, axes = plt.subplots(1, 3, figsize=(20, 6))

    # Encryption/Decryption Time vs Key Length
    sns.lineplot(data=df, x="Key Length", y="Time (ms)", hue="Cipher", style="Phase", ax=axes[0])
    axes[0].set_title("Time vs Key Length")
    axes[0].set_xlabel("Key Length")
    axes[0].set_ylabel("Time (ms)")

    # Encryption/Decryption Time vs Text Length
    sns.lineplot(data=df, x="Text Length", y="Time (ms)", hue="Cipher", style="Phase", ax=axes[1])
    axes[1].set_xscale("log")  # Log scale for text length
    axes[1].set_title("Time vs Log(Text Length)")
    axes[1].set_xlabel("Text Length (Log Scale)")
    axes[1].set_ylabel("Time (ms)")

    # ADFGVX: Time vs Side Length of a Square
    adfgvx_df = df[df["Cipher"] == "ADFGVX"]
    sns.lineplot(data=adfgvx_df, x="Square Dimension", y="Time (ms)", hue="Phase", ax=axes[2])
    axes[2].set_title("ADFGVX: Time vs Side Length of a Square")
    axes[2].set_xlabel("Side Length of a Square")
    axes[2].set_ylabel("Time (ms)")

    fig.suptitle(f"Cipher Performance Analysis ({NUM_ITERATIONS} Iterations, {NUM_CORES} Cores)", fontsize=16)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig("cipher_performance_analysis.png")
    print("Plots saved to 'cipher_performance_analysis.png'")
    plt.show()

# Main Execution
if __name__ == "__main__":
    key_lengths = [2, 4, 6, 8, 10, 20, 50]
    text_lengths = [100, 500, 1000, 5000, 10000, 50000, 100000]

    # Analyse and Visualise
    analyse_ciphers(text_lengths, key_lengths)
    df = pd.DataFrame(results)
    df.to_csv("cipher_performance_results.csv", index=False)  # Save results for offline analysis
    visualise_results(df)
