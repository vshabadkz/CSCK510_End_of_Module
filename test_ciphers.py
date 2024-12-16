import time
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os
import random
import string
import numpy as np
from math import ceil, sqrt
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor

# Parameters
NUM_ITERATIONS = 50
NUM_CORES = os.cpu_count()
results = []

# Helper Functions
def time_execution(func, *args, iterations=NUM_ITERATIONS):
    start = time.time()
    for _ in range(iterations):
        func(*args)
    elapsed_time = (time.time() - start) * 1000 / iterations
    return elapsed_time

def generate_random_text(length):
    """Generate random alphanumeric text."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_substitution_map():
    """Generate a substitution map for ADFGVX."""
    alphabet = string.ascii_lowercase + string.digits
    adfgvx_set = "ADFGVX"
    return {char: random.choice(adfgvx_set) + random.choice(adfgvx_set) for char in alphabet}

def reverse_substitution_map(substitution_map):
    """Generate the reverse substitution map."""
    return {v: k for k, v in substitution_map.items()}

# Cipher Implementations with NumPy
def columnar_encrypt(text, key_length):
    """Encrypt using Columnar Transposition Cipher."""
    rows = ceil(len(text) / key_length)
    # Create a padded matrix and encrypt column by column
    matrix = np.array(list(text.ljust(rows * key_length, "_"))).reshape(rows, key_length)
    return ''.join(''.join(matrix[:, col]) for col in range(key_length))


def columnar_decrypt(ciphertext, key_length):
    """Decrypt using Columnar Transposition Cipher."""
    rows = ceil(len(ciphertext) / key_length)
    matrix = np.empty((rows, key_length), dtype="U1")
    idx = 0
    for col in range(key_length):
        for row in range(rows):
            if idx < len(ciphertext):
                matrix[row, col] = ciphertext[idx]
                idx += 1
    # Flatten the matrix row-wise and strip padding
    return ''.join(matrix.flatten()).rstrip("_")

def rail_fence_encrypt(text, key_length):
    """Encrypt using Rail Fence Cipher."""
    fence = np.zeros((key_length, len(text)), dtype="U1")
    rail, direction = 0, 1
    for idx, char in enumerate(text):
        fence[rail, idx] = char
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1
    return ''.join(fence[fence != ''])

def rail_fence_decrypt(ciphertext, key_length):
    """Decrypt using Rail Fence Cipher."""
    # Step 1: Determine the zigzag pattern (fence positions)
    fence = np.zeros((key_length, len(ciphertext)), dtype=bool)
    rail, direction = 0, 1
    for idx in range(len(ciphertext)):
        fence[rail, idx] = True
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1

    # Step 2: Fill the fence with ciphertext characters
    idx = 0
    plaintext = np.empty_like(fence, dtype="U1")
    for row in range(key_length):
        for col in range(len(ciphertext)):
            if fence[row, col]:
                plaintext[row, col] = ciphertext[idx]
                idx += 1

    # Step 3: Reconstruct the plaintext from the zigzag pattern
    rail, direction = 0, 1
    result = []
    for col in range(len(ciphertext)):
        result.append(plaintext[rail, col])
        rail += direction
        if rail == 0 or rail == key_length - 1:
            direction *= -1
    return ''.join(result)

def adfgvx_encrypt_wrapped(text, key_length, substitution_map):
    """Encrypt using ADFGVX Cipher (wrapper)."""
    substituted_text = ''.join(substitution_map.get(char, char) for char in text)
    return columnar_encrypt(substituted_text, key_length), ceil(sqrt(len(substituted_text)))

def adfgvx_decrypt_wrapped(ciphertext, key_length, substitution_map):
    """Decrypt using ADFGVX Cipher (wrapper)."""
    reverse_map = reverse_substitution_map(substitution_map)
    substituted_text = columnar_decrypt(ciphertext, key_length)
    return ''.join(reverse_map.get(substituted_text[i:i+2], '') for i in range(0, len(substituted_text), 2))

# Analysis and Results Processing
def process_cipher_analysis(args):
    cipher_name, encrypt_fn, decrypt_fn, text_length, key_length, substitution_map = args
    text = generate_random_text(text_length)
    
    if cipher_name == "ADFGVX":
        ciphertext, square_dim = encrypt_fn(text, key_length, substitution_map)
    else:
        ciphertext = encrypt_fn(text, key_length)
        square_dim = None  # Square Dimension only applies to ADFGVX
    
    encrypt_time = time_execution(encrypt_fn, text, key_length, substitution_map) if cipher_name == "ADFGVX" else time_execution(encrypt_fn, text, key_length)
    decrypt_time = time_execution(decrypt_fn, ciphertext, key_length, substitution_map) if cipher_name == "ADFGVX" else time_execution(decrypt_fn, ciphertext, key_length)
    
    return [
        {
            "Cipher": cipher_name,
            "Phase": "Encryption",
            "Key Length": key_length,
            "Text Length": text_length,
            "Square Dimension": square_dim,  # Include Square Dimension
            "Time (ms)": encrypt_time,
        },
        {
            "Cipher": cipher_name,
            "Phase": "Decryption",
            "Key Length": key_length,
            "Text Length": text_length,
            "Square Dimension": square_dim,  # Include Square Dimension
            "Time (ms)": decrypt_time,
        },
    ]

def analyse_ciphers(text_lengths, key_lengths):
    substitution_map = generate_substitution_map()
    ciphers = {
        "Columnar": (columnar_encrypt, columnar_decrypt),
        "Rail Fence": (rail_fence_encrypt, rail_fence_decrypt),
        "ADFGVX": (adfgvx_encrypt_wrapped, adfgvx_decrypt_wrapped)
    }
    tasks = [(name, *funcs, t, k, substitution_map) for name, funcs in ciphers.items() for t in text_lengths for k in key_lengths if k <= t]
    with ProcessPoolExecutor(max_workers=NUM_CORES) as executor:
        for result_set in tqdm(executor.map(process_cipher_analysis, tasks), total=len(tasks)):
            results.extend(result_set)

def visualise_results(df):
    sns.set_style("whitegrid")
    cipher_order = ["ADFGVX", "Columnar", "Rail Fence"]
    df["Cipher"] = pd.Categorical(df["Cipher"], categories=cipher_order, ordered=True)

    # Plot 1: Time vs Key Length
    plt.figure(figsize=(8, 6))
    sns.lineplot(data=df, x="Key Length", y="Time (ms)", hue="Cipher", style="Phase", hue_order=cipher_order)
    plt.title("Time vs Key Length")
    plt.tight_layout()
    plt.savefig("time_vs_key_length.png")
    plt.close()

    # Plot 2: Time vs Log(Text Length)
    plt.figure(figsize=(8, 6))
    sns.lineplot(data=df, x="Text Length", y="Time (ms)", hue="Cipher", style="Phase", hue_order=cipher_order)
    plt.xscale("log")
    plt.title("Time vs Log(Text Length)")
    plt.tight_layout()
    plt.savefig("time_vs_text_length.png")
    plt.close()

    # Plot 3: ADFGVX Time vs Side Length
    adfgvx_df = df[df["Cipher"] == "ADFGVX"]
    plt.figure(figsize=(8, 6))
    sns.lineplot(data=adfgvx_df, x="Square Dimension", y="Time (ms)", hue="Phase")
    plt.title("ADFGVX: Time vs Side Length of a Square")
    plt.tight_layout()
    plt.savefig("adfgvx_time_vs_square.png")
    plt.close()


if __name__ == "__main__":
    key_lengths = [2, 4, 6, 8, 10, 20, 50]
    text_lengths = [100, 500, 1000, 5000, 10000]
    analyse_ciphers(text_lengths, key_lengths)
    df = pd.DataFrame(results)
    df.to_csv("cipher_performance_results.csv", index=False)
    visualise_results(df)
