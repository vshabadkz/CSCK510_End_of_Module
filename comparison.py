import random
import time
import string
from collections import Counter
from multiprocessing import cpu_count
from itertools import islice
from concurrent.futures import ProcessPoolExecutor, as_completed
import numpy as np
from tqdm import tqdm

# English Letter Frequencies (normalised for comparison)
ENGLISH_FREQUENCIES = np.array([
    12.70, 9.06, 8.17, 7.51, 6.97, 6.75, 6.33, 6.09, 5.99, 4.25, 4.03,
    2.78, 2.76, 2.41, 2.36, 2.23, 2.02, 1.97, 1.93, 1.49, 0.98, 0.77,
    0.15, 0.15, 0.10, 0.07
])

# Stopping criteria
STOP_ACCURACY = 95.0  # Stop if accuracy reaches or exceeds 95%
TIME_LIMIT = 5*60*60  # Stop after 5 hours
BATCH_SIZE = 1000000   # Number of keys per batch for processing

# Accuracy Calculation
def calculate_accuracy(plaintext, decrypted_text):
    correct = sum(1 for p, d in zip(plaintext.upper(), decrypted_text) if p == d)
    return correct / len(plaintext) * 100


# Generate Ciphertext
def generate_ciphertext(plaintext, key):
    alphabet = string.ascii_uppercase
    key_map = {alphabet[i]: key[i] for i in range(len(alphabet))}
    return "".join(key_map.get(char, char) for char in plaintext.upper())


# Scoring Function
def calculate_score(decrypted_text, freq_table):
    observed_freq = Counter(decrypted_text)
    observed_freq_vector = np.array([
        observed_freq.get(char, 0) for char in string.ascii_uppercase
    ])
    # Normalise frequencies
    observed_freq_vector = observed_freq_vector / observed_freq_vector.sum()
    # Compute similarity using cosine similarity or direct dot product
    return np.dot(observed_freq_vector, freq_table)


def generate_random_permutations(alphabet):
    """
    Generate an unlimited number of random permutations of the given alphabet.
    """
    alphabet_array = np.array(list(alphabet))
    while True:  # Infinite generator
        np.random.shuffle(alphabet_array)
        yield "".join(alphabet_array)


# Process Key Batch
def process_key_batch(args):
    """
    Processes a batch of keys, evaluating each one for accuracy and score.
    Returns the best key, score, and accuracy in the batch.
    """
    keys, ciphertext, plaintext = args
    best_key = None
    best_score = 0
    best_accuracy = 0

    for key in keys:
        decrypted_text = generate_ciphertext(ciphertext, key)
        score = calculate_score(decrypted_text, ENGLISH_FREQUENCIES)
        current_accuracy = calculate_accuracy(plaintext, decrypted_text)

        if current_accuracy > best_accuracy:
            best_key, best_score, best_accuracy = key, score, current_accuracy

    return best_key, best_score, best_accuracy


# Exhaustive Search with Concurrent Futures

def exhaustive_search_parallel(ciphertext, plaintext):
    """
    Exhaustive search with multiprocessing using random permutations of keys.
    """
    start_time = time.time()
    alphabet = string.ascii_uppercase
    key_generator = generate_random_permutations(alphabet)  # Infinite key generator
    total_keys_processed = 0
    best_key = None
    best_score = 0
    best_accuracy = 0

    with ProcessPoolExecutor(max_workers=cpu_count() * 2) as executor:  # Double workers
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time >= TIME_LIMIT:
                print(f"Stopped due to time limit: {TIME_LIMIT} seconds")
                break
            if best_accuracy >= STOP_ACCURACY:
                print(f"Stopped due to reaching accuracy: {best_accuracy:.2f}%")
                break

            # Create a large batch of random keys
            key_batch = list(islice(key_generator, BATCH_SIZE))
            if not key_batch:
                print("All possible keys processed.")
                break

            # Divide the batch evenly among workers
            chunk_size = len(key_batch) // cpu_count()
            futures = [
                executor.submit(process_key_batch, (key_batch[i * chunk_size:(i + 1) * chunk_size], ciphertext, plaintext))
                for i in range(cpu_count())
            ]

            # Process results immediately
            for future in as_completed(futures):
                result_key, result_score, result_accuracy = future.result()
                total_keys_processed += chunk_size
                if result_accuracy > best_accuracy:
                    best_key, best_score, best_accuracy = result_key, result_score, result_accuracy

    elapsed_time = time.time() - start_time
    print(f"\nBest Key: {best_key}, Score: {best_score:.4f}, Accuracy: {best_accuracy:.2f}%, Time: {elapsed_time:.2f}s")
    print(f"Total Keys Processed: {total_keys_processed}")
    return best_key, best_score, best_accuracy, elapsed_time


# Example Usage
if __name__ == "__main__":
    plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    print(f"Using key: {key}")

    ciphertext = generate_ciphertext(plaintext, key)

    print("\nCiphertext:", ciphertext)
    print("\nExhaustive Search:")
    exhaustive_search_parallel(ciphertext, plaintext)
