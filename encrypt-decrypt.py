#!/usr/bin/env python3
import sys
import traceback
from src.text_processor import load_and_normalize_text
from src.cipher_base import initialize_ciphers, create_cipher_machine
from src.performance.encryption import measure_encryption
from src.performance.decryption import measure_decryption
from src.analyzers.rail_fence import RailFenceAnalyzer
from src.visualization.visualizer import create_comparison_visualizations
from deap import creator
import pandas as pd

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
        # Load and normalize text
        normalised_text = load_and_normalize_text(pdf_file)

        # Initialize ciphers
        ciphers = initialize_ciphers(init_vector, keyword)
        all_results = []

        # Process each cipher
        for name, cipher, alphabet, key in ciphers:
            print(f"\nProcessing {name} cipher...")
            cm = create_cipher_machine(cipher, key, alphabet)

            # Stage 1: Encryption
            encrypted_texts, encryption_times = measure_encryption(name, cm, normalised_text, num_runs)
            
            # Stage 2: Decryption
            decryption_times = measure_decryption(name, cm, encrypted_texts, num_runs)
            
            # Stage 3: Cryptanalysis (only for Rail Fence)
            if name == 'Railfence':
                print(f"\n{'='*20} Stage 3: Rail Fence Cryptanalysis {'='*20}")
                analyzer = RailFenceAnalyzer()
                cryptanalysis_results = analyzer.compare_methods(encrypted_texts, normalised_text, num_runs)
                
                # Store results with cryptanalysis method
                methods = ["Brute Force", "Brute Force with Frequency", "Genetic Algorithm"]
                for i in range(num_runs):
                    for j, method in enumerate(methods):
                        result = {
                            'cipher': name,
                            'run': i + 1,
                            'encrypt_time': encryption_times[i],
                            'decrypt_time': decryption_times[i],
                            'cryptanalysis_time': cryptanalysis_results[j * num_runs + i],
                            'cryptanalysis_method': method
                        }
                        all_results.append(result)
            else:
                # Store results without cryptanalysis for other ciphers
                for i in range(num_runs):
                    result = {
                        'cipher': name,
                        'run': i + 1,
                        'encrypt_time': encryption_times[i],
                        'decrypt_time': decryption_times[i],
                        'cryptanalysis_time': None,
                        'cryptanalysis_method': None
                    }
                    all_results.append(result)

        # Convert results to DataFrame for easier processing
        results_df = pd.DataFrame(all_results)

        # Stage 4: Create visualizations and comparison table
        create_comparison_visualizations(results_df, num_runs)

    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Clean up DEAP creator classes
        if hasattr(creator, "FitnessMax"):
            del creator.FitnessMax
        if hasattr(creator, "Individual"):
            del creator.Individual

if __name__ == "__main__":
    main()