import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from tabulate import tabulate

def create_comparison_visualizations(results_data, num_runs):
    """Create visualizations and comparison table"""
    print(f"\n{'='*20} Stage 4: Comparison Analysis {'='*20}")
    
    # Create visualization
    plt.figure(figsize=(15, 5))
    
    # Encryption comparison
    plt.subplot(1, 3, 1)
    sns.boxplot(x='cipher', y='encrypt_time', data=results_data)
    plt.title('Encryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    # Decryption comparison
    plt.subplot(1, 3, 2)
    sns.boxplot(x='cipher', y='decrypt_time', data=results_data)
    plt.title('Decryption Time Distribution')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=30)
    
    # Rail Fence Cryptanalysis comparison
    plt.subplot(1, 3, 3)
    rail_fence_data = results_data[results_data['cipher'] == 'Railfence']
    sns.boxplot(x='cryptanalysis_method', y='cryptanalysis_time', data=rail_fence_data)
    plt.title('Rail Fence Cryptanalysis Time')
    plt.ylabel('Time (ms)')
    plt.xticks(rotation=45)
    
    plt.tight_layout()
    plt.savefig('cipher_comparison.png')
    print(f"\nVisualization saved as 'cipher_comparison.png' ({num_runs} runs per cipher)")

    # Calculate and display statistics table
    stats = []
    for cipher in results_data['cipher'].unique():
        cipher_data = results_data[results_data['cipher'] == cipher]
        stats_row = {
            'Cipher': cipher,
            'Encrypt Median (ms)': f"{cipher_data['encrypt_time'].median():.2f}",
            'Encrypt StdDev': f"{cipher_data['encrypt_time'].std():.2f}",
            'Decrypt Median (ms)': f"{cipher_data['decrypt_time'].median():.2f}",
            'Decrypt StdDev': f"{cipher_data['decrypt_time'].std():.2f}"
        }
        if cipher == 'Railfence':
            stats_row.update({
                'Cryptanalysis Median (ms)': f"{cipher_data['cryptanalysis_time'].median():.2f}",
                'Cryptanalysis StdDev': f"{cipher_data['cryptanalysis_time'].std():.2f}"
            })
        stats.append(stats_row)
    
    print("\nStatistical Summary:")
    print(tabulate(stats, headers='keys', tablefmt='pretty'))