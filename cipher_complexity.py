import sys
import time
import random
import string
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from secretpy import ADFGVX, ColumnarTransposition, Zigzag, CryptMachine
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import multiprocessing

# Analysis parameters
TEXT_LENGTHS = [1000, 5000, 10000, 50000, 100000]
KEY_LENGTHS = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
NUM_RUNS = 100

class CipherTest:
    """Class to handle cipher configuration and testing."""
    def __init__(self, name, cipher_class, needs_alphabet=False):
        self.name = name
        self.cipher_class = cipher_class
        self.needs_alphabet = needs_alphabet

    def create_machine(self, key_length):
        """Create configured cipher machine."""
        key = self._generate_key(key_length)
        alphabet = self._generate_alphabet() if self.needs_alphabet else None

        cm = CryptMachine(self.cipher_class())
        cm.set_key(key)
        if alphabet:
            cm.set_alphabet(alphabet)
        return cm

    def _generate_key(self, length):
        """Generate appropriate key for cipher type."""
        if self.name == 'Rail Fence':
            return length
        return ''.join(random.sample(string.ascii_lowercase[:length], length))

    def _generate_alphabet(self):
        """Generate alphabet for ADFGVX cipher."""
        return ''.join(random.sample(string.ascii_lowercase, 26))

class ComplexityAnalyzer:
    """Main class for analyzing cipher complexity."""
    def __init__(self, text):
        self.text = text
        self.ciphers = [
            CipherTest('ADFGVX', ADFGVX, needs_alphabet=True),
            CipherTest('Columnar', ColumnarTransposition),
            CipherTest('Rail Fence', Zigzag)
        ]

    def measure_time(self, cipher_test, text, key_length):
        """Measure encryption and decryption time."""
        cm = cipher_test.create_machine(key_length)

        start = time.time()
        encrypted = cm.encrypt(text)
        encrypt_time = (time.time() - start) * 1000

        start = time.time()
        cm.decrypt(encrypted)
        decrypt_time = (time.time() - start) * 1000

        return encrypt_time, decrypt_time

    def parallel_measure(self, cipher_test, text, key_length, runs):
        """Run multiple encryption/decryption measurements in parallel."""
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda _: self.measure_time(cipher_test, text, key_length), range(runs)))
        return results

    def analyze(self):
        """Perform complexity analysis."""
        results = []

        # Test text length impact
        print("\nAnalyzing text length impact...")
        for length in tqdm(TEXT_LENGTHS):
            if length > len(self.text):
                continue
            text_slice = self.text[:length]
            for cipher in self.ciphers:
                for _ in range(NUM_RUNS):
                    enc_time, dec_time = self.measure_time(cipher, text_slice, 6)
                    results.extend([
                        {'type': 'text', 'size': length, 'cipher': cipher.name, 
                         'operation': 'encryption', 'time': enc_time},
                        {'type': 'text', 'size': length, 'cipher': cipher.name, 
                         'operation': 'decryption', 'time': dec_time}
                    ])

        # Test key length impact
        print("\nAnalyzing key length impact...")
        text_slice = self.text[:10000]
        for length in tqdm(KEY_LENGTHS):
            for cipher in self.ciphers:
                runs_results = self.parallel_measure(cipher, text_slice, length, NUM_RUNS)
                for enc_time, dec_time in runs_results:
                    results.extend([
                        {'type': 'key', 'size': length, 'cipher': cipher.name, 
                         'operation': 'encryption', 'time': enc_time},
                        {'type': 'key', 'size': length, 'cipher': cipher.name, 
                         'operation': 'decryption', 'time': dec_time}
                    ])

        return pd.DataFrame(results)

    def visualize_results(self, df):
        """Create visualizations of analysis results."""
        sns.set_style("whitegrid")
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))

        # Plot text length impact
        text_data = df[df['type'] == 'text']
        
        sns.lineplot(data=text_data[text_data['operation'] == 'encryption'],
                    x='size', y='time', hue='cipher', marker='o', ax=axes[0,0])
        axes[0,0].set_title('Text Length vs Encryption Time')
        axes[0,0].set_xlabel('Text Length (characters)')
        axes[0,0].set_ylabel('Time (ms)')

        sns.lineplot(data=text_data[text_data['operation'] == 'decryption'],
                    x='size', y='time', hue='cipher', marker='o', ax=axes[0,1])
        axes[0,1].set_title('Text Length vs Decryption Time')
        axes[0,1].set_xlabel('Text Length (characters)')
        axes[0,1].set_ylabel('Time (ms)')

        # Plot key length impact
        key_data = df[df['type'] == 'key']
        
        sns.lineplot(data=key_data[key_data['operation'] == 'encryption'],
                    x='size', y='time', hue='cipher', marker='o', ax=axes[1,0])
        axes[1,0].set_title('Key Length vs Encryption Time')
        axes[1,0].set_xlabel('Key Length')
        axes[1,0].set_ylabel('Time (ms)')

        sns.lineplot(data=key_data[key_data['operation'] == 'decryption'],
                    x='size', y='time', hue='cipher', marker='o', ax=axes[1,1])
        axes[1,1].set_title('Key Length vs Decryption Time')
        axes[1,1].set_xlabel('Key Length')
        axes[1,1].set_ylabel('Time (ms)')

        num_cores = multiprocessing.cpu_count()
        plt.suptitle('Cipher Complexity Analysis ({} Runs, {} Cores)'.format(NUM_RUNS, num_cores), y=1.02, size=16)
        plt.tight_layout()
        plt.savefig('cipher_analysis.png', bbox_inches='tight', dpi=300)
        print("\nVisualization saved as 'cipher_analysis.png'")

def load_text(filepath):
    """Load and normalize text from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            text = ''.join(c.lower() for c in file.read() if c.isalpha())
        print("Loaded text length: {} characters".format(len(text)))
        return text
    except Exception as e:
        print("Error loading file: {}".format(e))
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: python cipher_analysis.py <text_file>")
        sys.exit(1)

    text = load_text(sys.argv[1])
    analyzer = ComplexityAnalyzer(text)
    
    print("Starting complexity analysis...")
    results = analyzer.analyze()
    analyzer.visualize_results(results)
    print("Analysis complete!")

if __name__ == "__main__":
    main()
