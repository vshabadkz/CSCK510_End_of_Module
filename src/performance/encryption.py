import time
from statistics import mean, stdev
from tqdm import tqdm

def measure_encryption(cipher_name, cm, text, num_runs):
    """Measure encryption performance"""
    encryption_times = []
    encrypted_texts = []
    
    print(f"\n{'='*20} Stage 1: Encryption - {cipher_name} {'='*20}")
    print(f"Performing {num_runs} encryption runs...")
    
    for run in tqdm(range(num_runs), desc="Encryption"):
        start_time = time.time()
        encrypted_text = cm.encrypt(text)
        encrypt_time = (time.time() - start_time) * 1000
        encryption_times.append(encrypt_time)
        encrypted_texts.append(encrypted_text)
    
    avg_time = mean(encryption_times)
    std_time = stdev(encryption_times) if len(encryption_times) > 1 else 0
    print(f"Average encryption time: {avg_time:.2f}ms")
    print(f"Standard deviation: {std_time:.2f}ms")
    
    return encrypted_texts, encryption_times