import time
from statistics import mean, stdev
from tqdm import tqdm

def measure_decryption(cipher_name, cm, encrypted_texts, num_runs):
    """Measure decryption performance"""
    decryption_times = []
    
    print(f"\n{'='*20} Stage 2: Decryption - {cipher_name} {'='*20}")
    print(f"Performing {num_runs} decryption runs...")
    
    for run in tqdm(range(num_runs), desc="Decryption"):
        start_time = time.time()
        decrypted_text = cm.decrypt(encrypted_texts[run])
        decrypt_time = (time.time() - start_time) * 1000
        decryption_times.append(decrypt_time)
    
    avg_time = mean(decryption_times)
    std_time = stdev(decryption_times) if len(decryption_times) > 1 else 0
    print(f"Average decryption time: {avg_time:.2f}ms")
    print(f"Standard deviation: {std_time:.2f}ms")
    
    return decryption_times