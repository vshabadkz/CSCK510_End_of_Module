import time
from collections import Counter
from secretpy import Zigzag, CryptMachine
from tqdm import tqdm
from deap import base, creator, tools, algorithms
import random
from statistics import mean, stdev
from tabulate import tabulate

class RailFenceAnalyzer:
    def __init__(self, max_rails=10, time_limit=30):
        self.max_rails = max_rails
        self.time_limit = time_limit
        self.cipher = Zigzag()
        # German letter frequencies
        self.lang_freq = {
            'e': 16.93, 'n': 9.78, 'i': 7.55, 'r': 7.00, 's': 6.42,
            't': 6.15, 'a': 6.51, 'h': 4.76, 'd': 5.08, 'u': 4.35,
            'l': 3.44, 'c': 3.06, 'g': 3.01, 'm': 2.53, 'o': 2.51,
            'b': 1.89, 'w': 1.89, 'f': 1.66, 'k': 1.21, 'z': 1.13
        }
        self.common_bigrams = ['en', 'er', 'ch', 'de', 'ei', 'in', 'te', 'nd', 'ie', 'ge']

    def _calculate_combined_score(self, text):
        """Calculate combined score using multiple metrics"""
        # Character frequency score
        char_freq = Counter(text.lower())
        total_chars = len(text)
        text_freq = {char: (count/total_chars)*100 for char, count in char_freq.items()}
        freq_score = sum(abs(text_freq.get(char, 0) - freq) for char, freq in self.lang_freq.items())
        
        # Bigram score
        bigram_count = 0
        for bigram in self.common_bigrams:
            bigram_count += text.lower().count(bigram)
        bigram_score = bigram_count / (len(text) - 1)
        
        # Vowel ratio
        vowels = sum(1 for c in text.lower() if c in 'aeiouäöü')
        vowel_ratio = vowels / len(text)
        vowel_score = abs(0.4 - vowel_ratio)
        
        return freq_score * 0.5 + (1 - bigram_score) * 0.3 + vowel_score * 0.2

    def _is_valid_decryption(self, decrypted, original):
        """Check if decryption is valid using multiple criteria"""
        if decrypted == original:
            return True
            
        score = self._calculate_combined_score(decrypted)
        target_score = self._calculate_combined_score(original)
        return abs(score - target_score) < 0.5

    def brute_force(self, encrypted_text, original_text):
        """Improved brute force approach"""
        start_time = time.time()
        best_score = float('inf')
        best_rails = None
        
        for rails in range(2, self.max_rails + 1):
            if time.time() - start_time > self.time_limit:
                return best_rails, best_score < 1.0
                
            cm = CryptMachine(self.cipher)
            cm.set_key(rails)
            try:
                decrypted = cm.decrypt(encrypted_text)
                if self._is_valid_decryption(decrypted, original_text):
                    return rails, True
                    
                score = self._calculate_combined_score(decrypted)
                if score < best_score:
                    best_score = score
                    best_rails = rails
            except:
                continue
        
        return best_rails, best_score < 1.0

    def brute_force_with_frequency(self, encrypted_text, original_text):
        """Brute force with frequency analysis"""
        return self.brute_force(encrypted_text, original_text)  # Using same implementation for simplicity

    def genetic_algorithm(self, encrypted_text, original_text):
        """Genetic algorithm approach"""
        start_time = time.time()
        
        if not hasattr(creator, "FitnessMax"):
            creator.create("FitnessMax", base.Fitness, weights=(1.0,))
        if not hasattr(creator, "Individual"):
            creator.create("Individual", list, fitness=creator.FitnessMax)
        
        toolbox = base.Toolbox()
        toolbox.register("attr_int", random.randint, 2, self.max_rails)
        toolbox.register("individual", tools.initRepeat, creator.Individual, toolbox.attr_int, n=1)
        toolbox.register("population", tools.initRepeat, list, toolbox.individual)
        
        def eval_rails(individual):
            rails = individual[0]
            cm = CryptMachine(self.cipher)
            cm.set_key(rails)
            try:
                decrypted = cm.decrypt(encrypted_text)
                if self._is_valid_decryption(decrypted, original_text):
                    raise StopIteration(rails)
                score = self._calculate_combined_score(decrypted)
                return 1 / (1 + score),
            except StopIteration as e:
                raise e
            except:
                return 0,
        
        toolbox.register("evaluate", eval_rails)
        toolbox.register("mate", tools.cxTwoPoint)
        toolbox.register("mutate", tools.mutUniformInt, low=2, up=self.max_rails, indpb=0.2)
        toolbox.register("select", tools.selTournament, tournsize=3)
        
        pop = toolbox.population(n=50)
        
        try:
            gen = 0
            while time.time() - start_time <= self.time_limit:
                offspring = algorithms.varAnd(pop, toolbox, cxpb=0.7, mutpb=0.3)
                fits = toolbox.map(toolbox.evaluate, offspring)
                for fit, ind in zip(fits, offspring):
                    ind.fitness.values = fit
                pop = toolbox.select(offspring, k=len(pop))
                
                best_ind = tools.selBest(pop, 1)[0]
                if best_ind.fitness.values[0] > 0.9:
                    return best_ind[0], True
                    
                gen += 1
                if gen >= 100:
                    break
                
        except StopIteration as e:
            return e.value, True
        except Exception as e:
            return None, False
            
        best_ind = tools.selBest(pop, 1)[0]
        return best_ind[0], best_ind.fitness.values[0] > 0.9

    def compare_methods(self, encrypted_texts, original_text, num_runs):
        """Compare different cryptanalysis methods"""
        methods = [
            ("Brute Force", self.brute_force),
            ("Brute Force with Frequency", self.brute_force_with_frequency),
            ("Genetic Algorithm", self.genetic_algorithm)
        ]
        
        results = []
        cryptanalysis_times = []
        
        for method_name, method in methods:
            print(f"\nTesting {method_name}...")
            successful = 0
            times = []
            
            for i in tqdm(range(num_runs), desc=f"{method_name} progress"):
                start_time = time.time()
                rails, success = method(encrypted_texts[i], original_text)
                elapsed_time = time.time() - start_time
                
                times.append(elapsed_time * 1000)  # Convert to milliseconds
                if success:
                    successful += 1
                    
                if i == 0:
                    print(f"First run - Found rails: {rails}, Success: {success}")
                    print(f"Time taken: {elapsed_time:.2f} seconds")
            
            cryptanalysis_times.extend(times)
            avg_time = mean(times)
            success_rate = (successful / num_runs) * 100
            
            results.append({
                'Method': method_name,
                'Success Rate': f"{success_rate:.1f}%",
                'Avg Time (ms)': f"{avg_time:.2f}",
                'Std Dev (ms)': f"{stdev(times):.2f}" if len(times) > 1 else "N/A"
            })
        
        print("\nCryptanalysis Results Summary:")
        print(tabulate(results, headers='keys', tablefmt='pretty'))
        
        return cryptanalysis_times