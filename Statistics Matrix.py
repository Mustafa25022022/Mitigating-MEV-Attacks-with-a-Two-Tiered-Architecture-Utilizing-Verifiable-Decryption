import numpy as np
from scipy.stats import chisquare

def simulate_consecutive_nodes(n, trials):
    consecutive_counts = 0
    for _ in range(trials):
        nodes = np.random.choice(n, 2, replace=False)  # Pick two random nodes
        if abs(nodes[1] - nodes[0]) == 1:  # Check if they are consecutive
            consecutive_counts += 1
    return consecutive_counts

# Parameters
nodes = [200, 300, 400, 500, 600,700,800,900,1000]  # Different node sizes
trials = [20000, 30000, 40000, 50000, 60000,7000,8000,9000,10000]  # Corresponding trials

results = []
for n, t in zip(nodes, trials):
    observed = simulate_consecutive_nodes(n, t)
    expected = 2 * t / n  # Theoretical expectation of consecutive nodes
    chi_stat, p_value = chisquare([observed, t - observed], f_exp=[expected, t - expected])
    results.append((n, t, observed/t, expected/t, chi_stat, p_value))

# Print results
for result in results:
    print("Nodes: {}, Trials: {}, Empirical Prob: {:.4f}, Theoretical Prob: {:.4f}, Chi-square Stat: {:.2f}, p-value: {:.3f}".format(*result))
