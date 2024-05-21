import numpy as np
import scipy.stats as stats

# Hypothetical data
attacks_experimental = 30  # Number of MEV attacks in the experimental group
total_experimental = 1000 # Total trials in the experimental group
attacks_control = 60      # Number of MEV attacks in the control group
total_control = 1000      # Total trials in the control group

# Calculating probabilities
prob_experimental = attacks_experimental / total_experimental
prob_control = attacks_control / total_control

# Relative Risk (RR)
RR = prob_experimental / prob_control

# Absolute Risk Reduction (ARR)
ARR = prob_control - prob_experimental

# Confidence Interval for RR using log transformation
SE_log_RR = np.sqrt((1/attacks_experimental - 1/total_experimental) + (1/attacks_control - 1/total_control))
CI_low = np.exp(np.log(RR) - 1.96 * SE_log_RR)
CI_high = np.exp(np.log(RR) + 1.96 * SE_log_RR)

# Display results
print(f"Relative Risk (RR): {RR:.2f}")
print(f"Absolute Risk Reduction (ARR): {ARR:.2f}")
print(f"95% Confidence Interval for RR: [{CI_low:.2f}, {CI_high:.2f}]")


