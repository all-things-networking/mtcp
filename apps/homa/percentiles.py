import sys
import numpy as np

def compute_percentiles(filename):
    # Read numbers from file
    with open(filename, "r") as f:
        numbers = [float(line.strip()) for line in f if line.strip()]
    
    if not numbers:
        print("File is empty or contains no valid numbers.")
        return
    
    # Compute percentiles
    p90 = np.percentile(numbers, 90)
    p95 = np.percentile(numbers, 95)
    p99 = np.percentile(numbers, 99)

    avg = np.mean(numbers)

    print(f"avg: {avg}")
    print(f"90th percentile: {p90}")
    print(f"95th percentile: {p95}")
    print(f"99th percentile: {p99}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <filename>")
    else:
        compute_percentiles(sys.argv[1])

