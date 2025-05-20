import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import time
import os
import msvcrt  # Windows-specific module for key press detection
import colorama
from colorama import Fore, Style
import sys

# Initialize colorama for colored terminal output
colorama.init()

# Import our SMS alert system
try:
    from sms_alert import send_anomaly_alert
    SMS_ALERT_AVAILABLE = True
    print(Fore.GREEN + "SMS Alert System loaded successfully" + Style.RESET_ALL)

    # Try to import Twilio to check if it's available
    try:
        from twilio.rest import Client
        print(Fore.GREEN + "Twilio library loaded - Real SMS sending enabled" + Style.RESET_ALL)
    except ImportError:
        print(Fore.YELLOW + "Twilio library not available - SMS will be simulated" + Style.RESET_ALL)
except ImportError as e:
    SMS_ALERT_AVAILABLE = False
    print(Fore.RED + f"SMS Alert System not available: {e}" + Style.RESET_ALL)

# Load the dataset and skip malformed lines
data = pd.read_csv('combined_network_anomaly_dataset.csv', on_bad_lines='skip')

# Clean column names by replacing spaces with underscores
data.columns = data.columns.str.replace(' ', '_')

# Ensure all data is numeric, converting non-numeric values to NaN
data = data.apply(pd.to_numeric, errors='coerce')

# Fill missing values with the mean of each column
data = data.fillna(data.mean())

# Split the dataset into training (80%) and testing (20%) sets
n_rows = len(data)
train_size = int(0.8 * n_rows)
train_data = data.iloc[:train_size]
test_data = data.iloc[train_size:]

# Train the Isolation Forest model on the training data
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(train_data)

# Compute decision scores for the training data to determine scaling range
train_decision_scores = model.decision_function(train_data)
train_anomaly_scores = -train_decision_scores  # Negative scores indicate anomalies
min_anomaly = train_anomaly_scores.min()
max_anomaly = train_anomaly_scores.max()

# Specify output file and determine if header should be written
output_file = 'results.csv'
write_header = not os.path.exists(output_file)

# Clear the console
os.system('cls' if os.name == 'nt' else 'clear')

# Print header
print(Fore.CYAN + "=" * 80)
print(Fore.YELLOW + "REAL-TIME NETWORK METRICS MONITORING".center(80))
print(Fore.CYAN + "=" * 80 + Style.RESET_ALL)
print("\nPress 'q' to quit early.\n")

# Process each row in the test data every second
for i, (index, row) in enumerate(test_data.iterrows()):
    # Check if a key has been pressed and if it's 'q'
    if msvcrt.kbhit():
        key = msvcrt.getch()
        if key.decode('utf-8').lower() == 'q':
            print(Fore.RED + "\nQuit signal received. Stopping processing." + Style.RESET_ALL)
            break

    # Convert the row to a DataFrame for scoring
    row_df = pd.DataFrame([row])

    # Compute the anomaly score for this row
    decision_score = model.decision_function(row_df)[0]
    anomaly_score = -decision_score

    # Scale the anomaly score to a range of 1 to 10 based on training data
    normalized_score = (anomaly_score - min_anomaly) / (max_anomaly - min_anomaly)
    normalized_score = np.clip(normalized_score, 0, 1)  # Ensure score is between 0 and 1
    final_score = 1 + 9 * normalized_score  # Scale to 1-10

    # Add the computed anomaly score to the row
    row['anomaly_score'] = final_score

    # Get the binary anomaly flag using the model's predict method
    # IsolationForest returns -1 for anomalies and 1 for normal points.
    prediction = model.predict(row_df)[0]
    anomaly_flag = 1 if prediction == -1 else 0
    row['anomaly_flag'] = anomaly_flag

    # Clear previous metrics display (move cursor up and clear lines)
    if i > 0:
        # Always move up 10 lines since we're always displaying all metrics
        sys.stdout.write("\033[F" * 10)  # Move cursor up 10 lines
        sys.stdout.write("\033[K" * 10)  # Clear 10 lines

    # Get the network metrics
    latency = row['latency']
    throughput = row['throughput']
    # Handle both possible column names for packet loss
    packet_loss = row['packet_Loss'] if 'packet_Loss' in row else row['packet_loss']
    bandwidth = row['bandwidth']
    jitter = row['jitter']
    network_speed = row['network_speed']
    error_rate = row['error_rate']

    # Display timestamp and anomaly status
    print(f"{Fore.CYAN}Timestamp:{Style.RESET_ALL} {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Color coding based on values (green for good, yellow for moderate, red for concerning)
    def get_color(value, thresholds):
        low, high = thresholds
        if value <= low:
            return Fore.GREEN
        elif value <= high:
            return Fore.YELLOW
        else:
            return Fore.RED

    # Define thresholds for each metric (low, high)
    latency_thresholds = (50, 100)
    throughput_thresholds = (500, 800)  # Higher is better, so reversed logic
    packet_loss_thresholds = (2, 5)
    bandwidth_thresholds = (500, 800)  # Higher is better, so reversed logic
    jitter_thresholds = (3, 7)
    network_speed_thresholds = (500, 800)  # Higher is better, so reversed logic
    error_rate_thresholds = (1, 3)

    # Get colors with reversed logic for metrics where higher is better
    latency_color = get_color(latency, latency_thresholds)
    throughput_color = Fore.RED if throughput < throughput_thresholds[0] else (Fore.YELLOW if throughput < throughput_thresholds[1] else Fore.GREEN)
    packet_loss_color = get_color(packet_loss, packet_loss_thresholds)
    bandwidth_color = Fore.RED if bandwidth < bandwidth_thresholds[0] else (Fore.YELLOW if bandwidth < bandwidth_thresholds[1] else Fore.GREEN)
    jitter_color = get_color(jitter, jitter_thresholds)
    network_speed_color = Fore.RED if network_speed < network_speed_thresholds[0] else (Fore.YELLOW if network_speed < network_speed_thresholds[1] else Fore.GREEN)
    error_rate_color = get_color(error_rate, error_rate_thresholds)

    # Display metrics with appropriate colors
    if anomaly_flag == 1:
        print(f"{Fore.RED}ANOMALY DETECTED!{Style.RESET_ALL}")

        # Only send SMS alerts if the system is available and enabled
        if SMS_ALERT_AVAILABLE:
            # Collect metrics for SMS alert
            metrics = {
                'latency': latency,
                'throughput': throughput,
                'packet_loss': packet_loss,
                'bandwidth': bandwidth,
                'jitter': jitter,
                'network_speed': network_speed,
                'error_rate': error_rate
            }

            # Send SMS alert with detailed metrics
            send_anomaly_alert(metrics, final_score)
        else:
            print(Fore.YELLOW + "SMS Alert System not available - skipping alert" + Style.RESET_ALL)
    else:
        print(f"{Fore.GREEN}Status: Normal{Style.RESET_ALL}")

    print(f"{Fore.CYAN}Latency:{Style.RESET_ALL} {latency_color}{latency:.2f} ms{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Throughput:{Style.RESET_ALL} {throughput_color}{throughput:.2f} Mbps{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Packet Loss:{Style.RESET_ALL} {packet_loss_color}{packet_loss:.2f}%{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Bandwidth:{Style.RESET_ALL} {bandwidth_color}{bandwidth:.2f} Mbps{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Jitter:{Style.RESET_ALL} {jitter_color}{jitter:.2f} ms{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Network Speed:{Style.RESET_ALL} {network_speed_color}{network_speed:.2f} Mbps{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Error Rate:{Style.RESET_ALL} {error_rate_color}{error_rate:.2f}%{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Anomaly Score:{Style.RESET_ALL} {Fore.RED if anomaly_flag == 1 else Fore.GREEN}{final_score:.2f}/10{Style.RESET_ALL}")

    # Convert the updated row back to a DataFrame for writing
    row_df = pd.DataFrame([row])

    # Write to CSV: write header only if file does not exist; otherwise, append without header
    if write_header:
        row_df.to_csv(output_file, mode='w', index=False, header=True)
        write_header = False  # Only write header the first time
    else:
        row_df.to_csv(output_file, mode='a', index=False, header=False)

    # Wait for one second before processing the next row
    time.sleep(1)

print(Fore.GREEN + "\nProcessing complete. Results saved to '{}'".format(output_file) + Style.RESET_ALL)

# Append the data from results.csv to the main CSV file
# Append to the combined dataset file
results_data = pd.read_csv(output_file)
results_data.to_csv('combined_network_anomaly_dataset.csv', mode='a', index=False, header=False)

print(Fore.GREEN + "Results appended to main CSV file ('combined_network_anomaly_dataset.csv')." + Style.RESET_ALL)
os.remove('results.csv')  # Remove the temporary results file

