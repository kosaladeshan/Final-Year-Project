import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import time
import os
import msvcrt
from typing import Tuple, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NetworkAnomalyDetector:
    def __init__(self, csv_path='../combined_network_anomaly_dataset.csv', contamination=0.1):
        self.csv_path = csv_path
        self.contamination = contamination
        self.model = None
        self.min_anomaly = None
        self.max_anomaly = None

        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Dataset file not found: {csv_path}")

        self._initialize_model()

    def _initialize_model(self) -> None:
        """Initialize and train the model with data"""
        try:
            logging.info("Loading and preprocessing data...")
            data = pd.read_csv(self.csv_path, on_bad_lines='skip')
            if data.empty:
                raise ValueError("Dataset is empty")

            # Standardize column names
            data.columns = data.columns.str.replace(' ', '_')
            # Ensure consistent column naming
            if 'packet_Loss' in data.columns:
                data.rename(columns={'packet_Loss': 'packet_loss'}, inplace=True)
            if 'network_speed' in data.columns:
                data.rename(columns={'network_speed': 'network_speed'}, inplace=True)
            if 'error_rate' in data.columns:
                data.rename(columns={'error_rate': 'error_rate'}, inplace=True)
            data = data.apply(pd.to_numeric, errors='coerce')
            data = data.fillna(data.mean())

            n_rows = len(data)
            train_size = int(0.8 * n_rows)
            train_data = data.iloc[:train_size]

            logging.info("Training Isolation Forest model...")
            self.model = IsolationForest(contamination=self.contamination, random_state=42)
            self.model.fit(train_data)

            train_decision_scores = self.model.decision_function(train_data)
            train_anomaly_scores = -train_decision_scores
            self.min_anomaly = train_anomaly_scores.min()
            self.max_anomaly = train_anomaly_scores.max()
            logging.info("Model initialization complete")

        except Exception as e:
            logging.error(f"Error initializing model: {str(e)}")
            raise

    def process_single_row(self, row) -> Tuple[int, float]:
        """Process a single row and return anomaly flag and score"""
        try:
            row_df = pd.DataFrame([row])
            decision_score = self.model.decision_function(row_df)[0]
            anomaly_score = -decision_score
            normalized_score = (anomaly_score - self.min_anomaly) / (self.max_anomaly - self.min_anomaly)
            normalized_score = np.clip(normalized_score, 0, 1)
            final_score = 1 + 9 * normalized_score
            prediction = self.model.predict(row_df)[0]
            anomaly_flag = 1 if prediction == -1 else 0
            return anomaly_flag, final_score
        except Exception as e:
            logging.error(f"Error processing row: {str(e)}")
            return 0, 0.0

    def get_latest_anomaly_flag(self) -> int:
        """Get anomaly flag for the latest data point"""
        try:
            data = pd.read_csv(self.csv_path, on_bad_lines='skip')
            if data.empty:
                logging.warning("Dataset is empty")
                return 0

            # Standardize column names
            data.columns = data.columns.str.replace(' ', '_')
            # Ensure consistent column naming
            if 'packet_Loss' in data.columns:
                data.rename(columns={'packet_Loss': 'packet_loss'}, inplace=True)
            if 'network_speed' in data.columns:
                data.rename(columns={'network_speed': 'network_speed'}, inplace=True)
            if 'error_rate' in data.columns:
                data.rename(columns={'error_rate': 'error_rate'}, inplace=True)

            latest_row = data.iloc[-1]
            anomaly_flag, _ = self.process_single_row(latest_row)
            return anomaly_flag

        except Exception as e:
            logging.error(f"Error getting latest anomaly flag: {str(e)}")
            return 0

    def process_test_data(self) -> None:
        """Process all test data and save results"""
        output_file = 'results.csv'
        try:
            data = pd.read_csv(self.csv_path, on_bad_lines='skip')
            # Standardize column names
            data.columns = data.columns.str.replace(' ', '_')
            # Ensure consistent column naming
            if 'packet_Loss' in data.columns:
                data.rename(columns={'packet_Loss': 'packet_loss'}, inplace=True)
            if 'network_speed' in data.columns:
                data.rename(columns={'network_speed': 'network_speed'}, inplace=True)
            if 'error_rate' in data.columns:
                data.rename(columns={'error_rate': 'error_rate'}, inplace=True)
            data = data.apply(pd.to_numeric, errors='coerce')
            data = data.fillna(data.mean())

            n_rows = len(data)
            train_size = int(0.8 * n_rows)
            test_data = data.iloc[train_size:]

            write_header = not os.path.exists(output_file)

            logging.info("Starting test data processing...")
            print("Processing test data. Press 'q' to quit early.")

            for i, (index, row) in enumerate(test_data.iterrows()):
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key.decode('utf-8').lower() == 'q':
                        logging.info("User requested early termination")
                        break

                anomaly_flag, final_score = self.process_single_row(row)
                row['anomaly_score'] = final_score
                row['anomaly_flag'] = anomaly_flag

                row_df = pd.DataFrame([row])
                if write_header:
                    row_df.to_csv(output_file, mode='w', index=False, header=True)
                    write_header = False
                else:
                    row_df.to_csv(output_file, mode='a', index=False, header=False)

                time.sleep(1)

            logging.info(f"Processing complete. Saving results...")
            results_data = pd.read_csv(output_file)
            # Use the combined dataset path
            results_data.to_csv(self.csv_path, mode='a', index=False, header=False)

            if os.path.exists(output_file):
                os.remove(output_file)

            logging.info("Results successfully appended to main CSV file")

        except Exception as e:
            logging.error(f"Error processing test data: {str(e)}")
            if os.path.exists(output_file):
                os.remove(output_file)
            raise

def get_analyzer() -> NetworkAnomalyDetector:
    """Helper function to get an instance of the analyzer"""
    return NetworkAnomalyDetector()

# Example usage
if __name__ == "__main__":
    analyzer = NetworkAnomalyDetector()
    # Only remove results.csv if it exists
    if os.path.exists('results.csv'):
        os.remove('results.csv')
