import sys
import time
import random
import psutil
import socket
import threading
import numpy as np
import json
import os
from datetime import datetime
from collections import deque
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QLabel, QGroupBox, QSizePolicy, QPushButton)
from PyQt6.QtCore import QTimer, Qt, pyqtSignal, QObject
import matplotlib
matplotlib.use('Qt5Agg')  # Set the backend before importing pyplot
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class NetworkWorker(QObject):
    update_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.prev_bytes_sent = 0
        self.prev_bytes_recv = 0
        self.prev_time = time.time()
        
        # Initialize latency and jitter measurements
        self.packet_latencies = deque(maxlen=10)
        
        # Initialize packet tracking for packet loss calculation
        self.packets_sent = 0
        self.packets_received = 0
        self.ping_host = "8.8.8.8"  # Google DNS server
        
        # Get network interface speed for utilization calculation
        self.network_capacity = self.get_network_capacity()
        
    def get_network_capacity(self):
        """Get the actual network interface speed in Mbps"""
        try:
            # Try to get the actual network speed from the active interface
            # This is platform-dependent and might need adjustments
            if sys.platform == 'win32':
                import subprocess
                output = subprocess.check_output('wmic NIC where NetEnabled=true get Name, Speed', shell=True)
                lines = output.decode('utf-8').strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) > 1 and parts[-1].isdigit():
                            # Convert from bits/s to Mbps
                            return int(parts[-1]) / 1_000_000
            
            # Fallback to a reasonable default if we can't determine actual speed
            return 100  # 100 Mbps as default
        except Exception as e:
            print(f"Error getting network capacity: {e}")
            return 100  # Default to 100 Mbps
    
    def measure_packet_loss(self):
        """Measure actual packet loss using ping"""
        try:
            # Use ping to measure packet loss
            if sys.platform == 'win32':
                ping_cmd = f"ping -n 10 -w 1000 {self.ping_host}"
            else:
                ping_cmd = f"ping -c 10 -W 1 {self.ping_host}"
            
            result = os.popen(ping_cmd).read()
            
            # Parse the ping output to get packet loss percentage
            if sys.platform == 'win32':
                # Windows ping output
                loss_line = [line for line in result.split('\n') if 'loss' in line.lower()]
                if loss_line:
                    # Extract percentage from something like "Packets: Sent = 10, Received = 9, Lost = 1 (10% loss)"
                    loss_str = loss_line[0].split('(')[1].split('%')[0]
                    return float(loss_str)
            else:
                # Linux/Mac ping output
                loss_line = [line for line in result.split('\n') if 'packet loss' in line.lower()]
                if loss_line:
                    # Extract percentage from something like "10 packets transmitted, 9 received, 10% packet loss"
                    loss_str = loss_line[0].split(',')[-1].split('%')[0].strip()
                    return float(loss_str)
            
            return 0  # Default if parsing fails
        except Exception as e:
            print(f"Error measuring packet loss: {e}")
            return 0
            
    def measure_latency(self, host="8.8.8.8"):
        """Measure latency to a target host"""
        try:
            start_time = time.time()
            # Create a socket and connect with a timeout
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, 53))
            s.close()
            latency = (time.time() - start_time) * 1000  # Convert to ms
            return latency
        except Exception:
            return None
            
    def calculate_jitter(self):
        """Calculate jitter based on the last few latency measurements"""
        if len(self.packet_latencies) < 2:
            return 0
        
        differences = []
        for i in range(1, len(self.packet_latencies)):
            differences.append(abs(self.packet_latencies[i] - self.packet_latencies[i-1]))
        
        if differences:
            return sum(differences) / len(differences)
        return 0
        
    def run(self):
        # Initialize packet loss measurement thread
        packet_loss = 0
        packet_loss_thread = None
        packet_loss_time = 0
        
        while self.running:
            # Get current network stats
            net_stats = psutil.net_io_counters()
            current_time = time.time()
            time_diff = current_time - self.prev_time
            
            # Calculate bandwidth (bytes per second)
            bytes_sent_diff = net_stats.bytes_sent - self.prev_bytes_sent
            bytes_recv_diff = net_stats.bytes_recv - self.prev_bytes_recv
            
            # Convert to Mbps
            upload_speed = (bytes_sent_diff * 8) / (time_diff * 1_000_000)
            download_speed = (bytes_recv_diff * 8) / (time_diff * 1_000_000)
            
            # Measure packet loss every 10 seconds to avoid excessive pinging
            if current_time - packet_loss_time > 10 or packet_loss_thread is None:
                # Run packet loss measurement in a separate thread to avoid blocking
                if packet_loss_thread is None or not packet_loss_thread.is_alive():
                    packet_loss_thread = threading.Thread(target=lambda: setattr(self, 'packet_loss', self.measure_packet_loss()))
                    packet_loss_thread.daemon = True
                    packet_loss_thread.start()
                    packet_loss_time = current_time
            
            # Measure latency
            latency = self.measure_latency()
            if latency is not None:
                self.packet_latencies.append(latency)
            
            # Calculate jitter based on latency variations
            jitter = self.calculate_jitter()
            
            # Calculate actual network utilization based on measured capacity
            network_utilization = ((upload_speed + download_speed) / self.network_capacity) * 100
            
            # Update previous values
            self.prev_bytes_sent = net_stats.bytes_sent
            self.prev_bytes_recv = net_stats.bytes_recv
            self.prev_time = current_time
            
            # Emit signal with network data
            network_data = {
                'upload': upload_speed,
                'download': download_speed,
                'packet_loss': getattr(self, 'packet_loss', 0),  # Get the value set by the thread
                'latency': latency if latency is not None else 0,
                'jitter': jitter,
                'utilization': network_utilization
            }
            
            self.update_signal.emit(network_data)
            time.sleep(1)  # Update every second
            
    def stop(self):
        self.running = False


class NetworkMonitorPlot(FigureCanvas):
    def __init__(self, title, ylabel, data_length=60, parent=None):
        self.fig = Figure(figsize=(5, 3), dpi=100)
        self.axes = self.fig.add_subplot(111)
        super().__init__(self.fig)
        
        self.setParent(parent)
        self.title = title
        self.ylabel = ylabel
        
        self.data_length = data_length
        self.xdata = list(range(data_length))
        self.ydata = [0] * data_length
        
        # Setup plot
        self.axes.set_title(self.title)
        self.axes.set_xlabel('Time (s)')
        self.axes.set_ylabel(self.ylabel)
        self.axes.grid(True)
        
        # Create line plot
        self.line, = self.axes.plot(self.xdata, self.ydata, 'b-')
        
        # Set layout
        self.fig.tight_layout()
        
        # Create size policy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.updateGeometry()
        
        # Track if widget is being deleted
        self._is_deleting = False
        
    def update_data(self, new_value):
        # Check if widget is being deleted or is already deleted
        if self._is_deleting or not self.isVisible():
            return
            
        try:
            # Add new data and remove old data
            self.ydata = self.ydata[1:] + [new_value]
            self.line.set_ydata(self.ydata)
            
            # Adjust y axis if needed
            max_value = max(self.ydata) if max(self.ydata) > 0 else 1
            min_value = min(self.ydata) if min(self.ydata) >= 0 else 0
            self.axes.set_ylim(min_value - (max_value * 0.1), max_value * 1.1)
            
            # Draw the new figure
            if self.fig and self.fig.canvas:
                self.fig.canvas.draw()
                self.fig.canvas.flush_events()
        except Exception as e:
            print(f"Error updating plot {self.title}: {str(e)}")
            
    def closeEvent(self, event):
        self._is_deleting = True
        super().closeEvent(event)
        
    def deleteLater(self):
        self._is_deleting = True
        super().deleteLater()


class NetworkMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Setup UI
        self.setWindowTitle("Network Monitoring Dashboard")
        self.setMinimumSize(800, 600)
        
        # Create data_temp directory if it doesn't exist
        self.data_dir = 'data_temp'
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        # Initialize data storage
        self.data_history = []
        self.save_timer = QTimer()
        self.save_timer.timeout.connect(self.save_data_to_json)
        self.save_timer.start(5000)  # Save every 5 seconds
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create status group
        status_group = QGroupBox("Network Status")
        status_layout = QHBoxLayout()
        status_group.setLayout(status_layout)
        
        # Create status labels
        self.download_label = QLabel("Download: 0 Mbps")
        self.upload_label = QLabel("Upload: 0 Mbps")
        self.latency_label = QLabel("Latency: 0 ms")
        self.jitter_label = QLabel("Jitter: 0 ms")
        self.packet_loss_label = QLabel("Packet Loss: 0%")
        self.utilization_label = QLabel("Network Utilization: 0%")
        
        # Add status labels to layout
        status_layout.addWidget(self.download_label)
        status_layout.addWidget(self.upload_label)
        status_layout.addWidget(self.latency_label)
        status_layout.addWidget(self.jitter_label)
        status_layout.addWidget(self.packet_loss_label)
        status_layout.addWidget(self.utilization_label)
        
        # Add status group to main layout
        main_layout.addWidget(status_group)
        
        # Create plot layout - two rows of plots
        plots_layout = QVBoxLayout()
        
        # First row - Download and Upload speeds
        row1_layout = QHBoxLayout()
        self.download_plot = NetworkMonitorPlot("Download Speed", "Mbps")
        self.upload_plot = NetworkMonitorPlot("Upload Speed", "Mbps")
        row1_layout.addWidget(self.download_plot)
        row1_layout.addWidget(self.upload_plot)
        plots_layout.addLayout(row1_layout)
        
        # Second row - Latency and Jitter
        row2_layout = QHBoxLayout()
        self.latency_plot = NetworkMonitorPlot("Latency", "ms")
        self.jitter_plot = NetworkMonitorPlot("Jitter", "ms")
        row2_layout.addWidget(self.latency_plot)
        row2_layout.addWidget(self.jitter_plot)
        plots_layout.addLayout(row2_layout)
        
        # Third row - Packet Loss and Network Utilization
        row3_layout = QHBoxLayout()
        self.packet_loss_plot = NetworkMonitorPlot("Packet Loss", "%")
        self.utilization_plot = NetworkMonitorPlot("Network Utilization", "%")
        row3_layout.addWidget(self.packet_loss_plot)
        row3_layout.addWidget(self.utilization_plot)
        plots_layout.addLayout(row3_layout)
        
        # Add plots to main layout
        main_layout.addLayout(plots_layout)
        
        # Network monitoring thread
        self.network_worker = None
        self.network_thread = None
        
        # Window resize event
        self.resizeEvent = self.on_resize
        
        # Add this to auto-start monitoring when window opens
        self.start_monitoring()
    
    def start_monitoring(self):
        # Create network worker and thread
        self.network_worker = NetworkWorker()
        self.network_thread = threading.Thread(target=self.network_worker.run)
        
        # Connect signal to update UI
        self.network_worker.update_signal.connect(self.update_network_data)
        
        # Start thread
        self.network_thread.daemon = True
        self.network_thread.start()
        
    def stop_monitoring(self):
        if self.network_worker:
            self.network_worker.stop()
            self.network_worker = None
            
    def on_resize(self, event):
        # Trigger plot redraw on window resize
        for plot in [self.download_plot, self.upload_plot, self.latency_plot, 
                    self.jitter_plot, self.packet_loss_plot, self.utilization_plot]:
            plot.fig.tight_layout()
            plot.draw()
        super().resizeEvent(event)
        
    def update_network_data(self, data):
        try:
            # Add timestamp to data
            data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.data_history.append(data)
            
            # Update status labels
            self.download_label.setText(f"Download: {data['download']:.2f} Mbps")
            self.upload_label.setText(f"Upload: {data['upload']:.2f} Mbps")
            self.latency_label.setText(f"Latency: {data['latency']:.2f} ms")
            self.jitter_label.setText(f"Jitter: {data['jitter']:.2f} ms")
            self.packet_loss_label.setText(f"Packet Loss: {data['packet_loss']:.2f}%")
            self.utilization_label.setText(f"Network Utilization: {data['utilization']:.2f}%")
            
            # Update plots with safety checks
            if hasattr(self, 'download_plot') and self.download_plot:
                self.download_plot.update_data(data['download'])
            if hasattr(self, 'upload_plot') and self.upload_plot:
                self.upload_plot.update_data(data['upload'])
            if hasattr(self, 'latency_plot') and self.latency_plot:
                self.latency_plot.update_data(data['latency'])
            if hasattr(self, 'jitter_plot') and self.jitter_plot:
                self.jitter_plot.update_data(data['jitter'])
            if hasattr(self, 'packet_loss_plot') and self.packet_loss_plot:
                self.packet_loss_plot.update_data(data['packet_loss'])
            if hasattr(self, 'utilization_plot') and self.utilization_plot:
                self.utilization_plot.update_data(data['utilization'])
        except Exception as e:
            print(f"Error updating network data: {str(e)}")
        
    def save_data_to_json(self):
        try:
            file_path = os.path.join(self.data_dir, 'monitoring_dashboard.json')
            with open(file_path, 'w') as f:
                json.dump(self.data_history, f, indent=4)
        except Exception as e:
            print(f"Error saving data to JSON: {str(e)}")
            
    def closeEvent(self, event):
        # Save final data before closing
        self.save_data_to_json()
        # Stop network monitoring thread when closing window
        self.stop_monitoring()
        event.accept()


if __name__ == "__main__":
    print("Starting application...")
    try:
        print("Creating QApplication...")
        app = QApplication(sys.argv)
        print("Created QApplication")
        
        print("Creating NetworkMonitorApp...")
        window = NetworkMonitorApp()
        print("Created NetworkMonitorApp window")
        
        print("Showing window...")
        window.show()
        print("Window shown")
        
        print("Starting event loop...")
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")  # Keep the window open to see the error
