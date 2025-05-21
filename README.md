# Network Root Cause Analysis Tool

## Overview

 This Network Root Cause Analysis Tool is a comprehensive suite designed for network administrators and IT professionals to efficiently monitor, analyse, and troubleshoot network issues. The application combines advanced network monitoring capabilities with machine learning-based anomaly detection to provide a complete network management solution.

### What Problem Does It Solve?

Network administrators face numerous challenges in maintaining network health and security:
- Difficulty in identifying the root cause of network issues quickly
- Lack of real-time visibility into network traffic and device behaviour
- Challenges in detecting and responding to network anomalies
- Time-consuming manual network scanning and reporting processes

### Key Benefits

1. **Unified Monitoring Interface**
   - Single dashboard for all network monitoring needs
   - Real-time visibility into network performance
   - Intuitive visualisation of network metrics

2. **Automated Issue Detection**
   - Machine learning-based anomaly detection
   - Instant SMS alerts for critical issues
   - Proactive identification of potential problems

3. **Enhanced Security**
   - Continuous network vulnerability scanning
   - Device fingerprinting and tracking
   - Unauthorized device detection

4. **Time-Saving Features**
   - Automated report generation
   - Quick troubleshooting workflows
   - Batch scanning capabilities

### Technical Innovation

The tool leverages several cutting-edge technologies:
- Machine Learning for anomaly detection
- Real-time packet analysis using advanced filtering
- Automated vulnerability assessment
- WiFi signal strength analysis and optimisation
- Integration with Twilio for instant notifications

![Project Poster](images/Final_Year_Project.png)

## Features

- **Central Dashboard**: Unified control centre for accessing all modules
- **Real-time Packet Analysis**: Capture and analyse network packets with filtering capabilities
- **Network Device Scanner**: Discover devices on your network and scan for vulnerabilities
- **WiFi Signal Analyzer**: Monitor and analyze wireless networks and signal strength
- **Anomaly Detection**: Machine learning-based system to identify unusual network behavior
- **SMS Alert System**: Receive notifications when network anomalies are detected
- **Reporting System**: Generate comprehensive PDF reports of network status and issues
- **Network Troubleshooting**: Tools to diagnose and resolve common network problems

## Technical Architecture

### Core Components

1. **Network Analysis Engine**
   - Built with Python and Scapy for packet capture and analysis
   - Real-time traffic monitoring and filtering
   - Deep packet inspection capabilities

2. **Machine Learning Module**
   - Anomaly detection using advanced ML algorithms
   - Pattern recognition for network behavior analysis
   - Continuous learning from network traffic patterns

3. **Security Scanner**
   - Port scanning and vulnerability assessment
   - Device fingerprinting and OS detection
   - Network topology mapping

4. **Alert System**
   - SMS notifications via Twilio integration
   - Configurable alert thresholds
   - Alert history tracking and analysis

5. **Reporting Engine**
   - PDF report generation with detailed metrics
   - Historical data analysis
   - Customizable report templates

### Technology Stack

- **Frontend**: PyQt6 for the graphical user interface
- **Backend**: Python 3.9+ for core functionality
- **Libraries**:
  - Scapy for packet manipulation
  - Pandas for data analysis
  - Matplotlib for data visualization
  - NumPy for numerical computations
  - Twilio for SMS notifications

## System Requirements

- Windows 10/11 (64-bit)
- Python 3.9 or higher
- Administrator privileges (required for packet capture)
- Minimum 4GB RAM
- 1GB free disk space

## Installation

### Step 1: Clone or Download the Repository

```
git clone https://github.com/yourusername/network-root-cause-analysis.git
cd network-root-cause-analysis
```

### Step 2: Create a Virtual Environment (Recommended)

```
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Required Dependencies

```
pip install -r requirements.txt
```

The `requirements.txt` file includes all necessary libraries like PyQt6, matplotlib, numpy, scapy, pandas, and more.

### Step 4: Optional - Install Twilio for SMS Alerts

If you want to use real SMS alerts (instead of simulated ones):

```
pip install twilio
```

## Configuration

### SMS Alert Configuration

1. Open `sms_alert_settings.json` in the root directory
2. Set `"enabled"` to `true` to enable SMS alerts
3. Update `"phone_number"` with your phone number in international format (e.g., "+1234567890")

Example configuration:
```json
{
    "enabled": true,
    "phone_number": "+1234567890",
    "alert_history": []
}
```

### Twilio Configuration (Optional)

If you want to use real SMS alerts with Twilio:

1. Sign up for a Twilio account at https://www.twilio.com
2. Get your Account SID and Auth Token from the Twilio dashboard
3. Create a file named `secret.py` in the SMS gateway directory with:

```python
account_sid = "your_account_sid"
auth_token = "your_auth_token"
twilio_number = "your_twilio_phone_number"
```

## Usage

### Running the Application

1. Ensure you're in the project directory
2. Run the main application with administrator privileges:

```
python Main.py
```

### Module Descriptions

- **Main Dashboard**: Central hub for accessing all tools
- **Network Monitoring**: Real-time tracking of network performance metrics
- **Network Troubleshooting**: Tools for diagnosing common network issues
- **Network Device Scanner**: Discovers devices and checks for vulnerabilities
- **WiFi Scanner**: Analyzes wireless networks and signal strength
- **Real-time Packet Filtering**: Captures and analyzes network packets
- **Report Generator**: Creates PDF reports of network status and issues

## Data Storage

The application stores temporary data in the `data_temp` directory, including:
- Packet analysis data
- WiFi scanning results
- Device scanning results
- Network monitoring data
- Troubleshooting history

## Troubleshooting

### Common Issues

1. **Permission Errors**: Run the application as Administrator
2. **Missing Modules**: Verify all dependencies are installed
3. **Packet Capture Issues**: Install WinPcap or Npcap on Windows
4. **SMS Alerts Not Working**: Check your SMS configuration

### Logs

Check the console output for error messages and debugging information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Project Documentation

The detailed project documentation is available in the following formats:
- [Final Report](final-report/Final%20Report%2010898583.pdf) - Comprehensive project documentation and analysis
- [Network Reports](reports/) - Sample network analysis reports generated by the tool

## Acknowledgments

This project was developed as a university final year project, utilizing Python, PyQt6, and various open-source libraries.
