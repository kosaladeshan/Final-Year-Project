#!/usr/bin/env python
"""
Silent Report Generator
This script generates a PDF report using data from the temp folder without any user interaction.
The report is saved directly to the root folder.
"""

import sys
import os
from Report import SaveInterface
from PyQt6.QtWidgets import QApplication

def main():
    """Generate a silent report without any user interaction"""
    print("Starting silent report generation...")
    
    # Create Qt application (required for the SaveInterface class)
    app = QApplication(sys.argv)
    
    # Create report generator
    report_generator = SaveInterface()
    
    # Generate report silently
    result = report_generator.generateSilentReport()
    
    if result:
        print("Report generated successfully!")
    else:
        print("Failed to generate report.")
    
    # No need to start the event loop
    return 0

if __name__ == "__main__":
    sys.exit(main())
