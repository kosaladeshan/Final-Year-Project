import sys
import os
from PyQt6.QtWidgets import QApplication
from Report import SaveInterface

def main():
    try:
        print("Creating QApplication...")
        app = QApplication(sys.argv)
        
        print("Creating SaveInterface...")
        window = SaveInterface()
        
        print("Showing window...")
        window.show()
        
        print("Starting event loop...")
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
