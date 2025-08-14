import os
import sys
import datetime
import colorama

class Logger:
    _instance = None # Singleton instance to ensure only one Logger object exists

    def __new__(cls, log_dir=None):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._init_logger(log_dir) # Call actual initialization method
        return cls._instance

    def _init_logger(self, log_dir):
        """Initializes the logger instance (called only once by the singleton)."""
        # Ensure initialization happens only once for the singleton
        if not hasattr(self, '_initialized'):
            colorama.init(autoreset=True) # Initialize colorama for colored output

            # Determine log_dir if not explicitly provided
            if log_dir is None:
                # Default log directory: 'logs' subdirectory relative to logger.py's location
                # This makes the logger self-sufficient in finding its log location
                script_dir = os.path.dirname(os.path.abspath(__file__))
                log_dir = os.path.join(script_dir, "logs")
            
            self.log_dir = log_dir
            os.makedirs(self.log_dir, exist_ok=True) # Ensure log directory exists

            # Create a unique log file name with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_file = os.path.join(self.log_dir, f"burp-frame_{timestamp}.log") # Consistent log file naming
            self._initialized = True # Mark as initialized

    def _log(self, level, message):
        """Internal method to write logs to console and file."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message) # Print to console
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(log_message + "\n") # Write to log file

    def info(self, message):
        """Logs an informational message."""
        self._log("INFO", f"{colorama.Fore.WHITE}{message}")

    def warn(self, message):
        """Logs a warning message."""
        self._log("WARNING", f"{colorama.Fore.YELLOW}⚠ {message}")

    def error(self, message):
        """Logs an error message."""
        self._log("ERROR", f"{colorama.Fore.RED}❌ {message}")

    def success(self, message):
        """Logs a success message."""
        self._log("SUCCESS", f"{colorama.Fore.GREEN}✓ {message}")
    
    def progress(self, message, current, total):
        """Displays a progress bar in the console."""
        bar_length = 20
        filled = int(bar_length * current / total)
        bar = '█' * filled + ' ' * (bar_length - filled)
        # Use carriage return '\r' to overwrite the line, creating a dynamic progress bar
        sys.stdout.write(f"\r[{message}] [{colorama.Fore.CYAN}{bar}{colorama.Style.RESET_ALL}] {current*100/total:.0f}%")
        sys.stdout.flush() # Ensure immediate display
        if current == total:
            print("\n") # Newline when progress is complete
