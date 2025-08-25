import os
import sys
import datetime
import colorama

class Logger:
    _instance = None # Singleton instance to ensure only one Logger object exists

    # Define logging levels for filtering messages
    _LOG_LEVELS = {
        "DEBUG": 0,
        "INFO": 1,
        "WARNING": 2,
        "ERROR": 3,
        # SUCCESS messages are generally important to show, treating them like INFO for display purposes
        "SUCCESS": 1
    }

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
                script_dir = os.path.dirname(os.path.abspath(__file__))
                self.log_dir = os.path.join(script_dir, "logs")
            else:
                self.log_dir = log_dir
            
            os.makedirs(self.log_dir, exist_ok=True) # Ensure log directory exists

            # Create a unique log file name with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_file = os.path.join(self.log_dir, f"burp-frame_{timestamp}.log") # Consistent log file naming
            self._current_level = self._LOG_LEVELS["INFO"] # Default to INFO level verbosity
            self._initialized = True # Mark as initialized

    def set_level(self, level_name):
        """
        Sets the minimum logging level that will be displayed in the console.
        Messages below this level will be suppressed from console output but still written to file.
        
        Args:
            level_name (str): The name of the desired logging level (e.g., "INFO", "DEBUG", "WARNING", "ERROR").
        """
        level_name = level_name.upper()
        if level_name in self._LOG_LEVELS:
            self._current_level = self._LOG_LEVELS[level_name]
            # Log this change only if the new level allows INFO messages
            if self._current_level <= self._LOG_LEVELS["INFO"]:
                self.info(f"Logging verbosity level set to '{level_name}'.")
        else:
            self.error(f"Invalid logging level: '{level_name}'. Valid options: {', '.join(self._LOG_LEVELS.keys())}")

    def _log(self, level_name, message_content, console_color):
        """Internal method to write logs to console and file, respecting current level."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        file_message = f"[{timestamp}] [{level_name}] {message_content}" # Always write full message to file

        # Print to console only if the message's level is greater than or equal to the current console level
        if self._LOG_LEVELS[level_name] >= self._current_level:
            console_message = f"[{timestamp}] [{level_name}] {console_color}{message_content}{colorama.Style.RESET_ALL}"
            print(console_message)
        
        # Write to log file
        with open(self.log_file, "a", encoding='utf-8') as f:
            f.write(file_message + "\n")

    def debug(self, message):
        """Logs a debug message. Visible only in verbose mode."""
        self._log("DEBUG", message, colorama.Fore.BLUE)

    def info(self, message):
        """Logs an informational message. Visible by default."""
        self._log("INFO", message, colorama.Fore.WHITE)

    def warn(self, message):
        """Logs a warning message. Visible by default."""
        self._log("WARNING", f"⚠ {message}", colorama.Fore.YELLOW)

    def error(self, message):
        """Logs an error message. Visible by default."""
        self._log("ERROR", f"❌ {message}", colorama.Fore.RED)

    def success(self, message):
        """Logs a success message. Visible by default."""
        self._log("SUCCESS", f"✓ {message}", colorama.Fore.GREEN)
    
    def progress(self, message, current, total):
        """Displays a progress bar in the console. Always shown regardless of level."""
        bar_length = 20
        filled = int(bar_length * current / total)
        bar = '█' * filled + ' ' * (bar_length - filled)
        # Use carriage return '\r' to overwrite the line, creating a dynamic progress bar
        sys.stdout.write(f"\r[{message}] [{colorama.Fore.CYAN}{bar}{colorama.Style.RESET_ALL}] {current*100/total:.0f}%")
        sys.stdout.flush() 
        if current == total:
            print("\n") 
