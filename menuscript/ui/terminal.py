#!/usr/bin/env python3
"""
menuscript.ui.terminal - Terminal configuration and input handling
"""
import sys
import readline
import atexit
import os


def init_readline():
    """
    Initialize readline for proper line editing support.

    Enables:
    - Backspace/Delete key support
    - Arrow key navigation
    - Command history
    - Emacs-style editing keybindings
    """
    # Set up history
    histfile = os.path.join(os.path.expanduser("~"), ".menuscript_history")
    try:
        readline.read_history_file(histfile)
        # Limit history to 1000 entries
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass

    # Save history on exit
    atexit.register(readline.write_history_file, histfile)

    # Enable tab completion (can be customized later)
    readline.parse_and_bind('tab: complete')

    # Set up proper keybindings for editing
    # These handle backspace, delete, arrow keys properly
    readline.parse_and_bind('set editing-mode emacs')

    # Ensure proper character handling
    if hasattr(readline, 'set_completer_delims'):
        # Set delimiters for word completion
        readline.set_completer_delims(' \t\n;')

    # Try to fix terminal settings
    try:
        import termios
        import tty

        # Get current terminal settings
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        # Make a copy to modify
        new_settings = termios.tcgetattr(fd)

        # Set ERASE character to handle backspace
        # VERASE is typically index 2 in the cc array
        new_settings[6][termios.VERASE] = b'\x7f'  # DEL character

        # Apply the settings
        termios.tcsetattr(fd, termios.TCSANOW, new_settings)

    except (ImportError, OSError, termios.error):
        # If termios isn't available or fails, continue anyway
        # readline will still provide basic functionality
        pass


def setup_terminal():
    """
    Set up terminal for interactive use.

    Call this at the start of interactive mode to ensure
    proper terminal configuration.
    """
    # Initialize readline first
    init_readline()

    # Ensure stdout is unbuffered for immediate output
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
