"""
Secure P2P Instant Messaging Tool — entry point.

See crypto.py and gui.py for the implementation.
"""

import tkinter as tk

from gui import SecureChatApp


def main():
    root = tk.Tk()
    SecureChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
