# GUI Module for CryptXfer
# Author: Nguyen Duong Quang
# www.m3rooted.com

import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import os
import threading
from core import (
    send_file, receive_file,
    validate_password, validate_host, validate_port,
    MIN_PASSWORD_LENGTH, PORT_MIN, PORT_MAX,
    logger
)

class CryptXferGUI:
    """Modern GUI for CryptXfer secure file transfer"""
    
    # Modern color scheme
    BG_COLOR = '#1a1a2e'
    SECONDARY_BG = '#16213e'
    ACCENT_COLOR = '#0f3460'
    BUTTON_COLOR = '#533483'
    BUTTON_HOVER = '#7b4397'
    TEXT_COLOR = '#eee'
    ACCENT_TEXT = '#00d4ff'
    SUCCESS_COLOR = '#00ff88'
    ERROR_COLOR = '#ff4757'
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptXfer - Secure File Transfer")
        self.root.geometry('500x650')
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG_COLOR)
        
        self.selected_file = None
        self.setup_ui()
    
    def configure_label(self, label, font_size=10, bold=False, color=None):
        """Configure label styling"""
        if color is None:
            color = self.TEXT_COLOR
        font_weight = 'bold' if bold else 'normal'
        label.configure(
            bg=self.BG_COLOR, 
            fg=color, 
            font=('Segoe UI', font_size, font_weight)
        )
    
    def configure_entry(self, entry, width=35):
        """Configure entry field styling"""
        entry.configure(
            bg=self.SECONDARY_BG,
            fg=self.TEXT_COLOR,
            font=('Segoe UI', 11),
            insertbackground=self.ACCENT_TEXT,
            relief='flat',
            bd=2,
            highlightthickness=2,
            highlightbackground=self.ACCENT_COLOR,
            highlightcolor=self.ACCENT_TEXT,
            width=width
        )
    
    def configure_button(self, button, width=20):
        """Configure button styling"""
        button.configure(
            bg=self.BUTTON_COLOR,
            fg=self.TEXT_COLOR,
            font=('Segoe UI', 10, 'bold'),
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2',
            activebackground=self.BUTTON_HOVER,
            activeforeground=self.TEXT_COLOR,
            width=width
        )
    
    def setup_ui(self):
        """Setup all UI components"""
        # Header
        header_frame = tk.Frame(self.root, bg=self.ACCENT_COLOR, height=80)
        header_frame.pack(fill='x', pady=(0, 20))
        
        title_label = tk.Label(header_frame, text="🔐 CryptXfer", 
                              font=('Segoe UI', 24, 'bold'), 
                              bg=self.ACCENT_COLOR, fg=self.ACCENT_TEXT)
        title_label.pack(pady=(15, 0))
        
        author_label = tk.Label(header_frame, text="by Nguyen Duong Quang", 
                               font=('Segoe UI', 9, 'italic'), 
                               bg=self.ACCENT_COLOR, fg=self.TEXT_COLOR)
        author_label.pack()
        
        website_label = tk.Label(header_frame, text="www.m3rooted.com", 
                                font=('Segoe UI', 8), 
                                bg=self.ACCENT_COLOR, fg='#888')
        website_label.pack(pady=(2, 10))
        
        # Mode selection
        mode_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        mode_frame.pack(pady=10)
        
        self.mode_var = tk.StringVar(value="send")
        send_radio = tk.Radiobutton(
            mode_frame, 
            text="📤 Send", 
            variable=self.mode_var, 
            value="send",
            bg=self.BG_COLOR,
            fg=self.TEXT_COLOR,
            font=('Segoe UI', 11, 'bold'),
            selectcolor=self.ACCENT_COLOR,
            activebackground=self.BG_COLOR,
            activeforeground=self.ACCENT_TEXT,
            cursor='hand2'
        )
        send_radio.pack(side='left', padx=20)
        
        receive_radio = tk.Radiobutton(
            mode_frame, 
            text="📥 Receive", 
            variable=self.mode_var, 
            value="receive",
            bg=self.BG_COLOR,
            fg=self.TEXT_COLOR,
            font=('Segoe UI', 11, 'bold'),
            selectcolor=self.ACCENT_COLOR,
            activebackground=self.BG_COLOR,
            activeforeground=self.ACCENT_TEXT,
            cursor='hand2'
        )
        receive_radio.pack(side='left', padx=20)
        
        # Host input
        host_label = tk.Label(self.root, text="🌐 Host Address:")
        self.configure_label(host_label, 10, True)
        host_label.pack(pady=(15, 5))
        self.host_entry = tk.Entry(self.root)
        self.configure_entry(self.host_entry)
        self.host_entry.pack(pady=5, ipady=5)
        
        # Port input
        port_label = tk.Label(self.root, text="🔌 Port:")
        self.configure_label(port_label, 10, True)
        port_label.pack(pady=(10, 5))
        self.port_entry = tk.Entry(self.root)
        self.configure_entry(self.port_entry)
        self.port_entry.pack(pady=5, ipady=5)
        
        # Password input
        password_label = tk.Label(self.root, text="🔑 Password (min 8 chars):")
        self.configure_label(password_label, 10, True)
        password_label.pack(pady=(10, 5))
        self.password_entry = tk.Entry(self.root, show="●")
        self.configure_entry(self.password_entry)
        self.password_entry.pack(pady=5, ipady=5)
        
        # File selection
        file_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        file_frame.pack(pady=15)
        
        self.file_path_label = tk.Label(file_frame, text="📄 No file chosen", 
                                        font=('Segoe UI', 9, 'italic'))
        self.configure_label(self.file_path_label, 9, False, '#aaa')
        self.file_path_label.pack(pady=5)
        
        choose_file_button = tk.Button(file_frame, text="📁 Choose File", 
                                      command=self.choose_file)
        self.configure_button(choose_file_button, 18)
        choose_file_button.pack(pady=5)
        
        # Execute button
        execute_button = tk.Button(
            self.root, 
            text="⚡ Execute Transfer", 
            command=self.execute_transfer
        )
        self.configure_button(execute_button, 22)
        execute_button.pack(pady=20)
        
        # Status label
        self.status_label = tk.Label(self.root, text="Ready", font=('Segoe UI', 9))
        self.configure_label(self.status_label, 9, False, self.SUCCESS_COLOR)
        self.status_label.pack(pady=10)
    
    def choose_file(self):
        """Handle file selection"""
        filename = filedialog.askopenfilename()
        if filename:
            display_name = os.path.basename(filename)
            if len(display_name) > 40:
                display_name = display_name[:37] + "..."
            self.file_path_label.config(text=f"📄 {display_name}", fg=self.SUCCESS_COLOR)
            self.selected_file = filename
        else:
            self.file_path_label.config(text="📄 No file chosen", fg='#aaa')
            self.selected_file = None
    
    def execute_transfer(self):
        """Execute send or receive based on mode"""
        if self.mode_var.get() == "send":
            self.send_file_gui()
        else:
            self.receive_file_gui()
    
    def send_file_gui(self):
        """GUI wrapper for sending file with validation and threading"""
        password = self.password_entry.get()
        filename = self.selected_file
        host = self.host_entry.get()
        port_str = self.port_entry.get()
        
        # Input validation
        if not validate_password(password):
            self.status_label.config(
                text=f"❌ Password must be at least {MIN_PASSWORD_LENGTH} characters!", 
                fg=self.ERROR_COLOR
            )
            messagebox.showerror("Validation Error", 
                               f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
            return
        
        if not validate_host(host):
            self.status_label.config(text="❌ Host cannot be empty!", fg=self.ERROR_COLOR)
            messagebox.showerror("Validation Error", "Host cannot be empty")
            return
        
        valid_port, port = validate_port(port_str)
        if not valid_port:
            self.status_label.config(
                text=f"❌ Port must be between {PORT_MIN} and {PORT_MAX}!", 
                fg=self.ERROR_COLOR
            )
            messagebox.showerror("Validation Error", 
                               f"Port must be between {PORT_MIN} and {PORT_MAX}")
            return
        
        if not filename or not os.path.exists(filename):
            self.status_label.config(text="❌ Please choose a valid file!", fg=self.ERROR_COLOR)
            messagebox.showerror("Validation Error", "Please choose a valid file")
            return
        
        # Run in thread to prevent GUI freeze
        def send_thread():
            try:
                self.status_label.config(text="📤 Sending file...", fg=self.ACCENT_TEXT)
                sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sender_socket.connect((host, port))
                send_file(sender_socket, filename, password)
                sender_socket.close()
                self.status_label.config(text="✅ File sent successfully!", fg=self.SUCCESS_COLOR)
                messagebox.showinfo("Success", "File sent successfully!")
            except Exception as e:
                logger.error(f"Send error: {e}")
                self.status_label.config(text=f"❌ Error: {str(e)[:50]}", fg=self.ERROR_COLOR)
                messagebox.showerror("Error", f"Failed to send file: {str(e)}")
        
        thread = threading.Thread(target=send_thread, daemon=True)
        thread.start()
    
    def receive_file_gui(self):
        """GUI wrapper for receiving file with validation and threading"""
        password = self.password_entry.get()
        port_str = self.port_entry.get()
        
        # Input validation
        if not validate_password(password):
            self.status_label.config(
                text=f"❌ Password must be at least {MIN_PASSWORD_LENGTH} characters!", 
                fg=self.ERROR_COLOR
            )
            messagebox.showerror("Validation Error", 
                               f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
            return
        
        valid_port, port = validate_port(port_str)
        if not valid_port:
            self.status_label.config(
                text=f"❌ Port must be between {PORT_MIN} and {PORT_MAX}!", 
                fg=self.ERROR_COLOR
            )
            messagebox.showerror("Validation Error", 
                               f"Port must be between {PORT_MIN} and {PORT_MAX}")
            return
        
        # Run in thread to prevent GUI freeze
        def receive_thread():
            try:
                self.status_label.config(text="📥 Waiting for file...", fg=self.ACCENT_TEXT)
                receive_file(password, port)
                self.status_label.config(text="✅ File received successfully!", fg=self.SUCCESS_COLOR)
                messagebox.showinfo("Success", "File received successfully!")
            except Exception as e:
                logger.error(f"Receive error: {e}")
                self.status_label.config(text=f"❌ Error: {str(e)[:50]}", fg=self.ERROR_COLOR)
                messagebox.showerror("Error", f"Failed to receive file: {str(e)}")
        
        thread = threading.Thread(target=receive_thread, daemon=True)
        thread.start()
    
    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()


def main():
    """Main entry point for GUI"""
    app = CryptXferGUI()
    app.run()


if __name__ == "__main__":
    main()
