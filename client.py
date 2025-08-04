import socket
import threading
from urllib import response

import customtkinter as ctk

SERVER_HOST = "0.0.0.0"  # Your server's IP address
SERVER_PORT = 5002  # Port the server is listening on
separator_token = "<SEP>" # we will use this to separate the client name & message

class ChatApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Group 4 Chat System")
        self.geometry("600x500")

        # Initialize frames for login, chat, and log history
        self.login_frame = ctk.CTkFrame(self)
        self.chat_frame = ctk.CTkFrame(self)
        self.log_frame = ctk.CTkFrame(self)
        self.signup_frame = ctk.CTkFrame(self)

        for frame in (self.login_frame, self.chat_frame, self.log_frame, self.signup_frame):
            frame.grid(row=0, column=0, sticky="nsew")

        self._build_login_frame()
        self._build_signup_frame()
        self._build_chat_frame()
        self._build_log_frame()

        self.show_frame(self.login_frame)

        # Initialize socket
        #self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_thread = None
        self.username = ""

    def show_frame(self, frame):
        """Show the specified frame."""
        frame.tkraise()

    def _build_login_frame(self):
        """Build the login frame."""
        username_label = ctk.CTkLabel(self.login_frame, text="Username:")
        username_label.pack(pady=(50, 5))
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Enter username")
        self.username_entry.pack(pady=5, padx=20)

        password_label = ctk.CTkLabel(self.login_frame, text="Password:")
        password_label.pack(pady=5)
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Enter password", show="*")
        self.password_entry.pack(pady=5, padx=20)

        start_button = ctk.CTkButton(self.login_frame, text="Start Chat", command=self.start_chat)
        start_button.pack(pady=20)

        self.login_error = ctk.CTkLabel(self.login_frame, text="", text_color="red")
        self.login_error.pack(pady=5)

        # Sign up prompt and button
        ctk.CTkLabel(self.login_frame, text="Don't have an account? Sign up here").pack(pady=5)
        ctk.CTkButton(self.login_frame, text="Sign up", command=lambda: self.show_frame(self.signup_frame)).pack(pady=5)

    def _build_signup_frame(self):
        """Build the signup frame."""
        ctk.CTkLabel(self.signup_frame, text="Sign up for a new account", font=("Arial", 16)).pack(pady=(40, 10))

        self.new_username_entry = ctk.CTkEntry(self.signup_frame, placeholder_text="New username")
        self.new_username_entry.pack(pady=5, padx=20)

        self.new_password_entry = ctk.CTkEntry(self.signup_frame, placeholder_text="New password", show="*")
        self.new_password_entry.pack(pady=5, padx=20)

        self.confirm_password_entry = ctk.CTkEntry(self.signup_frame, placeholder_text="Confirm password", show="*")
        self.confirm_password_entry.pack(pady=5, padx=20)

        # Error or success label
        self.signup_error = ctk.CTkLabel(self.signup_frame, text="", text_color="red")
        self.signup_error.pack(pady=5)

        ctk.CTkButton(self.signup_frame, text="Create Account", command=self.create_account).pack(pady=5)
        ctk.CTkButton(self.signup_frame, text="Back to Login", command=lambda: self.show_frame(self.login_frame)).pack()

    def create_account(self):
        """Create a new account."""
        new_username = self.new_username_entry.get().strip()
        new_password = self.new_password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()
        self.signup_error.configure(text="")

        if not new_username or not new_password or not confirm_password:
            self.signup_error.configure(text="Please enter all fields.")
            return
        elif new_password != confirm_password:
            self.signup_error.configure(text="Passwords do not match.")
            return

        try:
            # New socket for sign up
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.connect((SERVER_HOST, SERVER_PORT))
            new_socket.send(f"/signup{separator_token}{new_username}{separator_token}{new_password}".encode())
            response = new_socket.recv(1024).decode()
            new_socket.close()

            if response.startswith("Signup successful."):
                self.signup_error.configure(text="Account created successfully. Please log in.", text_color="green")
            else:
                self.signup_error.configure(text=response, text_color="red")

        except Exception as e:
            self.signup_error.configure(text=f"Error creating account: {e}", text_color="red")

    def _build_chat_frame(self):
        """Build the chat frame."""
        self.chat_textbox = ctk.CTkTextbox(self.chat_frame, width=550, height=300)
        self.chat_textbox.insert("1.0", "Chat messages will appear here...\n")
        self.chat_textbox.configure(state="disabled")
        self.chat_textbox.pack(pady=10)

        entry_frame = ctk.CTkFrame(self.chat_frame)
        entry_frame.pack(fill="x", pady=10, padx=10)

        self.message_entry = ctk.CTkEntry(entry_frame, placeholder_text="Type your message here...")
        self.message_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))

        send_button = ctk.CTkButton(entry_frame, text="Send", command=self.send_message)
        send_button.pack(side="left")

        log_button = ctk.CTkButton(self.chat_frame, text="View Chat Log", command=self.view_chat_log)
        log_button.pack(pady=5)

        # adding line to bind return key for easy chat use (instead of having to hit send message)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

    def _build_log_frame(self):
        """Build the chat log frame."""
        log_label = ctk.CTkLabel(self.log_frame, text="Chat History", font=("Arial", 14))
        log_label.pack(pady=(20, 10))

        self.log_textbox = ctk.CTkTextbox(self.log_frame, width=550, height=300)
        self.log_textbox.insert("1.0", "Past chat history will appear here...\n")
        self.log_textbox.configure(state="disabled")
        self.log_textbox.pack(pady=5)

        back_button = ctk.CTkButton(self.log_frame, text="Back to Chat",
                                    command=lambda: self.show_frame(self.chat_frame))
        back_button.pack(pady=20)

    def start_chat(self):
        """Start the chat by connecting to the server."""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.username = self.username_entry.get().strip()
        self.password = self.password_entry.get().strip()

        self.login_error.configure(text="")

        # if not self.username:
        #     return  # Don't proceed if the username is empty
        if not self.username or not self.password:
            self.login_error.configure(text="Please enter both username and password.")
            return

        try:
            self.s.connect((SERVER_HOST, SERVER_PORT))  # Connect to the server
            self.s.send(f"{self.username}{separator_token}{self.password}".encode())  # Send the username and password to the server
            #self.s.send(self.username.encode())  # Send the username to the server

            # wait for authentication response
            auth_response = self.s.recv(1024).decode()
            if auth_response != "Authentication successful.":
                self.login_error.configure(text="Authentication failed. Please sign up for an account.")
                self.s.close()
                return

            # Start a background thread after authentication to receive messages
            self.client_thread = threading.Thread(target=self.receive_messages)
            self.client_thread.daemon = True
            self.client_thread.start()

            # Switch to the chat frame
            self.show_frame(self.chat_frame)
        except Exception as e:
            self.login_error.configure(text=f"Error connecting to server: {e}")
            self.chat_textbox.configure(state="normal")
            self.chat_textbox.insert("1.0", f"Error connecting to server: {e}\n")
            self.chat_textbox.configure(state="disabled")

    def send_message(self):
        """Send a message to the server."""
        message = self.message_entry.get().strip()
        if message:
            try:
                self.s.send(message.encode('utf-8'))
                self.message_entry.delete(0, 'end')  # Clear the message entry
            except BrokenPipeError:
                self.chat_textbox.configure(state="normal")
                self.chat_textbox.insert("1.0", "Error: Connection to server lost.\n")
                self.chat_textbox.configure(state="disabled")

    def receive_messages(self):
        """Listen for incoming messages from the server."""
        while True:
            try:
                msg = self.s.recv(1024).decode('utf-8')
                if not msg:
                    break
                self.display_message(msg)
            except (ConnectionResetError, OSError):
                break
        self.s.close()

    def display_message(self, message):
        """Display a message in the chat textbox."""
        self.chat_textbox.configure(state='normal')
        self.chat_textbox.insert('end', message + '\n')
        self.chat_textbox.configure(state='disabled')
        self.chat_textbox.see('end')

    def view_chat_log(self):
        """Request chat history from the server and display it in the log frame."""
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete(1.0, 'end')  # Clear previous chat history

        # Send a request for chat history to the server
        self.s.send("/history".encode())

        self.log_textbox.insert('end', "Loading chat history...\n")
        self.log_textbox.configure(state="disabled")

    def on_closing(self):
        """Handle when the Tkinter window is closed."""
        try:
            self.s.close()
        except:
            pass
        self.destroy()


if __name__ == "__main__":
    ctk.set_appearance_mode("light")  # Set appearance mode
    ctk.set_default_color_theme("blue")  # Set color theme
    app = ChatApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()