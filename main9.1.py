from PyQt5.QtWidgets import *
from PyQt5 import QtCore
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtWebChannel import *
from PyQt5.QtWebEngineCore import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sqlite3, re, smtplib, time, os, base64, pyaudio, sys, numpy as np, cv2, struct
import random, socket, threading, json, math, traceback, collections
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Tuple


# Change this depending on the admin's IP address
server_ip = "172.20.10.7" 



class GUI_Window(QMainWindow): # Defines a custom GUI window class which uses PyQT to inherit from.
    def __init__(self, title="Encrypta Secure Intranet"): # Constructor method initialises the window.
        super().__init__() # Calls the parent class contructor to set up the base functions.

        # Sets the title of the window to the value passed as an argument (defaults to it).                              
        self.setWindowTitle(title)

        # Set the minimum size of the window. 
        self.setMinimumSize(1000, 600)

        # Create a main container for the window's components here and set it.
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Create a vertical box layout for organising widgets in columns.
        self.layout = QVBoxLayout(self.central_widget)

        # Sets the icon of the window.
        self.setWindowIcon(QIcon("icon.png"))





class Log_In_Window(GUI_Window):
    # Constructor method initialises the window.
    def __init__(self):
        super().__init__(title="Encrypta - Log In")
        self.init_ui()
        self.showMaximized()

    def init_ui(self):
        # Create a main layout for the window.
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        # Create a left container for the window.
        left_container = QWidget()
        left_container.setStyleSheet("background-color: white;")
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(50, 50, 50, 50)
        # Create a label for the login image.
        login_image_container = QLabel()
        login_image_container.setMinimumSize(350, 400)
        login_image_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        login_image_container.setAlignment(Qt.AlignCenter)
        login_pixmap = QPixmap("login.png")
        login_image_container.setPixmap(login_pixmap)
        login_image_container.setScaledContents(True)
        left_layout.addWidget(login_image_container)
        # Create a right container for the window.
        right_container = QWidget()
        right_container.setStyleSheet("background-color: white;")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(80, 50, 80, 50)
        # Create a container for the logo.
        logo_container = QLabel()
        logo_container.setMinimumSize(200, 100)
        logo_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        logo_container.setAlignment(Qt.AlignCenter)
        logo_pixmap = QPixmap("logo2.png")
        logo_container.setPixmap(logo_pixmap)
        logo_container.setScaledContents(True)
        right_layout.addWidget(logo_container)
        # Create a container for the login form.
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(30)
        # Create a label for the login form.
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setMinimumSize(450, 60)
        self.username_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.username_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;} """)
        form_layout.addWidget(self.username_input)
        # Create a label for the password input.
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumSize(450, 60)
        self.password_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.password_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;}""")
        form_layout.addWidget(self.password_input)
        # Create a container for the login button.
        form_layout.addSpacing(30)
        login_button_container = QWidget()
        login_button_layout = QHBoxLayout(login_button_container)
        login_button = QPushButton("Log In")
        login_button.setFixedSize(450, 60)
        login_button.setStyleSheet("""QPushButton {background-color: #007BFF; 
                                   color: white; border: none; 
                                   border-radius: 5px; font-size: 20px;
                                    font-weight: bold;}
            QPushButton:hover {background-color: #0056b3;}""")
        login_button.clicked.connect(self.handle_login)
        login_button_layout.addWidget(login_button)
        form_layout.addWidget(login_button_container)
        # Create a container for the sign up button.
        form_layout.addSpacing(20)
        signup_button_container = QWidget()
        signup_button_layout = QHBoxLayout(signup_button_container)
        signup_button = QPushButton("Sign Up")
        signup_button.setFixedSize(300, 40)
        signup_button.setStyleSheet("""QPushButton {background-color: transparent;
                                     color: #007BFF; border: none; font-size: 18px; 
                                    font-weight: bold; text-align: center;}
            QPushButton:hover {color: #0056b3;}""")
        signup_button.clicked.connect(self.redirect_to_signup)
        signup_button_layout.addWidget(signup_button)
        form_layout.addWidget(signup_button_container)
        # Add the form container to the right layout.
        right_layout.addWidget(form_container, alignment=Qt.AlignHCenter)
        right_layout.addStretch()
        main_layout.addWidget(left_container, 1)
        main_layout.addWidget(right_container, 1)
        self.layout.addLayout(main_layout)



    def handle_login(self):
        # Handle the login process
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        # Check if the fields are empty
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return False
        # Check if the user is an admin
        if username == "admin" and password == "adminpassword":
            self.redirect = Admin_Dash_Window()
            self.redirect.show()
            self.close()
        else:
            login_result, username = Log_In(username, password)
            if login_result:
                self.redirect = Main_Menu_Window(username)  
                self.close()
                return True
            else:
                self.username_input.clear()
                self.password_input.clear()


    def redirect_to_signup(self):
        # Redirect to the sign up window
        self.redirect = Sign_Up_Window()
        self.redirect.show()
        self.close()





class Sign_Up_Window(GUI_Window):    
    # Constructor method initialises the window.
    def __init__(self):
        super().__init__(title="Encrypta - Sign Up")
        self.init_ui()
        self.showMaximized()


    def init_ui(self):
        # Create a main layout for the window.
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        # Create a left container for the window.
        left_container = QWidget()
        left_container.setStyleSheet("background-color: white;")
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(50, 50, 50, 50)
        # Create a label for the sign up image.
        login_image_container = QLabel()
        login_image_container.setMinimumSize(350, 400)
        login_image_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        login_image_container.setAlignment(Qt.AlignCenter)
        login_pixmap = QPixmap("signup.png")
        login_image_container.setPixmap(login_pixmap)
        login_image_container.setScaledContents(True)
        left_layout.addWidget(login_image_container)
        # Create a right container for the window.
        right_container = QWidget()
        right_container.setStyleSheet("background-color: white;")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(80, 50, 80, 50)
        # Create a container for the logo.
        logo_container = QLabel()
        logo_container.setMinimumSize(200, 100)
        logo_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        logo_container.setAlignment(Qt.AlignCenter)
        logo_pixmap = QPixmap("logo2.png")
        logo_container.setPixmap(logo_pixmap)
        logo_container.setScaledContents(True)
        right_layout.addWidget(logo_container)
        # Create a container for the sign up form.
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(30)
        # Create a label for the sign up form. 
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.setMinimumSize(450, 60)
        self.username_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.username_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;} """)
        form_layout.addWidget(self.username_input)
        # Create a label for the email input.
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter Email")
        self.email_input.setMinimumSize(450, 60)
        self.email_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.email_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;}""")
        form_layout.addWidget(self.email_input)
        # Create a label for the password input.
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumSize(450, 60)
        self.password_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.password_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;}""")
        form_layout.addWidget(self.password_input)
        # Create a label for the confirm password input.
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm Password")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setMinimumSize(450, 60)
        self.confirm_password_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.confirm_password_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc; border-radius: 5px; padding: 8px; font-size: 20px;}
            QLineEdit:focus {border: 1px solid #007BFF;}""")
        form_layout.addWidget(self.confirm_password_input)
        # Create a container for the sign up button.
        form_layout.addSpacing(30)
        signup_button_container = QWidget()
        signup_button_layout = QHBoxLayout(signup_button_container)
        signup_button = QPushButton("Sign Up")
        signup_button.setFixedSize(450, 60)
        signup_button.setStyleSheet("""QPushButton {background-color: #007BFF;
                                     color: white; border: none; border-radius: 5px;
                                    font-size: 20px; font-weight: bold;}
            QPushButton:hover {background-color: #0056b3;}""")
        signup_button.clicked.connect(self.handle_signup)
        signup_button_layout.addWidget(signup_button)
        form_layout.addWidget(signup_button_container)
        # Create a container for the login button.
        form_layout.addSpacing(20)
        login_button_container = QWidget()
        login_button_layout = QHBoxLayout(login_button_container)
        login_button = QPushButton("Log In")
        login_button.setFixedSize(300, 40)
        login_button.setStyleSheet("""QPushButton {background-color: transparent; 
                                   color: #007BFF; border: none; font-size: 18px;
                                    font-weight: bold; text-align: center;}
            QPushButton:hover {color: #0056b3;}""")
        login_button.clicked.connect(self.redirect_to_login)
        login_button_layout.addWidget(login_button)
        form_layout.addWidget(login_button_container)
        # Add the form container to the right layout.
        right_layout.addWidget(form_container, alignment=Qt.AlignHCenter)
        right_layout.addStretch()
        main_layout.addWidget(left_container, 1)
        main_layout.addWidget(right_container, 1)
        self.layout.addLayout(main_layout)


    def redirect_to_login(self):
        self.redirect = Log_In_Window()
        self.redirect.show()
        self.close()


    def handle_signup(self):
        # Handle the sign up process
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        # Check if the fields are empty
        if not username or not password or not confirm_password or not email:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return False
        # Check if the passwords match
        if Sign_Up(username, password, confirm_password, email):
            self.redirect = Log_In_Window()
            self.redirect.show()
            self.close()
            return True
        else:
            self.username_input.clear()
            self.password_input.clear()
            self.confirm_password_input.clear()
            self.email_input.clear()  





class ConnectionHandler(QObject):
    # Update the signal to include sender_ip
    connection_request_received = pyqtSignal(str, str, object, str)  
    # username, public_key, client_socket, sender_ip
    connection_accepted = pyqtSignal(str, str, str)  
    # username, public_key
    connection_rejected = pyqtSignal(str) 
     # username
    connection_error = pyqtSignal(str)  
    # error message





class Main_Menu_Window(GUI_Window):xq
    server_running = False
    active_connections = []

    # Constructor method initialises the window.
    def __init__(self, username):
        super().__init__(title="Encrypta - Main Menu")
        self.username = username
        self.client_socket = None
        self.server_thread = None
        self.is_listening = False
        self.connection_handler = ConnectionHandler()
        self.init_ui()
        self.showMaximized()
        self.load_existing_connections()

        # Only start the connection listener if no server is running
        if not Main_Menu_Window.server_running:
            self.start_connection_listener()
        else:
            # Update the status label to show we're already listening
            self.status_label.setText("Connection Status: Listening")
            self.status_label.setStyleSheet("color: #28a745; margin-bottom: 10px;")

        self.handle_connection_request

        # Connect signals to their respective handlers
        self.connection_handler.connection_request_received.connect(
            self.handle_connection_request,
            type=Qt.QueuedConnection  # Ensure cross-thread signal haSndling
        )
        self.connection_handler.connection_accepted.connect(
            self.handle_connection_accepted,
            type=Qt.QueuedConnection
        )
        self.connection_handler.connection_rejected.connect(
            self.handle_connection_rejected,
            type=Qt.QueuedConnection
        )
        self.connection_handler.connection_error.connect(
            self.handle_connection_error,
            type=Qt.QueuedConnection
        )


    def init_ui(self):
        main_layout = QHBoxLayout()
        
        # Left Panel (70% width)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Header with logout button
        header = QHBoxLayout()
        self.logout_button = QPushButton("Log Out")
        self.logout_button.setStyleSheet("""
            QPushButton { background-color: #dc3545; color: white; border: none;
                        border-radius: 3px; padding: 13px 10px; font-size: 20px;
                        font-weight: bold;}
            QPushButton:hover { background-color: #c82333; }""")
        self.logout_button.clicked.connect(self.log_out)
        header.addWidget(self.logout_button)
        header.addStretch()
        left_layout.addLayout(header)
        
        # Main Menu Title
        title = QLabel(f"Main Menu - {self.username}")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 50px; font-weight: bold; margin: 20px 0;")
        left_layout.addWidget(title)
        
        # Main Action Buttons
        buttons_layout = QHBoxLayout()
        buttons = [
            ("User Dashboard", "user-dash"),
            ("Direct Messages", "direct-messages"),
            ("Group Chats", "group-chats"),
            ("Calls", "calls")
        ]
        
        # Create buttons and connect them to their respective actions
        for button_text, button_id in buttons:
            button = QPushButton(button_text)
            button.setProperty("id", button_id)
            button.setStyleSheet("""
                QPushButton { background-color: #007BFF; color: white; border: none;
                            border-radius: 10px; padding: 30px 20px; font-size: 24px;
                            font-weight: bold; margin: 10px; }
                QPushButton:hover { background-color: #0056b3; } """)
            if button_id == "user-dash":
                button.clicked.connect(self.redirect_to_dash)
            elif button_id == "direct-messages":
                button.clicked.connect(self.redirect_to_direct_messages)
            elif button_id == "group-chats":
                button.clicked.connect(self.redirect_to_group_chats)
            else:
                button.clicked.connect(self.redirect_to_calls)
            buttons_layout.addWidget(button)
        
        left_layout.addLayout(buttons_layout)
        
        # Activity Feed
        activity_group = QGroupBox("Recent Activity")
        activity_group.setStyleSheet("""
            QGroupBox {font-size: 18px; font-weight: bold; border: 1px solid #ddd;
                border-radius: 5px; margin-top: 20px; padding: 15px;}""")
        activity_layout = QVBoxLayout()

        # Create a list widget to display activity feed
        self.activity_list = QListWidget()
        self.activity_list.setStyleSheet("""
            QListWidget {border: none;font-size: 14px;}
            QListWidget::item {padding: 10px;border-bottom: 1px solid #eee;}""")
        activity_layout.addWidget(self.activity_list)
        activity_group.setLayout(activity_layout)
        left_layout.addWidget(activity_group)
        
        # Right Panel (30% width)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Connections Management
        connections_group = QGroupBox("Connections")
        connections_group.setStyleSheet("""
            QGroupBox { font-size: 24px; font-weight: bold; border: 1px solid #ddd;
                border-radius: 5px; padding: 15px;}""")
        connections_layout = QVBoxLayout()
        
        # Connection status indicator
        self.status_label = QLabel("Connection Status: Not Listening")
        self.status_label.setStyleSheet("color: #dc3545; margin-bottom: 10px;")
        # INcrease font size of status label
        self.status_label.setFont(QFont("Arial", 12))
        connections_layout.addWidget(self.status_label)
        
        # Connections list
        self.connections_list = QTableWidget()
        self.connections_list.setColumnCount(2)
        self.connections_list.setHorizontalHeaderLabels(["Username", "Status"])
        self.connections_list.setStyleSheet("""
            QTableWidget {border: none; font-size: 17px;}
            QHeaderView::section {background-color: #f8f9fa; padding: 8px; border: none;
                                font-weight: bold;}""")
        self.connections_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.connections_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.connections_list.setColumnWidth(1, 100)
        connections_layout.addWidget(self.connections_list)
        
        # Add connection interface
        add_connection_layout = QHBoxLayout()
        self.connection_input = QLineEdit()
        self.connection_input.setPlaceholderText("Enter IP address")
        self.connection_input.setStyleSheet("""
            QLineEdit { padding: 8px; border: 1px solid #ccc; border-radius: 5px;
                            font-size: 20px;}""")
        add_connection_layout.addWidget(self.connection_input)

        # Add connection button
        self.add_button = QPushButton("Add Connection")
        self.add_button.setStyleSheet("""
            QPushButton {background-color: #28a745; color: white; border: none;
                border-radius: 5px; padding: 8px 15px; font-size: 16px; font-weight: bold;}
            QPushButton:hover { background-color: #218838; }""")
        # Connect the button to the send_connection_request method
        self.add_button.clicked.connect(self.send_connection_request)
        add_connection_layout.addWidget(self.add_button)
        connections_layout.addLayout(add_connection_layout)
        connections_group.setLayout(connections_layout)
        right_layout.addWidget(connections_group)
        
        # Set layouts
        main_layout.addWidget(left_panel, 70)
        main_layout.addWidget(right_panel, 30)
        self.layout.addLayout(main_layout)



    def load_existing_connections(self):
        """Load existing connections from database"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            # Get current user's ID
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            current_user_id = cursor.fetchone()[0]
            
            # Get all active connections for current user
            cursor.execute("""
                SELECT u.username, c.status
                FROM Connection c
                JOIN User u ON (c.sender_id = u.user_id OR c.receiver_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND u.username != ?
                AND c.status = 'connected'
            """, (current_user_id, current_user_id, self.username))
            
            connections = cursor.fetchall()
            
            # Add each connection to the UI and store in class-level list
            for username, status in connections:
                self.add_connection(username, 'Connected')
                if username not in [conn[0] for conn in Main_Menu_Window.active_connections]:
                    Main_Menu_Window.active_connections.append((username, 'Connected'))
                    
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()



    def start_connection_listener(self):
        if not Main_Menu_Window.server_running:
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.is_listening = True
            Main_Menu_Window.server_running = True
            self.status_label.setText("Connection Status: Listening")
            self.status_label.setStyleSheet("color: #28a745; margin-bottom: 10px;")


    def _run_server(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Add this line
            server.bind(('0.0.0.0', 5001))
            server.listen(5)
            
            while self.is_listening:
                try:
                    client, addr = server.accept()
                    threading.Thread(target=self._handle_connection, args=(client,)).start()
                except Exception as e:
                    if self.is_listening:
                        print(f"Error in server thread: {e}")
                        
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server.close()
            Main_Menu_Window.server_running = False



    def _handle_connection(self, client):
        """Handle incoming connection requests with improved reliability"""
        MAX_RETRIES = 3
        RETRY_DELAY = 0.5  # seconds
        

        def receive_with_timeout(client_socket, buffer_size=1024, timeout=5):
            """Helper function to receive data with timeout and retries"""
            start_time = time.time()
            received_data = ""
            
            while time.time() - start_time < timeout:
                try:
                    chunk = client_socket.recv(buffer_size).decode()
                    if chunk:
                        received_data += chunk
                        if received_data.endswith('}'):  # Basic check for complete JSON
                            return received_data
                    elif received_data:  # If we already have some data but got empty chunk
                        return received_data
                    else:
                        time.sleep(0.1)  # Small delay before retry
                except socket.timeout:
                    if received_data:
                        return received_data
                    continue
            
            raise TimeoutError("Timeout waiting for complete data")

        for attempt in range(MAX_RETRIES):
            try:
                # Set socket timeout for each attempt
                client.settimeout(5)
                
                # Try to receive data with improved handling
                try:
                    data = receive_with_timeout(client)
                    if not data:
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(RETRY_DELAY)
                            continue
                        raise ValueError("Received empty data after retries")
                except TimeoutError as te:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                        continue
                    raise
                    
                # Log received data for debugging
                print(f"Received data (attempt {attempt + 1}): {data[:100]}...")
                    
                # Parse JSON with validation
                try:
                    request = json.loads(data)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON received: {data[:100]}...")
                    
                if 'type' not in request:
                    raise ValueError("Request missing 'type' field")

                # Handle different types of requests
                if request['type'] == 'check_username':
                    response = {
                        'username': self.username
                    }
                    client.send(json.dumps(response).encode())
                    return
                    
                elif request['type'] == 'connection_request':
                    if 'username' not in request or 'public_key' not in request:
                        raise ValueError("Connection request missing required fields")
                        
                    # Check existing connections
                    for row in range(self.connections_list.rowCount()):
                        username_item = self.connections_list.item(row, 0)
                        status_item = self.connections_list.item(row, 1)
                        if (username_item and status_item and 
                            username_item.text() == request['username'] and 
                            status_item.text() == "Connected"):
                            rejection = {
                                'type': 'connection_rejected',
                                'username': self.username,
                                'message': f"Already connected to {self.username}"
                            }
                            client.send(json.dumps(rejection).encode())
                            return

                    self.connection_handler.connection_request_received.emit(
                        request['username'],
                        request['public_key'],
                        client,
                        request.get('sender_ip', '')
                    )
                    return  # Successful handling
                    
                elif request['type'] == 'connection_accepted':
                    if 'username' not in request or 'public_key' not in request:
                        raise ValueError("Connection acceptance missing required fields")
                        
                    self.connection_handler.connection_accepted.emit(
                        request['username'],
                        request['public_key'],
                        request.get('sender_ip', '')
                    )
                    return  # Successful handling
                    
                elif request['type'] == 'connection_rejected':
                    if 'username' not in request:
                        raise ValueError("Connection rejection missing username")
                        
                    self.connection_handler.connection_rejected.emit(request['username'])
                    return  # Successful handling
                    
                else:
                    raise ValueError(f"Unknown request type: {request['type']}")
                    
            except (json.JSONDecodeError, ValueError, TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    print(f"Attempt {attempt + 1} failed: {str(e)}. Retrying...")
                    time.sleep(RETRY_DELAY)
                    continue
                self.connection_handler.connection_error.emit(str(e))
                break
            except Exception as e:
                self.connection_handler.connection_error.emit(f"Unexpected error: {str(e)}")
                break
            finally:
                if attempt == MAX_RETRIES - 1:  # Only close on last attempt
                    try:
                        client.close()
                    except:
                        pass

    

    
    def handle_connection_request(self, username, public_key, client, sender_ip):
        """Handle incoming connection request from another user"""
        try:
            # Get local IP address first
            local_ip = get_ip_address()  # Make sure this function is imported/defined
            
            # Ask the user to accept or reject the connection
            response = QMessageBox.question(
                self,
                "Connection Request",
                f"Connection request from {username} ({sender_ip}). Accept?",
                QMessageBox.Yes | QMessageBox.No
            )
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()

            # Get current user's data
            cursor.execute("SELECT user_id, public_key FROM User WHERE username = ?", (self.username,))
            current_user_data = cursor.fetchone()
            if not current_user_data:
                raise Exception(f"Current user {self.username} not found in database")
            current_user_id, my_public_key = current_user_data

            # Create new socket to send response back to original sender
            response_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            response_socket.settimeout(5)

            if response == QMessageBox.Yes:
                # Store sender in local database
                cursor.execute("""
                    INSERT OR REPLACE INTO User (username, public_key)
                    VALUES (?, ?)
                """, (username, public_key))
                sender_id = cursor.lastrowid

                # Store connection in local database
                cursor.execute("""
                    INSERT OR REPLACE INTO Connection 
                    (sender_id, receiver_id, username, status, connection_ip_address)
                    VALUES (?, ?, ?, 'connected', ?)
                """, (sender_id, current_user_id, username, sender_ip))

                # Update local UI
                self.add_activity(f"Accepted connection from {username}")
                self.add_connection(username, 'Connected')

                # Send acceptance message back to sender using their IP
                try:
                    response_socket.connect((sender_ip, 5001))
                    acceptance = {
                        'type': 'connection_accepted',
                        'username': self.username,
                        'public_key': my_public_key,
                        'sender_ip': local_ip,  # Use the local_ip variable instead of self.local_ip
                        'message': f"Connection request accepted by {self.username}"
                    }
                    response_socket.send(json.dumps(acceptance).encode())
                except Exception as e:
                    print(f"Error sending acceptance back to sender: {e}")
                    
                # Show confirmation
                QMessageBox.information(
                    self,
                    "Connection Accepted",
                    f"You have accepted the connection request from {username}"
                )
            else:  # Handle rejection
                # Send rejection message back to sender using their IP
                try:
                    response_socket.connect((sender_ip, 5001))
                    rejection = {
                        'type': 'connection_rejected',
                        'username': self.username,
                        'message': f"{self.username} has rejected your connection request"
                    }
                    response_socket.send(json.dumps(rejection).encode())
                except Exception as e:
                    print(f"Error sending rejection back to sender: {e}")
                    
                # Update local UI
                self.add_activity(f"Rejected connection request from {username}")
                
                # Show confirmation
                QMessageBox.information(
                    self,
                    "Connection Rejected",
                    f"You have rejected the connection request from {username}"
                )
                
            conn.commit()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to process connection: {str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()
            if 'response_socket' in locals():
                try:
                    response_socket.close()
                except:
                    pass
            if client:
                try:
                    client.close()
                except:
                    pass





    def handle_connection_accepted(self, username, public_key, sender_ip):
        """Handle when another user accepts our connection request"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            print(f"Starting connection acceptance for user: {username}")
            
            # Store the accepting user in our local database
            cursor.execute("""
                INSERT OR REPLACE INTO User (username, public_key)
                VALUES (?, ?)
            """, (username, public_key))
            other_user_id = cursor.lastrowid
            print(f"Other user ID: {other_user_id}")
            
            # Get our user_id
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            my_user_id_result = cursor.fetchone()
            if not my_user_id_result:
                raise Exception(f"Could not find user_id for {self.username}")
            my_user_id = my_user_id_result[0]
            print(f"My user ID: {my_user_id}")
            
            # Store connection in our local database
            print(f"Inserting connection with values: {username}, {my_user_id}, {other_user_id}, {sender_ip}")
            cursor.execute("""
                INSERT OR REPLACE INTO Connection 
                (username, sender_id, receiver_id, status, connection_ip_address)
                VALUES (?, ?, ?, 'connected', ?)
            """, (username, my_user_id, other_user_id, sender_ip))
            
            # Verify the connection was stored
            cursor.execute("""
                SELECT username, sender_id, receiver_id, status, connection_ip_address 
                FROM Connection 
                WHERE username = ?
            """, (username,))
            stored_connection = cursor.fetchone()
            print(f"Stored connection: {stored_connection}")
            
            if not stored_connection:
                raise Exception("Failed to store connection in database")
            conn.commit()
            
            # Update UI and class-level list
            self.add_activity(f"Connection established with {username}")
            self.add_connection(username, 'Connected')
            
            QMessageBox.information(
                self,
                "Connection Established",
                f"Connection established with {username}"
            )
            
        except sqlite3.Error as e:
            QMessageBox.warning(self, "Database Error", f"Failed to update connection: {str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()




    def handle_connection_rejected(self, username):
        # Handle when our connection request is rejected
        try:
            # Update our local UI only
            self.add_activity(f"Connection request rejected by {username}")
            
            QMessageBox.information(
                self,
                "Connection Rejected",
                f"Your connection request was rejected by {username}"
            )
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to handle rejection: {str(e)}")

             


    # Handle connection error on the main thread         
    def handle_connection_error(self, error_message):
        QMessageBox.warning(
            self,
            "Connection Error",
            f"Connection error: {error_message}"
        )



    def send_connection_request(self):
        target_ip = self.connection_input.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        # Check if the target IP is the same as our IP
        if target_ip == get_ip_address():
            QMessageBox.warning(self, "Error", "Cannot connect to self")
            return
        
        # Check if the target IP is already in the connections list via the database
        conn = sqlite3.connect("encrypta.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM Connection WHERE connection_ip_address = ?", (target_ip,))
        existing_connection = cursor.fetchone()
        conn.close()
        if existing_connection:
            QMessageBox.warning(self, "Error", "Connection already exists")
            return
        
        
        # Check if the value entered is even an IP address format
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            QMessageBox.warning(self, "Error", "Invalid IP address format")
            return
        
        client = None
        conn = None
        try:
            MAX_RETRIES = 3
            RETRY_DELAY = 1
            last_error = None
            
            for attempt in range(MAX_RETRIES):
                try:
                    # Initialize connection
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(15)  # Increased timeout
                    
                    print(f"Attempt {attempt + 1}: Connecting to {target_ip}:5001...")
                    client.connect((target_ip, 5001))
                    
                    # Get our public key
                    if not conn:  # Only get from DB once
                        conn = sqlite3.connect("encrypta.db")
                        cursor = conn.cursor()
                        cursor.execute("SELECT public_key FROM User WHERE username = ?", (self.username,))
                        result = cursor.fetchone()
                        if not result:
                            raise Exception(f"User {self.username} not found in database")
                        my_public_key = result[0]
                        if not my_public_key:
                            raise Exception("Public key not found in database")

                    # Send request
                    my_ip = get_ip_address()
                    request = {
                        'type': 'connection_request',
                        'username': self.username,
                        'public_key': my_public_key,
                        'sender_ip': my_ip
                    }
                    
                    print(f"Sending connection request (attempt {attempt + 1})...")
                    request_data = json.dumps(request).encode()
                    client.sendall(request_data)  # Use sendall instead of send
                    
                    # Wait briefly for potential immediate error response
                    time.sleep(0.5)
                    
                    print("Connection request sent successfully")
                    self.add_activity(f"Sent connection request to {target_ip}")
                    self.connection_input.clear()
                    return  # Success - exit the function
                    
                except socket.timeout as te:
                    last_error = f"Connection attempt {attempt + 1} timed out"
                    print(last_error)
                except Exception as e:
                    last_error = str(e)
                    print(f"Attempt {attempt + 1} failed: {last_error}")
                
                # Clean up before retry
                if client:
                    try:
                        client.close()
                    except:
                        pass
                    client = None
                    
                if attempt < MAX_RETRIES - 1:
                    print(f"Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                    
            # If we get here, all retries failed
            if last_error:
                QMessageBox.warning(self, "Connection Error", 
                                f"Failed to send connection request after {MAX_RETRIES} attempts: {last_error}")
        
        finally:
            if conn:
                conn.close()
            if client:
                try:
                    client.close()
                except:
                    pass


    def add_activity(self, message):
        """Add an activity to the activity feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_list.insertItem(0, f"{timestamp} - {message}")



    def add_connection(self, username, status):
        """Add a connection to the connections table"""
        # Check if connection already exists in the table
        for row in range(self.connections_list.rowCount()):
            if self.connections_list.item(row, 0).text() == username:
                return  # Connection already exists, don't add it again
                
        row_position = self.connections_list.rowCount()
        self.connections_list.insertRow(row_position)
        self.connections_list.setItem(row_position, 0, QTableWidgetItem(username))
        status_item = QTableWidgetItem(status)
        status_item.setBackground(QColor("#28a745") if status == "Connected" else QColor("#dc3545"))
        self.connections_list.setItem(row_position, 1, status_item)
        
        # Add to class-level list if not already present
        if username not in [conn[0] for conn in Main_Menu_Window.active_connections]:
            Main_Menu_Window.active_connections.append((username, status))



    def closeEvent(self, event):
        """Clean up when closing the window"""
        self.is_listening = False
        Main_Menu_Window.server_running = False  # Reset the class-level server state
        if self.client_socket:
            self.client_socket.close()
        super().closeEvent(event)



    def redirect_to_dash(self):
        self.redirect = User_Dash_Window(self.username)
        self.redirect.show()
        self.close()


    def redirect_to_direct_messages(self):
        self.redirect = Direct_Messages_Window(self.username)
        self.redirect.show()
        self.close()


    def redirect_to_calls(self):
        self.redirect = Calls_Window(self.username)
        self.redirect.show()
        self.close()

    def redirect_to_group_chats(self):
        self.redirect = Group_Messages_Window(self.username)
        self.redirect.show()
        self.close()



    def log_out(self):
        # Update to offline in the local database
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE User SET status = 'offline' WHERE username = ?", 
                        (self.username,))
            cursor.execute("""
                DELETE FROM Session 
                WHERE user_id = (SELECT user_id FROM User WHERE username = ?)
            """, (self.username,))
            conn.commit()
            # Notify admin server
            send_status_update(self.username, 'logout', get_ip_address())
            # Redirect to log in window
            self.redirect = Log_In_Window()
            self.redirect.show()
            self.close()
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"An error occurred during logout: {str(e)}")
        finally:
            if conn:
                conn.close()





def send_status_update(username, status_type, ip_address):
    # Send status update to admin server via sockets
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 5000))
        # JSON message and sending it
        message = {
            'type': status_type,
            'username': username,
            'ip': ip_address
        }
        client_socket.send(json.dumps(message).encode())
        client_socket.close()
        return True
    # If server is not running, proceed to log in with an info box    
    except (socket.timeout, ConnectionRefusedError):
        QMessageBox.information(None, "Info", "Admin server is not running. Proceeding without sending status update.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False





class StatusServer:
    # Initialise the class for the server used by admin
    def __init__(self, host=server_ip, port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False
        self.clients = {}
        self.callback = None

    # Method called when start button is pressed    
    def start(self, status_callback):
        # Start the server and store callback for UI updates
        if self.is_running:
            return False   
        try:
            # Creating a server and listening for incoming requests
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            self.callback = lambda: QtCore.QTimer.singleShot(0, status_callback)
            # Start listener thread
            self.listener_thread = threading.Thread(target=self._listen_for_connections)
            self.listener_thread.daemon = True
            self.listener_thread.start()
            return True
        except Exception as e:
            print(f"Server start failed: {e}")
            self.is_running = False
            return False

    # Method called when stop server button is pressed
    def stop(self):
         # Stop the server
        if not self.is_running:
            return False    
        try:
            self.is_running = False
            if self.server_socket:
                self.server_socket.close()
            return True
        except Exception as e:
            print(f"Server stop failed: {e}")
            return False

    # Method for listening to connections
    def _listen_for_connections(self):
        while self.is_running:
            # Accept new incoming connection request
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()   
            except Exception as e:
                if self.is_running:  # Only log if not stopped intentionally
                    print(f"Connection accept failed: {e}")

    # Method for client request handling
    def _handle_client(self, client_socket, address):
        try:
            while self.is_running:
                data = client_socket.recv(1024)
                if not data:
                    break
                # Unpack the JSON message 
                message = json.loads(data.decode())
                if message['type'] == 'login':
                    self.clients[message['username']] = {
                        'ip': message['ip'],
                        'status': 'online',
                        'last_seen': datetime.now()
                    }
                elif message['type'] == 'logout':
                    if message['username'] in self.clients:
                        self.clients[message['username']]['status'] = 'offline'
                # Call UI callback to refresh display
                if self.callback:
                    self.callback()
        except Exception as e:
            print(f"Client handler error: {e}")
        finally:
            client_socket.close()

    def get_client_status(self):
        # Return current client status for UI display
        return self.clients
    




class User_Dash_Window(GUI_Window):
    # Constructor method initialises the window.
    def __init__(self, username):
        self.username = username
        self.ipaddress = get_ip_address()
        super().__init__(title="Encrypta - User Dashboard")
        self.init_ui()
        self.showMaximized()
        
    def init_ui(self):
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(40, 20, 40, 20)
        
        # Back Button - kept same style as it looks good
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("""
            QPushButton {background-color: #dc3545; color: white; border: none;
            border-radius: 3px;padding: 13px 10px; font-size: 20px;
            font-weight: bold;max-width: 100px;} 
            QPushButton:hover {background-color: #c82333;}""")
        left_layout.addWidget(self.back_button, alignment=Qt.AlignLeft)
        self.back_button.clicked.connect(self.back)
        
        # Title
        title_label = QLabel("User Dashboard")
        title_label.setStyleSheet("""
            QLabel {font-size: 40px;font-weight: bold;color: #2c3e50;margin: 20px 0;}""")
        left_layout.addWidget(title_label, alignment=Qt.AlignCenter)
        
        # Info Container Widget
        info_container = QWidget()
        info_container.setStyleSheet("""
            QWidget {background-color: white;border-radius: 10px;padding: 20px;}""")
        info_layout = QVBoxLayout(info_container)
        info_layout.setSpacing(20)
        
        # Username Box
        username_container = QWidget()
        username_container.setStyleSheet("""
            QWidget {background-color: #f8f9fa;border-radius: 8px;padding: 15px;}""")
        username_layout = QVBoxLayout(username_container)
        
        username_label = QLabel("USERNAME")
        username_label.setStyleSheet("""
            QLabel {color: #6c757d;font-size: 20px;font-weight: bold;letter-spacing: 1px;}""")
        
        username_value = QLabel(self.username)
        username_value.setStyleSheet("""
            QLabel {color: #212529;font-size: 27px;font-weight: 500;margin-top: 5px;}""")
        
        username_layout.addWidget(username_label)
        username_layout.addWidget(username_value)
        info_layout.addWidget(username_container)
        
        # IP Address Box
        ip_container = QWidget()
        ip_container.setStyleSheet("""
            QWidget {background-color: #f8f9fa;border-radius: 8px;padding: 15px;}""")
        ip_layout = QVBoxLayout(ip_container)
        
        ip_label = QLabel("IP ADDRESS")
        ip_label.setStyleSheet("""
            QLabel {color: #6c757d;font-size: 20px;font-weight: bold;letter-spacing: 1px;}""")
        
        ip_value = QLabel(self.ipaddress)
        ip_value.setStyleSheet("""
            QLabel {color: #212529;font-size: 27px;font-weight: 500;margin-top: 5px;}""")
        
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(ip_value)
        info_layout.addWidget(ip_container)
        left_layout.addWidget(info_container)
        
        # Reset Password Button
        self.reset_password_button = QPushButton("Change Password")
        self.reset_password_button.setStyleSheet("""
            QPushButton {background-color: #007bff;color: white;border: none;
            border-radius: 5px;padding: 15px 30px;font-size: 20px;font-weight: bold;
            margin-top: 30px;margin-bottom: 40px;min-width: 200px;}
            QPushButton:hover {background-color: #0056b3;}""")
        left_layout.addWidget(self.reset_password_button, alignment=Qt.AlignCenter)
        self.reset_password_button.clicked.connect(self.open_change_password_dialogue)
        
        # Dashboard Image
        dashboard_image = QLabel()
        dashboard_pixmap = QPixmap("dashboard.png")
        scaled_pixmap = dashboard_pixmap.scaled(340, 340, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        dashboard_image.setPixmap(scaled_pixmap)
        dashboard_image.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(dashboard_image)
        
        left_layout.addStretch()
        main_layout.addLayout(left_layout)
        self.layout.addLayout(main_layout)
    
    
    def open_change_password_dialogue(self):
        dialog = ChangePasswordDialog(self.username, self)
        if dialog.exec_() == QDialog.Accepted:
            # Password was successfully changed, redirect to login
            self.login_window = Log_In_Window()
            self.login_window.show()
            self.close()


    def back(self):
        self.redirect = Main_Menu_Window(self.username)
        self.redirect.show()
        self.close()





class Direct_Messages_Window(GUI_Window):
    # Constructor method initialises the window.
    def __init__(self, username):
        super().__init__(title="Encrypta - Direct Messages")
        self.username = username
        self.encryption = AsymmetricEncryption()
        self.init_ui()
        self.showMaximized()
        
    def init_ui(self):
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Header with back button
        header = QWidget()
        header.setStyleSheet("background-color: #f8f9fa;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 15, 20, 15)
        
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-size: 20px;
                font-weight: 600;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        header_layout.addWidget(self.back_button, alignment=Qt.AlignLeft)
        header_layout.addStretch()
        self.back_button.clicked.connect(self.back)
        main_layout.addWidget(header)
        
        # Main content container
        content_widget = QWidget()
        content_layout = QHBoxLayout(content_widget)
        content_layout.setSpacing(0)
        content_layout.setContentsMargins(0, 0, 0, 0)
        
        # Left image panel
        left_panel = QWidget()
        left_panel.setStyleSheet("background-color: #f8f9fa;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(25, 25, 25, 25)
        
        left_image = QLabel()
        left_pixmap = QPixmap("group.png")
        left_scaled = left_pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        left_image.setPixmap(left_scaled)
        left_image.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(left_image, alignment=Qt.AlignCenter)
        
        # Center panel - Direct Messages
        center_panel = QWidget()
        center_panel.setStyleSheet("""
            QWidget {
                background-color: white;
                border-left: 1px solid #e9ecef;
                border-right: 1px solid #e9ecef;
            }
        """)
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(20, 20, 20, 20)
        center_layout.setSpacing(15)
        
        dm_header = QLabel("Direct Messages")
        dm_header.setStyleSheet("""
            QLabel {
                font-size: 40px;
                font-weight: bold;
                color: #212529;
                padding-bottom: 5px;
            }
        """)
        dm_header.setAlignment(Qt.AlignCenter)
        center_layout.addWidget(dm_header)

        # DM list with enhanced styling
        self.dm_list = QListWidget()
        self.dm_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #e9ecef;
                border-radius: 8px;
                background-color: white;
                padding: 5px;
            }
            QListWidget::item {
                padding: 12px 15px;
                border-bottom: 1px solid #f1f3f5;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background-color: #f8f9fa;
            }
            QListWidget::item:selected {
                background-color: #e9ecef;
                color: #212529;
            }
        """)


        # increase font size of the list items
        font = self.dm_list.font()
        font.setPointSize(24)
        self.dm_list.setFont(font)


        center_layout.addWidget(self.dm_list)
        self.dm_list.itemDoubleClicked.connect(self.open_direct_message)
        
        # Right image panel
        right_panel = QWidget()
        right_panel.setStyleSheet("background-color: #f8f9fa;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(25, 25, 25, 25)
        
        right_image = QLabel()
        right_pixmap = QPixmap("group.png")
        right_scaled = right_pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        right_image.setPixmap(right_scaled)
        right_image.setAlignment(Qt.AlignCenter)
        right_layout.addWidget(right_image, alignment=Qt.AlignCenter)
        
        # Set panel sizes and policies
        left_panel.setMinimumWidth(300)
        center_panel.setMinimumWidth(400)
        right_panel.setMinimumWidth(300)
        
        left_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        center_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        # Add panels to content layout
        content_layout.addWidget(left_panel)
        content_layout.addWidget(center_panel)
        content_layout.addWidget(right_panel)
        
        # Add content to main layout
        main_layout.addWidget(content_widget)
        
        # Load user connections
        self.load_connections()




    def load_connections(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get current user's ID from the database
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Get all connected users except the current user
            cursor.execute("""
                SELECT u.username 
                FROM Connection c
                JOIN User u ON (c.receiver_id = u.user_id OR c.sender_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND c.status = 'connected'
                AND u.username != ?
                ORDER BY u.username
            """, (user_id, user_id, self.username))

            connections = cursor.fetchall()

            # Clear existing items
            self.dm_list.clear()

            # Add items to the list
            for connection in connections:
                username = connection[0]
                item = QListWidgetItem(username)
                item.setToolTip(f"Double click to chat with {username}")
                self.dm_list.addItem(item)
            # Add placeholder if no connections    
            if self.dm_list.count() == 0:
                placeholder = QListWidgetItem("No connections yet")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                self.dm_list.addItem(placeholder)
        # Error handling         
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load connections: {str(e)}")
            print(f"Database error details: {str(e)}")  # For debugging
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            print(f"Error details: {str(e)}")  # For debugging
        finally:
            if conn:
                conn.close()


    def open_direct_message(self, item):
        """Open direct message window when connection is double-clicked"""
        selected_username = item.text()
        if selected_username != "No connections yet":
            self.dm_window = DirectMessage(self.username, selected_username)
            self.dm_window.show()
            self.close()

    def back(self):
        self.redirect = Main_Menu_Window(self.username)
        self.redirect.show()
        self.close()






class DirectMessage(GUI_Window):
    message_received = pyqtSignal(str, str, str, bool)
    # sender, filename, timestamp, file_data, is_sender
    file_received = pyqtSignal(str, str, str, str, bool)  

    def __init__(self, username, connection_username):
        super().__init__()
        self.setWindowTitle(f"Chat with {connection_username}")

        # Store attributes
        self.message_received.connect(self.display_message)
        self.file_received.connect(self.display_file)
        self.username = username
        self.connection = connection_username
        self.encryption = AsymmetricEncryption()
        self.message_port = 5002
        self.file_port = 5003
        self.is_listening = False
        self._file_cache = {}

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout(central_widget)
        self.main_layout.setSpacing(0)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        self.init_ui()
        
        # Connect loadFinished signal to load messages and files
        self.chat_area.loadFinished.connect(self.on_web_view_loaded)
        
        self.start_message_server()
        self.start_file_server()
        self.showMaximized()

    
    def on_web_view_loaded(self, ok):
        # Load messages and files only after web view is ready
        if ok:
            # Load messages and files only after web view is ready
            self.load_messages()
            self.load_files()


    # GUI setup method
    def init_ui(self):
        # Top bar
        top_bar = QWidget()
        top_bar.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                stop:0 #2c3e50, stop:1 #3498db);
                color: white;
            }
        """)
        top_bar.setFixedHeight(60)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(15, 0, 15, 0)

        # # Back button
        back_button = QPushButton("← Back")
        back_button.setStyleSheet("""
            QPushButton {
                color: white;
                border: none;
                padding: 8px 15px;
                font-size: 14px;
                font-weight: bold;
                background: transparent;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 5px;
            }
        """)
        back_button.clicked.connect(self.back)
        top_layout.addWidget(back_button)

        # Chat title
        title_label = QLabel(f"Chat with {self.connection}")
        title_label.setStyleSheet("color: white; font-size: 20px; font-weight: bold;")
        top_layout.addWidget(title_label)
        top_layout.addStretch()

        self.main_layout.addWidget(top_bar)

        # Chat area
        chat_container = QWidget()
        chat_container.setStyleSheet("background-color: #f0f2f5;")
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(20, 20, 20, 20)

        # Chat area (QWebEngineView) for displaying messages and files
        self.chat_area = QWebEngineView()
        self.chat_area.setStyleSheet("""
            QWebEngineView {
                border: none;
                border-radius: 10px;
                background-color: #f0f2f5;
            }
        """)

        # Create a bridge object to handle file downloads
        class Bridge(QObject):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.parent = parent
            # Method to download file
            @pyqtSlot(str)
            def downloadFile(self, file_id):
                self.parent.save_file(file_id)
        # Register the bridge object with the web view
        self.bridge = Bridge(self)
        self.channel = QWebChannel()
        self.channel.registerObject('bridge', self.bridge)
        self.chat_area.page().setWebChannel(self.channel)

        # Initialise HTML content
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="qrc:///qtwebchannel/qwebchannel.js"></script>
            <style>
                body { 
                    background-color: #f0f2f5;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 20px;
                }
                #chat-content {
                    width: 100%;
                }
            </style>
            <script>
                let bridge;
                document.addEventListener('DOMContentLoaded', function() {
                    new QWebChannel(qt.webChannelTransport, function(channel) {
                        bridge = channel.objects.bridge;
                        window.downloadFile = function(fileId) {
                            bridge.downloadFile(fileId);
                        };
                    });
                });
            </script>
        </head>
        <body>
            <div id="chat-content"></div>
        </body>
        </html>
        """
        # Set the HTML content to the web view
        self.chat_area.setHtml(html_content)
        chat_layout.addWidget(self.chat_area)
        # Add the chat area to the main layout
        self.main_layout.addWidget(chat_container, stretch=1)

        # Bottom input area
        bottom_container = QWidget()
        bottom_container.setStyleSheet("""
            QWidget {
                background-color: white;
                border-top: 1px solid #e0e0e0;
            }
        """)
        bottom_layout = QHBoxLayout(bottom_container)
        bottom_layout.setContentsMargins(20, 15, 20, 15)

        # File button
        self.file_button = QPushButton("📎")
        self.file_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #2980b9;
                border: 2px solid #e0e0e0;
                border-radius: 20px;
                padding: 12px 20px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.file_button.clicked.connect(self.select_file)
        bottom_layout.addWidget(self.file_button)

        # Message input
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #e0e0e0;
                border-radius: 20px;
                padding: 12px 25px;
                font-size: 16px;
                background-color: #f8f9fa;
            }
            QLineEdit:focus {
                border: 2px solid #3498db;
                background-color: white;
            }
        """)
        bottom_layout.addWidget(self.message_input)

        # Send button
        self.send_button = QPushButton("Send")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #2980b9;
                color: white;
                border: none;
                border-radius: 20px;
                padding: 12px 30px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3498db;
            }
        """)
        self.send_button.clicked.connect(self.send_message)
        bottom_layout.addWidget(self.send_button)

        self.main_layout.addWidget(bottom_container)




    def start_message_server(self):
        # Initialize and start message server 
        try:
            # Create a socket and start listening for incoming messages
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', self.message_port))
            self.server_socket.listen(5)
            # Start listening thread
            self.is_listening = True
            self.server_thread = threading.Thread(target=self.listen_for_messages)
            self.server_thread.daemon = True
            self.server_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start message server: {str(e)}")


    # Method to load messages from the database
    def listen_for_messages(self):
        # Listen for incoming messages
        while self.is_listening:
            client = None
            try:
                # Accept incoming connection
                client, addr = self.server_socket.accept()
                client.settimeout(5)  # 5 second timeout
                data = client.recv(4096)
                if data:
                    message = json.loads(data.decode())
                    # Get private key and decrypt
                    private_key = self._get_private_key()
                    decrypted = self.encryption.decrypt(message['content'], private_key)
                    
                    # Update UI in thread-safe way
                    QMetaObject.invokeMethod(self, "display_message",
                    # Use Qt.QueuedConnection to ensure thread safety
                                           Qt.QueuedConnection,
                                           Q_ARG(str, message['sender']),
                                           Q_ARG(str, decrypted),
                                           Q_ARG(str, message['timestamp']),
                                           Q_ARG(bool, False))
            # Handle exceptions
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving message: {e}")
            finally:
                if client:
                    try:
                        client.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
                    client.close()

    # Method to get private key from the database
    def _get_private_key(self):
        conn = None
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            cursor.execute("""
                SELECT private_key 
                FROM User 
                WHERE username = ?
            """, (self.username,))
            # Get private key from the database
            result = cursor.fetchone()
            if not result:
                raise Exception(f"No private key found for user {self.username}")
                
            private_key_str = result[0]
            # Note: Parse as (d, n) to match encryption class expectations
            d, n = map(int, private_key_str.split(','))
            return (d, n)
        finally:
            if conn:
                conn.close()

    # Method to display messages in the chat area
    def send_message(self):
        content = self.message_input.text().strip()
        if not content:
            QMessageBox.warning(self, "Error", "Message cannot be empty")
            return
        # Send message to the recipient
        conn = None
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()

            # Get recipient's IP address first
            cursor.execute("""
                SELECT connection_ip_address 
                FROM Connection 
                WHERE username = ?
            """, (self.connection,))
            ip_result = cursor.fetchone()
            if not ip_result:
                raise Exception("Recipient connection not found")
            ip = ip_result[0]

            # Check if recipient's server is online
            if not self.check_server_online(ip, self.message_port):
                QMessageBox.warning(
                    self, 
                    "User Offline",
                    f"{self.connection} is currently offline. Please try again later."
                )
                return

            # Get recipient's public key
            cursor.execute("""
                SELECT public_key, user_id FROM User 
                WHERE username = ?
            """, (self.connection,))
            result = cursor.fetchone()
            # Check if recipient exists
            if not result:
                raise Exception("Recipient not found")
            # Parse public key and user ID
            public_key_str, receiver_id = result
            e, n = map(int, public_key_str.split(','))
            public_key = (e, n)

            # Get sender's user_id
            cursor.execute("SELECT user_id FROM User WHERE username = ?", 
                        (self.username,))
            sender_id = cursor.fetchone()[0]

            # Encrypt message
            encrypted_list = self.encryption.encrypt(content, public_key)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Prepare message packet
            message = {
                'sender': self.username,
                'content': encrypted_list,
                'timestamp': timestamp
            }

            # Send message via socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect((ip, self.message_port))
                client.send(json.dumps(message).encode())

            # Store in database with both encrypted and plain content
            cursor.execute("""
                INSERT INTO Messages 
                (sender_id, receiver_id, content, plain_content, timestamp) 
                VALUES (?, ?, ?, ?, ?)
            """, (sender_id, receiver_id, json.dumps(encrypted_list), content, timestamp))
            conn.commit()

            # Update UI
            self.display_message(self.username, content, timestamp, True)
            self.message_input.clear()

        # Handle exceptions
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send message: {str(e)}")
        finally:
            if conn:
                conn.close()

                
    def listen_for_messages(self):
        # Listen for incoming messages
        while self.is_listening:
            try:
                # Accept incoming connection
                client, _ = self.server_socket.accept()
                client.settimeout(5)
                # Receive message
                data = client.recv(4096)
                if data:
                    message = json.loads(data.decode())
                    
                    # Get private key for decryption
                    private_key = self._get_private_key()
                    
                    # Get encrypted content and ensure it's a list
                    encrypted_list = message['content']
                    if isinstance(encrypted_list, str):
                        encrypted_list = json.loads(encrypted_list)
                    
                    # Decrypt the message
                    decrypted = self.encryption.decrypt(encrypted_list, private_key)
                    
                    # Save to database
                    with sqlite3.connect("encrypta.db") as conn:
                        cursor = conn.cursor()
                        
                        # Get user IDs
                        cursor.execute("SELECT user_id FROM User WHERE username = ?", 
                                     (message['sender'],))
                        sender_id = cursor.fetchone()[0]
                        cursor.execute("SELECT user_id FROM User WHERE username = ?", 
                                     (self.username,))
                        receiver_id = cursor.fetchone()[0]
                        
                        # Store message
                        cursor.execute("""
                            INSERT INTO Messages 
                            (sender_id, receiver_id, content, timestamp)
                            VALUES (?, ?, ?, ?)
                        """, (sender_id, receiver_id, json.dumps(encrypted_list), 
                             message['timestamp']))
                        conn.commit()
                    
                    # Update UI
                    self.message_received.emit(
                        message['sender'],
                        decrypted,
                        message['timestamp'],
                        False
                    )
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error in listen_for_messages: {str(e)}")
            finally:
                if 'client' in locals():
                    try:
                        client.close()
                    except:
                        pass



    def load_messages(self):
        # Load messages from the database
        try:
            with sqlite3.connect("encrypta.db") as conn:
                cursor = conn.cursor()
                # Get messages between the current user and the connection
                cursor.execute("""
                    SELECT m.content, m.plain_content, m.timestamp, u.username, m.sender_id
                    FROM Messages m
                    JOIN User u ON m.sender_id = u.user_id
                    WHERE (m.sender_id = (SELECT user_id FROM User WHERE username = ?)
                    AND m.receiver_id = (SELECT user_id FROM User WHERE username = ?))
                    OR (m.sender_id = (SELECT user_id FROM User WHERE username = ?)
                    AND m.receiver_id = (SELECT user_id FROM User WHERE username = ?))
                    ORDER BY m.timestamp ASC
                """, (self.username, self.connection, self.connection, self.username))
                # Fetch all messages
                messages = cursor.fetchall()
                private_key = self._get_private_key()
                # Display messages
                for content, plain_content, timestamp, username, sender_id in messages:
                    is_sender = username == self.username
                    
                    if is_sender:
                        # Use plain content for messages we sent
                        display_content = plain_content
                    else:
                        # Decrypt received messages
                        try:
                            encrypted_list = json.loads(content)
                            display_content = self.encryption.decrypt(encrypted_list, private_key)
                        except Exception as e:
                            display_content = f"[Unable to decrypt message: {str(e)}]"
                    
                    self.display_message(username, display_content, timestamp, is_sender)
        # Error handling
        except Exception as e:
            print(f"Error loading messages: {str(e)}")
            QMessageBox.warning(self, "Warning", 
                              "Some messages could not be loaded properly.")




    def display_message(self, username, content, timestamp, is_sender):
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        formatted_time = dt.strftime("%I:%M %p")
        formatted_date = dt.strftime("%B %d, %Y")
        
        message_html = f"""
            <div style="
                margin: 35px 0; 
                display: flex;
                flex-direction: column;
                clear: both;
                float: {'right' if is_sender else 'left'};
                max-width: 70%;
            ">
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: baseline;
                    margin-bottom: 12px;
                ">
                    <span style="font-size: 16px; color: #444; font-weight: bold;">
                        {username}
                    </span>
                    <span style="font-size: 14px; color: #777; margin-left: 15px;">
                        {formatted_time} • {formatted_date}
                    </span>
                </div>
                <div style="
                    background-color: {'#dcf8c6' if is_sender else '#fff'};
                    padding: 25px;
                    border-radius: 16px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                    border: 1px solid {'#c5e9b4' if is_sender else '#e5e5e5'};
                    font-size: 18px;
                    line-height: 1.6;
                    word-wrap: break-word;
                ">
                    {content}
                </div>
            </div>
        """
        
        script = f"""
            var content = document.getElementById('chat-content');
            if (content) {{
                content.insertAdjacentHTML('beforeend', `{message_html}`);
                window.scrollTo(0, document.body.scrollHeight);
            }}
        """
        self.chat_area.page().runJavaScript(script)


    # Method to handle back button click
    def back(self):
        try:
            # First stop the listening thread and close socket
            self.is_listening = False
            # Close existing client connections first
            if hasattr(self, 'server_socket'):
                try:
                    # Create a final connection to unblock accept()
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                            s.connect(('localhost', self.message_port))
                        except:
                            pass
                    # Now close the server socket
                    self.server_socket.close()
                except:
                    pass
            
            # Wait for thread to finish
            if hasattr(self, 'server_thread'):
                self.server_thread.join(timeout=1)
            
            # Create new window and show it
            self.redirect = Direct_Messages_Window(self.username)
            self.redirect.show()
            self.close()

        # Error handling
        except Exception as e:
            print(f"Back button error: {e}")
            QMessageBox.critical(self, "Error", f"Error returning to messages: {str(e)}")

    def closeEvent(self, event):
        """Clean up servers on window close"""
        self.is_listening = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
        if hasattr(self, 'file_socket'):
            self.file_socket.close()
        super().closeEvent(event)

    # Method to check if a server is online    
    def check_server_online(self, ip, port, timeout=2):
        try:
            # Check if server is online
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False




    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*.*)")
        
        if file_path:
            self.send_file(file_path)




    def send_file(self, file_path):
        try:
            # Read file data
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            # Get filename
            filename = os.path.basename(file_path)
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()

            # Get sender's user_id
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            sender_id = cursor.fetchone()[0]

            # Get recipient's IP and public key
            cursor.execute("""
                SELECT C.connection_ip_address, U.public_key, U.user_id 
                FROM Connection C
                JOIN User U ON U.username = C.username
                WHERE C.username = ?
            """, (self.connection,))
            
            result = cursor.fetchone()
            if not result:
                raise Exception("Recipient not found")
            
            ip, public_key_str, receiver_id = result
            e, n = map(int, public_key_str.split(','))
            public_key = (e, n)

            # Check if recipient is online
            if not self.check_server_online(ip, self.file_port):
                QMessageBox.warning(
                    self, 
                    "User Offline",
                    f"{self.connection} is currently offline. Please try again later."
                )
                return

            # Convert file data to base64 for encryption
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # Encrypt file data
            encrypted_data = self.encryption.encrypt(file_data_b64, public_key)
            
            # Prepare file packet
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_packet = {
                'sender': self.username,
                'filename': filename,
                'content': encrypted_data,
                'timestamp': timestamp,
                'type': 'file'
            }

            # Send file via socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(30)  # Longer timeout for files
                client.connect((ip, self.file_port))
                client.send(json.dumps(file_packet).encode())

            # Store in Files table
            cursor.execute("""
                INSERT INTO Files 
                (sender_id, receiver_id, filename, content, timestamp) 
                VALUES (?, ?, ?, ?, ?)
            """, (
                sender_id,
                receiver_id,
                filename,
                json.dumps(encrypted_data),  # Encrypted content as JSON string
                timestamp
            ))
            conn.commit()

            # Display file in chat
            self.display_file(self.username, filename, timestamp, file_data_b64, True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send file: {str(e)}")
        finally:
            if conn:
                conn.close()




    def start_file_server(self):
        # Start file server
        try:
            # Create a socket and start listening for incoming files
            self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.file_socket.bind(('', self.file_port))
            self.file_socket.listen(5)
            # Start listening thread
            self.file_thread = threading.Thread(target=self.listen_for_files)
            self.file_thread.daemon = True
            self.file_thread.start()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start file server: {str(e)}")



    def listen_for_files(self):
        # Listen for incoming files
        while self.is_listening:
            try:
                # Accept incoming connection
                client, _ = self.file_socket.accept()
                client.settimeout(30)  # Longer timeout for files
                # Receive file data
                data = b""
                while True:
                    chunk = client.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                # Parse file packet
                if data:
                    file_packet = json.loads(data.decode())
                    
                    # Get private key
                    private_key = self._get_private_key()
                    
                    # Decrypt file data
                    encrypted_data = file_packet['content']
                    if isinstance(encrypted_data, str):
                        encrypted_data = json.loads(encrypted_data)
                    # Decrypt file data
                    decrypted_data = self.encryption.decrypt(encrypted_data, private_key)
                    
                    # Store in database
                    with sqlite3.connect("encrypta.db") as conn:
                        cursor = conn.cursor()
                        
                        # Get user IDs
                        cursor.execute("SELECT user_id FROM User WHERE username = ?", 
                                    (file_packet['sender'],))
                        sender_id = cursor.fetchone()[0]
                        # Get receiver IDD
                        cursor.execute("SELECT user_id FROM User WHERE username = ?", 
                                    (self.username,))
                        receiver_id = cursor.fetchone()[0]
                        
                        # Insert into Files table
                        cursor.execute("""
                            INSERT INTO Files 
                            (sender_id, receiver_id, filename, content, timestamp)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            sender_id,
                            receiver_id,
                            file_packet['filename'],
                            json.dumps(encrypted_data),  # Store encrypted content
                            file_packet['timestamp']
                        ))
                        
                        conn.commit()

                    # Emit signal to update UI
                    self.file_received.emit(
                        file_packet['sender'],
                        file_packet['filename'],
                        file_packet['timestamp'],
                        decrypted_data,
                        False
                    )

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving file: {e}")
            finally:
                if 'client' in locals():
                    client.close()

    def display_file(self, username, filename, timestamp, file_data, is_sender):
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        formatted_time = dt.strftime("%I:%M %p")
        formatted_date = dt.strftime("%B %d, %Y")

        file_id = f"file_{timestamp.replace(' ', '_')}_{filename}"
        self._file_cache[file_id] = file_data

        message_html = f"""
            <div style="
                margin: 35px 0; 
                display: flex;
                flex-direction: column;
                clear: both;
                float: {'right' if is_sender else 'left'};
                max-width: 70%;
            ">
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: baseline;
                    margin-bottom: 12px;
                ">
                    <span style="font-size: 16px; color: #444; font-weight: bold;">
                        {username}
                    </span>
                    <span style="font-size: 14px; color: #777; margin-left: 15px;">
                        {formatted_time} • {formatted_date}
                    </span>
                </div>
                <div style="
                    background-color: {'#dcf8c6' if is_sender else '#fff'};
                    padding: 25px;
                    border-radius: 16px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                    border: 1px solid {'#c5e9b4' if is_sender else '#e5e5e5'};
                ">
                    <div style="
                        display: flex;
                        align-items: center;
                    ">
                        <span>📎 {filename}</span>
                        <button 
                            onclick="downloadFile('{file_id}')"
                            style="
                                background-color: #2980b9;
                                color: white;
                                padding: 5px 15px;
                                border-radius: 15px;
                                margin-left: 15px;
                                font-size: 14px;
                                border: none;
                                cursor: pointer;
                            "
                        >
                            Download
                        </button>
                    </div>
                </div>
            </div>
        """
        
        script = f"""
            var content = document.getElementById('chat-content');
            if (content) {{
                content.insertAdjacentHTML('beforeend', `{message_html}`);
                window.scrollTo(0, document.body.scrollHeight);
            }}
        """
        self.chat_area.page().runJavaScript(script)





    def save_file(self, file_id):
        # Save file to disk
        if file_id not in self._file_cache:
            QMessageBox.warning(self, "Error", "File data not found")
            return
        # Get file data from cache
        file_data = self._file_cache[file_id]
        filename = file_id.split('_')[-1]

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save File", filename, "All Files (*.*)")
        # Save file to disk
        if save_path:
            try:
                file_bytes = base64.b64decode(file_data)
                with open(save_path, 'wb') as f:
                    f.write(file_bytes)
                QMessageBox.information(self, "Success", "File downloaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")





    def load_files(self):
        # Load files from the database
        try:
            with sqlite3.connect("encrypta.db") as conn:
                cursor = conn.cursor()
                
                # Get all files between current user and connection
                cursor.execute("""
                    SELECT F.content, F.timestamp, U.username, F.sender_id, F.filename
                    FROM Files F
                    JOIN User U ON F.sender_id = U.user_id
                    WHERE (F.sender_id = (SELECT user_id FROM User WHERE username = ?)
                        AND F.receiver_id = (SELECT user_id FROM User WHERE username = ?))
                    OR (F.sender_id = (SELECT user_id FROM User WHERE username = ?)
                        AND F.receiver_id = (SELECT user_id FROM User WHERE username = ?))
                    ORDER BY F.timestamp ASC
                """, (self.username, self.connection, self.connection, self.username))
                # Fetch all files
                files = cursor.fetchall()
                
                # Get private key for decryption
                private_key = self._get_private_key()
                
                for encrypted_content, timestamp, username, sender_id, filename in files:
                    is_sender = username == self.username
                    # Decrypt file content
                    if is_sender:
                        # For files we sent, we need to decrypt them again for display
                        encrypted_data = json.loads(encrypted_content)
                        content = self.encryption.decrypt(encrypted_data, private_key)
                    else:
                        # For received files, decrypt the stored content
                        encrypted_data = json.loads(encrypted_content)
                        content = self.encryption.decrypt(encrypted_data, private_key)
                    
                    self.display_file(username, filename, timestamp, content, is_sender)
                    
        except Exception as e:
            print(f"Error loading files: {str(e)}")
            QMessageBox.warning(self, "Warning", 
                            "Some files could not be loaded properly.")






class Group_Messages_Window(GUI_Window):

    # Add new signal at class level
    group_notification_received = pyqtSignal(str, str, str)  # group_name, creator, group_id
    create_group_chat_signal = pyqtSignal(str, str, str)

    # Constructor method initialises the window.
    def __init__(self, username):
        super().__init__(title="Encrypta - Group Messages")
        self.username = username
        # Initialize the group chat windows dictionary
        self.group_chat_windows = {}
        # Initialize server-related attributes
        self.server_running = True
        self.base_port = 5000
        self.symmetric = SymmetricEncryption()
        # Connect the signal to window creation method
        self.create_group_chat_signal.connect(self.create_group_chat_window)
        self.group_notification_received.connect(self.handle_group_notification)
        self.init_server()
        self.init_ui()
        self.showMaximized()


    def create_group_chat_window(self, username, group_name, group_id):
        """Create group chat window in the main thread"""
        print(f"Creating group chat window for group {group_name} (ID: {group_id})")
        try:
            if group_id not in self.group_chat_windows:
                window = GroupMessage(username, group_name, group_id)
                self.group_chat_windows[group_id] = window
                window.show()
            return self.group_chat_windows[group_id]
        except Exception as e:
            print(f"Error creating group chat window: {e}")
            traceback.print_exc()

    
    def handle_group_message(self, notification):
        """Handle incoming group message"""
        try:
            group_id = str(notification['group_id'])
            
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get group key
            cursor.execute("SELECT symmetric_key FROM 'Group' WHERE group_id = ?", (group_id,))
            group_key = cursor.fetchone()[0]
            
            # Decrypt message
            encrypted = bytes.fromhex(notification['message'])
            decrypted = self.symmetric.decrypt(group_key, encrypted)
            message_text = decrypted.decode()
            
            # Store message
            cursor.execute("""
                INSERT INTO GroupMessages 
                (group_id, sender_id, message_content, timestamp)
                VALUES (?, 
                    (SELECT user_id FROM User WHERE username = ?),
                    ?, ?)
            """, (group_id, notification['sender'], message_text, notification['timestamp']))
            
            conn.commit()
            
            # Update UI
            if group_id in self.group_chat_windows:
                window = self.group_chat_windows[group_id]
                window.message_received.emit(
                    notification['sender'],
                    message_text,
                    notification['timestamp']
                )
            else:
                # Create new window if needed
                cursor.execute("SELECT group_name FROM 'Group' WHERE group_id = ?", (group_id,))
                group_name = cursor.fetchone()[0]
                
                self.create_group_chat_signal.emit(
                    self.username,
                    group_name,
                    group_id
                )
                
        except Exception as e:
            print(f"Error processing group message: {e}")
            traceback.print_exc()
        finally:
            if conn:
                conn.close()



    def _process_message_safe(self, window, notification):
        """Process message in main thread"""
        try:
            window.process_incoming_message(notification)
        except Exception as e:
            print(f"Error processing message: {e}")
            traceback.print_exc()


    def init_server(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Start socket server for online status
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                # Use 0.0.0.0 instead of localhost to accept external connections
                self.server_socket.bind(('0.0.0.0', self.base_port))
                self.server_socket.listen(5)
                print(f"Server started for {self.username} on port {self.base_port}")
                
                # Start listener thread
                self.server_running = True
                self.listener_thread = threading.Thread(target=self.listen_for_connections)
                self.listener_thread.daemon = True
                self.listener_thread.start()
                
            except Exception as e:
                print(f"Server initialization error: {str(e)}")
                QMessageBox.warning(self, "Warning", f"Server initialization error: {str(e)}")
        except Exception as e:
            print(f"Database error during server init: {str(e)}")
        finally:
            if conn:
                conn.close()


        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Back button with modern styling
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-size: 20px;
                font-weight: bold;
                max-width: 100px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        main_layout.addWidget(self.back_button, alignment=Qt.AlignLeft)
        self.back_button.clicked.connect(self.back)

        # Keep DM functionality but hide it
        self.dm_web = QWebEngineView()
        self.dm_list = QListWidget()
        self.dm_list.hide()  # Hide the DM list
        
        # Main container for centered content
        main_container = QWidget()
        main_container_layout = QHBoxLayout(main_container)
        main_container_layout.setContentsMargins(50, 20, 50, 20)  # Add padding around the main container
        
        # Center container for Group Chats
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        
        # Group header with modern styling
        header_container = QWidget()
        header_container.setStyleSheet("""
            QWidget {
                background-color: #f8f9fa;
                border-radius: 10px;
                margin-bottom: 10px;
            }
        """)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(20, 15, 20, 15)
        
        group_title = QLabel("Group Chats")
        group_title.setStyleSheet("""
            font-size: 40px;
            font-weight: bold;
            color: #2c3e50;
        """)
        
        create_group_btn = QPushButton("Create Group")
        create_group_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 12px 25px;
                font-size: 20px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)
        create_group_btn.clicked.connect(self.show_create_group_dialog)
        
        header_layout.addWidget(group_title)
        header_layout.addStretch()
        header_layout.addWidget(create_group_btn)
        
        center_layout.addWidget(header_container)
        
        # Group list with modern styling
        self.group_list = QListWidget()
        self.group_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #e9ecef;
                border-radius: 10px;
                padding: 10px;
                background-color: white;
                font-size: 24px;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #f1f3f5;
                border-radius: 5px;
                margin-bottom: 5px;
                
            }
            QListWidget::item:hover {
                background-color: #f8f9fa;
            }
            QListWidget::item:selected {
                background-color: #e9ecef;
                color: #212529;
            }
        """)
        
        
        self.group_list.itemDoubleClicked.connect(self.open_group_chat)
        center_layout.addWidget(self.group_list)
        
        # Add center widget to main container
        main_container_layout.addWidget(center_widget)
        
        # Add main container to main layout
        main_layout.addWidget(main_container)
        
        # Set window minimum size
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)
        
        # Load connections and groups
        self.load_connections()
        self.load_groups()
        
        # Start online status check timer
        self.ping_timer = QTimer()
        self.ping_timer.timeout.connect(self.check_user_online)
        self.ping_timer.start(30000)


    def load_groups(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT DISTINCT g.group_name, g.group_id
                FROM "Group" g
                JOIN GroupMembership gm ON g.group_id = gm.group_id
                JOIN User u ON gm.user_id = u.user_id
                WHERE u.username = ?
                GROUP BY g.group_id
                ORDER BY g.group_name
            """, (self.username,))
            
            groups = cursor.fetchall()
            
            js_code = "const groupList = document.getElementById('group-list'); groupList.innerHTML = '';"
            
            if groups:
                for group_name, group_id in groups:
                    js_code += f"""
                    const item = document.createElement('div');
                    item.className = 'item';
                    item.innerHTML = '{group_name}';
                    item.onclick = function() {{ window.qt.open_group_chat('{group_id}', '{group_name}'); }};
                    groupList.appendChild(item);
                    """
            else:
                js_code += """
                const placeholder = document.createElement('div');
                placeholder.className = 'placeholder';
                placeholder.textContent = 'No group chats yet';
                groupList.appendChild(placeholder);
                """
                
            self.web_view.page().runJavaScript(js_code)
            
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load groups: {str(e)}")
        finally:
            if conn:
                conn.close()



    @pyqtSlot(str)
    def open_direct_message(self, username):
        self.dm_window = DirectMessage(self.username, username)
        self.dm_window.show()
        self.close()



    def handle_group_notification(self, group_name, creator, group_id):
        """Handle group notification in the main thread"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Verify the group membership exists
            cursor.execute("""
                SELECT COUNT(*) FROM GroupMembership gm
                JOIN User u ON u.user_id = gm.user_id
                WHERE gm.group_id = ? AND u.username = ?
            """, (group_id, self.username))
            
            if cursor.fetchone()[0] == 0:
                print(f"Group membership not found for group {group_id}")
                return
                
            QMessageBox.information(
                self,
                "New Group Chat",
                f"You have been added to group '{group_name}' by {creator}"
            )
            self.load_groups()  # Refresh groups list
            
        except Exception as e:
            print(f"Error handling group notification: {e}")
        finally:
            if conn:
                conn.close()


        
    
    def load_connections(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get current user's ID from the database
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Get all connected users except the current user
            cursor.execute("""
                SELECT u.username, c.connection_ip_address 
                FROM Connection c
                JOIN User u ON (c.receiver_id = u.user_id OR c.sender_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND c.status = 'connected'
                AND u.username != ?
                ORDER BY u.username
            """, (user_id, user_id, self.username))

            connections = cursor.fetchall()
            
            # Clear existing items
            self.dm_list.clear()

            # Add items to the list with online status
            for username, ip_address in connections:
                is_online = self.check_server_online(ip_address, user_id)
                item = QListWidgetItem()
                status_text = "🟢 Online" if is_online else "🔴 Offline"
                item.setText(f"{username} ({status_text})")
                item.setToolTip(f"Double click to chat with {username}")
                self.dm_list.addItem(item)

            # Add placeholder if no connections    
            if self.dm_list.count() == 0:
                placeholder = QListWidgetItem("No connections yet")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                self.dm_list.addItem(placeholder)
                
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load connections: {str(e)}")
        finally:
            if conn:
                conn.close()



    def open_direct_message(self, item):
        """Open direct message window when connection is double-clicked"""
        selected_username = item.text()
        if selected_username != "No connections yet":
            self.dm_window = DirectMessage(self.username, selected_username)
            self.dm_window.show()
            self.close()





    def check_server_online(self, ip, user_id):
        """Check if a server is running at the given IP and port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Increase timeout
                print(f"Checking {ip}:{self.base_port}")  # Debug print
                result = s.connect_ex((ip, self.base_port))
                is_online = result == 0
                print(f"Server check result for {ip}: {is_online}")  # Debug print
                return is_online
        except Exception as e:
            print(f"Error checking server {ip}: {e}")
            return False


    
    def listen_for_connections(self):
        """Listen for incoming connections, notifications, and group updates"""
        while self.server_running:
            try:
                self.server_socket.settimeout(1)
                client, addr = self.server_socket.accept()
                
                data = client.recv(4096).decode()
                if data:
                    try:
                        notification = json.loads(data)
                        print(f"Received notification: {notification}")  # Debug print
                        
                        if notification['type'] == 'new_group':
                            self.handle_new_group_notification(notification)
                        elif notification['type'] == 'group_message':
                            self.handle_group_message(notification)
                            
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                    except Exception as e:
                        print(f"Error processing notification: {e}")
                        
                client.close()
            except socket.timeout:
                continue
            except Exception as e:
                if self.server_running:
                    print(f"Server error: {e}")


    def handle_new_group_notification(self, notification):
        """Handle new group creation notification"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Begin transaction
            cursor.execute("BEGIN TRANSACTION")
            
            group_key = bytes.fromhex(notification['group_key'])
            
            # First create/update group record
            cursor.execute("""
                INSERT OR REPLACE INTO "Group" 
                (group_id, group_name, group_size, creator, creator_id, symmetric_key)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                notification['group_id'],
                notification['group_name'],
                notification['group_size'],
                notification['creator'],
                notification['creator_id'],
                group_key
            ))
            
            # Add membership
            cursor.execute("""
                INSERT OR REPLACE INTO GroupMembership (group_id, user_id)
                VALUES (?, ?)
            """, (notification['group_id'], user_id))
            
            # Store all member IPs
            for username, ip in notification['members']:
                cursor.execute("""
                    INSERT OR REPLACE INTO GroupMemberConnections 
                    (group_id, username, member_ip) 
                    VALUES (?, ?, ?) """, (notification['group_id'], username, ip))
            


            cursor.execute("SELECT connection_ip_address FROM Connection WHERE username = ?", (notification['creator'],))
            creator_ip = cursor.fetchone()[0]

            conn.commit()
            
            # Update UI
            self.group_notification_received.emit(
                notification['group_name'],
                notification['creator'],
                str(notification['group_id'])
            )
            
        except Exception as e:
            print(f"Error handling new group: {e}")
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()


    def handle_group_message_notification(self, notification):
        """Handle incoming group message notification"""
        try:
            group_id = str(notification['group_id'])
            print(f"Handling group message for {group_id}")
            
            # If window doesn't exist, create it
            if group_id not in self.group_chat_windows:
                conn = sqlite3.connect("encrypta.db")
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        SELECT group_name FROM "Group" 
                        WHERE group_id = ?
                    """, (group_id,))
                    group_name = cursor.fetchone()[0]
                    
                    # Create window via signal
                    self.create_group_chat_signal.emit(
                        self.username,
                        group_name,
                        group_id
                    )
                finally:
                    conn.close()
            
            # Process message in window
            if group_id in self.group_chat_windows:
                window = self.group_chat_windows[group_id]
                # Use QTimer to ensure main thread processing
                QTimer.singleShot(0, lambda: window.process_incoming_message(notification))
            else:
                print(f"Error: Window for group {group_id} not found")
                
        except Exception as e:
            print(f"Error handling group message: {e}")
            traceback.print_exc()




    def show_create_group_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Group Chat")
        dialog.setModal(True)
        layout = QVBoxLayout()

        # Group name input with validation
        name_layout = QHBoxLayout()
        name_label = QLabel("Group Name:")
        name_input = QLineEdit()
        name_input.setPlaceholderText("Enter group name (3-30 characters)")
        name_layout.addWidget(name_label)
        name_layout.addWidget(name_input)
        layout.addLayout(name_layout)

        # Connections list
        connections_label = QLabel("Select Members:")
        layout.addWidget(connections_label)
        
        connections_list = QListWidget()
        connections_list.setSelectionMode(QListWidget.MultiSelection)
        
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get current user's ID
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Get all connected users
            cursor.execute("""
                SELECT u.username, u.user_id, c.connection_ip_address 
                FROM Connection c
                JOIN User u ON (c.receiver_id = u.user_id OR c.sender_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND c.status = 'connected'
                AND u.username != ?
                ORDER BY u.username
            """, (user_id, user_id, self.username))

            connections = cursor.fetchall()

            # Add connections to list with online status
            for username, conn_user_id, ip_address in connections:
                print(f"Checking user {username}: ID={conn_user_id}, IP={ip_address}")  # Debug print
                is_online = self.check_server_online(ip_address, conn_user_id)
                print(f"Online status: {is_online}")  # Debug print
                item = QListWidgetItem()
                status_text = "🟢 Online" if is_online else "🔴 Offline"
                item.setText(f"{username} ({status_text})")
                item.setData(Qt.UserRole, (conn_user_id, ip_address, is_online))
                connections_list.addItem(item)
            
            if connections_list.count() == 0:
                placeholder = QListWidgetItem("No connections available")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                connections_list.addItem(placeholder)
                
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load connections: {str(e)}")
        finally:
            if conn:
                conn.close()
            
        layout.addWidget(connections_list)

        # Buttons
        button_layout = QHBoxLayout()
        create_btn = QPushButton("Create")
        cancel_btn = QPushButton("Cancel")
        button_layout.addWidget(create_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        dialog.setLayout(layout)

        def create_group():
            group_name = name_input.text().strip()
            
            if not group_name:
                QMessageBox.warning(dialog, "Error", "Please enter a group name")
                return
                
            if len(group_name) < 3 or len(group_name) > 30:
                QMessageBox.warning(dialog, "Error", "Group name must be between 3 and 30 characters")
                return

            # Check if group name already exists
            for i in range(self.group_list.count()):
                item = self.group_list.item(i)
                if item.text() == group_name:
                    QMessageBox.warning(dialog, "Error", "Group name already exists")
                    return

            selected_members = []
            offline_members = []
            
            for i in range(connections_list.count()):
                item = connections_list.item(i)
                if item.isSelected():
                    username = item.text().split(" (")[0]  # Extract username without status
                    user_id, ip_address, is_online = item.data(Qt.UserRole)
                    
                    # Double-check online status before creating group
                    if self.check_server_online(ip_address, user_id):
                        selected_members.append((username, user_id))
                    else:
                        offline_members.append(username)
                                
            if offline_members:
                QMessageBox.warning(
                    dialog, 
                    "Offline Members", 
                    f"Cannot create group: The following members are offline:\n{', '.join(offline_members)}"
                )
                return
                
            if len(selected_members) == 0:
                QMessageBox.warning(dialog, "Error", "Please select at least one online member")
                return
                
            success = self.create_group(group_name, selected_members)
            if success:
                QMessageBox.information(dialog, "Success", f"Group '{group_name}' created successfully!")
                dialog.accept()
        
        create_btn.clicked.connect(create_group)
        cancel_btn.clicked.connect(dialog.reject)
        
        dialog.exec_()




    def create_group(self, group_name, members):
        """Create a new group and notify members"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Start transaction
            cursor.execute("BEGIN TRANSACTION")
            
            # Get current user's ID
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            creator_id = cursor.fetchone()[0]
            print(f"Creator ID: {creator_id}")  # Debug print

            # Generate symmetric key for the group
            group_key = self.symmetric.generate_key()
            print(f"Group key: {group_key.hex()}")  # Debug print
            
            # Create new group
            cursor.execute("""
                INSERT INTO "Group" (group_name, group_size, creator, creator_id, symmetric_key)
                VALUES (?, ?, ?, ?, ?)
            """, (group_name, len(members) + 1, self.username, creator_id, group_key))

            print(f"Group created: {group_name}")  # Debug print
            
            group_id = cursor.lastrowid
            
            # Add creator to group membership
            cursor.execute("""
                INSERT INTO GroupMembership (group_id, user_id)
                VALUES (?, ?)
            """, (group_id, creator_id))

            print(f"Creator added to group: {self.username}")  # Debug print
            
            creator_ip = get_ip_address()

            print(f"Creator IP: {creator_ip}")  # Debug print
            
            # Store creator's connection
            cursor.execute("""
                INSERT INTO GroupMemberConnections (group_id, member_id, member_ip, username)
                VALUES (?, ?, ?, ?)
            """, (group_id, creator_id, creator_ip, self.username))
            
            print(f"Creator connection stored")  # Debug print

            # Process each member
            notification_failures = []
            for username, user_id in members:
                try:
                    # Get member's IP directly from Connection table
                    cursor.execute("""
                        SELECT connection_ip_address FROM Connection
                        WHERE username = ?
                    """, (username,))
                    
                    ip_address = cursor.fetchone()[0]
                    print(f"Member {username} IP: {ip_address}")  # Debug print
                    
                    # Add to group membership
                    cursor.execute("""
                        INSERT INTO GroupMembership (group_id, user_id)
                        VALUES (?, ?)
                    """, (group_id, user_id))

                    print(f"Member {username} added to group")  # Debug print
                    
                    # Store member connection
                    cursor.execute("""
                        INSERT INTO GroupMemberConnections (group_id, member_id, member_ip, username)
                        VALUES (?, ?, ?, ?)
                    """, (group_id, user_id, ip_address, username))
                    

                    print(f"Member {username} connection stored")  # Debug print


                    # Prepare member notification
                    notification_data = {
                        'type': 'new_group',
                        'group_id': group_id,
                        'group_name': group_name,
                        'group_size': len(members) + 1,
                        'creator': self.username,
                        'creator_id': creator_id,
                        'group_key': group_key.hex(),
                        # List of all members in the group
                        'members': [ (self.username, creator_ip) ] + members
                    }
                    
                    if not self.notify_new_group_member(ip_address, notification_data):
                        notification_failures.append(username)
                        
                except Exception as e:
                    print(f"Error processing member {username}: {e}")
                    notification_failures.append(username)
                    continue
            
            conn.commit()
            
            # Refresh group list
            self.load_groups()
            
            if notification_failures:
                QMessageBox.warning(
                    self, 
                    "Partial Success", 
                    f"Group created but failed to notify: {', '.join(notification_failures)}"
                )
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            QMessageBox.critical(self, "Error", f"Failed to create group: {str(e)}")
            return False
            
        finally:
            if conn:
                conn.close()



    def notify_new_group_member(self, ip_address, notification_data):
        """Send notification and key to new group member"""
        try:
            print(f"Attempting to notify member at {ip_address}")  # Debug print
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip_address, self.base_port))
                data = json.dumps(notification_data).encode()
                s.send(data)
                print(f"Successfully sent notification: {data}")  # Debug print
            return True
        except Exception as e:
            print(f"Failed to notify member at {ip_address}: {str(e)}")
            return False

    def notify_member(self, user_id, group_name, group_id):
        """Send notification to group member about new group"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get member's IP address
            cursor.execute("""
                SELECT connection_ip_address 
                FROM Connection 
                WHERE (sender_id = ? OR receiver_id = ?)
                AND status = 'connected'
            """, (user_id, user_id))
            
            ip_address = cursor.fetchone()[0]
            
            # Create notification message
            notification = {
                'type': 'group_invite',
                'group_name': group_name,
                'group_id': group_id,
                'creator': self.username
            }
            
            # Send notification to member's IP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip_address, self.base_port))
                    s.send(json.dumps(notification).encode())
            except Exception as e:
                print(f"Failed to notify member: {str(e)}")
                
        except sqlite3.Error as e:
            print(f"Database error in notify_member: {str(e)}")
        finally:
            if conn:
                conn.close()





    def check_user_online(self):
        """Check online status of all connected users"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get current user's ID
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Get all connections
            cursor.execute("""
                SELECT u.username, c.connection_ip_address, u.user_id 
                FROM Connection c
                JOIN User u ON (c.receiver_id = u.user_id OR c.sender_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND c.status = 'connected'
                AND u.username != ?
            """, (user_id, user_id, self.username))
            
            connections = cursor.fetchall()
            
            # Update DM list items
            for i in range(self.dm_list.count()):
                item = self.dm_list.item(i)
                username = item.text().split(" (")[0]  # Remove any existing status
                
                # Find matching connection
                connection = next((conn for conn in connections if conn[0] == username), None)
                if connection:
                    username, ip_address, conn_user_id = connection
                    is_online = self.check_server_online(ip_address, conn_user_id)
                    
                    if is_online:
                        item.setForeground(QColor('#28a745'))
                        item.setText(f"{username} (Online)")
                    else:
                        item.setForeground(QColor('#dc3545'))
                        item.setText(f"{username} (Offline)")
        
        except sqlite3.Error as e:
            print(f"Database error in check_user_online: {str(e)}")
        except Exception as e:
            print(f"Error in check_user_online: {str(e)}")
        finally:
            if conn:
                conn.close()



    def load_groups(self):
        """Load all groups for current user"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Simple query to get user's groups
            cursor.execute("""
                SELECT DISTINCT g.group_name, g.group_id
                FROM "Group" g
                JOIN GroupMembership gm ON g.group_id = gm.group_id
                JOIN User u ON gm.user_id = u.user_id
                WHERE u.username = ?
                ORDER BY g.group_name
            """, (self.username,))
            
            groups = cursor.fetchall()
            
            self.group_list.clear()
            
            for group_name, group_id in groups:
                item = QListWidgetItem(group_name)
                item.setData(Qt.UserRole, group_id)
                item.setToolTip(f"Double click to open {group_name}")
                self.group_list.addItem(item)
                
            if self.group_list.count() == 0:
                placeholder = QListWidgetItem("No group chats yet")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                self.group_list.addItem(placeholder)
                
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load groups: {str(e)}")
            print(f"Database error: {e}")
            
        finally:
            if conn:
                conn.close()


    def open_group_chat(self, item):
        """Open group chat window when group is double-clicked"""
        if item.text() != "No group chats yet":
            try:
                group_id = str(item.data(Qt.UserRole))  # Convert to string to ensure consistency
                group_name = item.text()
                print(f"Opening group chat: {group_name} (ID: {group_id})")  # Debug print
                
                # Create and show the group chat window using self.username
                group_window = GroupMessage(self.username, group_name, group_id)
                self.group_chat_windows[group_id] = group_window  # Store reference to window
                group_window.show()
                
            except Exception as e:
                print(f"Error opening group chat: {e}")
                QMessageBox.critical(self, "Error", f"Failed to open group chat: {str(e)}")


    def back(self):
        self.redirect = Main_Menu_Window(self.username)
        self.redirect.show()
        self.close()


    def closeEvent(self, event):
        """Clean up server on window close"""
        self.server_running = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
        super().closeEvent(event)





class GroupMessage(GUI_Window):
    # Add message signal at class level
    message_received = pyqtSignal(str, str, str)  # sender, message, timestamp

    def __init__(self, username, group_name, group_id):
        super().__init__(title=f"Encrypta - {group_name}")
        self.username = username
        self.group_name = group_name 
        self.group_id = group_id
        self.symmetric = SymmetricEncryption()
        self.base_port = 5000
        self.members = []
        
        # Initialize UI components
        self.init_ui()
        
        # Connect signal after UI setup
        self.message_received.connect(self.update_chat)
        
        # Load data after UI and signal setup
        self.load_group_key()
        self.load_members()
        
        # Important: Load messages after web view is fully loaded
        self.web_view.loadFinished.connect(self.on_web_view_loaded)
        
        # Store reference to main window
        self.messages_window = None
        for window in QApplication.topLevelWidgets():
            if isinstance(window, Group_Messages_Window):
                self.messages_window = window
                self.messages_window.group_chat_windows[str(group_id)] = self
                break

        # Start status check timer
        self.start_status_timer()
        
        self.showMaximized()


    def process_incoming_message(self, notification):
        """Process incoming encrypted message"""
        try:
            print(f"Processing message in group {self.group_id} from {notification['sender']}")
            
            # Decrypt message
            encrypted = bytes.fromhex(notification['message'])
            decrypted = self.symmetric.decrypt(self.group_key, encrypted)
            message_text = decrypted.decode()
            timestamp = notification['timestamp']
            
            print(f"Decrypted message: {message_text}")  # Debug print
            
            # Save to database first
            self.save_message(
                message_text,
                notification['sender'],
                timestamp
            )
            
            # Update UI in main thread using signal
            self.message_received.emit(
                notification['sender'],
                message_text, 
                timestamp
            )
                
        except Exception as e:
            print(f"Error processing message: {e}")
            traceback.print_exc()



    @pyqtSlot(str, str, str)
    def update_chat(self, sender, message, timestamp):
        """Update chat area with new message"""
        try:
            formatted_message = f"[{timestamp}] {sender}: {message}\n"
            
            # Always update in main thread
            if QThread.currentThread() == QApplication.instance().thread():
                self.web_view.append(formatted_message)
                self.web_view.verticalScrollBar().setValue(
                    self.web_view.verticalScrollBar().maximum()
                )
            else:
                QMetaObject.invokeMethod(
                    self.web_view,
                    "append",
                    Qt.QueuedConnection,
                    Q_ARG(str, formatted_message)
                )
            print(f"Message displayed: {formatted_message}")  # Debug print
        
        except Exception as e:
            print(f"Error in update_chat: {e}")
            traceback.print_exc()


    def load_group_key(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT symmetric_key 
                FROM "Group" 
                WHERE group_name = ?
            """, (self.group_name,))
            
            result = cursor.fetchone()
            if not result or not result[0]:
                raise Exception("Group key not found")
                
            key_data = result[0]
            print(f"Raw key data type: {type(key_data)}")
            print(f"Raw key length: {len(key_data)}")
            
            # Convert to bytes if needed
            if isinstance(key_data, str):
                try:
                    # Try hex decode if it's hex encoded
                    self.group_key = bytes.fromhex(key_data)
                except:
                    # Otherwise encode as bytes
                    self.group_key = key_data.encode()
            else:
                # Already bytes
                self.group_key = key_data
                
            print(f"Final key type: {type(self.group_key)}")
            print(f"Final key length: {len(self.group_key)}")
            print(f"Key hex: {self.group_key.hex()}")
            
        except Exception as e:
            print(f"Error loading group key: {e}")
            QMessageBox.critical(self, "Error", "Failed to load encryption key")
            self.close()
        finally:
            if conn:
                conn.close()




    def init_ui(self):
        """Initialize the UI components with improved layout"""
        # Main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Top bar with search - now using QGridLayout for better alignment
        top_bar = QGridLayout()
        top_bar.setSpacing(10)
        
        # Back button
        back_button = QPushButton("←")
        back_button.clicked.connect(self.back)
        back_button.setFixedWidth(40)
        back_button.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """)
        top_bar.addWidget(back_button, 0, 0)
        
        # Group name label
        group_label = QLabel(self.group_name)
        group_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        top_bar.addWidget(group_label, 0, 1)
        
        # Search bar - aligned with members list
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search messages...")
        self.search_bar.returnPressed.connect(self.search_messages)
        self.search_bar.setFixedWidth(200)
        self.search_bar.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #2196F3;
            }
        """)
        top_bar.addWidget(self.search_bar, 0, 2, Qt.AlignRight)
        
        # Add stretch to push search bar to the right
        top_bar.setColumnStretch(1, 1)
        
        main_layout.addLayout(top_bar)
        
        # Chat area and members list in horizontal layout
        chat_container = QHBoxLayout()
        chat_container.setSpacing(15)  # Increased spacing between chat and members
        
        # Messages area
        self.web_view = QWebEngineView()
        self.web_view.setMinimumHeight(400)
        chat_container.addWidget(self.web_view, stretch=7)
        
        # Members section with improved styling
        members_container = QWidget()
        members_container.setFixedWidth(220)  # Slightly wider for better appearance
        members_container.setStyleSheet("""
            QWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
            }
        """)
        
        members_layout = QVBoxLayout(members_container)
        members_layout.setContentsMargins(10, 10, 10, 10)
        members_layout.setSpacing(10)
        
        members_label = QLabel("Group Members")
        members_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #333;
                padding: 5px;
                border-bottom: 1px solid #eee;
            }
        """)
        members_layout.addWidget(members_label)
        
        self.members_list = QListWidget()
        self.members_list.setStyleSheet("""
            QListWidget {
                border: none;
                background-color: transparent;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background-color: #f5f5f5;
            }
        """)
        members_layout.addWidget(self.members_list)
        
        chat_container.addWidget(members_container)
        
        main_layout.addLayout(chat_container)
        
        # Message input area with improved styling
        input_container = QHBoxLayout()
        input_container.setSpacing(10)
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self.send_message_from_input)
        self.message_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 20px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #2196F3;
            }
        """)
        
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message_from_input)
        send_button.setStyleSheet("""
            QPushButton {
                padding: 8px 20px;
                border: none;
                border-radius: 20px;
                background-color: #2196F3;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """)
        
        input_container.addWidget(self.message_input)
        input_container.addWidget(send_button)
        
        main_layout.addLayout(input_container)
        
        # Set up web channel and load HTML template
        self.setup_web_channel()
        self.load_html_template()



    def on_web_view_loaded(self, success):
        """Handle web view load completion"""
        if success:
            # Now it's safe to load messages
            self.load_messages()
        else:
            print("Failed to load web view")


    def setup_web_channel(self):
        """Set up web channel for JS communication"""
        self.channel = QWebChannel()
        self.web_view.page().setWebChannel(self.channel)
        # Create handler object to send messages
        class Handler(QObject):
            def __init__(self, parent):
                super().__init__()
                self.parent = parent
            # Send message to Python
            @pyqtSlot(str)
            def sendMessage(self, message):
                self.parent.send_group_message(message)
        # Register handler object
        self.handler = Handler(self)
        self.channel.registerObject("handler", self.handler)



    def update_chat(self, sender, message, timestamp):
        """Update chat with proper message display"""
        try:
            # Escape special characters for JavaScript
            sender_escaped = sender.replace('"', '\\"').replace("'", "\\'")
            message_escaped = message.replace('"', '\\"').replace("'", "\\'")
            timestamp_escaped = timestamp.replace('"', '\\"').replace("'", "\\'")
            
            # Check if message is from current user
            is_self = sender == self.username
            
            js_code = f"""
            try {{
                addMessage("{sender_escaped}", "{message_escaped}", "{timestamp_escaped}", {str(is_self).lower()});
            }} catch (error) {{
                console.error('Error adding message:', error);
            }}
            """
            self.web_view.page().runJavaScript(js_code)
            
        except Exception as e:
            print(f"Error in update_chat: {e}")
            traceback.print_exc()

    def start_status_timer(self):
        """Start timer to check online status periodically"""
        self.status_timer = QTimer(self)  # Pass self as parent
        self.status_timer.timeout.connect(self.check_members_online)
        self.status_timer.start(5000)  # Check every 5 seconds


    def load_members(self):
        try:
            # Load all members of the group
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            print(f"\n=== DEBUG INFO FOR GROUP {self.group_id} ===")
            # Get all members with their IPs
            cursor.execute("""
                SELECT DISTINCT gmc.username, 
                    CASE 
                        WHEN gmc.username = ? THEN ?
                        ELSE c.connection_ip_address 
                    END as ip_address
                FROM GroupMemberConnections gmc
                LEFT JOIN Connection c ON c.username = gmc.username
                WHERE gmc.group_id = ? AND gmc.username != ?
            """, (self.username, get_ip_address(), self.group_id, self.username))

            # Store all members in a list
            self.members = cursor.fetchall()
            # Add current user to the list
            self.members.append((self.username, get_ip_address()))  

            print(f"\nMembers query result: {self.members}")
            # Clear and re-populate members list
            self.members_list.clear()
            # Add each member to the list
            for username, ip in self.members:
                item = QListWidgetItem()
                is_online = self.check_server_online(ip)
                status = "🟢 Online" if is_online else "🔴 Offline"
                item.setText(f"{username} ({status})")
                self.members_list.addItem(item)

        except sqlite3.Error as e:
            print(f"Database error loading members: {e}")
            traceback.print_exc()
        finally:
            if conn:
                conn.close()



    def check_members_online(self):
        """Check online status of all group members"""
        if not hasattr(self, 'members') or not self.members:
            self.load_members()
            return
            
        try:
            for i in range(self.members_list.count()):
                item = self.members_list.item(i)
                if not item:
                    continue
                    
                username = item.text().split(" (")[0]
                member = next((m for m in self.members if m[0] == username), None)
                
                if member and member[1]:  # Check if we have IP
                    is_online = self.check_server_online(member[1])
                    status = "🟢 Online" if is_online else "🔴 Offline" 
                    item.setText(f"{username} ({status})")
                    
        except Exception as e:
            print(f"Error checking members online: {e}")
            traceback.print_exc()


    def load_html_template(self):
        """Load HTML template with fixed styling"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0;
                    padding: 15px;
                    background: #e5ddd5;
                    color: #333;
                    height: 100vh;
                    overflow-y: auto;
                }
                
                #messages {
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                    padding-bottom: 20px; /* Add padding at bottom for better scrolling */
                }
                
                .message-container {
                    display: flex;
                    flex-direction: column;
                    max-width: 65%;
                }
                
                .message-container.sent {
                    align-self: flex-end;
                }
                
                .message-container.received {
                    align-self: flex-start;
                }
                
                .message {
                    padding: 8px 12px;
                    border-radius: 12px;
                    position: relative;
                    word-wrap: break-word;
                    box-shadow: 0 1px 1px rgba(0, 0, 0, 0.1);
                }
                
                .message.sent {
                    background: #dcf8c6;
                    margin-left: auto;
                    border-top-right-radius: 4px;
                }
                
                .message.received {
                    background: #ffffff;
                    margin-right: auto;
                    border-top-left-radius: 4px;
                }
                
                .sender {
                    font-size: 0.8em;
                    font-weight: 500;
                    color: #1f7aec;
                    margin-bottom: 2px;
                }
                
                .message-content {
                    line-height: 1.4;
                }
                
                .timestamp {
                    font-size: 0.7em;
                    color: #667781;
                    margin-top: 2px;
                    text-align: right;
                }

                /* Scrollbar styling */
                ::-webkit-scrollbar {
                    width: 8px;
                }
                
                ::-webkit-scrollbar-track {
                    background: rgba(0, 0, 0, 0.1);
                    border-radius: 4px;
                }
                
                ::-webkit-scrollbar-thumb {
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 4px;
                }
                
                ::-webkit-scrollbar-thumb:hover {
                    background: rgba(0, 0, 0, 0.3);
                }
            </style>
        </head>
        <body>
            <div id="messages"></div>
            
            <script>
                let messageHistory = [];
                
                function addMessage(sender, message, timestamp, isSelf) {
                    const messagesDiv = document.getElementById('messages');
                    if (!messagesDiv) return;
                    
                    const container = document.createElement('div');
                    container.className = `message-container ${isSelf ? 'sent' : 'received'}`;
                    
                    const messageDiv = document.createElement('div');
                    messageDiv.className = `message ${isSelf ? 'sent' : 'received'}`;
                    
                    if (!isSelf) {
                        const senderDiv = document.createElement('div');
                        senderDiv.className = 'sender';
                        senderDiv.textContent = sender;
                        messageDiv.appendChild(senderDiv);
                    }
                    
                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'message-content';
                    contentDiv.textContent = message;
                    messageDiv.appendChild(contentDiv);
                    
                    const timeDiv = document.createElement('div');
                    timeDiv.className = 'timestamp';
                    timeDiv.textContent = timestamp;
                    messageDiv.appendChild(timeDiv);
                    
                    container.appendChild(messageDiv);
                    messagesDiv.appendChild(container);
                    
                    messageHistory.push({sender, message, timestamp, isSelf});
                    
                    // Scroll to bottom after adding message
                    document.body.scrollTo({
                        top: document.body.scrollHeight,
                        behavior: 'smooth'
                    });
                }

                if (typeof QWebChannel !== 'undefined') {
                    new QWebChannel(qt.webChannelTransport, function(channel) {
                        window.handler = channel.objects.handler;
                    });
                }
            </script>
        </body>
        </html>
        """
        self.web_view.setHtml(html_content)


    def send_message_from_input(self):
        """Handle sending message from input field"""
        message = self.message_input.text().strip()
        if message:
            self.send_group_message(message)
            self.message_input.clear()


    # Override closeEvent to clean up timer
    def search_messages(self):
        """Search messages implementation with proper error handling"""
        search_text = self.search_bar.text().strip().lower()
        if not search_text:
            # Reload all messages if search is empty
            self.load_messages()  
            return
                
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Search for messages containing the text
            cursor.execute("""
                SELECT u.username, gm.message_content, gm.timestamp
                FROM GroupMessages gm
                JOIN User u ON gm.sender_id = u.user_id
                WHERE gm.group_id = ? 
                AND LOWER(gm.message_content) LIKE ?
                ORDER BY gm.timestamp
            """, (self.group_id, f"%{search_text}%"))
            
            messages = cursor.fetchall()
            
            # Clear current messages
            self.web_view.page().runJavaScript(
                "document.getElementById('messages').innerHTML = '';"
            )
            
            if not messages:
                # Show "no results" message using JavaScript
                self.web_view.page().runJavaScript(
                    'addMessage("System", "No messages found matching your search.", "' + 
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '", false);'
                )
                return
                
            # Display search results
            for username, content, timestamp in messages:
                self.update_chat(username, content, timestamp)
                
        except sqlite3.Error as e:
            print(f"Database error in search: {e}")
            QMessageBox.warning(
                self, 
                "Search Error",
                "Failed to search messages. Please try again."
            )
        except Exception as e:
            print(f"Unexpected error in search: {e}")
            QMessageBox.warning(
                self, 
                "Search Error",
                f"An unexpected error occurred: {str(e)}"
            )
        finally:
            if conn:
                conn.close()





    def check_server_online(self, ip):
        """Check if a server is running at the given IP and port"""
        if ip == '127.0.0.1' and self.username == self.username:
            return True
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Shorter timeout
                print(f"Checking {ip}:{self.base_port}")
                result = s.connect_ex((ip, self.base_port))
                is_online = result == 0
                print(f"Server check result for {ip}: {is_online}")
                return is_online
        except Exception as e:
            print(f"Error checking server {ip}: {e}")
            return False





    def check_all_members_online(self):
        """Check if all members are online"""
        offline_members = []
        for username, user_id, ip in self.members:
            if not self.check_server_online(ip, user_id):
                offline_members.append(username)
        return offline_members



    def send_group_message(self, message_text):
        """Modified to work with new UI"""
        try:
            if not message_text:
                return

            # Check if all members are online before sending
            offline_members = []
            for username, ip_address in self.members:
                if username != self.username:
                    if not self.messages_window.check_server_online(ip_address, None):
                        offline_members.append(username)

            if offline_members:
                self.web_view.page().runJavaScript(
                    f'alert("Cannot send message. The following members are offline: {", ".join(offline_members)}")'
                )
                return

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Encrypt message
            encrypted = self.symmetric.encrypt(self.group_key, message_text.encode())

            # Create notification
            notification = {
                'type': 'group_message',
                'group_id': self.group_id,
                'sender': self.username,
                'message': encrypted.hex(),
                'timestamp': timestamp
            }

            # Send to all other members
            send_failures = []
            for username, ip_address in self.members:
                if username != self.username:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(2)
                            s.connect((ip_address, self.base_port))
                            s.send(json.dumps(notification).encode())
                    except Exception as e:
                        print(f"Failed to send to {username}: {e}")
                        send_failures.append(username)

            if send_failures:
                self.web_view.page().runJavaScript(
                    f'alert("Failed to deliver message to: {", ".join(send_failures)}")'
                )
                return

            # Save and display own message
            self.save_message(message_text, self.username, timestamp)
            self.update_chat(self.username, message_text, timestamp)

        except Exception as e:
            print(f"Error sending message: {e}")
            self.web_view.page().runJavaScript(
                f'alert("Failed to send message: {str(e)}")'
            )



    def send_via_parent(self, ip, notification):
        """Send message through parent window's server connection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, self.base_port))
                s.send(json.dumps(notification).encode())
            return True
        except Exception as e:
            print(f"Failed to send via parent: {e}")
            return False



    def send_to_member(self, ip, message_data):
        """Send message to a specific member"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, self.base_port))
                s.send(json.dumps(message_data).encode())
            return True
        except Exception as e:
            print(f"Failed to send to {ip}: {e}")
            return False




    def save_message(self, content, sender=None, timestamp=None):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            if sender is None:
                sender = self.username
            if timestamp is None:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
            cursor.execute("""
                INSERT INTO GroupMessages 
                (group_id, message_content, timestamp, sender_id, encryption_type)
                VALUES (?, ?, ?, 
                    (SELECT user_id FROM User WHERE username = ?),
                    'AES'
                )
            """, (self.group_id, content, timestamp, sender))
            
            conn.commit()
        except Exception as e:
            print(f"Failed to save message: {e}")
        finally:
            if conn:
                conn.close()



    def load_messages(self):
        """Load message history from database"""
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # First clear existing messages
            self.web_view.page().runJavaScript("document.getElementById('messages').innerHTML = '';")
            
            cursor.execute("""
                SELECT u.username, gm.message_content, gm.timestamp
                FROM GroupMessages gm
                JOIN User u ON gm.sender_id = u.user_id 
                WHERE gm.group_id = ?
                ORDER BY gm.timestamp
            """, (self.group_id,))
            
            messages = cursor.fetchall()
            
            # Use JavaScript to display messages
            for username, content, timestamp in messages:
                self.update_chat(username, content, timestamp)
                
        except Exception as e:
            print(f"Failed to load messages: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load messages: {str(e)}")
        finally:
            if conn:
                conn.close()



    def display_message(self, sender, message, timestamp=None):
        """Thread-safe message display"""
        try:
            # Use current timestamp if not provided
            if timestamp is None:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Format message for display   
            formatted_message = f"[{timestamp}] {sender}: {message}\n"
            
            # Ensure we're in the main thread
            if QThread.currentThread() == QApplication.instance().thread():
                self.web_view.append(formatted_message)
                self.web_view.verticalScrollBar().setValue(
                    self.web_view.verticalScrollBar().maximum()
                )
            else:
                QMetaObject.invokeMethod(self.web_view,
                                    "append",
                                    Qt.QueuedConnection,
                                    Q_ARG(str, formatted_message))
        except Exception as e:
            print(f"Error displaying message: {e}")
            traceback.print_exc()





    def back(self):
        """Return to group chat list"""
        self.messages_window.show()
        self.close()




    def closeEvent(self, event):
        """Clean up resources when window is closed"""
        self.server_running = False
        if hasattr(self, 'status_timer'):
            self.status_timer.stop()
        super().closeEvent(event)








class Calls_Window(GUI_Window):
    def __init__(self, username):
        super().__init__("Encrypta - Calls")

        self.username = username
        self.call_port = 5000  # TCP signaling port
        self.audio_port = 5001  # UDP audio port
        self.video_port = 5002  # TCP signaling port for video
        self.current_call = None
        self.call_server = None
        self.video_server = None
        
        # Setup UI
        self.setup_ui()
        
        # Start call server
        self.start_call_server()
        self.start_video_server()
        
        # Load connections
        self.load_connections()

        self.showMaximized()
        



    def setup_ui(self):
        # Create main layout container
        self.calls_container = QWidget()
        self.layout.addWidget(self.calls_container)
        self.calls_layout = QHBoxLayout(self.calls_container)
        
        # Set consistent styling for the entire container
        self.calls_container.setStyleSheet("""
            QWidget {
                background-color: #f8f9fa;
                font-size: 16px;
            }
            QLabel {
                font-size: 30px;
                font-weight: bold;
                color: #212529;
                padding: 10px 0;
            }
            QListWidget {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
                font-size: 24px;
                min-width: 300px;
            }
            QListWidget::item {
                padding: 18px;
                border-bottom: 1px solid #e9ecef;
            }
            QListWidget::item:selected {
                background-color: #007bff;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #e9ecef;
            }
        """)
        
        # Create splitter for voice/video sections
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.calls_layout.addWidget(self.splitter)
        
        # Voice calls section
        self.voice_widget = QWidget()
        self.voice_layout = QVBoxLayout(self.voice_widget)
        self.voice_label = QLabel("Voice Calls")
        self.call_list = QListWidget()
        self.voice_layout.addWidget(self.voice_label)
        self.voice_layout.addWidget(self.call_list)
        
        # Add spacing between sections
        self.voice_layout.setContentsMargins(20, 20, 20, 20)
        self.voice_layout.setSpacing(15)
        
        # Video calls section  
        self.video_widget = QWidget()
        self.video_layout = QVBoxLayout(self.video_widget)
        self.video_label = QLabel("Video Calls")
        self.video_list = QListWidget()
        self.video_layout.addWidget(self.video_label)
        self.video_layout.addWidget(self.video_list)
        
        # Add spacing between sections
        self.video_layout.setContentsMargins(20, 20, 20, 20)
        self.video_layout.setSpacing(15)
        
        # Add both sections to splitter
        self.splitter.addWidget(self.voice_widget)
        self.splitter.addWidget(self.video_widget)
        
        # Connect double click event to video call request too
        self.call_list.itemDoubleClicked.connect(self.handle_call_request)
        self.video_list.itemDoubleClicked.connect(self.handle_video_call_request)
        
        # Style the back button
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 15px 20px;
                font-size: 18px;
                font-weight: bold;
                min-width: 10px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        
        # Move back button to top left, above the calls container
        self.layout.insertWidget(0, self.back_button, 0, Qt.AlignLeft)
        self.back_button.clicked.connect(self.back)
        
        
    def back(self):
        self.redirect = Main_Menu_Window(self.username)
        self.redirect.show()
        self.close()
        



    def load_connections(self):
        try:
            conn = sqlite3.connect("encrypta.db")
            cursor = conn.cursor()
            
            # Get current user's ID from the database
            cursor.execute("SELECT user_id FROM User WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]
            
            # Get all connected users except the current user
            cursor.execute("""
                SELECT u.username 
                FROM Connection c
                JOIN User u ON (c.receiver_id = u.user_id OR c.sender_id = u.user_id)
                WHERE (c.sender_id = ? OR c.receiver_id = ?)
                AND c.status = 'connected'
                AND u.username != ?
                ORDER BY u.username
            """, (user_id, user_id, self.username))

            connections = cursor.fetchall()

            # Clear existing items
            self.call_list.clear()

            # Add items to the list
            for connection in connections:
                username = connection[0]
                item = QListWidgetItem(username)
                item.setToolTip(f"Double click to chat with {username}")
                self.call_list.addItem(item)

            # Add placeholder if no connections    
            if self.call_list.count() == 0:
                placeholder = QListWidgetItem("No connections yet")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                self.call_list.addItem(placeholder)

            # Add items to video container too
            self.video_list.clear()
            for connection in connections:
                username = connection[0]
                item = QListWidgetItem(username)
                item.setToolTip(f"Double click to chat with {username}")
                self.video_list.addItem(item)
            # Add a placeholder if the list is empty
            if self.video_list.count() == 0:
                placeholder = QListWidgetItem("No connections yet")
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
                self.video_list.addItem(placeholder)

            

        # Error handling         
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load connections: {str(e)}")
            print(f"Database error details: {str(e)}")  # For debugging
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            print(f"Error details: {str(e)}")  # For debugging
        finally:
            if conn:
                conn.close()






    def check_server_online(self, ip):
        """Check if a server is running at the given IP and port"""
        if ip == '127.0.0.1' and self.username == self.username:
            return True
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Shorter timeout
                print(f"Checking {ip}:{self.call_port}")
                result = s.connect_ex((ip, self.call_port))
                is_online = result == 0
                print(f"Server check result for {ip}: {is_online}")
                return is_online
        except Exception as e:
            print(f"Error checking server {ip}: {e}")
            return False



    def start_call_server(self):
        """Start TCP server to handle incoming calls"""
        self.call_server = CallServer(self.call_port, self.audio_port)
        self.call_server.call_received.connect(self.handle_incoming_call)
        self.call_server.start()
        

    def start_video_server(self):
        """Start TCP server to handle incoming video calls"""
        self.video_server = VideoServer(self.video_port)
        self.video_server.video_call_received.connect(self.handle_incoming_video_call)
        self.video_server.start()





    def handle_call_request(self, item):
        """Handle outgoing call request"""
        username = item.text().strip()

        conn = sqlite3.connect("encrypta.db")
        cursor = conn.cursor()
        cursor.execute("SELECT connection_ip_address FROM Connection WHERE username = ?", (username,))
        ip = cursor.fetchone()[0]

        # Check user is online
        if not self.check_server_online(ip):
            QMessageBox.critical(self, "Error", f"{username} is not online")
            return
        
        try:
            # Send call request
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, self.call_port))
                s.send(json.dumps({
                    'type': 'call_request',
                    'username': self.username
                }).encode())
            
            # Create call window
            self.current_call = ActiveCallWindow(username, ip, self.audio_port)
            self.current_call.call_ended.connect(self.handle_call_ended)
            self.current_call.show()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start call: {str(e)}")

    # Handle incoming call request
    def handle_incoming_call(self, username, ip):
        # Ask user to accept or reject call
        response = QMessageBox.question(self, "Incoming Call",
                                      f"Incoming voice call from {username}. Accept?",
                                      QMessageBox.StandardButton.Yes | 
                                      QMessageBox.StandardButton.No)                        
        try:
            # Connect to the caller
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, self.call_port))

                # Send response
                if response == QMessageBox.StandardButton.Yes:
                    s.send(json.dumps({'type': 'call_accepted'}).encode())
                    
                    # Create call window
                    self.current_call = ActiveCallWindow(username, ip, self.audio_port)
                    self.current_call.call_ended.connect(self.handle_call_ended)
                    self.current_call.show()
                else:
                    # Send rejection
                    s.send(json.dumps({'type': 'call_rejected'}).encode())
                    
        except Exception as e:
            # Handle errors
            QMessageBox.critical(self, "Error", f"Failed to handle call: {str(e)}")



    def handle_video_call_request(self, item):
        """Handle outgoing video call request"""
        username = item.text().strip()

        conn = sqlite3.connect("encrypta.db")
        cursor = conn.cursor()
        cursor.execute("SELECT connection_ip_address FROM Connection WHERE username = ?", (username,))
        ip = cursor.fetchone()[0]

        # Check user is online
        if not self.check_server_online(ip):
            QMessageBox.critical(self, "Error", f"{username} is not online")
            return
        
        try:
            # Send video call request
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, self.video_port))
                s.send(json.dumps({
                    'type': 'video_call_request',
                    'username': self.username
                }).encode())
            
            # Create video call window
            self.current_call = VideoCallWindow(username, ip, self.video_port)
            self.current_call.call_ended.connect(self.handle_call_ended)
            self.current_call.show()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start video call: {str(e)}")


    

    def handle_incoming_video_call(self, username, ip):
        """Handle incoming video call request"""
        response = QMessageBox.question(self, "Incoming Video Call",
                                    f"Incoming video call from {username}. Accept?",
                                    QMessageBox.StandardButton.Yes | 
                                    QMessageBox.StandardButton.No)
                                    
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, self.video_port))
                
                if response == QMessageBox.StandardButton.Yes:
                    s.send(json.dumps({'type': 'video_call_accepted'}).encode())
                    
                    # Create video call window
                    self.current_call = VideoCallWindow(username, ip, self.video_port)
                    self.current_call.call_ended.connect(self.handle_call_ended)
                    self.current_call.show()
                else:
                    s.send(json.dumps({'type': 'video_call_rejected'}).encode())
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to handle video call: {str(e)}")



    def handle_call_ended(self):
        """Clean up after call ends"""
        if self.current_call:
            self.current_call.close()
            self.current_call = None




    def closeEvent(self, event):
        """Clean up on window close"""
        if self.call_server:
            self.call_server.running = False
            self.call_server.wait()
        if self.current_call:
            self.current_call.close()
        super().closeEvent(event)







class VideoCallWindow(QWidget):
    call_ended = pyqtSignal()
    
    def __init__(self, username, ip, video_port, audio_port=5001):
        super().__init__()
        self.username = username
        self.ip = ip
        self.video_port = video_port
        self.audio_port = audio_port
        self.running = True
        
        # Add control socket for call termination signals
        self.control_port = video_port + 2  # Use a different port for control signals
        self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control_socket.bind(('', self.control_port))

        # Start control message listener thread
        self.control_thread = threading.Thread(target=self.listen_for_control_messages)
        self.control_thread.daemon = True
        self.control_thread.start()

        # Initialize audio stream
        self.audio_input = pyaudio.PyAudio()
        self.audio_output = pyaudio.PyAudio()
        self.setup_audio()


        self.setup_ui()
        self.setup_video()




    def listen_for_control_messages(self):
        """Listen for control messages from the other user"""
        while self.running:
            try:
                data, addr = self.control_socket.recvfrom(1024)
                message = data.decode()
                if message == "CALL_TERMINATED":
                    # Use invokeMethod to safely call GUI-related code from another thread
                    QMetaObject.invokeMethod(self, "handle_remote_termination",
                                           Qt.ConnectionType.QueuedConnection)
            except:
                if not self.running:
                    break
                continue



    @pyqtSlot()
    def handle_remote_termination(self):
        """Handle call termination from the other user"""
        self.status_label.setText(f"{self.username} has ended the call")
        self.status_label.setStyleSheet("color: #dc3545; font-size: 12px;")
        
        # Show a notification dialog
        QMessageBox.information(self, "Call Ended",
                              f"{self.username} has ended the call",
                              QMessageBox.StandardButton.Ok)
        
        # Close the window
        self.close()




    def send_termination_signal(self):
        """Send termination signal to the other user"""
        try:
            self.control_socket.sendto("CALL_TERMINATED".encode(),
                                     (self.ip, self.control_port))
        except:
            pass  # Handle any network errors silently




        
    def setup_ui(self):
        # Window setup
        self.setWindowTitle(f"Video Call with {self.username}")
        self.setMinimumWidth(1000)  # Wider window
        self.setMinimumHeight(600)  # Taller window
        
        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setSpacing(20)  # Add spacing between elements
        
        # Video feeds container
        self.video_container = QHBoxLayout()
        self.video_container.setSpacing(30)  # Add spacing between videos
        
        # Local video widget
        self.local_widget = QWidget()
        self.local_layout = QVBoxLayout(self.local_widget)
        self.local_label = QLabel("Your Video")
        self.local_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.local_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        
        # Video frame container with fixed aspect ratio
        self.local_video_container = QWidget()
        self.local_video_container.setFixedSize(480, 360)  # 4:3 aspect ratio
        self.local_video_container.setStyleSheet("background-color: #f0f0f0; border: 2px solid #ddd; border-radius: 10px;")
        self.local_video = QLabel(self.local_video_container)
        self.local_video.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.local_video.setFixedSize(480, 360)
        
        self.local_layout.addWidget(self.local_label)
        self.local_layout.addWidget(self.local_video_container)
        
        # Remote video widget
        self.remote_widget = QWidget()
        self.remote_layout = QVBoxLayout(self.remote_widget)
        self.remote_label = QLabel(f"{self.username}'s Video")
        self.remote_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.remote_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 5px;")
        
        # Remote video container with fixed aspect ratio
        self.remote_video_container = QWidget()
        self.remote_video_container.setFixedSize(480, 360)  # 4:3 aspect ratio
        self.remote_video_container.setStyleSheet("background-color: #f0f0f0; border: 2px solid #ddd; border-radius: 10px;")
        self.remote_video = QLabel(self.remote_video_container)
        self.remote_video.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.remote_video.setFixedSize(480, 360)
        
        self.remote_layout.addWidget(self.remote_label)
        self.remote_layout.addWidget(self.remote_video_container)
        
        # Add video widgets to container
        self.video_container.addWidget(self.local_widget)
        self.video_container.addWidget(self.remote_widget)
        
        # Controls container
        self.controls_container = QWidget()
        self.controls_layout = QHBoxLayout(self.controls_container)
        self.controls_layout.setSpacing(20)  # Add spacing between buttons
        
        # Camera button
        self.camera_button = QPushButton("Turn Off Camera")
        self.camera_button.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 15px 30px;
                font-size: 14px;
                font-weight: bold;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        self.camera_button.clicked.connect(self.toggle_video)
        
        # Microphone button
        self.mic_button = QPushButton("Mute Microphone")
        self.mic_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 15px 30px;
                font-size: 14px;
                font-weight: bold;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        self.mic_button.clicked.connect(self.toggle_audio)
        
        # End call button
        self.end_call_button = QPushButton("End Call")
        self.end_call_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 15px 30px;
                font-size: 14px;
                font-weight: bold;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        self.end_call_button.clicked.connect(self.end_call)
        
        # Mute video button
        self.mute_video_button = QPushButton("Turn Off Camera")
        self.mute_video_button.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        self.mute_video_button.clicked.connect(self.toggle_video)
                                             
        # Add buttons to controls
        self.controls_layout.addStretch()
        self.controls_layout.addWidget(self.mic_button)
        self.controls_layout.addWidget(self.end_call_button)
        self.controls_layout.addWidget(self.mute_video_button)
        self.controls_layout.addStretch()
        
        # Status bar
        self.status_label = QLabel("Connected")
        self.status_label.setStyleSheet("color: #28a745; font-size: 12px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Add everything to main layout
        self.main_layout.addLayout(self.video_container)
        self.main_layout.addWidget(self.controls_container)
        self.main_layout.addWidget(self.status_label)




    def setup_audio(self):
        # Audio settings
        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 44100
        self.audio_muted = False
        
        # Setup audio stream
        self.audio_stream = self.audio_input.open(
            format=self.FORMAT,
            channels=self.CHANNELS,
            rate=self.RATE,
            input=True,
            frames_per_buffer=self.CHUNK
        )
        
        # Setup audio socket
        self.audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Start audio threads
        self.audio_sender = AudioSender(
            self.audio_stream,
            self.audio_socket,
            self.ip,
            self.audio_port,
            self.CHUNK
        )
        self.audio_receiver = AudioReceiver(
            self.audio_output,
            self.audio_port,
            self.FORMAT,
            self.CHANNELS,
            self.RATE,
            self.CHUNK
        )
        
        self.audio_sender.start()
        self.audio_receiver.start()



    def toggle_audio(self):
        self.audio_muted = not self.audio_muted
        if self.audio_muted:
            self.mic_button.setText("Unmute Microphone")
            self.mic_button.setStyleSheet("""
                QPushButton {
                    background-color: #6c757d;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 15px 30px;
                    font-size: 14px;
                    font-weight: bold;
                    min-width: 150px;
                }
                QPushButton:hover {
                    background-color: #5a6268;
                }
            """)
            self.audio_sender.mute()
        else:
            self.mic_button.setText("Mute Microphone")
            self.mic_button.setStyleSheet("""
                QPushButton {
                    background-color: #28a745;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 15px 30px;
                    font-size: 14px;
                    font-weight: bold;
                    min-width: 150px;
                }
                QPushButton:hover {
                    background-color: #218838;
                }
            """)
            self.audio_sender.unmute()


        
    def setup_video(self):
        # Initialize video capture
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            self.status_label.setText("Failed to open camera!")
            self.status_label.setStyleSheet("color: red;")
            return
            
        # Start video threads
        self.video_muted = False
        self.start_video_stream()
        
    def start_video_stream(self):
        # Start sender thread
        self.sender = VideoSender(self.cap, self.ip, self.video_port, self.local_video)
        self.sender.start()
        
        # Start receiver thread
        self.receiver = VideoReceiver(self.video_port, self.remote_video)
        self.receiver.start()
        
    def toggle_video(self):
        self.video_muted = not self.video_muted
        if self.video_muted:
            self.mute_video_button.setText("Turn On Camera")
            self.local_video.clear()
            self.local_video.setText("Camera Off")
            self.sender.mute()
        else:
            self.mute_video_button.setText("Turn Off Camera")
            self.sender.unmute()

     
            
    def end_call(self):
        """Handle the end call button click"""
        # Send termination signal before closing
        self.send_termination_signal()
        
        # Update status and close window
        self.status_label.setText("Call ended")
        self.status_label.setStyleSheet("color: #dc3545; font-size: 12px;")
        self.call_ended.emit()
        self.close()

    def closeEvent(self, event):
        """Clean up on window close"""
        # Send termination signal if window is closed directly
        if self.running:
            self.send_termination_signal()
        
        self.running = False
        
        # Close control socket
        if hasattr(self, 'control_socket'):
            self.control_socket.close()
        
        # Stop video
        if hasattr(self, 'cap') and self.cap.isOpened():
            self.cap.release()
        if hasattr(self, 'sender'):
            self.sender.stop()
        if hasattr(self, 'receiver'):
            self.receiver.stop()
            
        # Stop audio
        if hasattr(self, 'audio_sender'):
            self.audio_sender.stop()
        if hasattr(self, 'audio_receiver'):
            self.audio_receiver.stop()
            
        # Close audio streams
        if hasattr(self, 'audio_stream'):
            self.audio_stream.stop_stream()
            self.audio_stream.close()
        if hasattr(self, 'audio_input'):
            self.audio_input.terminate()
        if hasattr(self, 'audio_output'):
            self.audio_output.terminate()
            
        self.call_ended.emit()
        event.accept()


class VideoServer(QThread):
    video_call_received = pyqtSignal(str, str)  # username, ip
    error_signal = pyqtSignal(str)
    
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.running = True
        
        # Setup TCP socket for signaling
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)  # Add timeout for checking running status
        except Exception as e:
            self.error_signal.emit(f"Failed to start video server: {e}")
            self.running = False
            
    def handle_client(self, client_socket, addr):
        """Handle individual client connections"""
        try:
            # Receive the request
            data = client_socket.recv(1024).decode()
            if data:
                request = json.loads(data)
                
                if request['type'] == 'video_call_request':
                    # Emit signal for incoming call
                    self.video_call_received.emit(request['username'], addr[0])
                    
                elif request['type'] == 'video_call_accepted':
                    # Handle call acceptance
                    response = {'type': 'video_call_started'}
                    client_socket.send(json.dumps(response).encode())
                    
                elif request['type'] == 'video_call_rejected':
                    # Handle call rejection
                    response = {'type': 'video_call_ended', 'reason': 'rejected'}
                    client_socket.send(json.dumps(response).encode())
                    
                elif request['type'] == 'end_call':
                    # Handle call ending
                    response = {'type': 'video_call_ended', 'reason': 'ended'}
                    client_socket.send(json.dumps(response).encode())
                    
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            
    def run(self):
        while self.running:
            try:
                # Accept new connections
                client_socket, addr = self.socket.accept()
                
                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only show error if we're still supposed to be running
                    print(f"Server error: {e}")
                    self.error_signal.emit(f"Video server error: {e}")
                continue
                
    def stop(self):
        """Stop the server"""
        self.running = False
        try:
            # Create dummy connection to unblock accept()
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect(('localhost', self.port))
            temp_socket.close()
        except:
            pass
        
        self.socket.close()
        self.wait()


class VideoSender(QThread):
    def __init__(self, cap, ip, port, label):
        super().__init__()
        self.cap = cap
        self.ip = ip
        self.port = port
        self.label = label
        self.running = True
        self.muted = False
        
        # Setup UDP socket with minimal buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set smaller buffer size
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        
    def run(self):
        while self.running:
            if not self.muted:
                ret, frame = self.cap.read()
                if ret:
                    # Reduce frame size even further
                    frame = cv2.resize(frame, (240, 180))
                    
                    # Display local video
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    h, w, ch = rgb_frame.shape
                    q_img = QImage(rgb_frame.data, w, h, ch * w, QImage.Format_RGB888)
                    self.label.setPixmap(QPixmap.fromImage(q_img))
                    
                    try:
                        # Maximum compression
                        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 20])
                        data = buffer.tobytes()
                        
                        # Use very small chunks (1KB)
                        chunk_size = 1024
                        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
                        
                        # Send frame metadata
                        header = struct.pack('!II', len(chunks), len(data))
                        self.socket.sendto(header, (self.ip, self.port))
                        
                        # Send chunks with minimal overhead
                        for i, chunk in enumerate(chunks):
                            # Just 2 bytes for sequence number to reduce overhead
                            header = struct.pack('!H', i)
                            packet = header + chunk
                            self.socket.sendto(packet, (self.ip, self.port))
                            # Larger delay between packets to prevent overwhelming
                            time.sleep(0.002)
                            
                    except Exception as e:
                        print(f"Error sending frame: {e}")
                        continue
                        
            time.sleep(0.05)  # Reduce to 20 FPS
            
    def mute(self):
        self.muted = True
        self.label.clear()
        self.label.setText("Camera Off")
        
    def unmute(self):
        self.muted = False
        
    def stop(self):
        self.running = False
        self.socket.close()
        self.wait()


class VideoReceiver(QThread):
    error_signal = pyqtSignal(str)
    
    def __init__(self, port, label):
        super().__init__()
        self.port = port
        self.label = label
        self.running = True
        
        # Setup UDP socket with minimal buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set smaller receive buffer
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        self.socket.settimeout(0.5)  # Shorter timeout
        
        try:
            self.socket.bind(('', port))
        except Exception as e:
            self.error_signal.emit(f"Failed to bind to port {port}: {e}")
            self.running = False
            
    def run(self):
        while self.running:
            try:
                # Receive frame metadata
                header, _ = self.socket.recvfrom(8)  # 8 bytes for two integers
                if not self.running:
                    break
                    
                num_chunks, total_size = struct.unpack('!II', header)
                
                # Initialize frame data
                chunks = {}
                start_time = time.time()
                
                # Collect chunks with timeout
                while len(chunks) < num_chunks and (time.time() - start_time) < 0.5:
                    try:
                        packet, _ = self.socket.recvfrom(1026)  # 2 bytes seq + 1024 data
                        seq_num = struct.unpack('!H', packet[:2])[0]
                        chunk = packet[2:]
                        chunks[seq_num] = chunk
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if "10040" not in str(e):  # Ignore buffer errors
                            print(f"Error receiving chunk: {e}")
                        break
                
                if not self.running:
                    break
                    
                # Process complete frames only
                if len(chunks) == num_chunks:
                    # Reconstruct frame data
                    ordered_chunks = [chunks[i] for i in range(num_chunks)]
                    data = b''.join(ordered_chunks)
                    
                    # Skip frame if data is incomplete
                    if len(data) != total_size:
                        continue
                        
                    # Decode and display frame
                    frame = cv2.imdecode(
                        np.frombuffer(data, dtype=np.uint8),
                        cv2.IMREAD_COLOR
                    )
                    
                    if frame is not None:
                        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        h, w, ch = rgb_frame.shape
                        q_img = QImage(
                            rgb_frame.data,
                            w, h, ch * w,
                            QImage.Format_RGB888
                        )
                        self.label.setPixmap(QPixmap.fromImage(q_img))
                    
            except socket.timeout:
                continue
            except Exception as e:
                if "10040" not in str(e):  # Only log non-buffer errors
                    print(f"Error in receiver: {e}")
                    self.label.setText("Connection Lost")
                time.sleep(0.1)
                
    def stop(self):
        self.running = False
        try:
            dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dummy_socket.sendto(b'stop', ('localhost', self.port))
            dummy_socket.close()
        except:
            pass
        self.socket.close()
        self.wait()


class AudioSender(QThread):
    def __init__(self, audio_stream, socket, ip, port, chunk_size):
        super().__init__()
        self.audio_stream = audio_stream
        self.socket = socket
        self.ip = ip
        self.port = port
        self.chunk_size = chunk_size
        self.running = True
        self.muted = False

    def run(self):
        while self.running:
            try:
                if not self.muted:
                    # Read audio data
                    data = self.audio_stream.read(self.chunk_size, exception_on_overflow=False)
                    
                    # Send audio data
                    try:
                        self.socket.sendto(data, (self.ip, self.port))
                    except Exception as e:
                        print(f"Error sending audio data: {e}")
                        
                # Small sleep to prevent CPU overload
                time.sleep(0.001)
                
            except Exception as e:
                print(f"Error in audio sender: {e}")
                time.sleep(0.1)  # Sleep longer on error

    def mute(self):
        self.muted = True

    def unmute(self):
        self.muted = False

    def stop(self):
        self.running = False
        self.wait()


class AudioReceiver(QThread):
    def __init__(self, audio_output, port, format, channels, rate, chunk_size):
        super().__init__()
        self.audio_output = audio_output
        self.port = port
        self.format = format
        self.channels = channels
        self.rate = rate
        self.chunk_size = chunk_size
        self.running = True
        
        # Setup socket for receiving audio
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', port))
        self.socket.settimeout(0.2)  # Short timeout for responsiveness
        
        # Setup audio output stream
        self.output_stream = self.audio_output.open(
            format=self.format,
            channels=self.channels,
            rate=self.rate,
            output=True,
            frames_per_buffer=self.chunk_size
        )
        
        # Setup jitter buffer
        self.jitter_buffer = collections.deque(maxlen=10)  # Buffer 10 chunks max
        self.buffer_target = 3  # Target number of chunks in buffer

    def run(self):
        while self.running:
            try:
                # Receive audio data
                try:
                    data, _ = self.socket.recvfrom(self.chunk_size * 2)  # Extra space for safety
                    self.jitter_buffer.append(data)
                except socket.timeout:
                    # No data received, check if we need to play from buffer
                    pass
                except Exception as e:
                    print(f"Error receiving audio data: {e}")
                    continue

                # Process buffered audio
                self.process_buffer()
                
                # Small sleep to prevent CPU overload
                time.sleep(0.001)
                
            except Exception as e:
                print(f"Error in audio receiver: {e}")
                time.sleep(0.1)  # Sleep longer on error

    def process_buffer(self):
        """Process audio from jitter buffer"""
        try:
            # Play audio if we have enough data
            if len(self.jitter_buffer) >= self.buffer_target:
                data = self.jitter_buffer.popleft()
                self.output_stream.write(data)
            elif len(self.jitter_buffer) > 0 and self.running:
                # Buffer running low, play anyway to reduce latency
                data = self.jitter_buffer.popleft()
                self.output_stream.write(data)
                
        except Exception as e:
            print(f"Error processing audio buffer: {e}")

    def stop(self):
        self.running = False
        try:
            # Send dummy packet to unblock recvfrom
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.sendto(b'', ('localhost', self.port))
            temp_socket.close()
        except:
            pass
            
        # Clean up audio stream
        if hasattr(self, 'output_stream'):
            try:
                self.output_stream.stop_stream()
                self.output_stream.close()
            except:
                pass
                
        self.socket.close()
        self.wait()




        
class CallServer(QThread):
    """TCP server to handle call signaling"""
    call_received = pyqtSignal(str, str)  # username, ip
    
    def __init__(self, call_port, audio_port):
        super().__init__()
        self.call_port = call_port
        self.audio_port = audio_port
        self.running = True
        
    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('', self.call_port))
        server.listen(5)
        server.settimeout(1)
        
        while self.running:
            try:
                client, addr = server.accept()
                data = client.recv(1024).decode()
                if data:
                    msg = json.loads(data)
                    if msg['type'] == 'call_request':
                        self.call_received.emit(msg['username'], addr[0])
                client.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Call server error: {e}")
                
        server.close()



class AudioStream(QThread):
    """Handles audio streaming over UDP"""
    audio_level = pyqtSignal(float)
    call_ended_by_peer = pyqtSignal(str)  # New signal for call end notification
    

    def __init__(self, peer_ip, audio_port):
        super().__init__()
        self.peer_ip = peer_ip
        self.audio_port = audio_port
        self.running = True
        self.muted = False
        self.socket_closed = False
        
        # Audio settings
        self.chunk_size = 1024
        self.format = pyaudio.paFloat32
        self.channels = 1
        self.rate = 44100
        
        # Setup UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self.audio_port))
        
        # Setup audio
        self.audio = pyaudio.PyAudio()
        self.setup_streams()

        
    def setup_streams(self):
        """Setup audio input and output streams"""
        self.input_stream = self.audio.open(
            format=self.format,
            channels=self.channels,
            rate=self.rate,
            input=True,
            frames_per_buffer=self.chunk_size
        )
        
        self.output_stream = self.audio.open(
            format=self.format,
            channels=self.channels,
            rate=self.rate,
            output=True,
            frames_per_buffer=self.chunk_size
        )

    def set_muted(self, muted):
        """Safely handle mute state"""
        self.muted = muted
        
    def run(self):
        """Main audio streaming loop"""
        # Start receive thread
        receive_thread = threading.Thread(target=self.receive_audio)
        receive_thread.start()
        
        # Send audio
        while self.running:
            try:
                # Read from microphone
                data = self.input_stream.read(self.chunk_size, exception_on_overflow=False)
                
                # Only send if not muted
                if not self.muted:
                    # Send to peer
                    self.sock.sendto(data, (self.peer_ip, self.audio_port))
                    
                    # Calculate audio level
                    audio_array = np.frombuffer(data, dtype=np.float32)
                    level = float(np.abs(audio_array).mean())
                    self.audio_level.emit(level)
                else:
                    # Emit zero level when muted
                    self.audio_level.emit(0.0)
                    
            except Exception as e:
                print(f"Error sending audio: {e}")
                if not self.running:
                    break
                    
        receive_thread.join()
        self.cleanup()
        


    def receive_audio(self):
        """Receive and play audio from peer"""
        self.sock.settimeout(1)
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(self.chunk_size * 4)
                
                # Check if this might be a control message (they're typically much smaller than audio chunks)
                if len(data) < 100:  # Control messages are small
                    try:
                        # First character of json will be {
                        if data[0] == ord('{'):
                            message = json.loads(data.decode())
                            if message.get('type') == 'END_CALL':
                                self.running = False
                                self.call_ended_by_peer.emit(message.get('peer_name', 'Unknown user'))
                                break
                        else:
                            # Not JSON, treat as audio
                            self.output_stream.write(data)
                    except Exception as e:
                        # If any error occurs, assume it's audio data
                        self.output_stream.write(data)
                else:
                    # Regular audio data
                    self.output_stream.write(data)
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error in receive_audio: {e}")
                if not self.running:
                    break



    def send_end_call(self, peer_name):
        """Send end call notification"""
        if self.socket_closed:
            return
            
        try:
            # Create a control message
            end_message = json.dumps({
                'type': 'END_CALL',
                'peer_name': peer_name
            }).encode()
            
            # Send it multiple times to ensure delivery
            for _ in range(5):
                if not self.socket_closed:
                    self.sock.sendto(end_message, (self.peer_ip, self.audio_port))
                    time.sleep(0.1)
        except Exception as e:
            print(f"Error sending end call: {e}")

    def cleanup(self):
        """Clean up audio resources"""
        try:
            self.input_stream.stop_stream()
            self.input_stream.close()
            self.output_stream.stop_stream()
            self.output_stream.close()
            self.audio.terminate()
            self.socket_closed = True
            self.sock.close()
        except Exception as e:
            print(f"Error in cleanup: {e}")



class ActiveCallWindow(QWidget):
    """Active call window with enhanced controls"""
    call_ended = pyqtSignal()
    
    def __init__(self, peer_username, peer_ip, audio_port):
        super().__init__()
        self.peer_username = peer_username
        self.peer_ip = peer_ip
        self.audio_port = audio_port
        
        # Call duration tracking
        self.call_start_time = QDateTime.currentDateTime()
        self.duration_timer = None
        
        self.setup_ui()
        self.setup_duration_timer()
        
        # Start audio streaming
        self.audio_stream = AudioStream(peer_ip, audio_port)
        self.audio_stream.audio_level.connect(self.update_audio_level)
        self.audio_stream.call_ended_by_peer.connect(self.handle_peer_ended_call)
        self.audio_stream.start()



    def handle_peer_ended_call(self):
        """Handle peer ending the call"""
        QMessageBox.information(self, "Call Ended", f"{self.peer_username} has ended the call")
        self.end_call(notify_peer=False)


        
    def setup_ui(self):
        """Setup enhanced call window UI"""
        self.setWindowTitle(f"Call with {self.peer_username}")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Status section
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel(f"In call with {self.peer_username}")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        self.duration_label = QLabel("00:00:00")
        self.duration_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.duration_label.setStyleSheet("color: #666;")
        status_layout.addWidget(self.duration_label)
        
        layout.addLayout(status_layout)
        
        # Audio levels section
        levels_layout = QHBoxLayout()
        
        # Local audio level
        local_level_layout = QVBoxLayout()
        local_level_layout.addWidget(QLabel("Your Audio:"))
        self.local_level_bar = QProgressBar()
        self.local_level_bar.setMaximum(100)
        self.local_level_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
        local_level_layout.addWidget(self.local_level_bar)
        levels_layout.addLayout(local_level_layout)
        
    
        layout.addLayout(levels_layout)
        
        # Controls section
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)
        
        # Mute button
        self.mute_button = QPushButton()
        self.mute_button.setCheckable(True)
        self.mute_button.setFixedSize(50, 50)
        self.mute_button.setStyleSheet("""
            QPushButton {
                border: 2px solid #666;
                border-radius: 25px;
                background-color: #fff;
            }
            QPushButton:checked {
                background-color: #ff9800;
            }
        """)
        self.mute_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))
        self.mute_button.toggled.connect(self.handle_mute)
        controls_layout.addWidget(self.mute_button)
        
        # End call button
        self.end_button = QPushButton("End Call")
        self.end_button.setStyleSheet("""
            QPushButton {
                background-color: #ff4444;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff0000;
            }
        """)
        self.end_button.clicked.connect(self.handle_end_button)
        controls_layout.addWidget(self.end_button)
        
        layout.addLayout(controls_layout)
        


    def handle_end_button(self):
        """Handle end call button click"""
        self.end_call(notify_peer=True)
        self.close()




    def setup_duration_timer(self):
        """Setup timer for call duration"""
        self.duration_timer = QTimer(self)
        self.duration_timer.timeout.connect(self.update_duration)
        self.duration_timer.start(1000)  # Update every second
        

    def update_duration(self):
        """Update call duration display"""
        duration = self.call_start_time.secsTo(QDateTime.currentDateTime())
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        self.duration_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        

    def update_audio_level(self, level):
        """Update audio level indicators"""
        self.local_level_bar.setValue(int(level * 100))
        # Remote level is updated via the AudioStream class
        

    
    def handle_mute(self, muted):
        """Handle mute button toggle safely"""
        if hasattr(self, 'audio_stream'):
            self.audio_stream.set_muted(muted)
            if muted:
                self.mute_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolumeMuted))
                self.local_level_bar.setValue(0)
            else:
                self.mute_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaVolume))


                
    def listen_for_end_call(self):
        """Listen for end call signal from peer"""
        self.end_call_socket.settimeout(1)
        while hasattr(self, 'audio_stream') and self.audio_stream.running:
            try:
                data, _ = self.end_call_socket.recvfrom(1024)
                if data.decode() == "END_CALL":
                    self.peer_ended_call()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error in end call listener: {e}")
                


    def peer_ended_call(self):
        """Handle peer ending the call"""
        QMessageBox.information(self, "Call Ended", f"Call has been ended by other user")
        self.end_call(notify_peer=False)
                
    
    def end_call(self, notify_peer=True):
        """End the call and notify peer if specified"""
        if notify_peer and hasattr(self, 'audio_stream'):
            try:
                self.audio_stream.send_end_call(self.peer_username)
            except Exception as e:
                print(f"Error in end_call notification: {e}")
        # Stop the audio stream
        if hasattr(self, 'audio_stream'):
            self.audio_stream.running = False
            self.audio_stream.wait()
        # Stop the timer    
        if self.duration_timer:
            self.duration_timer.stop()
        # Emit the end call signal
        self.call_ended.emit()



    def closeEvent(self, event):
        """Handle window close event (X button)"""
        self.end_call(notify_peer=True)  # Always notify peer when closing window
        super().closeEvent(event)







class Admin_Dash_Window(GUI_Window):
    def __init__(self):
        super().__init__(title="Encrypta - Admin Dashboard")
        self.server = StatusServer()
        self.init_ui()
        self.showMaximized()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Server control panel
        server_panel = QHBoxLayout()
        self.server_status_label = QLabel("Server Status: Stopped")
        self.server_status_label.setStyleSheet("""
            QLabel { font-size: 14px; font-weight: bold; color: #dc3545; }""")
        server_panel.addWidget(self.server_status_label)

        # Start server button
        self.start_server_btn = QPushButton("Start Server")
        self.start_server_btn.setStyleSheet("""
            QPushButton {background-color: #28a745; color: white;
            border: none;border-radius: 5px;padding: 8px 15px;font-size: 14px;}
            QPushButton:hover { background-color: #218838; }""")
        self.start_server_btn.clicked.connect(self.start_server)
        server_panel.addWidget(self.start_server_btn)

        # Stop server button
        self.stop_server_btn = QPushButton("Stop Server")
        self.stop_server_btn.setStyleSheet("""
            QPushButton {background-color: #dc3545;color: white;border: none;
            border-radius: 5px;padding: 8px 15px;font-size: 14px;}
            QPushButton:hover { background-color: #c82333; }""")
        self.stop_server_btn.setEnabled(False)
        self.stop_server_btn.clicked.connect(self.stop_server)
        server_panel.addWidget(self.stop_server_btn)
        
        server_panel.addStretch()
        
        # Refresh and logout buttons
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet("""
            QPushButton {background-color: #17a2b8;color: white;border: none;
            border-radius: 5px;padding: 8px 15px;font-size: 14px;}
            QPushButton:hover { background-color: #138496; }""")
        refresh_button.clicked.connect(self.load_user_data)
        server_panel.addWidget(refresh_button)
        
        logout_button = QPushButton("Log Out")
        logout_button.setStyleSheet("""
            QPushButton {background-color: #6c757d;color: white;border: none;
            border-radius: 5px;padding: 8px 15px;font-size: 14px;}
            QPushButton:hover { background-color: #5a6268; }""")
        logout_button.clicked.connect(self.handle_logout)
        server_panel.addWidget(logout_button)
        
        main_layout.addLayout(server_panel)
        
        # User table
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(3)
        self.table_widget.setHorizontalHeaderLabels(["Username", "IPv4 Address", "Status"])
        self.table_widget.setStyleSheet("""
            QTableWidget {border: 1px solid #ddd;border-radius: 5px;padding: 5px;}
            QHeaderView::section {background-color: #f8f9fa;padding: 5px;
            border: 1px solid #ddd;font-weight: bold;}""")
        
        # Resizing and stretching formatting with containers
        header = self.table_widget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        self.table_widget.setColumnWidth(2, 100)
        main_layout.addWidget(self.table_widget)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        self.load_user_data()

    def start_server(self):
        if self.server.start(self.load_user_data):
            self.server_status_label.setText("Server Status: Running")
            self.server_status_label.setStyleSheet("""QLabel { font-size: 14px; font-weight: bold; color: #28a745; }""")
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
            QMessageBox.information(self, "Success", "Server started successfully")
        else:
            QMessageBox.warning(self, "Error", "Failed to start server")

    def stop_server(self):
        if self.server.stop():
            self.server_status_label.setText("Server Status: Stopped")
            self.server_status_label.setStyleSheet("""QLabel { font-size: 14px; font-weight: bold; color: #dc3545; }""")
            self.start_server_btn.setEnabled(True)
            self.stop_server_btn.setEnabled(False)
            QMessageBox.information(self, "Success", "Server stopped successfully")
        else:
            QMessageBox.warning(self, "Error", "Failed to stop server") 

    def load_user_data(self):
        # Load user data into the table widget from the server's dictionary.
        try:
            # Get real-time status from the server
            server_status = self.server.get_client_status()

            if not server_status:
                self.table_widget.setRowCount(1)
                # Placeholder row
                placeholder_item = QTableWidgetItem("No Users Online")
                placeholder_item.setFlags(placeholder_item.flags() & ~Qt.ItemIsEditable)
                self.table_widget.setItem(0, 0, placeholder_item)
                # Empty other columns
                for col in range(1, 3):
                    empty_item = QTableWidgetItem("")
                    empty_item.setFlags(empty_item.flags() & ~Qt.ItemIsEditable)
                    self.table_widget.setItem(0, col, empty_item)

            self.table_widget.setRowCount(len(server_status))

            for row, (username, user_info) in enumerate(server_status.items()):
                # Username
                username_item = QTableWidgetItem(username)
                username_item.setFlags(username_item.flags() & ~Qt.ItemIsEditable)
                self.table_widget.setItem(row, 0, username_item)

                # IP Address
                ip_address = user_info.get("ip", "Not Connected")
                ip_item = QTableWidgetItem(ip_address)
                ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)
                self.table_widget.setItem(row, 1, ip_item)

                # Status
                status = user_info.get("status", "offline")
                status_item = QTableWidgetItem(status)
                status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)

                if status == "online":
                    status_item.setBackground(QColor("#28a745"))  # Green
                else:
                    status_item.setBackground(QColor("#dc3545"))  # Red
                status_item.setForeground(QColor("white"))
                self.table_widget.setItem(row, 2, status_item)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")


    def handle_logout(self):
        if self.server.is_running:
            self.stop_server()
        self.redirect = Log_In_Window()
        self.redirect.show()
        self.close()

    def closeEvent(self, event):
        if self.server.is_running:
            self.stop_server()
        super().closeEvent(event)

        



class Two_Factor_Dialogue(QDialog):

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.code = None
        self.code_expiry = None
        self.setup_ui()
        self.send_new_code()


    def setup_ui(self):

        self.setWindowTitle("2FA Verification")
        self.setMinimumWidth(400)
        layout = QVBoxLayout()

        self.message_label = QLabel("Please check your email for the 2FA code.")
        self.message_label.setStyleSheet("font-size: 14px; margin: 10px;")
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter 2FA Code")
        self.code_input.setStyleSheet("""QLineEdit {border: 1px solid #ccc;border-radius: 5px;padding: 8px;font-size: 14px;margin: 10px;}
            QLineEdit:focus {border: 1px solid #007BFF;}""")
        layout.addWidget(self.code_input)

        button_layout = QVBoxLayout()
        self.verify_button = QPushButton("Verify Code")
        self.verify_button.setStyleSheet("""QPushButton {background-color: #007BFF;
                                         color: white;border: none; border-radius: 5px;
                                         padding: 8px 16px;font-size: 14px;
                                         font-weight: bold;margin: 5px;}
            QPushButton:hover {background-color: #0056b3;}""")
        self.resend_button = QPushButton("Resend Code")

        self.resend_button.setStyleSheet("""QPushButton {background-color: #6c757d;
                                         color: white;border: none; border-radius: 5px;
                                         padding: 8px 16px;font-size: 14px;
                                         font-weight: bold;margin: 5px;}
            QPushButton:hover {background-color: #5a6268;}""")
        
        button_layout.addWidget(self.verify_button)
        button_layout.addWidget(self.resend_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.verify_button.clicked.connect(self.verify_code)
        self.resend_button.clicked.connect(self.send_new_code)


    def send_new_code(self):
        self.code = str(random.randint(100000, 999999))
        print(self.code)
        self.code_expiry = datetime.now() + timedelta(minutes=1)
        success = self.send_2fa_code(self.username, self.code)
        if success:
            self.message_label.setText("New code sent! Please check your email.")
            self.code_input.clear()
            QMessageBox.information(self, "Code Sent", "A new verification code has been sent to your email.")
        else:
            self.message_label.setText("Failed to send code. Please try again.")
            QMessageBox.warning(self, "Error", "Failed to send verification code. Please try again.")


    def verify_code(self):
        entered_code = self.code_input.text()
        if not entered_code:
            QMessageBox.warning(self, "Error", "Please enter the code.")
            return False
        if datetime.now() > self.code_expiry:
            QMessageBox.warning(self, "Error", "Code has expired. Please request a new code.")
            return False
        if entered_code == self.code:
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Incorrect code. Please try again.")


    def send_2fa_code(self, recipient_email, code):
        sender_email = "encryptasecure@gmail.com"
        app_password = "vampfjvokuqktlzd"  
        try:
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "Your Two-Factor Authentication Code"
            body = f"""
            Hello,

            Your two-factor authentication code is: {code}

            This code will expire in 10 minutes.
            If you didn't request this code, please ignore this email.

            Kind regards,
            Encrypta Secure Intranet
            """
            msg.attach(MIMEText(body, 'plain'))
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, app_password)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"Failed to send 2FA code: {str(e)}")
            return False  
        




def hash_password(password):
    ascii_values = []
    password = str(password)
    for char in password:
        ascii_values.append(ord(char))
    hash_value = len(password) * 7919
    position = 1
    previous_value = 0
    sum = 0
    for value in ascii_values:
        position_factor = position * 31
        hash_value = (hash_value * position_factor + value) % (2**32)
        if position > 1:
            hash_value = (hash_value + value * previous_value * 17) % (2**32)
        sum = sum + value
        position = position + 1
    mix_count = 3
    while mix_count > 0:
        hash_value = (hash_value * 7919) % (2**32)
        hash_value = (hash_value * 6007) % (2**32)
        hash_value = (hash_value + (hash_value ** 2 % 10000) * 31) % (2**32)
        mix_count = mix_count - 1
    result = ""
    while len(result) < 32:
        hash_value = (hash_value * 7919 + 123) % (2**32)
        hex_part = hex(hash_value)[2:]
        while len(hex_part) < 8:
            hex_part = "0" + hex_part
        result = result + hex_part
    return result[:32]





def Validate_Password(password):
    if len(password) < 8:
        return False
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_number = any(char.isdigit() for char in password)
    if not has_upper or not has_lower:
        return False
    if not has_number:
        return False
    return True 





def Validate_Email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, email):
        return True
    else:
        return False
    




def generate_user_id():
    conn = sqlite3.connect("encrypta.db")
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM User")
    user_ids = [row[0] for row in cursor.fetchall()]
    if user_ids:
        next_user_id = (max(user_ids) + 1)
    else:
        next_user_id = 1
    conn.close()
    return next_user_id





def Sign_Up(username, password, confirm_password, email):
    try:
        conn = sqlite3.connect("encrypta.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM User WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            QMessageBox.warning(None, "Error", "Username already taken.")
            return False
        if len(username) < 5:
            QMessageBox.warning(None, "Error", "Username must be at least five characters long.")
            return False
        if not Validate_Password(password):
            QMessageBox.warning(None, "Error", "Invalid password format.\n Password must contain uppercase, lowercase and a number, minimum 8 characters.")
            return False
        if password != confirm_password:
            QMessageBox.warning(None, "Error", "Passwords must match.")
            return False
        if not Validate_Email(email):
            QMessageBox.warning(None, "Error", "Invalid email format.")
            return False
        cursor.execute("SELECT * FROM User WHERE email = ?", (email,))
        if cursor.fetchone() is not None:
            QMessageBox.warning(None, "Error", "Email already exists.")
            return False
        password_hash = hash_password(password)
        user_id = generate_user_id()
        crypto = AsymmetricEncryption()
        crypto.generate_keypair()
        public_key, private_key = crypto.keys_to_string()
        cursor.execute('''
            INSERT INTO User (user_id, username, password_hash, email, role, status, private_key, public_key)
            VALUES (?, ?, ?, ?, "user", "offline", ?, ?)
        ''', (user_id, username, password_hash, email, private_key, public_key))
        conn.commit()
        QMessageBox.information(None, "Success", "Sign-up successful!")
        return True
    except sqlite3.Error as e:
        QMessageBox.critical(None, "Database Error", f"An error occurred: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()





def Log_In(username, password):
    try:
        conn = sqlite3.connect("encrypta.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, email, user_id FROM User WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result is None:
            QMessageBox.warning(None, "Error", "Username does not exist.")
            return False, None
            
        stored_password_hash, user_email, user_id = result
        hashed_password = hash_password(password)
        
        if hashed_password == stored_password_hash:
            two_fa_dialog = Two_Factor_Dialogue(user_email)
            if two_fa_dialog.exec_() == QDialog.Accepted:
                ip_address = get_ip_address()
                
                # Update database
                cursor.execute("UPDATE User SET status = 'online' WHERE username = ?", (username,))
                cursor.execute("SELECT * FROM Session WHERE user_id = ?", (user_id,))
                if cursor.fetchone() is None:
                    cursor.execute("INSERT INTO Session (user_id, ip_address) VALUES (?, ?)", 
                                 (user_id, ip_address))
                else:
                    cursor.execute("UPDATE Session SET ip_address = ? WHERE user_id = ?", 
                                 (ip_address, user_id))
                conn.commit()
                
                # Notify admin server
                send_status_update(username, 'login', ip_address)
                
                return True, username
            return False, username
        else:
            QMessageBox.warning(None, "Error", "Incorrect password entered.")
            return False, None
            
    except sqlite3.Error as e:
        QMessageBox.critical(None, "Database Error", f"An error occurred: {str(e)}")
        return False, None
    finally:
        if conn:
            conn.close()





def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address





class AsymmetricEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        
    def generate_prime(self, min_val: int, max_val: int) -> int:
        # Generate a prime number within the given range
        def is_prime(n: int) -> bool:
            if n < 2:
                return False
            for i in range(2, int(math.sqrt(n)) + 1):
                if n % i == 0:
                    return False
            return True
        
        while True:
            num = random.randint(min_val, max_val)
            if is_prime(num):
                return num
    
    def generate_keypair(self) -> None:
        # Generate two prime numbers
        p = self.generate_prime(100, 1000)
        q = self.generate_prime(100, 1000)
        # Calculate n
        n = p * q
        # Calculate phi (Euler's totient function)
        phi = (p - 1) * (q - 1)
        # Generate public key (e)
        def find_coprime(phi: int) -> int:
            # Find a number coprime with phi
            def gcd(a: int, b: int) -> int:
                while b:
                    a, b = b, a % b
                return a
            e = random.randint(3, phi - 1)
            while gcd(e, phi) != 1:
                e = random.randint(3, phi - 1)
            return e
        
        e = find_coprime(phi)
        
        # Generate private key (d)
        def mod_inverse(e: int, phi: int) -> int:
            # Calculate modular multiplicative inverse
            def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y
            
            _, d, _ = extended_gcd(e, phi)
            return d % phi
        
        d = mod_inverse(e, phi)
        
        # Store the keys
        self.public_key = (e, n)
        self.private_key = (d, n)
    
    def encrypt(self, message: str, public_key: Tuple[int, int]) -> list:
        e, n = public_key
        # Convert each character to its ASCII value and encrypt
        encrypted = []
        for char in message:
            m = ord(char)
            # Encryption formula: c = (m^e) mod n
            c = pow(m, e, n)
            encrypted.append(c)
        return encrypted
    
    
    def decrypt(self, encrypted_msg: list, private_key: Tuple[int, int]) -> str:
        d, n = private_key
        # Decrypt each value and convert back to character
        decrypted = ""
        for c in encrypted_msg:
            # Decryption formula: m = (c^d) mod n
            m = pow(c, d, n)
            decrypted += chr(m)
        return decrypted
    

    def get_public_key(self) -> Tuple[int, int]:
        """Return the public key"""
        return self.public_key
    
    def get_private_key(self) -> Tuple[int, int]:
        """Return the private key"""
        return self.private_key
    
    # Methods for storing and retrieving keys
    def keys_to_string(self) -> Tuple[str, str]:
        """Convert keys to string format for storage"""
        if not self.public_key or not self.private_key:
            return None, None
        
        public_str = f"{self.public_key[0]},{self.public_key[1]}"
        private_str = f"{self.private_key[0]},{self.private_key[1]}"
        return public_str, private_str
    
    # Method to convert string format back to key tuples
    @staticmethod
    def keys_from_string(public_str: str, private_str: str) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Convert string format back to key tuples"""
        try:
            e, n1 = map(int, public_str.split(','))
            d, n2 = map(int, private_str.split(','))
            return (e, n1), (d, n2)
        except:
            return None, None





class ChangePasswordDialog(QDialog):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Change Password")
        self.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        
        # New password input
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setStyleSheet("""
            QLineEdit {padding: 10px;border: 1px solid #ccc;
            border-radius: 4px;font-size: 14px;}""")
        layout.addWidget(QLabel("New Password:"))
        layout.addWidget(self.new_password)
        
        # Password requirements label
        requirements_label = QLabel(
            "Password must contain:\n"
            "- At least 8 characters\n"
            "- At least one uppercase letter\n"
            "- At least one lowercase letter\n"
            "- At least one number"
        )
        requirements_label.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(requirements_label)

        # Confirm password input
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setStyleSheet("""
            QLineEdit {padding: 10px;border: 1px solid #ccc;
            border-radius: 4px;font-size: 14px;}""")
        layout.addWidget(QLabel("Confirm Password:"))
        layout.addWidget(self.confirm_password)
        
        # Change password button
        self.change_btn = QPushButton("Change Password")
        self.change_btn.setStyleSheet("""
            QPushButton {background-color: #007bff;color: white;
            border: none;border-radius: 4px;padding: 10px;
            font-size: 14px;font-weight: bold;margin-top: 10px;}
            QPushButton:hover {background-color: #0056b3;}""")
        self.change_btn.clicked.connect(self.change_password)
        layout.addWidget(self.change_btn)
        self.setLayout(layout)

    
    def change_password(self):
        new_pass = self.new_password.text()
        confirm_pass = self.confirm_password.text()
        # Validate input
        if not new_pass or not confirm_pass:
            QMessageBox.warning(self, "Error", "Please fill in all fields")
            return
        # Check if passwords match
        if new_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return
        # Hash the new password    
        password_hash = hash_password(new_pass)

        if not Validate_Password(new_pass):
             QMessageBox.warning(self,"Error", "Invalid Password")
             return
        # Check if new password is same as current password
        conn = sqlite3.connect('encrypta.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash 
            FROM User 
            WHERE username = ?
        ''', (self.username,))
        current_hash = cursor.fetchone()[0]
        if password_hash == current_hash:
            QMessageBox.warning(self, "Error", "New password cannot be the same as the current password")
            return
        # Update the password in database 
        try:
            conn = sqlite3.connect('encrypta.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE User 
                SET password_hash = ? 
                WHERE username = ?
            ''', (password_hash, self.username))
            conn.commit()
            conn.close()
            
            QMessageBox.information(self, "Success", "Password changed successfully!")
            self.accept()  # Close dialogue with success status
            
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Error", f"Database error: {str(e)}")
            self.reject()  # Close dialogue with failure status




class SymmetricEncryption:
    # Class variable
    def __init__(self):
        self.block_size = 16
    
    # Static method to generate a random key of specified length
    @staticmethod
    def generate_key(length=16):
        """Generate a random encryption key of specified length"""
        import random
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    # Encrypt/decrypt a single block using the key (XOR operation)
    def _transform_block(self, block, key, encrypt=True):
        """Transform a single block using the key"""
        if len(key) != self.block_size:
            raise ValueError(f"Key must be {self.block_size} bytes long")
            
        result = bytearray()
        for b, k in zip(block, key):
            if encrypt:
                val = (b + k) % 256
            else:
                val = (b - k) % 256
            result.append(val)
        return bytes(result)
    
    # Add PKCS7 padding to data to make it multiple of block size
    def pad_data(self, data):
        """Add PKCS7 padding"""
        pad_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([pad_length] * pad_length)
        return data + padding
    
    # Remove PKCS7 padding from data (inverse of padding)
    def unpad_data(self, padded_data):
        """Remove PKCS7 padding"""
        pad_length = padded_data[-1]
        return padded_data[:-pad_length]
    
    # Encrypt data using the key (CBC mode) with PKCS7 padding
    def encrypt(self, key, plaintext):
        """
        Encrypt data using provided key
        
        Args:
            key (bytes): Encryption key
            plaintext (str/bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # Add padding
        padded_data = self.pad_data(plaintext)
        
        # Encrypt each block
        encrypted_blocks = []
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            encrypted_block = self._transform_block(block, key, encrypt=True)
            encrypted_blocks.append(encrypted_block)
        
        return b''.join(encrypted_blocks)
    
    # Decrypt data using the key (CBC mode) and remove padding 
    def decrypt(self, key, ciphertext):
        """
        Decrypt data using provided key
        
        Args:
            key (bytes): Encryption key
            ciphertext (bytes): Data to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        # Decrypt each block
        decrypted_blocks = []
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = self._transform_block(block, key, encrypt=False)
            decrypted_blocks.append(decrypted_block)
        
        # Join blocks and remove padding
        decrypted_data = b''.join(decrypted_blocks)
        return self.unpad_data(decrypted_data)





if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Log_In_Window()
    window.show()  
    app.exec_()
