# Importing necessary libraries
from burp import IBurpExtender, ITab
from javax import swing
from java.awt import BorderLayout
import sys, time, socket, threading
from exceptions_fix import FixBurpExeceptions

# Class definition for the BurpExtender
class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Initializing variables
        self.clicked = False
        self.response_data = None
        self.kill_threads = False

        # Redirecting stdout to Burp's output
        sys.stdout = callbacks.getStdout()

        self.callbacks = callbacks

        self.callbacks.setExtensionNAme("Bind Shell")

        # Creating Swing GUI components
        self.tab = swing.JPanel(BorderLayout())

        text_panel = swing.JPanel()
        box_vertical = swing.Box.createVerticalBox()

        # IP Address input field
        box_horizontal = swing.Box.createHorizontalBox()
        self.ip_address = swing.JTextArea('', 2, 100)
        self.ip_address.setLineWrap(True)
        self.ip_address.border = swing.BorderFactory.createTitledBorder("IP Address:")
        box_horizontal.add(self.ip_address)
        box_vertical.add(box_horizontal)

        # Command input field
        box_horizontal = swing.Box.createHorizontalBox()
        self.user_command = swing.JTextArea('', 2, 100)
        self.user_command.setLineWrap(True)
        self.user_command.border = swing.BorderFactory.createTitledBorder("Command:")
        box_horizontal.add(self.user_command)
        box_vertical.add(box_horizontal)

        # Buttons for Connect, Send, and Disconnect
        box_horizontal = swing.Box.createHorizontalBox()
        button_panel = swing.JPanel()

        self.connect_button = swing.JButton('[ --- Connect --- ]', actionPerformed=self.connect)
        self.send_button = swing.JButton('[ --- Send Command --- ]', actionPerformed=self.send)
        self.disconnect_button = swing.JButton('[ --- Disconnect --- ]', actionPerformed=self.disconnect)

        self.disconnect_button.enabled = False
        self.send_button.enabled = False

        button_panel.add(self.connect_button)
        button_panel.add(self.send_button)
        button_panel.add(self.disconnect_button)

        box_horizontal.add(button_panel)
        box_vertical.add(box_horizontal)

        # Output area for displaying responses
        box_horizontal = swing.Box.createHorizontalBox()
        self.output = swing.JTextArea('', 25, 100)
        self.output.setLineWrap(True)
        self.output.setEditable(False)

        scroll = swing.JScrollPane(self.output)

        box_horizontal.add(scroll)
        box_vertical.add(box_horizontal)

        text_panel.add(box_vertical)

        self.tab.add(text_panel)

        # Adding the tab to Burp's UI
        callbacks.addSuiteTab(self)
        return
    
    # Function to set the tab caption
    def getTabCaption(self):
        return "Bind Shell"
    
    # Function to get the UI component
    def getUiComponent(self):
        return self.tab
    
    # Function to handle sending the command
    def send(self, event):
        self.clicked = True
        time.sleep(0.5)
        self.output.text = self.response_data
    
    # Thread for sending commands
    def send_thread(self):
        while True:
            if self.kill_threads:
                sys.exit()
            
            if self.clicked:
                self.clicked = False
                self.s.send(self.user_command.text)

    # Thread for receiving responses
    def recv_thread(self):
        while True:
            if self.kill_threads:
                self.exit()
            data = self.s.recv(4096).replace("Enter Command > ", "")
            if data:
                self.response_data = data

    # Function to handle connecting to the bind shell
    def connect(self, event):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.ip_address.text, 1234))
            self.kill_threads = False

            threading.Thread(target=self.send_thread).start()
            threading.Thread(target=self.recv_thread).start()

            self.connect_button.enabled = False
            self.disconnect_button.enabled = True
            self.send_button.enabled = True
            self.ip_address.enabled = False

            self.output.text = "Connected to Bind Shell!"
        except:
            self.output.text = "Could not connect, try again!"
    
    # Function to handle disconnecting from the bind shell
    def disconnect(self, event):
        self.s.send("exit")
        self.s.close()
        self.kill_threads = True
    
# Fixing exceptions in Burp
FixBurpExeceptions()
