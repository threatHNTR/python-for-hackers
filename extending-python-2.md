# Extending Python 2

## BeautifulSoup

```py
import requests
from bs4 import BeautifulSoup

# Fetch the webpage content.
page = requests.get("https://247ctf.com/scoreboard")

# Analyze the HTML structure of the page.
# Use BeautifulSoup to parse HTML.
soup = BeautifulSoup(page.content, "html.parser")

# Print only the text, excluding HTML elements.
print(soup.text)

# Print the title string of the webpage.
print(soup.title.string)

# Find the first link in the page.
print(soup.find("a"))

# Find and print all links along with their href attributes.
for link in soup.find_all("a"):
    print(link)
    print(link.get("href"))

# Fetch elements with a particular id.
print(soup.find(id="fetch-error"))

# Print elements with a particular class.
# Note: class is a reserved keyword in Python, so class_ is used.
print(soup.find(class_="nav-link"))

# Get the table from the page.
table = soup.find("table")
table_body = table.find("tbody")
rows = table_body.find_all("tr")

# Iterate through table rows and extract data.
for row in rows:
    cols = [x.text.strip() for x in row.find_all("td")]
    # Multiple columns in each row of the table.
    # .text.strip() cleans out the contents.
    print("{} is in {} place with {}".format(cols[2], cols[0], cols[4]))
```

## Py2exe

```py
# py2exe can be used to bundle a Python program into an executable
# for running on a machine without a Python environment
# Assuming the program to be bundled ('hello.py') is already written

from py2exe import freeze

# Bundle the 'hello.py' script into an executable
# 'console' specifies the script to be bundled
# 'options' define py2exe options like bundling files and compression
freeze(
    console=[{'script': 'hello.py'}],
    options={'py2exe': {'bundle_files': 1, 'compressed': True}},
    zipfile=None
)
# The executable will be created in the destination subfolder specified when running the program

## Sockets

import socket

# Get the IP address of a domain
ip = socket.gethostbyname('247ctf.com')
print(ip)

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET is for IPv4 and SOCK_STREAM is for TCP

# Connect to a host on port 80
s.connect(("247ctf.com", 80))

# Send a HEAD request to the server
s.sendall(b"HEAD / HTTP/1.1\r\nHost: 247ctf.com\r\n\r\n")

# Print the received data (response from the server)
print(s.recv(1024).decode())
# 1024 bytes is the maximum amount of data received at once

# Close the socket connection
s.close()

# For creating and binding socket connections
client = False
server = False
port = 8080

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if server:
    # Bind the socket to the localhost and the specified port
    s.bind(("127.0.0.1", port))
    # Listen for incoming connections
    s.listen()
    while True:
        # Accept a connection
        connect, addr = s.accept()
        # Send data to the connected client
        connect.send(b"Connected to socket")
        connect.close()

if client:
    # Connect to the server
    s.connect(("127.0.0.1", port))
    # Receive data from the server
    print(s.recv(1024))
    s.close()

# Check if a server is able to send data (client = False, server = True)
# Then test if a client is able to receive data (client = True, server = False)

# We can also scan common ports and connect to any open port
for port in [22, 80, 139, 443, 445, 8080]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    # Set the timeout for waiting to 1 second
    result = s.connect_ex(("127.0.0.1", port))
    # Connect to the specified port and handle any errors
    if result == 0:
        print("Port {} is open".format(port))
    else:
        print("Port {} is closed".format(port))
    s.close()
```

## Scapy

```py
from scapy.all import *

# Library for packet manipulation
# We can craft packets at different layers as well

# Create IP and ICMP layers
ip_layer = IP(dst="247ctf.com")
icmp_layer = ICMP()
# Stack layers to create a packet
packet = ip_layer / icmp_layer

# Send the crafted packet and receive the response
r = send(packet)
# Print the details of the crafted packet
print(packet.show())

# To review the exact packet on Wireshark
# wireshark(packet)

# Send and receive packets to broadcast destination using ARP target address
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.10.0/24"), timeout=3, verbose=False)
# Print hosts which answered to sent packets
for i in ans:
    print(i[1].psrc)  # Print only IP

# Port scanner by identifying 3-way handshake
SYN = 0x02
RST = 0x04
ACK = 0x10

for port in [22, 80, 139, 443, 445, 8080]:
    # Sending SYN to destination with a randomly generated source port
    tcp_connect = sr1(IP(dst="127.0.0.1") / TCP(sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=False)

    # Successful handshake
    if tcp_connect and tcp_connect.haslayer(TCP):
        response_flags = tcp_connect.getlayer(TCP).flags
        if response_flags == (SYN + ACK):
            snd_rst = send(IP(dst="127.0.0.1") / TCP(sport=RandShort(), dport=port, flags="AR"), verbose=False)
            print("Port {} is open".format(port))
        elif response_flags == (RST + ACK):
            print("Port {} is closed".format(port))
    else:
        print("Port {} is closed".format(port))

# Packet sniffing
from scapy.layers.http import HTTPRequest

# Define a callback function for packet processing
def process(packet):
    if packet.haslayer(HTTPRequest):
        print(packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode())

# Use the built-in sniff function for packet sniffing based on the callback
sniff(filter="port 80", prn=process, store=False)

# Analyze pcap file
scapy_cap = rdpcap("test.pcap")
for packet in scapy_cap:
    if packet.getlayer(ICMP):
        print(packet.load)  # Extract data from ICMP packets
```

## Subprocess

```py
import subprocess

# Pass commands to be run as a list
# Use shell=True for invoking a shell
# This command opens the Windows calculator
subprocess.call(["calc"])

# check_call checks for errors
# Here, it tries to execute a non-existing command, which raises an error
# The error is captured and stored in the 'out' variable
out = subprocess.check_call(["cmd", "/c" "asd"])

# check_output captures the output of the command
# Here, it executes the 'whoami' command and captures the output
out = subprocess.check_output(["cmd", "/c", "whoami"])
# Print the captured output after decoding it from bytes to string
print("Output: {}".format(out.decode()))
```

## Threading

```py
import threading
import time
from datetime import datetime

def sleeper(i):
    """
    Function that sleeps for 'i' seconds.
    """
    print("hello from %d!" % i)
    time.sleep(i)
    print("goodbye from %d!" % i)

# Print the current time
print(datetime.now().strftime("%H:%M:%S"))

"""
If we call sleeper() multiple times,
we have to wait until it is completed.
By using threading, we can run it
on parallel threads for concurrent execution.
"""
# Start threads for the sleeper function with different arguments
threading.Thread(target=sleeper, args=(0,)).start()
threading.Thread(target=sleeper, args=(2,)).start()
threading.Thread(target=sleeper, args=(4,)).start()

# We can add a delay to it
# Start a thread with a timer to call the sleeper function after 1 second
threading.Timer(1, sleeper, [1]).start()

# Print the current time
print(datetime.now().strftime("%H:%M:%S"))

"""
Print output and get input at the same time.
"""
stop = False

def input_thread():
    """
    Function to get user input.
    """
    global stop
    while True:
        user_input = input("Should we stop?: ")
        print("User says: {}".format(user_input))
        if user_input == "yes":
            stop = True
            break

def output_thread():
    """
    Function to continuously print output until user stops.
    """
    global stop
    count = 0
    while not stop:
        print(count)
        count += 1
        time.sleep(1)

# Start threads for input and output simultaneously
t1 = threading.Thread(target=input_thread).start()
t2 = threading.Thread(target=output_thread).start()

```

```py
import threading

# Thread locking demo
# Pop elements from a list using synchronized threads
# Ensures that no two threads pop the same element, following a sequential order

data_lock = threading.Lock()  # Create a lock object
data = [x for x in range(1000)]  # Initialize a list with elements

def sync_consume_thread():
    """
    Function for synchronized thread consumption.
    """
    global data_lock, data
    while True:
        data_lock.acquire()  # Acquire the lock before accessing the shared resource
        if len(data) > 0:  # Check if there are elements in the list
            print(threading.current_thread().name, data.pop())  # Pop an element from the list and print
        data_lock.release()  # Release the lock after accessing the shared resource

# Start three threads for synchronized consumption
threading.Thread(target=sync_consume_thread).start()
threading.Thread(target=sync_consume_thread).start()
threading.Thread(target=sync_consume_thread).start()
```

## Pycryptodome

```py
# Install pycryptodome using pip
from Crypto.Random import get_random_bytes

# Generate a random 256-bit key
key = get_random_bytes(32)
print("Random key:", key)

from Crypto.Protocol.KDF import PBKDF2

# Generate a key using PBKDF2 with a password and a random salt
salt = get_random_bytes(32)
password = "password123"
key = PBKDF2(password, salt, dkLen=32)
print("Derived key:", key)

# Encryption using AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

to_encrypt = b"encrypt this string"
cipher = AES.new(key, AES.MODE_CBC)
print("Initialization vector (IV):", cipher.iv)
ciphered_data = cipher.encrypt(pad(to_encrypt, AES.block_size))
print("Ciphered data:", ciphered_data)

# Decryption using AES
cipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
plaintext_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
print("Decrypted data:", plaintext_data)

# Using stream ciphers
from Crypto.Cipher import ARC4

cipher = ARC4.new(key)
encrypted = cipher.encrypt(to_encrypt)
print("Encrypted data using ARC4:", encrypted)

cipher = ARC4.new(key)
plaintext = cipher.decrypt(encrypted)
print("Decrypted data using ARC4:", plaintext)

# Using asymmetric encryption with RSA
from Crypto.PublicKey import RSA

# Generate a 1024-bit RSA key pair
key = RSA.generate(1024)
encrypted_key = key.exportKey(passphrase=password)
print("Encrypted key:", encrypted_key)

pub = key.publickey()
print("Public key:", pub.exportKey())

# Inbuilt functions to check capabilities of the RSA key pair
print("Can encrypt:", key.can_encrypt())
print("Can sign:", key.can_sign())
print("Has private key:", key.has_private())
print("Public key has private key:", pub.has_private())

from Crypto.Cipher import PKCS1_OAEP

# Encryption and decryption using RSA
cipher = PKCS1_OAEP.new(pub)
encrypted = cipher.encrypt(to_encrypt)
print("Encrypted data using RSA:", encrypted)

cipher = PKCS1_OAEP.new(key)
plaintext = cipher.decrypt(encrypted)
print("Decrypted data using RSA:", plaintext)

# Verifying digital signatures
from Crypto.Hash import SHA512

plain_hash = SHA512.new(to_encrypt).digest()
hashed = int.from_bytes(plain_hash, byteorder='big')
print("Hashed data:", hashed)

signature = pow(hashed, key.d, key.n)
print("Digital signature:", signature)

signature_hash = pow(signature, key.e, key.n)
print("Signature hash:", signature_hash)

print("Signature validation:", hashed == signature_hash)
# If True, the signature is valid
```

## Argparse

```py
import argparse

# Create an ArgumentParser object with a description
parser = argparse.ArgumentParser(description="Example Python CLI")

# Define positional arguments
parser.add_argument("name", help="Enter name", type=str)
parser.add_argument("power", help="Enter power", type=int)

# Define optional arguments with flags and default values
parser.add_argument("-bh", "--blackhat", default=False, action="store_true")
parser.add_argument("-wh", "--whitehat", default=True, action="store_false")
# You can specify required=True if the parameter is mandatory

# Define an argument with specific choices
parser.add_argument("-ht", "--hackertype", choices=["whitehat", "blackhat", "greyhat"])

# Parse the command-line arguments
args = parser.parse_args()
print(args)

# Determine the hacker type based on the provided options
if args.blackhat:
    hacker_type = "blackhat"
elif args.whitehat:
    hacker_type = "whitehat"
else:
    hacker_type = "unknown"

# Print the name and hacker type
print("{} is a {} hacker".format(args.name, hacker_type))
```
