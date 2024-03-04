# Extending Python

## Package Manager and Virtual Environments

* We can use existing code packages (modules) to extend the functionality in Python.

* Package manager ```pip``` can be used to install packages:

```shell
# Install the "pwntools" library using pip
pip install pwntools

# List all installed Python packages along with their versions
pip list

# Display installed packages in a format suitable for generating requirements.txt
pip freeze

# Install Python packages listed in the requirements.txt file
pip install -r requirements.txt
```

* A virtual environment enables in creation of an isolated Python environment, independent of other environments and installed packages; this allows us to use multiple dependencies & versions.

```shell
# Install the virtualenv package using pip
pip install virtualenv

# Create a directory named 'virtual-demo'
mkdir virtual-demo

# Move into the 'virtual-demo' directory
cd virtual-demo

# Create a virtual environment named 'env' using Python 3
python3 -m venv env

# Activate the virtual environment (the prompt should include 'env' now)
source env/bin/activate

# Start Python interpreter within the activated virtual environment
python3

# In the virtual environment, check the Python executable being used (it should be different from /usr/bin/python3)
which python3

# Install the pwntools package within the virtual environment
pip install pwntools

# Deactivate the virtual environment
deactivate
```

## SYS

```python
import sys
import time

# Print the version of the Python interpreter
print(sys.version)

# Print the path to the Python binary used
print(sys.executable)

# Print the platform information (e.g., Linux)
print(sys.platform)

# Takes input from the user and prints it until "exit" is entered
for line in sys.stdin:
    if line.strip() == "exit":
        break
    sys.stdout.write(">> {}".format(line))

# Print numbers 1 to 4
for i in range(1, 5):
    sys.stdout.write(str(i))
    sys.stdout.flush()  # Clears the internal buffer of the file

# Simulate a progress bar
for i in range(0, 51):
    time.sleep(0)
    sys.stdout.write("{} [{}{}]\r".format(i, '#' * i, "." * (50 - i)))
    sys.stdout.flush()
sys.stdout.write("\n")

# List the arguments supplied to the script (the first name will always be the name of the script itself)
print(sys.argv)

# Check if the correct number of arguments is supplied to the script
if len(sys.argv) != 3:
    print("[X] To run {}, enter username and password".format(sys.argv[0]))
    sys.exit(5)  # Exit with a particular exit code

# Access the path for modules
print(sys.path)

# List of modules
print(sys.modules)

# Exit with a particular exit code
sys.exit(0)
```

## Requests

```python
import requests

# Make a GET Request to http://httpbin.org/get and store the response in variable x
x = requests.get('http://httpbin.org/get')

# Print the response headers
print(x.headers)

# Print the value of the Server header from the response
print(x.headers['Server'])

# Print the HTTP status code of the response
print(x.status_code)

# Print a success message if the status code is 200; otherwise, print a not found message if it's 404
if x.status_code == 200:
    print("Success!")
elif x.status_code == 404:
    print("Not Found!")

# Print the time elapsed for the request
print(x.elapsed)

# Print the cookies received in the response
print(x.cookies)

# Print the response content in bytes
print(x.content)

# Print the response content in Unicode
print(x.text)

# Make a GET Request to http://httpbin.org/get with parameters and print the URL
x = requests.get('http://httpbin.org/get', params={'id': '1'})
print(x.url)

# Make a GET Request to http://httpbin.org/get with parameters specified in the URL and print the URL
x = requests.get('http://httpbin.org/get?id=2')
print(x.url)

# Make a GET Request to http://httpbin.org/get with parameters and headers in JSON format, and print the response
x = requests.get('http://httpbin.org/get', params={'id': '3'}, headers={'Accept': 'application/json', 'test_header': 'test'})
print(x.text)

# Make a DELETE Request to http://httpbin.org/delete and print the response
x = requests.delete('http://httpbin.org/delete')
print(x.text)

# Make a POST Request to http://httpbin.org/post with form data and print the response
x = requests.post('http://httpbin.org/post', data={'a': 'b', 'c': 'd', 'e': 'f'})
print(x.text)

# Make a POST Request to http://httpbin.org/post to upload a file and print the response
files = {'file': open('google.jpg', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

# Make a GET Request to http://httpbin.org/get with basic authentication and print the response
x = requests.get('http://httpbin.org/get', auth=('username', 'password'))
print(x.text)

# Make a GET Request to a URL with an expired SSL certificate, ignoring SSL verification errors
x = requests.get('https://expired.badssl.com', verify=False)

# Make a GET Request to http://github.com without allowing redirects and print the response headers
x = requests.get('http://github.com', allow_redirects=False)
print(x.headers)

# Make a GET Request to http://httpbin.org/get with a timeout of 0.01 seconds and print the response content
x = requests.get('http://httpbin.org/get', timeout=0.01)
print(x.content)

# Make a GET Request to http://httpbin.org/cookies with specified cookies and print the response content
x = requests.get('http://httpbin.org/cookies', cookies={'a': 'b'})
print(x.content)

# Use a session to persist cookies across requests and print the response content
x = requests.Session()
x.cookies.update({'a': 'b'})
print(x.get('http://httpbin.org/cookies').text)

# Make a GET Request to https://api.github.com/events and print the response content in JSON format
x = requests.get('https://api.github.com/events')
print(x.json())

# Make a GET Request to download an image and save it as 'google2.png'
x = requests.get('https://www.google.com/images/googlelogo.png')
with open('google2.png', 'wb') as f:
    f.write(x.content)
```

## pwntools

```python
from pwn import *

# Generate a cyclic pattern of 50 characters
print(cyclic(50))

# Find the offset of the cyclic pattern where "laaa" starts
print(cyclic_find("laaa"))

# Generate shellcode for spawning a shell
print(shellcraft.sh())

# Disassemble shellcode and print hexdump
print(hexdump(asm(shellcraft.sh())))

# Start a new process for /bin/sh
p = process("/bin/sh")
# Send a command to the shell process
p.sendline("echo hello;")
# Interact with the process (allows interaction with the shell)
p.interactive()

# Connect to a remote process
r = remote("127.0.0.1", 1234)
# Send a message to the remote process
r.sendline("hello")
# Enter interactive mode to interact with the remote process
r.interactive()
# Close the connection to the remote process
r.close()

# Pack and unpack numbers for binary data manipulation
print(p32(0x13371337)) # Pack
print(hex(u32(p32(0x13371337)))) # Unpack

# Load binary files for analysis
l = ELF('/bin/bash')
print(hex(l.address)) # Base Address 
print(hex(l.entry)) # Entry Point
print(hex(l.got['write']))
print(hex(l.plt['write']))

# Search for specific strings or instructions within the binary
for address in l.search(b'/bin/sh\x00'):
    print(hex(address))

# Search for a specific instruction (e.g., jmp esp)
print(hex(next(l.search(asm('jmp esp')))))

# Perform encoding and hashing operations
print(xor("A", "B")) # XOR
print(b64e(b"test")) # Base64 Encoding
print(b64e(b"dGVxdA==")) # Base64 Decoding
print(md5sumhex(b"hello")) # MD5
print(sha1sumhex(b"hello")) # SHA1

# Low-level bit manipulation functions
bits = print(bits(b'a')) # Bits for 'a'
unbits = print(unbits(bits)) # Unbits for 'a'
```
