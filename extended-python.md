# Extending Python

## Package Manager and Virtual Environments

* We can use existing code packages (modules) to extend the functionality in Python.

* Package manager ```pip``` can be used to install packages:

```shell
pip install pwntools

# View Installed Libraries
pip list

# View Libraries and Version
pip freeze

# Install from requirements.txt
pip install -r requirements.txt
```

* A virtual environment enables in creation of an isolated Python environment, independent of other environments and installed packages; this allows us to use multiple dependencies & versions.

```shell
pip install virtualenv

mkdir virtual-demo

cd virtual-demo

# Start Virtual Environment
python3 -m venv env

# Activate Virtual Environment (prompt includes 'env' now)
source env/bin/activate
python3

# In Virtual Environment, Check Python Used (different from /usr/bin/python3)
which python3

# Install Package in Virtual Environment
pip install pwntools

# Deactivate Virtual Environment
deactivate

```

## SYS

```python
import sys
import time

# Version of Python Interpreter
print(sys.version)

# View Python Binary Used
print(sys.executable)

# Linux
print(sys.platform)

# Takes Input and Prints It Until "exit"
for line in sys.stdin:
  if line.strip() == "exit":
    break
  sys.stdout.write(">> {}".format(line))


for i in range(1,5):
  sys.stdout.write(str(i))
  sys.stdout.flush() # Clears Internal Buffer of File

# Simulate Progress Bar
for i in range(0,51):
  time.sleep(0)
  sys.stdout.write("{} [{}{}]\r".format(i, '#'*i, "."*(50 - i)))
  sys.stdout.flush()
sys.stdout.write("\n")

# List Arguments Supplied to Script (first name will always be name of script)
print(sys.argv)

if len(sys.argv) != 3:
  print("[X] To run {} enter username and password".format(sys.argv[0]))
  sys.exit(5) # Exit with Particular Exit Code

username = sys.argv[1]
password = sys.argv[2]

# Access Path for Modules
print(sys.path)

# List of Modules
print(sys.modules)

# Exit with Particular Exit Code
sys.exit(0)
```

## Requests

```python
import requests

# Make GET Request
x = requests.get('http://httpbin.org/get')

# Take a look at the Headers
print(x.headers)

# Look at Server Header
print(x.headers['Server'])

# Look at Status Code
print(x.status_code)
if x.status_code == 200:
  print("Success!")
elif x.status_code ==404:
  print("Not Found!")

# Time elapsed
print(x.elapsed)
print(x.cookies)

# In Bytes
print(x.content)

# In Unicode
print(x.text)

# Create a Request with Parameters
x = requests.get('http://httpbin.org/get', params={'id':'1'})
print(x.url)

# Specify Parameters in the Request
x = requests.get('httpL//httpbin.org/get?id=2')
print(x.url)

# Print Response in JSON Format
x = requests.get('http://httpbin.org/get', params={'id':'3'}, headers={'Accept':'application/json', 'test_header':'test'})
print(x.text)

# Delete Request
x = requests.delete('http://httpbin.org/delete')
print(x.text)

# POST Request
x = requests.post('http://httpbin.org/post', data={'a':'b', 'c':'d', 'e':'f'})
print(x.text)

# POST Request to Upload File
files = {'file': open('google.jpg', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

# Handle Basic Authorization
x = requests.get('http://httpbin.org/get', auth=('username','password'))
print(x.text)

# Gives SSL Error Unless 'verify=False'
x = requests.get('https://expired.badssl.com', verify=False)

# Prevent Redirects by Specifying 'allow_redirects=False'
x = requests.get('http://github.com', allow_redirects=False)
print(x.headers)

# Specify Timeout to Stop Waiting for a Response
x = requests.get('http://httpbin.org/get'. timeout=0.01)
print(x.content)

# Sessions and Cookies
x = requests.get('http://httpbin.org/cookies', cookies={'a':'b'})
print(x.content)

x = requests.Session()
x.cookies.update({'a':'b'})
print(x.get('http://httpbin.org/cookies').text)

# Pass JSON responses as JSON
x = requests.get('https://api.github.com/events')
print(x.json())

# Get Images as a Response
x = requests.get('https://www.google.com/images/googlelogo.png')
with open('google2.png', 'wb') as f:
  f.write(x.content)
```

## pwntools

```python
from pwn import *

# Example Functions for Buffer Overflow
print(cyclic(50))
print(cyclic_find("laaa"))

# Work with Shell Code or Assembly
print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))

# Start a Process
p = process("/bin/sh")
p.sendline("echo hello;")
# Interactive with Process
p.interactive()

# Interact with Remote Process
r = remote("127.0.0.1", 1234)
r.sendline("hello")
r.interactive() #Interative Session
r.close() # Close the Session

# Packing and Unpacking Numbers - Useful for Exploits and Passing Data Over the Network
print(p32(0x13371337)) #Pack
print(hex(u32(p32(0x13371337)))) #Unpack

# Load Files
l = ELF('/bin/bash')
print(hex(l.address)) # Base Address 
print(hex(l.entry)) # Entry Point
print(hex(l.got['write']))
print(hex(l.plt['write']))

# Jump Somewhere Specific in the Binary
for address in l.search(b'/bin/sh\x00'):
  print(hex(address))

# Search One Specific Address
print(hex(next(l.search(asm('jmp esp')))))

# Encoding and Hashing
print(xor("A", "B")) # XOR
print(b64e(b"test")) # Base64 Encoding
print(b64e(b"dGVxdA==")) # Base64 Decoding
print(md5sumhex(b"hello")) # MD5
print(sha1sumhex(b"hello")) # SHA1

# Low Level Functions
bits = print(bits(b'a')) # Bits for 'a'
unbits = print(unbits(bits)) # Unbits for 'a'
```
