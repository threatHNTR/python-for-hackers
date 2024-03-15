# Windows API

## C Data Types and Structures

* In C, we have some data types & structures which are not in Python:

  * Pointers - variables that store memory addresses, not values
  * Structures (struct) - collections of grouped variables under a single type

```py
from ctypes import *

# Importing ctypes module which provides C-compatible data types.
# It is used to directly call functions in DLLs from Python.

# Define boolean values using c_bool.
b0 = c_bool(0)  # False
b1 = c_bool(1)  # True

# Display the boolean values and their corresponding Python values.
print(b0)        # c_bool(False)
print(b0.value)  # False
print(b1)        # c_bool(True)
print(b1.value)  # True

# Define a string using c_char_p.
c0 = c_char_p(b"test")

# Display the value of the string.
print(c0.value)  # b'test'

# When changing the value of pointer instances,
# we are actually changing the memory location the variable is pointing to.

# Display the memory location of c0.
print(c0)  # Prints memory location.

# Change the value of c0.
c0 = c_char_p(b"test1")

# Display the new memory location and value of c0.
print(c0)        # Different memory location.
print(c0.value)  # b'test1'

# We can work with string buffers if the address needs to remain unchanged.
p0 = create_string_buffer(5)  # Create a 5-byte buffer, initialized with null bytes.

# Display the memory location, raw value, and value of the string buffer.
print(p0)         # Prints memory location.
print(p0.raw)     # b'\x00\x00\x00\x00\x00'
print(p0.value)   # b''

# Change the value of p0.
p0.value = b"a"

# Display the raw value and memory location of p0.
print(p0.raw)     # b'a\x00\x00\x00\x00'
print(p0)         # Unchanged memory location.

# Define an integer and create a pointer to it.
i = c_int(42)
pi = pointer(i)

# Display the integer value and the memory address of the pointer.
print(i)    # c_long(42)
print(pi)   # Prints address.

# We can also create a reference to a value using the byref() function,
# and look at the value pointed to using cast().

# Create a reference to p0.
pt = byref(p0)

# Display the address of pt and the value it points to.
print(pt)                                          # Prints address.
print(cast(pt, c_char_p).value)                   # b'a'
print(cast(pt, POINTER(c_int)).contents)          # c_long(97)
# View the integer representation.
```

```py
from ctypes import *

# Importing ctypes module which provides C-compatible data types.

# Define a structure in C using ctypes.
class PERSON(Structure):
    # Structure representing a person with name and age.
    _fields_ = [("name", c_char_p),  # Name as a character pointer.
                ("age", c_int)]      # Age as an integer.

# Create an instance of PERSON structure.
bob = PERSON(b"bob", 30)

# Display the name and age attributes of the structure.
print(bob.name)  # b'bob'
print(bob.age)   # 30

# Define an array type for holding multiple instances of PERSON structure.
person_array_t = PERSON * 3  # Create a list for 3 people.
print(person_array_t)

# Create the actual array of the defined type.
person_array = person_array_t()

# Populate the array with instances of PERSON structure.
person_array[0] = PERSON(b"bob", 30)
person_array[1] = PERSON(b"alice", 20)
person_array[2] = PERSON(b"mallory", 50)

# Iterate through the array and print details of each person.
for person in person_array:
    print(person)
    print(person.name)
    print(person.age)
```

## Interfacing with Windows API

```py
from ctypes import *
from ctypes.wintypes import HWND, LPCSTR, UINT, INT, LPSTR, LPDWORD, DWORD, HANDLE, BOOL

# Importing necessary modules and types from ctypes and ctypes.wintypes.

# For a MessageBox hello-world implementation, refer to Microsoft Win32 API docs.
# MessageBox function in user32.dll.
MessageBoxA = windll.user32.MessageBoxA
MessageBoxA.argtypes = (HWND, LPCSTR, LPCSTR, UINT)
MessageBoxA.restype = INT

# Display the function pointer for MessageBoxA.
print(MessageBoxA)

# Define parameter values.
lpText = LPCSTR(b"World")
lpCaption = LPCSTR(b"Hello")
MB_OK = 0x00000000

# Call the MessageBoxA function.
MessageBoxA(None, lpText, lpCaption, MB_OK)

# Retrieves the name of the user for the current thread.
GetUserNameA = windll.advapi32.GetUserNameA
GetUserNameA.argtypes = (LPSTR, LPDWORD)
GetUserNameA.restype = INT

# Define buffer size and create buffer to store username.
buffer_size = DWORD(8)
buffer = create_string_buffer(buffer_size.value)

# Call GetUserNameA function to retrieve username.
GetUserNameA(buffer, byref(buffer_size))
print(buffer.value)

# For debugging, we can use GetLastError to get the last error code.
error = GetLastError()

if error:
    print(error)
    print(WinError(error))

# Define a Windows-specific structure for RECT.
class RECT(Structure):
    _fields_ = [("left", c_long),
                ("top", c_long),
                ("right", c_long),
                ("bottom", c_long)]

# For GetWindowRect function.
rect = RECT()

GetWindowRect = windll.user32.GetWindowRect
GetWindowRect.argtypes = (HANDLE, POINTER(RECT))
GetWindowRect.restype = BOOL

# Fetch handle using GetForegroundWindow.
hwnd = windll.user32.GetForegroundWindow()
GetWindowRect(hwnd, byref(rect))

# Print the coordinates of the window rectangle.
print(rect.left)
print(rect.top)
print(rect.right)
print(rect.bottom)
```

## Undocumented API Calls

* Not all Windows APIs are documented on MSDN - most of the documented APIs operate in user mode.

* When calling a user mode API, we eventually end up in kernel mode as Windows API are an abstraction layer over the native API.

* The native API calls are defined in NTDLL; can be used for creating exploits as these are lesser used.

* Implementing ```VirtualAlloc``` using Windows API (MSDN):

```py
from ctypes import *
from ctypes import wintypes

# Import necessary modules and types from ctypes and ctypes.wintypes.

# Get kernel32 module for Windows and C types.
kernel32 = windll.kernel32

# Define SIZE_T as c_size_t.
SIZE_T = c_size_t

# Define VirtualAlloc function from kernel32.dll.
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = (wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAlloc.restype = wintypes.LPVOID

# Define values for constants from MSDN.
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Call VirtualAlloc to allocate memory.
ptr = VirtualAlloc(None, 1024 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
error = GetLastError()

# Check for any error during memory allocation.
if error:
    print(error)
    print(WinError(error))

# Print the memory address where memory is allocated.
print("VirtualAlloc: ", hex(ptr))

# To keep the Python process alive.
# Memory allocation can be verified using ProcessHacker.
input()
```

* Implementing ```VirtualAlloc``` using native API (NTDLL):

```py
from ctypes import *
from ctypes import wintypes

# Import necessary modules and types from ctypes and ctypes.wintypes.

# Get ntdll module for Windows and C types.
nt = windll.ntdll

# Define NTSTATUS as DWORD.
NTSTATUS = wintypes.DWORD

# Define NtAllocateVirtualMemory function from ntdll.dll.
NtAllocateVirtualMemory = nt.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = (
    wintypes.HANDLE,                # Process handle
    POINTER(wintypes.LPVOID),       # Base address
    wintypes.ULONG,                 # Zero bits
    POINTER(wintypes.ULONG),        # Region size
    wintypes.ULONG,                 # Allocation type
    wintypes.ULONG                  # Protection
)
NtAllocateVirtualMemory.restype = NTSTATUS

# GetCurrentProcess to get pseudo handle for the current process.
# Pseudo handle defined as a constant.
handle = 0xffffffffffffffff

# Define base address, zero bits, size, and memory allocation constants.
base_address = wintypes.LPVOID(0x0)
zero_bits = wintypes.ULONG(0)
size = wintypes.ULONG(1024 * 12)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Call NtAllocateVirtualMemory to allocate memory.
ptr = NtAllocateVirtualMemory(handle, byref(base_address), zero_bits, byref(size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

# Check if any error occurred during memory allocation.
if ptr != 0:
    print("Error occurred")
    print(ptr)

# Print the memory address where memory is allocated.
print("NtAllocateVirtualMemory: ", hex(base_address.value))

# Wait for user input to keep the Python process alive.
input()
```

## Direct Syscalls

* Every native API call has a specific number that represents it (syscall), these differ between different versions of Windows.

* To make a syscall, we need to move the correct number to a register; in x64, the syscall instruction will then enter kernel mode.

* With direct syscalls in Assembly, we can completely remove any Windows DLL imports:

```py
from ctypes import *
from ctypes import wintypes

# Import necessary modules and types from ctypes and ctypes.wintypes.

# Define SIZE_T as c_size_t and NTSTATUS as DWORD.
SIZE_T = c_size_t
NTSTATUS = wintypes.DWORD

# Define memory allocation constants.
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Define a function to verify syscall success.
def verify(x):
    if not x:
        raise WinError()

# Define the shellcode buffer.
# Shellcode can be obtained from tools like x64dbg and inserted here.
buf = create_string_buffer(b"insert shellcode from x64dbg")
buf_addr = addressof(buf)
print(hex(buf_addr))

# Change memory protection to allow execute operation for the shellcode to work.
VirtualProtect = windll.kernel32.VirtualProtect
VirtualProtect.argtypes = (wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtect.restype = wintypes.INT

old_protection = wintypes.DWORD(0)
protect = VirtualProtect(buf_addr, len(buf), PAGE_EXECUTE_READWRITE, byref(old_protection))
verify(protect)

# Define the syscall function type.
syscall_type = CFUNCTYPE(NTSTATUS, wintypes.HANDLE, POINTER(wintypes.LPVOID), wintypes.ULONG, POINTER(wintypes.ULONG), wintypes.ULONG, wintypes.ULONG)
syscall_function = syscall_type(buf_addr)

# Make the actual syscall to allocate memory.
handle = 0xffffffffffffffff
base_address = wintypes.LPVOID(0x0)
zero_bits = wintypes.ULONG(0)
size = wintypes.ULONG(1024 * 12)

ptr = syscall_function(handle, byref(base_address), zero_bits, byref(size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

# Check for any error occurred during syscall.
if ptr != 0:
    print("Error")
    print(ptr)

# Print the memory address where memory is allocated using syscall.
print("Syscall allocation: ", hex(base_address.value))

# Wait for user input to keep the Python process alive.
input()
```

## Execution from DLL

* DLLs (Dynamic Link Libraries) are similar to executables; these files contain code & data that can be used by multiple programs.

* DLLs cannot be directly executed, but they can be linked or loaded at run time.

* Custom DLL used for this example (can be compiled in Visual Studio):

```c
#include "pch.h"
#include <stdio.h>

// External C functions exposed for DLL export.

extern "C"
{
  // Function to print "hello from dll".
  __declspec(dllexport) void hello()
  {
    puts("hello from dll");
  }

  // Function to calculate the length of a string.
  // Returns the length of the input string.
  __declspec(dllexport) int length(char* input)
  {
    return strlen(input);
  }

  // Function to add two integers.
  // Returns the sum of the two integers.
  __declspec(dllexport) int add(int a, int b)
  {
    return a + b;
  }

  // Function to add two integers and store the result in a pointer.
  // Modifies the value at 'result' to store the sum of 'a' and 'b'.
  __declspec(dllexport) void add_p(int* a, int* b, int* result)
  {
    *result = *a + *b;
  }
};
```

* Using an app like ```Dependency Walker```, we can check the dependencies for our custom DLL.

* Execution from DLL:

```py
from ctypes import *

# Load the DLL.
lib = WinDLL("<path to Dll.dll>")

# Call the hello function from the DLL.
lib.hello()
# prints hello message

# Define argument types and return types for the length function.
lib.length.argtypes = (c_char_p, )
lib.length.restype = c_int

# Call the length function from the DLL with a test string.
str1 = c_char_p(b"test")
print(lib.length(str1))
# 4

# Define argument types and return types for the add function.
lib.add.argtypes = (c_int, c_int)
lib.add.restype = c_int

# Call the add function from the DLL with two integers.
print(lib.add(2, 3))
# 5

# Define argument types for the add_p function.
lib.add_p.argtypes = (POINTER(c_int), POINTER(c_int), POINTER(c_int))

# Create variables to store integers and result.
x = c_int(2)
y = c_int(4)
result = c_int(0)

# Print the result before addition.
print("Before addition ", result.value)

# Call the add_p function from the DLL to add two integers and store the result in 'result'.
lib.add_p(byref(x), byref(y), byref(result))

# Print the result after addition.
print("After addition ", result.value)
```
