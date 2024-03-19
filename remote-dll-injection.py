from ctypes import *
from ctypes import wintypes

# Load required functions from kernel32.dll
kernel32 = windll.kernel32

# Define required data types and function signatures

# OpenProcess function
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

# VirtualAllocEx function
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

# WriteProcessMemory function
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

# GetModuleHandleA function
GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR,)
GetModuleHandle.restype = wintypes.HANDLE

# GetProcAddress function
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = wintypes.LPVOID

# CreateRemoteThread function
CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

# Define constants
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

# Path to the DLL to be injected
dll = b"C:\\Users\\sv\\Documents\\hello_world.dll"

# Process ID of the target process
pid = 2160

# Obtain a handle to the target process
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not handle:
    raise WinError()
print("Handle obtained - {0:X}".format(handle))

# Allocate memory in the target process
remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not remote_memory:
    raise WinError()
print("Memory allocated - {0:X}".format(remote_memory))

# Write the DLL path to the allocated memory in the target process
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)
if not write:
    raise WinError()
print("Bytes written - {}".format(dll))

# Obtain the address of the LoadLibraryA function from kernel32.dll
load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
print("LoadLibraryA address - ", hex(load_lib))

# Create a remote thread in the target process to load the DLL
rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)
