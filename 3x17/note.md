
The binary is statically linked 

```
mark@rwx:~/Desktop/Labs/PwnableTW/3x17$ file 3x17
3x17: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/3x17$ checksec 3x17
[*] '/home/mark/Desktop/Labs/PwnableTW/3x17/3x17'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
mark@rwx:~/Desktop/Labs/PwnableTW/3x17
```

Here's the main function 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *data; // [rsp+8h] [rbp-28h]
  char addr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = ++is_called;
  if ( is_called == 1 )
  {
    write(1u, "addr:", 5uLL);
    read(0, addr, 24uLL);
    data = strtoul(addr);
    write(1u, "data:", 5uLL);
    read(0, data, 24uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    canary();
  return result;
}
```

We have an arbitrary write primitive that allows us to write up to 24 bytes to any address of our choice.

Although `Partial RELRO` is enabled, we cannot target the `Global Offset Table (GOT)` due to the way the binary was compiled.

However, the ELF binary contains a section called `.fini_array`. This section stores pointers to functions that are executed after main returns. So essentially acts like a destructor

```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  _UNKNOWN *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_401EB0(main, v4, &retaddr, sub_4028D0, sub_402960, a3, &v5);
  __halt();
}

__int64 sub_402960()
{
  signed __int64 v0; // rbx

  if ( (&unk_4B4100 - &off_4B40F0) >> 3 )
  {
    v0 = ((&unk_4B4100 - &off_4B40F0) >> 3) - 1;
    do
      (*(&off_4B40F0 + v0--))();
    while ( v0 != -1 );
  }
  return term_proc();
}
```

By overwriting an entry in `.fini_array`, we can redirect execution flow when the program exits.

However, this protection is flawed.

The `is_called` variable is defined as a `char`, meaning it is only 1 byte wide and can store values in the range `0–255`. Because of this, repeated increments will eventually cause it to overflow and wrap back to 0. This integer wraparound allows us to bypass the intended single-use restriction.

To repeatedly trigger the vulnerable logic, we take advantage of the `.fini_array section`.  We overwrite its entries using our arbitrary write primitive:

- `fini_array[1]` is overwritten with the address of `main`
- `fini_array[0]` is overwritten with the address of `sub_402960`

As a result, when main finishes execution, control flow is redirected back to execute a call instruction on `fini_array[0]()` which contains the function address that handles destruction, effectively creating a loop. This allows us to re-enter the program logic multiple times, increment `is_called` until it wraps around to 0, and ultimately bypass the restriction.

Re-entering main alone is not sufficient to achieve code execution. To gain full control and spawn a shell, we need to pivot execution to a controlled ROP chain.

To accomplish this, I wrote my ROP chain at the address `fini_array+0x10`

Since `rbp` contained the address of `fini_array` i made use of a `leave ; ret` gadget for stack pivot

Recall that `leave ; ret` essentially is:
- mov rsp, rbp
- pop rbp
- ret

Doing this makes the program continue execution from the ropchain placed at the "now" current stack

Profit!


