### Dubblesort

All protections are enabled

```
mark@rwx:~/Desktop/Labs/PwnableTW/dubblesort$ file dubblesort
dubblesort: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=12a217baf7cbdf2bb5c344ff14adcf7703672fb1, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/dubblesort$ checksec dubblesort
[*] '/home/mark/Desktop/Labs/PwnableTW/dubblesort/dubblesort'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
mark@rwx:~/Desktop/Labs/PwnableTW/dubblesort$
```

Here's the main function

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  _BYTE *v4; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int v8; // [esp+18h] [ebp-74h] BYREF
  _BYTE v9[32]; // [esp+1Ch] [ebp-70h] BYREF
  _BYTE buf[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int v11; // [esp+7Ch] [ebp-10h]

  v11 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");
  read(0, buf, 0x40u);
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &v8);
  v3 = v8;
  if ( v8 )
  {
    v4 = v9;
    for ( i = 0; i < v8; ++i )
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      v3 = v8;
      v4 += 4;
    }
  }
  sub_931(v9, v3);
  puts("Result :");
  if ( v8 )
  {
    for ( j = 0; j < v8; ++j )
      __printf_chk(1, "%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v11 )
    sub_BA0();
  return result;
}
```

There is an out-of-bounds write vulnerability because the program fails to verify that the number of integers requested for sorting does not exceed the size of the allocated array.

Although a stack canary is present, it can be bypassed. By supplying a `+` to `scanf`, we prevent it from overwriting the existing value, effectively preserving the original canary.

To leak memory, we exploit uninitialized stack data combined with the absence of proper null termination. When `printf` is invoked with the `%s` specifier, it continues reading until it reaches a null byte but in this case since there's no null termination it would keep reading past the intended buffer boundary, leaking adjacent memory contents.

Since the binary sorts the provided integers, we carefully choose input values such that the canary remains in the correct position and is not disrupted by the sorting operation.

And with the canary preserved and libc leak gotten we then perform `ret2libc`

Profit.
