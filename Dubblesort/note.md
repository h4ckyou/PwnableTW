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

There's an out of bound write since it doesn't verify that the number of values we want to sort isn't greater than the size of the numbers array, but the presence of canary makes it a bit tough

We can bypass the canary check by making `scanf` not overwrite the original value using `+`

To leak memory we leverage the uninitialized memory chained with not null termination making `printf` leak adjacent memory using the `%s` specifier

The binary does sort the provided integers so we give it values such that the canary doesn't get sorted

Profit.
