## Heap Paradise 

<img width="596" height="342" alt="image" src="https://github.com/user-attachments/assets/99b959f1-4f6e-4ad6-be5d-1e452129c7da" />


```
mark@rwx:~/Desktop/Labs/PwnableTW/heap_paradise$ file heap_paradise
heap_paradise: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=0f2c77e0e0c4e37c78f827f6ae317e208bbb202a, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/heap_paradise$ checksec heap_paradise
[*] '/home/mark/Desktop/Labs/PwnableTW/heap_paradise/heap_paradise'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    FORTIFY:    Enabled
```

Here's the decompilation of the two important functions

- allocate_chunk

```c
void allocate_chunk()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      puts("You can't allocate anymore !");
      return;
    }
    if ( !chunks[i] )
      break;
  }
  printf("Size :");
  size = read_int();
  if ( size <= 0x78 )
  {
    chunks[i] = malloc(size);
    if ( !chunks[i] )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Data :");
    read_to_buf(chunks[i], size);
  }
}
```

- free_chunk

```c
void free_chunk()
{
  __int64 v0; // [rsp+8h] [rbp-8h]

  printf("Index :");
  v0 = read_int();
  if ( v0 <= 15 )
    free(chunks[v0]);
}
```

Vulnerability discovered:
- Double Free

The constraint however is:
- We can only make at most 15 allocations
- The size passed to malloc can't exceed `0x78`
- No function to print the heap chunk data
  
The libc version is `2.23` so here it makes use of the fastbin

```
mark@rwx:~/Desktop/Labs/PwnableTW/heap_paradise$ ./ld-2.23.so ./libc.so.6 
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

Having leaks would have made this super easy due to the double free bug, but in this case we have no functions which can print the chunk data.

My goal was to first get a libc leak and i achieved this by doing:
- partial overwrite
- metadata corruption of chunk size to get chunk into unsorted bin
- fastbin corruption to write to `stdout`, so `FSOP` to leak libc address.

With libc gotten I did a fastbin corruption to overwrite `__malloc_hook` with my one gadget address but to trigger it, I needed to cause `free` to crash because it internally called `malloc`, reason i did this was because i had exhausted my allocations.
