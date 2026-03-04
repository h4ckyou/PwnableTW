## Secret Garden

```
mark@rwx:~/Desktop/Labs/PwnableTW/secretgarden$ file secretgarden
secretgarden: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=cc989aba681411cb235a53b6c5004923d557ab6a, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/secretgarden$ checksec secretgarden
[*] '/home/mark/Desktop/Labs/PwnableTW/secretgarden/secretgarden'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
```

From the menu on executing the program we can tell it's likely a heap challenge

```
mark@rwx:~/Desktop/Labs/PwnableTW/secretgarden$ ./secretgarden

☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ 
☆          Secret Garden          ☆ 
☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ 

  1 . Raise a flower 
  2 . Visit the garden 
  3 . Remove a flower from the garden
  4 . Clean the garden
  5 . Leave the garden

Your choice : 5
See you next time.
mark@rwx:
```

One thing about the program is that we control the size of allocations (name)

```c
int raise_flower()
{
  flower_t *mem; // rbx
  void *name; // rbp
  flower_t **array; // rcx
  int idx; // edx
  unsigned int size; // [rsp+4h] [rbp-24h] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  size = 0;
  if ( (unsigned int)count > 99 )
    return puts("The garden is overflow");
  mem = (flower_t *)malloc(0x28uLL);
  *(_QWORD *)&mem->in_use = 0LL;
  mem->name = 0LL;
  *(_QWORD *)mem->color = 0LL;
  *(_QWORD *)&mem->color[8] = 0LL;
  *(_QWORD *)&mem->color[16] = 0LL;
  __printf_chk(1LL, "Length of the name :");
  if ( (unsigned int)__isoc99_scanf("%u", &size) == -1 )
    exit(-1);
  name = malloc(size);
  if ( !name )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  __printf_chk(1LL, "The name of flower :");
  read(0, name, size);
  mem->name = (char *)name;
  __printf_chk(1LL, "The color of the flower :");
  __isoc99_scanf("%23s", mem->color);
  mem->in_use = 1;
  if ( flowers[0] )
  {
    array = &flowers[1];
    idx = 1;
    while ( *array )
    {
      ++idx;
      ++array;
      if ( idx == 100 )
        goto inc;
    }
  }
  else
  {
    idx = 0;
  }
  flowers[idx] = mem;
inc:
  ++count;
  return puts("Successful !");
}
```

The function `visit_garden` would only print chunks where their `in_use` flag is set

```c
void visit_garden()
{
  __int64 idx; // rbx
  flower_t *mem; // rax

  idx = 0LL;
  if ( count )
  {
    do
    {
      mem = flowers[idx];
      if ( mem )
      {
        if ( mem->in_use )
        {
          __printf_chk(1LL, "Name of the flower[%u] :%s\n", idx, mem->name);
          __printf_chk(1LL, "Color of the flower[%u] :%s\n", idx, flowers[idx]->color);
        }
      }
      ++idx;
    }
    while ( idx != 100 );
  }
  else
  {
    puts("No flower in the garden !");
  }
}
```

And finally the vulnerability is at `remove_flower` where after freeing the `name` it doesn't set the pointer to `null` only the `in_use` flag is, this causes Use After Free.

```c
int remove_flower()
{
  flower_t *v1; // rax
  unsigned int idx; // [rsp+4h] [rbp-14h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( !count )
    return puts("No flower in the garden");
  __printf_chk(1LL, "Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &idx);
  if ( idx <= 99 && (v1 = flowers[idx]) != 0LL )
  {
    v1->in_use = 0;
    free(flowers[idx]->name);
    return puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    return 0;
  }
}
```

My attack chain was to first gain libc leak, this was easy to achieve because we controlled the size of allocation, so just allocate a chunk that's greater than the maximum size the fastbin can hold, free it and reallocate and you get the leak.

Heap leak was gotten as well due to the fact there's a UAF bug, so make it the case such that two pointers points to the same memory which is already free.

The pointers `in_use` flag is also set while the other isn't, this makes it possible to get the heap leak.

And for code execution I did a fastbin attack and modified `_IO_list_all` to my fake file structure on the heap.

Although initially i targetted writing to `__malloc_hook` but the one gadget constraint wasn't satisfied.
